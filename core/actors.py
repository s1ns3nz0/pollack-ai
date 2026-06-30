"""공격자 프로필(`actors/`) 쓰기/읽기 게이트 + 저장소 계약(spec #2).

`exp/` 게이트 패턴 복제·확장 — 비대칭 신뢰(TP-only 적립 + explicit 한정 priority
영향) 로 본선 AI 공방전의 식별·예측 기반을 마련한다.

Spec: docs/superpowers/specs/2026-06-30-attacker-profile-store-design.md
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
import hashlib
from typing import Protocol, runtime_checkable

from pydantic import BaseModel

from core.actor_fingerprint import (
    is_empty_fingerprint,
    resolve_actor_id,
)
from core.exceptions import SOCPlatformError
from core.models import (
    ActorIocPattern,
    ActorKillChainStep,
    ActorProfile,
    ActorTtpStat,
    Alert,
    EnvVerdict,
    Provenance,
)
from utils.logging import get_logger

_KILL_CHAIN_CAP = 50


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class ActorWriteStatus(StrEnum):
    """actors 쓰기 결과."""

    WRITTEN = "written"
    REJECTED_NOT_TP = "rejected_not_tp"
    REJECTED_EMPTY = "rejected_empty"
    REJECTED_STORE_ERROR = "rejected_store_error"
    REJECTED_NO_ACTOR = "rejected_no_actor"  # spec B-1: outcome 측정 시 actor 미존재


class ActorWriteDecision(BaseModel):
    """actors 쓰기 게이트 결과."""

    status: ActorWriteStatus
    actor_id: str = ""
    reason: str = ""

    @property
    def written(self) -> bool:
        return self.status == ActorWriteStatus.WRITTEN


@runtime_checkable
class ActorStore(Protocol):
    """actors 데이터셋 저장소 계약."""

    async def aload(self, actor_id: str) -> ActorProfile | None:
        """actor_id 키로 프로필을 가져온다(없으면 None)."""
        ...

    async def awrite(self, profile: ActorProfile) -> None:
        """프로필을 저장한다(키 충돌 시 덮어쓰기 — 게이트가 머지 후 호출)."""
        ...


@runtime_checkable
class ActorSigner(Protocol):
    """변조탐지 서명기 계약."""

    def sign(self, content_hash: str) -> str: ...


class Sha256ActorSigner:
    """비밀키 없는 기본 서명기(MVP). 운영 시 HMAC 으로 교체."""

    def sign(self, content_hash: str) -> str:
        return hashlib.sha256(f"actor:{content_hash}".encode()).hexdigest()


class InMemoryActorStore:
    """프로세스 내 actors 저장소(테스트/MVP)."""

    def __init__(self) -> None:
        self._by_id: dict[str, ActorProfile] = {}

    async def aload(self, actor_id: str) -> ActorProfile | None:
        return self._by_id.get(actor_id)

    async def awrite(self, profile: ActorProfile) -> None:
        self._by_id[profile.actor_id] = profile

    def __len__(self) -> int:
        return len(self._by_id)


def _ip24_for_actor(ip: str) -> tuple[str, str] | None:
    """alert IOC 가 IPv4 면 ('ip_24', '<n>.<n>.<n>.0/24') 반환."""
    from core.actor_fingerprint import _ip24

    masked = _ip24(ip)
    if not masked:
        return None
    return ("ip_24", masked)


def _merge_profile(
    existing: ActorProfile | None,
    alert: Alert,
    actor_id: str,
    is_explicit: bool,
) -> ActorProfile:
    """기존 프로필(없으면 신규)에 새 alert 누적 머지."""
    now = _now_iso()
    profile = existing or ActorProfile(
        actor_id=actor_id, is_explicit=is_explicit, first_seen=now
    )
    profile.is_explicit = profile.is_explicit or is_explicit
    profile.last_seen = now
    profile.alert_count += 1

    # TTP 빈도
    techs_raw = alert.mitre.get("techniques", [])
    tactics_raw = alert.mitre.get("tactics", [])
    techs = [str(t) for t in techs_raw] if isinstance(techs_raw, list) else []
    tactics = [str(t) for t in tactics_raw] if isinstance(tactics_raw, list) else []
    default_tactic = tactics[0] if tactics else ""
    ttp_index = {(s.tactic, s.technique): s for s in profile.ttp_stats}
    for tech in techs:
        key = (default_tactic, tech)
        stat = ttp_index.get(key)
        if stat is None:
            stat = ActorTtpStat(
                tactic=default_tactic, technique=tech, count=0, last_seen=now
            )
            profile.ttp_stats.append(stat)
            ttp_index[key] = stat
        stat.count += 1
        stat.last_seen = now

    # IOC 패턴 (IPv4 → /24 마스킹만 우선; ASN/도메인은 후속)
    ioc_index = {(p.kind, p.value): p for p in profile.ioc_patterns}
    for ioc in alert.iocs:
        masked = _ip24_for_actor(ioc)
        if masked is None:
            continue
        pat = ioc_index.get(masked)
        if pat is None:
            pat = ActorIocPattern(
                kind=masked[0], value=masked[1], count=0, last_seen=now
            )
            profile.ioc_patterns.append(pat)
            ioc_index[masked] = pat
        pat.count += 1
        pat.last_seen = now

    # Kill chain — 슬라이드 윈도우 (앞 드롭)
    for tech in techs:
        profile.kill_chain.append(
            ActorKillChainStep(
                ts=now,
                alert_id=alert.id,
                scenario_id=alert.scenario_id,
                technique=tech,
            )
        )
    if len(profile.kill_chain) > _KILL_CHAIN_CAP:
        profile.kill_chain = profile.kill_chain[-_KILL_CHAIN_CAP:]
    return profile


class ActorWriteGate:
    """actors/ 적립 단일 통로 — TP-only + 빈 fp 거부 + 서명/머지."""

    def __init__(self, store: ActorStore, signer: ActorSigner | None = None) -> None:
        self._store = store
        self._signer = signer or Sha256ActorSigner()
        self._logger = get_logger("ActorWriteGate")

    async def submit(
        self,
        alert: Alert,
        env_verdict: EnvVerdict,
        provenance: Provenance | None = None,  # 호환 — actors 측은 미사용
    ) -> ActorWriteDecision:
        """alert + env_verdict 로부터 actor 프로필을 머지·서명·저장."""
        del provenance
        if env_verdict != EnvVerdict.CONFIRMED_TP:
            return ActorWriteDecision(
                status=ActorWriteStatus.REJECTED_NOT_TP,
                reason="actor 적립은 CONFIRMED_TP 만",
            )
        actor_id, is_explicit = resolve_actor_id(alert)
        if not is_explicit and is_empty_fingerprint(actor_id):
            return ActorWriteDecision(
                status=ActorWriteStatus.REJECTED_EMPTY,
                reason="빈 fingerprint — 적립 거부",
            )
        try:
            existing = await self._store.aload(actor_id)
        except SOCPlatformError as exc:
            return ActorWriteDecision(
                status=ActorWriteStatus.REJECTED_STORE_ERROR,
                reason=f"store 조회 실패: {exc}",
            )
        merged = _merge_profile(existing, alert, actor_id, is_explicit)
        merged.content_hash = merged.fingerprint()
        merged.signature = self._signer.sign(merged.content_hash)
        try:
            await self._store.awrite(merged)
        except SOCPlatformError as exc:
            return ActorWriteDecision(
                status=ActorWriteStatus.REJECTED_STORE_ERROR,
                reason=f"store 저장 실패: {exc}",
            )
        self._logger.info(
            "actor write: id=%s explicit=%s count=%d techs=%d",
            actor_id,
            merged.is_explicit,
            merged.alert_count,
            len(merged.ttp_stats),
        )
        return ActorWriteDecision(status=ActorWriteStatus.WRITTEN, actor_id=actor_id)


class ActorReadGate:
    """actors/ 회상 단일 통로 — 서명 검증 후 신뢰 프로필만 반환."""

    def __init__(self, store: ActorStore, signer: ActorSigner | None = None) -> None:
        self._store = store
        self._signer = signer or Sha256ActorSigner()
        self._logger = get_logger("ActorReadGate")

    async def recall(self, actor_id: str) -> ActorProfile | None:
        """actor_id 로 신뢰 프로필 회상. 미존재/위조/장애 시 None."""
        try:
            profile = await self._store.aload(actor_id)
        except SOCPlatformError as exc:
            self._logger.warning("actor 회상 실패, None: %s", exc)
            return None
        if profile is None or not self._verify(profile):
            return None
        return profile

    def _verify(self, p: ActorProfile) -> bool:
        if not p.signature or not p.content_hash:
            return False
        if p.content_hash != p.fingerprint():
            return False
        return p.signature == self._signer.sign(p.content_hash)
