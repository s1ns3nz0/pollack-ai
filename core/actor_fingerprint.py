"""공격자 식별 키 산정 — `Alert.actor_id` 또는 결정론 fingerprint(spec #2).

resolve_actor_id 가 반환하는 (key, is_explicit) 쌍을 사용한다. is_explicit=True 이면
운영자/시스템 부여 신뢰 ID, False 이면 (mitre, signals, ip/24) 기반 자동 클러스터.

빈 페이로드(모든 차원 빈 값)는 결정론 *고정 빈 키* 로 매핑되며 쓰기 게이트가
거부한다(`REJECTED_EMPTY`) — 동일 빈 키로 무한 충돌 방지.

Spec: docs/superpowers/specs/2026-06-30-attacker-profile-store-design.md
"""

from __future__ import annotations

import hashlib
import json
import re

from core.models import Alert

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _ip24(ip: str) -> str:
    """IPv4 → /24 마스킹 표기. 미일치 시 빈 문자열."""
    if not _IPV4_RE.match(ip):
        return ""
    parts = ip.split(".")
    if any(int(p) > 255 for p in parts):
        return ""
    return ".".join(parts[:3]) + ".0/24"


def _fingerprint_payload(alert: Alert) -> dict[str, list[str]]:
    """정규화된 fingerprint 입력 payload."""
    tactics_raw = alert.mitre.get("tactics", [])
    techs_raw = alert.mitre.get("techniques", [])
    tactics = (
        sorted([str(t) for t in tactics_raw]) if isinstance(tactics_raw, list) else []
    )
    techs = sorted([str(t) for t in techs_raw]) if isinstance(techs_raw, list) else []
    ip24s = sorted({_ip24(i) for i in alert.iocs if _ip24(i)})
    return {
        "tactics": tactics,
        "techniques": techs,
        "signals": sorted(alert.signals),
        "ip_24": ip24s,
    }


def fingerprint(alert: Alert) -> str:
    """결정론 fingerprint 키 `fp:<sha256-16>` 반환."""
    payload = _fingerprint_payload(alert)
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return "fp:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def empty_fingerprint() -> str:
    """모든 차원 빈값일 때 결정론 고정 키."""
    canonical = json.dumps(
        {"ip_24": [], "signals": [], "tactics": [], "techniques": []},
        sort_keys=True,
        ensure_ascii=False,
    )
    return "fp:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


_EMPTY_FP = empty_fingerprint()


def resolve_actor_id(alert: Alert) -> tuple[str, bool]:
    """alert 의 actor 식별 키와 explicit 여부를 반환.

    Returns:
        (actor_id, is_explicit). actor_id 가 EMPTY_FP 면 쓰기 게이트가 거부.
    """
    if alert.actor_id:
        return alert.actor_id.strip(), True
    return fingerprint(alert), False


def is_empty_fingerprint(actor_id: str) -> bool:
    """빈 fingerprint 키 여부."""
    return actor_id == _EMPTY_FP
