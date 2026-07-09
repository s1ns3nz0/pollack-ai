"""경험메모리(`exp/`) 쓰기 게이트 + 저장소/서명 계약.

`OutcomeProbe` 가 만든 환경검증 결과를 `ExperienceRecord` 로 적립하는 단일 통로다.
포이즈닝 방어를 위해 다음을 강제한다:

1. **보류 폐기** — `INCONCLUSIVE` 는 적립하지 않는다(적이 노리는 회색지대 배제).
2. **미신뢰 억제 거부** — `AUTO` 출처는 억제 학습(`CONFIRMED_FP`)을 만들 수 없다
   (억제는 위험 방향 → 신뢰 출처만). 탐지 학습(`CONFIRMED_TP`)은 출처 무관 허용.
3. **변조탐지 서명** — 적립 레코드에 지문 기반 서명을 부여(읽기 측이 신뢰 검증).
4. **중복 제거** — 동일 지문(`fingerprint`) 레코드는 재적립하지 않는다.

저장소(`ExperienceStore`)와 서명기(`Signer`)는 주입 가능한 계약으로 추상화한다 →
실연동 시 RAGFlow `exp/` 라이터 / HMAC 서명기로 교체(스왑 가능, ADR 0001 패턴).
→ docs/adr/0002-autonomous-self-improving-blue-soc.md
"""

from __future__ import annotations

from enum import StrEnum
import hashlib
from typing import Protocol, runtime_checkable

from pydantic import BaseModel

from core.models import EnvVerdict, ExperienceRecord, Provenance
from utils.logging import get_logger


class WriteStatus(StrEnum):
    """경험메모리 쓰기 결과."""

    WRITTEN = "written"
    SKIPPED_DUPLICATE = "skipped_duplicate"
    REJECTED_INCONCLUSIVE = "rejected_inconclusive"
    REJECTED_UNTRUSTED_SUPPRESSION = "rejected_untrusted_suppression"


class WriteDecision(BaseModel):
    """쓰기 게이트 판정 결과.

    Attributes:
        status: 쓰기 처리 결과.
        fingerprint: 레코드 의미 지문(거부 시 빈 문자열).
        reason: 사람이 읽을 처리 근거.
    """

    status: WriteStatus
    fingerprint: str = ""
    reason: str = ""

    @property
    def written(self) -> bool:
        """실제로 저장소에 적립됐는지 여부."""
        return self.status == WriteStatus.WRITTEN


@runtime_checkable
class ExperienceStore(Protocol):
    """경험메모리(`exp/`) 저장소 계약.

    구현체는 RAGFlow `exp/` 네임스페이스 등으로 백업된다. 모든 연산은 비동기이며,
    장애 시 `ExperienceStoreError` 를 던진다.
    """

    async def aexists(self, fingerprint: str) -> bool:
        """해당 지문의 레코드가 이미 있으면 True."""
        ...

    async def awrite(self, record: ExperienceRecord) -> None:
        """서명·지문이 부여된 레코드를 저장한다."""
        ...

    async def aquery(self, scenario_id: str, k: int = 20) -> list[ExperienceRecord]:
        """시나리오 관련 레코드를 최대 k 건 반환(미검증 — 신뢰판단은 읽기 게이트)."""
        ...


@runtime_checkable
class ReopenableStore(Protocol):
    """재심(cold-case) 능력을 갖춘 저장소 계약(`ExperienceStore` 확장).

    억제 재심은 시나리오 무관하게 actor/signature 로 과거 FP 를 스캔·revoke 해야
    하므로 별도 계약으로 분리한다. RAGFlow 영속 구현은 후속(현재는 InMemory MVP) —
    미구현 store 주입 시 재심 배선은 skip 한다(graceful).
    """

    async def ascan_suppressions(self) -> list[ExperienceRecord]:
        """미revoke 억제(CONFIRMED_FP) 레코드 전체를 반환한다."""
        ...

    async def arevoke(self, fingerprint: str, reason: str) -> bool:
        """지문 레코드를 revoke(억제 무효화). 성공 시 True(없으면 False)."""
        ...

    @property
    def last_suppression_scan_complete(self) -> bool:
        """마지막 억제 스캔이 완전 열거였으면 True."""
        ...


@runtime_checkable
class Signer(Protocol):
    """레코드 변조탐지 서명기 계약(실연동 시 비밀키 HMAC 으로 교체)."""

    def sign(self, content_hash: str) -> str:
        """내용 지문에 대한 서명 문자열을 반환한다."""
        ...


class Sha256Signer:
    """비밀키 없는 기본 서명기(SHA-256 변조탐지용 — MVP).

    비밀키 기반 진짜 위·변조 방지(authenticity)는 운영 시 HMAC 서명기로 교체한다.
    """

    def sign(self, content_hash: str) -> str:
        """`exp:` 접두 후 SHA-256 다이제스트를 반환한다."""
        return hashlib.sha256(f"exp:{content_hash}".encode()).hexdigest()


class InMemoryExperienceStore:
    """프로세스 내 경험메모리 저장소(테스트/MVP용)."""

    def __init__(self) -> None:
        self._by_fingerprint: dict[str, ExperienceRecord] = {}

    async def aexists(self, fingerprint: str) -> bool:
        """지문 존재 여부."""
        return fingerprint in self._by_fingerprint

    async def awrite(self, record: ExperienceRecord) -> None:
        """레코드를 지문 키로 저장(동일 지문은 덮어쓰기 — 게이트가 선차단)."""
        self._by_fingerprint[record.content_hash] = record

    async def aquery(self, scenario_id: str, k: int = 20) -> list[ExperienceRecord]:
        """시나리오 일치 레코드를 삽입순으로 최대 k 건 반환(MVP — 실연동은 의미검색)."""
        hits = [
            r for r in self._by_fingerprint.values() if r.scenario_id == scenario_id
        ]
        return hits[:k]

    async def ascan_suppressions(self) -> list[ExperienceRecord]:
        """미revoke 억제(CONFIRMED_FP) 레코드 전체(재심 스캔용)."""
        return [
            r
            for r in self._by_fingerprint.values()
            if r.env_verdict == EnvVerdict.CONFIRMED_FP and not r.revoked
        ]

    @property
    def last_suppression_scan_complete(self) -> bool:
        """인메모리 저장소는 전체 딕셔너리를 열거하므로 항상 완전 스캔."""
        return True

    async def arevoke(self, fingerprint: str, reason: str) -> bool:
        """지문 레코드를 revoke — content_hash/서명 유지(fingerprint 불포함)."""
        rec = self._by_fingerprint.get(fingerprint)
        if rec is None:
            return False
        self._by_fingerprint[fingerprint] = rec.model_copy(
            update={"revoked": True, "reopened_reason": reason}
        )
        return True

    def __len__(self) -> int:
        """적립된 레코드 수."""
        return len(self._by_fingerprint)


class MemoryWriteGate:
    """경험메모리 적립의 단일 통로(포이즈닝 방어 정책 강제).

    Args:
        store: 적립 대상 저장소.
        signer: 변조탐지 서명기(미지정 시 `Sha256Signer`).
    """

    def __init__(self, store: ExperienceStore, signer: Signer | None = None) -> None:
        self._store = store
        self._signer = signer or Sha256Signer()
        self._logger = get_logger("MemoryWriteGate")

    async def submit(self, record: ExperienceRecord) -> WriteDecision:
        """레코드를 정책 검증·서명·중복제거 후 적립한다.

        Args:
            record: 적립 후보(`env_verdict`·`provenance` 가 채워진 상태).

        Returns:
            처리 결과 `WriteDecision`. 적립 성공 시 `status=WRITTEN`.

        Raises:
            ExperienceStoreError: 저장소 읽기/쓰기 장애 시(저장소 구현이 던짐).
        """
        if record.env_verdict == EnvVerdict.INCONCLUSIVE:
            self._logger.info("write reject: 보류(INCONCLUSIVE) 적립 안 함")
            return WriteDecision(
                status=WriteStatus.REJECTED_INCONCLUSIVE,
                reason="환경검증 보류 — 회색지대 적립 배제",
            )

        if (
            record.env_verdict == EnvVerdict.CONFIRMED_FP
            and record.provenance == Provenance.AUTO
        ):
            self._logger.warning("write reject: AUTO 출처 억제 학습 차단")
            return WriteDecision(
                status=WriteStatus.REJECTED_UNTRUSTED_SUPPRESSION,
                reason="미신뢰(AUTO) 출처는 억제(CONFIRMED_FP) 학습 불가",
            )

        fingerprint = record.fingerprint()
        if await self._store.aexists(fingerprint):
            return WriteDecision(
                status=WriteStatus.SKIPPED_DUPLICATE,
                fingerprint=fingerprint,
                reason="동일 지문 레코드 존재 — 중복 적립 생략",
            )

        signed = record.model_copy(
            update={
                "content_hash": fingerprint,
                "signature": self._signer.sign(fingerprint),
            }
        )
        await self._store.awrite(signed)
        self._logger.info(
            "write ok: scenario=%s verdict=%s prov=%s fp=%s",
            signed.scenario_id,
            signed.env_verdict,
            signed.provenance,
            fingerprint[:12],
        )
        return WriteDecision(
            status=WriteStatus.WRITTEN, fingerprint=fingerprint, reason="적립 완료"
        )


class RecallPurpose(StrEnum):
    """경험 회상 목적(비대칭 신뢰의 읽기 측)."""

    DETECTION = "detection"  # 탐지 강화 — 과거 정탐 회상(전 출처 허용, 안전 방향)
    SUPPRESSION = "suppression"  # 억제 판단 — 과거 오탐 회상(신뢰 출처만, 위험 방향)


# 억제(suppression) 학습에 채택 가능한 출처 등급(미신뢰 AUTO 제외).
_TRUSTED_FOR_SUPPRESSION = (Provenance.ENV_VERIFIED, Provenance.REDGT_OFFLINE)


class MemoryReadGate:
    """경험메모리 회상의 단일 통로 — 서명 검증 + 비대칭 신뢰 필터.

    저장소를 직접 변조·주입한 미서명/위조 레코드는 회상 단계에서 폐기한다(쓰기
    게이트를 우회한 포이즈닝 방어). 목적별 비대칭:
    - `DETECTION`: 과거 정탐(`CONFIRMED_TP`) — 전 출처 허용(탐지 강화는 안전 방향).
    - `SUPPRESSION`: 과거 오탐(`CONFIRMED_FP`) — `env_verified`/`redgt_offline` 만
      (억제는 FN 위험 방향 → 신뢰 출처 한정).

    Args:
        store: 회상 대상 저장소.
        signer: 서명 검증기(쓰기 측과 동일 구현이어야 함).
    """

    def __init__(self, store: ExperienceStore, signer: Signer | None = None) -> None:
        self._store = store
        self._signer = signer or Sha256Signer()
        self._logger = get_logger("MemoryReadGate")

    async def recall(
        self, scenario_id: str, purpose: RecallPurpose, k: int = 5
    ) -> list[ExperienceRecord]:
        """목적에 맞는 신뢰 가능 경험 레코드를 최대 k 건 회상한다.

        Args:
            scenario_id: 회상 대상 시나리오.
            purpose: 회상 목적(탐지 강화 / 억제 판단).
            k: 반환할 최대 레코드 수.

        Returns:
            서명 검증 + 목적별 신뢰 필터를 통과한 레코드(최대 k 건).

        Raises:
            ExperienceStoreError: 저장소 조회 장애 시(저장소 구현이 던짐).
        """
        candidates = await self._store.aquery(scenario_id, k=max(k * 4, 20))
        trusted: list[ExperienceRecord] = []
        for record in candidates:
            if not self._verify(record):
                self._logger.warning(
                    "recall drop: 미서명/위조 레코드 폐기 scenario=%s", scenario_id
                )
                continue
            if self._purpose_match(record, purpose):
                trusted.append(record)
            if len(trusted) >= k:
                break
        self._logger.info(
            "recall: scenario=%s purpose=%s hits=%d",
            scenario_id,
            purpose,
            len(trusted),
        )
        return trusted

    def _verify(self, record: ExperienceRecord) -> bool:
        """레코드 무결성·진정성 검증(지문 일치 + 서명 일치)."""
        if not record.signature or not record.content_hash:
            return False
        if record.content_hash != record.fingerprint():
            return False
        return record.signature == self._signer.sign(record.content_hash)

    def _purpose_match(self, record: ExperienceRecord, purpose: RecallPurpose) -> bool:
        """목적별 채택 조건(env_verdict + 억제 시 출처 신뢰등급)을 만족하는지."""
        if purpose == RecallPurpose.DETECTION:
            return record.env_verdict == EnvVerdict.CONFIRMED_TP
        # 재심(cold-case): revoke 된 억제 근거는 무효 — 회상 제외.
        return (
            not record.revoked
            and record.env_verdict == EnvVerdict.CONFIRMED_FP
            and record.provenance in _TRUSTED_FOR_SUPPRESSION
        )
