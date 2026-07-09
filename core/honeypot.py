"""예측 유도 허니팟(디코이) 배치 — 다음 수 표적에 미끼(예측 폐루프).

SequencePredictor 가 발행한 다음 technique 후보를 알면, 그 표적 자산에 디코이
(가짜 GCS 세션 / 미끼 텔레메트리 엔드포인트 / 미끼 자격증명 / 미끼 파일)를 미리
배치한다. 공격자가 디코이를 건드리면 = **고신뢰 정탐 신호**(실제 업무 자산이 아닌
미끼 접촉). 단 이 모듈은 읽기전용 자문 — TP/verdict 격상은 여기서 하지 않고 반드시
신뢰 관측(OutcomeProbe)·검증 경로를 거친다([[deception]] 교리와 동일: alert 필드는
위조 가능하므로 신호 산출까지만). 전 과정 결정론 — LLM 무관. decoy_id/signature 는
(technique, target_asset) 기반 SHA-256 결정론 해시로 실제 자산과 미끼를 구분한다.

DefenseStager(선제 스테이징)와 동형 패턴: 예측 → 결정론 매핑 테이블 조회 → 산출물.
"""

from __future__ import annotations

from enum import StrEnum
import hashlib

from core.models import AttackPrediction, DecoyPlacement
from utils.logging import get_logger

_logger = get_logger("HoneypotPlanner")

_SIGNATURE_PREFIX = "decoy"


class DecoyType(StrEnum):
    """디코이 자산 유형 — 예측 technique 이 노리는 자산에 매핑된다."""

    GCS_SESSION = "gcs_session"  # 가짜 지상관제(GCS) 세션 — C2/명령 계열 유인
    TELEMETRY_ENDPOINT = "telemetry_endpoint"  # 미끼 텔레메트리/센서 엔드포인트
    CREDENTIAL = "credential"  # 미끼 자격증명(허니 토큰/계정)
    FILE_BAIT = "file_bait"  # 미끼 파일(가짜 임무 데이터) — 수집/유출 유인


# technique → DecoyType 결정론 매핑(UAV/ICS 도메인). 매핑 없는 technique 은 skip.
# C2·명령 계열       → GCS_SESSION (가짜 관제 세션으로 명령 주입 유도)
# 자격증명 계열       → CREDENTIAL  (미끼 계정/토큰)
# 수집·유출 계열      → FILE_BAIT   (미끼 임무 데이터)
# 센서·텔레메트리 계열 → TELEMETRY_ENDPOINT (미끼 센서 스트림)
TECHNIQUE_DECOY_MAP: dict[str, DecoyType] = {
    # --- C2 / 명령 주입 ---
    "T0855": DecoyType.GCS_SESSION,  # Unauthorized Command Message
    "T0814": DecoyType.GCS_SESSION,  # Denial of Service
    "T0831": DecoyType.GCS_SESSION,  # Manipulation of Control
    "T0836": DecoyType.GCS_SESSION,  # Modify Parameter
    # --- 자격증명 ---
    "T0859": DecoyType.CREDENTIAL,  # Valid Accounts
    "T0812": DecoyType.CREDENTIAL,  # Default Credentials
    # --- 수집 / 유출 ---
    "T0811": DecoyType.FILE_BAIT,  # Data from Information Repositories
    "T0882": DecoyType.FILE_BAIT,  # Theft of Operational Information
    "T0845": DecoyType.FILE_BAIT,  # Program Upload
    # --- 센서 / 텔레메트리 ---
    "T0801": DecoyType.TELEMETRY_ENDPOINT,  # Monitor Process State
    "T0861": DecoyType.TELEMETRY_ENDPOINT,  # Point & Tag Identification
    "T0887": DecoyType.TELEMETRY_ENDPOINT,  # Wireless Sniffing
}

# DecoyType 별 기본 표적 자산(asset_hint 미지정 시 결정론 fallback).
_DEFAULT_ASSET: dict[DecoyType, str] = {
    DecoyType.GCS_SESSION: "decoy-gcs-session",
    DecoyType.TELEMETRY_ENDPOINT: "decoy-telemetry-endpoint",
    DecoyType.CREDENTIAL: "decoy-credential-store",
    DecoyType.FILE_BAIT: "decoy-mission-files",
}


class HoneypotPlanner:
    """예측 → 디코이 배치안 생성기(결정론).

    Args:
        technique_map: technique→DecoyType 매핑. 생략 시 모듈 기본 테이블 사용.
    """

    def __init__(self, technique_map: dict[str, DecoyType] | None = None) -> None:
        self._map = technique_map or dict(TECHNIQUE_DECOY_MAP)

    def plan(
        self,
        predictions: list[AttackPrediction],
        asset_hint: str = "",
    ) -> list[DecoyPlacement]:
        """예측 목록을 디코이 배치안으로 변환한다(결정론).

        예측 technique 을 technique→DecoyType 매핑으로 조회해, 매핑된 것만 표적
        자산에 디코이를 배치한다. decoy_id/signature 는 (technique, target_asset)
        기반 SHA-256 으로, 동일 입력에 항상 동일한 미끼 식별 토큰을 낳는다.

        Args:
            predictions: SequencePredictor 발행 다음 technique 후보.
            asset_hint: 표적 자산 식별자 힌트. 비면 DecoyType 별 기본 자산 사용.

        Returns:
            매핑된 예측만 대상으로 한 배치안 목록(예측 순서 유지). 매핑 없는
            technique 은 제외. 예측이 없으면 빈 리스트.
        """
        out: list[DecoyPlacement] = []
        for pred in predictions:
            decoy_type = self._map.get(pred.next_technique)
            if decoy_type is None:
                continue
            target_asset = asset_hint or _DEFAULT_ASSET[decoy_type]
            signature = self._signature(pred.next_technique, target_asset)
            out.append(
                DecoyPlacement(
                    decoy_id=f"{_SIGNATURE_PREFIX}-{signature[:16]}",
                    decoy_type=decoy_type,
                    target_technique=pred.next_technique,
                    target_asset=target_asset,
                    probability=pred.probability,
                    signature=signature,
                )
            )
            _logger.info(
                "디코이 배치: tech=%s type=%s asset=%s p=%.2f",
                pred.next_technique,
                decoy_type.value,
                target_asset,
                pred.probability,
            )
        return out

    def is_decoy_hit(
        self,
        alert_signals: list[str],
        placements: list[DecoyPlacement],
    ) -> DecoyPlacement | None:
        """새 알람 신호에 디코이 signature 가 나타나면 그 placement 를 반환한다.

        디코이 접촉은 실제 자산이 아닌 미끼를 건드린 것이므로 고신뢰 공격 신호다.
        단 읽기전용 — verdict/TP 격상은 호출자가 신뢰 관측·검증 경로로만 수행한다.

        Args:
            alert_signals: 신규 알람의 신호 문자열 목록.
            placements: 앞서 배치된 디코이 배치안.

        Returns:
            접촉된 첫 placement(신호에 signature 노출). 접촉 없으면 None.
        """
        signals = set(alert_signals)
        for placement in placements:
            if placement.signature in signals:
                _logger.info(
                    "디코이 접촉(고신뢰 정탐 신호): decoy_id=%s tech=%s asset=%s",
                    placement.decoy_id,
                    placement.target_technique,
                    placement.target_asset,
                )
                return placement
        return None

    @staticmethod
    def _signature(technique: str, target_asset: str) -> str:
        """(technique, target_asset) 결정론 SHA-256 미끼 식별 토큰."""
        canonical = f"{_SIGNATURE_PREFIX}:{technique}:{target_asset}"
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
