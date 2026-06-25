"""합성 온보드 EO/IR 인식 추론 스트림 생성기(S8 — 인식 모델 없이 브리지 검증).

정상 정찰 중 EO(가시)/IR(열) 센서가 동일 표적을 일치되게 고신뢰로 인식하다가,
적대적 패치/디코이/dazzling 주입 구간에서 EO/IR 표적 클래스 불일치 + 신뢰도
이상분포(gap≥0.15)를 만든다. 출력 dict 는 perception NDJSON 키와 동일하므로 실
인식-탭 스트림으로 그대로 교체 가능하다.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sim_bridge.models import PerceptionRecord


def benign_perception(
    uav_id: str = "MPD-001", target_id: str = "TGT-01"
) -> dict[str, object]:
    """정상 인식 — EO/IR 동일 클래스 + 단봉 고신뢰(불일치/이상분포 없음)."""
    return {
        "TimeGenerated": "2026-06-25T00:00:00Z",
        "UAVId": uav_id,
        "MsgType": "PERCEPTION_INFERENCE",
        "TargetId": target_id,
        "EoClass": "vehicle",
        "IrClass": "vehicle",
        "EoConfidence": 0.93,
        "IrConfidence": 0.90,
    }


def adversarial_perception(
    uav_id: str = "MPD-001", target_id: str = "TGT-01"
) -> dict[str, object]:
    """적대 인식 — EO=vehicle / IR=bird 불일치 + 신뢰도 gap(0.46)."""
    return {
        "TimeGenerated": "2026-06-25T00:00:10Z",
        "UAVId": uav_id,
        "MsgType": "PERCEPTION_INFERENCE",
        "TargetId": target_id,
        "EoClass": "vehicle",
        "IrClass": "bird",
        "EoConfidence": 0.88,
        "IrConfidence": 0.42,
    }


def synth_perception_records(
    uav_id: str = "MPD-001", benign_n: int = 5
) -> list[PerceptionRecord]:
    """정상 N건 → 적대 2건(확정 스트릭 충족) 시퀀스."""
    raw: list[dict[str, object]] = [benign_perception(uav_id) for _ in range(benign_n)]
    raw.append(adversarial_perception(uav_id))
    raw.append(adversarial_perception(uav_id))
    return [PerceptionRecord.from_ndjson(r) for r in raw]


async def synth_perception_stream(
    uav_id: str = "MPD-001", benign_n: int = 5
) -> AsyncIterator[PerceptionRecord]:
    """비동기 스트림 버전(브리지 검증용)."""
    for record in synth_perception_records(uav_id, benign_n):
        yield record
