#!/usr/bin/env python3
"""S8 온보드 인식 AI 적대공격 주입 — 합성 EO/IR 적대 인식 스트림 방출.

SITL 엔 실제 인식 모델이 없으므로, BLUE 러너가 tail 하는 perception NDJSON
스트림 파일에 정상→적대 인식 레코드를 append 한다. 적대 구간은 EO/IR 표적
클래스 불일치 + 신뢰도 이상분포(gap≥0.15)를 만들어 OnboardAIDetector 가
탐지하게 한다. --clear 는 정상 레코드만 흘려 탐지기를 재무장시킨다(재촬영).

스트림 경로: 환경변수 PERCEPTION_STREAM (기본 /tmp/pollack_perception.ndjson).
사전: BLUE `scripts/sim_live_bridge_onboard.py` 가 같은 경로를 tail 중.
실행: python scripts/sim_inject_onboard_evade.py [--clear] [--benign-n 5]
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sim_bridge.perception_synth import (  # noqa: E402
    adversarial_perception,
    benign_perception,
)

STREAM = Path(os.environ.get("PERCEPTION_STREAM", "/tmp/pollack_perception.ndjson"))


def _emit(record: dict[str, object]) -> None:
    """레코드 한 줄을 스트림 파일에 append 하고 즉시 flush."""
    with STREAM.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        fh.flush()


def main() -> None:
    clear = "--clear" in sys.argv
    benign_n = 5
    if "--benign-n" in sys.argv:
        benign_n = int(sys.argv[sys.argv.index("--benign-n") + 1])

    STREAM.parent.mkdir(parents=True, exist_ok=True)
    STREAM.touch(exist_ok=True)
    print(f"[스트림] {STREAM}")

    if clear:
        for _ in range(benign_n):
            _emit(benign_perception())
            time.sleep(0.2)
        print("[복구] 정상 인식 레코드 송출 — 탐지기 재무장.")
        return

    for _ in range(benign_n):
        _emit(benign_perception())
        time.sleep(0.2)
    print("[정상] EO/IR 일치 인식 송출 완료. 적대 주입 시작...")
    for _ in range(4):
        _emit(adversarial_perception())
        time.sleep(0.2)
    print("[주입] 적대 인식(EO=vehicle/IR=bird 불일치 + 신뢰도 gap) 송출 완료.")
    print("       → BLUE OnboardAIDetector 탐지 예상.")


if __name__ == "__main__":
    main()
