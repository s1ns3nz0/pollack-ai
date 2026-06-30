"""Deployment B — 경험/학습 루프(버스티, 비동기, HPA 대상).

핫패스와 분리된 백그라운드 워커: 환경검증 결과(OutcomeProbe)를 경험메모리에 적립하고
(MemoryWriteGate), 누적된 오탐 패턴을 RuleUpdate(Watch List PR)로 증류한다. 독립
스케일/롤아웃(ADR 0002 D6). 헬스 서버는 백그라운드 스레드로 K8s 프로브에 응답.

본 모듈은 워커 골격이다 — 실제 큐/이벤트 소스 연결은 배포 환경에서 주입한다. 한 사이클
실패가 워커를 죽이지 않도록 예외를 격리한다.
"""

from __future__ import annotations

import asyncio

from app.health import serve_in_background
from core.settings import get_settings
from utils.logging import get_logger

_logger = get_logger("learning")


async def run_cycle() -> None:
    """학습 사이클 1회(골격) — 적립 대기열 처리 지점.

    실제 연결 시: OutcomeProbe 결과 수집 → MemoryWriteGate.submit → 임계 누적 시
    RuleUpdateAgent 발행. 여기서는 하트비트만 남긴다(이벤트 소스 미주입).
    """
    _logger.info("learning 사이클 tick")


async def main(interval_seconds: float | None = None) -> None:
    """헬스 서버 기동 후 학습 루프를 주기 실행한다(blocking)."""
    settings = get_settings()
    interval = interval_seconds if interval_seconds is not None else 30.0
    serve_in_background(port=8080)
    _logger.info("경험/학습 워커 기동: interval=%.0fs", interval)
    while True:
        try:
            await run_cycle()
        except Exception as exc:  # noqa: BLE001 - 사이클 실패가 워커를 죽이지 않게
            _logger.warning("learning 사이클 실패(계속): %s", exc)
        await asyncio.sleep(interval)
        del settings  # placeholder: 설정은 사이클 연결 시 사용


if __name__ == "__main__":
    asyncio.run(main())
