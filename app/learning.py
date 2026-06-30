"""Deployment B — 경험/학습 루프(버스티, 비동기, HPA 대상).

핫패스와 분리된 백그라운드 워커: 환경검증 결과(OutcomeProbe)를 경험메모리에 적립하고
(MemoryWriteGate), 누적된 오탐 패턴을 RuleUpdate(Watch List PR)로 증류한다. 독립
스케일/롤아웃(ADR 0002 D6). 헬스 서버는 백그라운드 스레드로 K8s 프로브에 응답.

spec T1: ThreatLandscapeAgent 주입 시 `feed_refresh_hours` 마다 위협 피드 갱신
사이클을 실행한다. 미주입 시 기존 거동 보존.
"""

from __future__ import annotations

import asyncio
import time

from agents.threat_landscape_agent import ThreatLandscapeAgent
from app.health import serve_in_background
from core.settings import Settings, get_settings
from utils.logging import get_logger

_logger = get_logger("learning")


async def run_cycle(
    threat_landscape: ThreatLandscapeAgent | None = None,
    last_landscape_refresh: list[float] | None = None,
    settings: Settings | None = None,
) -> None:
    """학습 사이클 1회 — exp 적립(미연결) + (선택) 위협 피드 갱신.

    Args:
        threat_landscape: ThreatLandscapeAgent — 주입 시 `feed_refresh_hours` 게이트
            통과 시 사이클 실행.
        last_landscape_refresh: 마지막 갱신 epoch(공유 리스트 — 0번 인덱스).
        settings: 전역 설정. 미주입 시 get_settings().
    """
    _logger.info("learning 사이클 tick")
    if threat_landscape is None:
        return
    s = settings or get_settings()
    state = last_landscape_refresh or [0.0]
    if (time.time() - state[0]) / 3600 < s.feed_refresh_hours:
        return
    try:
        report = await threat_landscape.run()
    except Exception as exc:  # noqa: BLE001 - 사이클 보호
        _logger.warning("threat_landscape 실패(계속): %s", exc)
        return
    state[0] = time.time()
    _logger.info(
        "threat_landscape: applied=%d prs=%d errors=%d",
        report.auto_applied,
        len(report.pr_urls),
        len(report.errors),
    )


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
