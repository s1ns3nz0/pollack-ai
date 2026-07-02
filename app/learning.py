"""Deployment B — 경험/학습 루프(버스티, 비동기, HPA 대상).

핫패스와 분리된 백그라운드 워커: 3 개 사이클 워커를 조정한다.

1. **OutcomeProbe** (매 사이클) — Observation → exp/actors/pb_scores 자동 라벨링.
2. **ThreatLandscape** (`feed_refresh_hours` 주기) — ATT&CK/ATLAS/KEV 갱신 →
   graph yaml 자동 패치 / 변경 PR.
3. **AutoKqlRuleSuggester** (T1 이 신규 technique 감지 시 즉시) — LLM 이 KQL draft
   생성 → dah-sentinel-content PR (운영자 검토 필수).

각 워커는 독립적으로 try/except 격리 — 하나가 실패해도 사이클은 계속.
독립 스케일/롤아웃(ADR 0002 D6). 헬스 서버는 백그라운드 스레드로 K8s 프로브 응답.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

from agents.outcome_probe_agent import OutcomeProbeAgent
from agents.threat_landscape_agent import ThreatLandscapeAgent
from app.health import serve_in_background
from core.models import LandscapeDiff, WorkerReport
from core.settings import Settings, get_settings
from utils.logging import get_logger

if TYPE_CHECKING:
    # A-2 (agents.auto_kql_rule_agent) 는 별도 PR — main 머지 전이면 런타임 import
    # 없이 타입만 참조. 실제 사용은 호출자가 인스턴스 주입 시에만.
    from agents.auto_kql_rule_agent import AutoKqlRuleAgent

_logger = get_logger("learning")


def _extract_added_techniques(diffs: list[LandscapeDiff]) -> list[str]:
    """T1 diff 목록에서 신규 technique ID 추출 (KEV 제외, 중복 제거)."""
    out: list[str] = []
    seen: set[str] = set()
    for d in diffs:
        if d.source == "kev":
            continue
        for tid in d.added:
            if tid not in seen:
                seen.add(tid)
                out.append(tid)
    return out


async def _run_outcome_probe(agent: OutcomeProbeAgent) -> None:
    try:
        report = await agent.run()
        _logger.info(
            "outcome_probe: applied=%d errors=%d",
            report.auto_applied,
            len(report.errors),
        )
    except Exception as exc:  # noqa: BLE001 - 사이클 보호
        _logger.warning("outcome_probe 실패(계속): %s", exc)


async def _run_threat_landscape(agent: ThreatLandscapeAgent) -> WorkerReport | None:
    try:
        report = await agent.run()
    except Exception as exc:  # noqa: BLE001 - 사이클 보호
        _logger.warning("threat_landscape 실패(계속): %s", exc)
        return None
    _logger.info(
        "threat_landscape: applied=%d prs=%d errors=%d",
        report.auto_applied,
        len(report.pr_urls),
        len(report.errors),
    )
    return report


async def _run_auto_kql(agent: AutoKqlRuleAgent, added: list[str]) -> None:
    if not added:
        _logger.debug("auto_kql: 신규 technique 없음 — skip")
        return
    try:
        report = await agent.run_for(added)
        _logger.info(
            "auto_kql: processed=%d applied=%d prs=%d errors=%d",
            len(added),
            report.auto_applied,
            len(report.pr_urls),
            len(report.errors),
        )
    except Exception as exc:  # noqa: BLE001 - 사이클 보호
        _logger.warning("auto_kql 실패(계속): %s", exc)


async def run_cycle(
    threat_landscape: ThreatLandscapeAgent | None = None,
    outcome_probe: OutcomeProbeAgent | None = None,
    auto_kql: AutoKqlRuleAgent | None = None,
    last_landscape_refresh: list[float] | None = None,
    settings: Settings | None = None,
) -> None:
    """학습 사이클 1회.

    Args:
        threat_landscape: T1 워커. `feed_refresh_hours` 게이트 통과 시 실행.
        outcome_probe: A-1 워커. 매 사이클 실행 (외부 신호 큐 flush).
        auto_kql: A-2 워커. T1 이 신규 technique 감지 시 즉시 호출.
        last_landscape_refresh: 마지막 갱신 epoch (공유 리스트 0번 인덱스).
        settings: 전역 설정. 미주입 시 `get_settings()`.
    """
    _logger.info("learning 사이클 tick")
    # 1. OutcomeProbe — 매 사이클.
    if outcome_probe is not None:
        await _run_outcome_probe(outcome_probe)
    # 2. ThreatLandscape — 24h 게이트.
    if threat_landscape is None:
        return
    s = settings or get_settings()
    state = last_landscape_refresh or [0.0]
    if (time.time() - state[0]) / 3600 < s.feed_refresh_hours:
        return
    report = await _run_threat_landscape(threat_landscape)
    if report is None:
        return
    state[0] = time.time()
    # 3. AutoKql — T1 신규 technique 이 있을 때만.
    if auto_kql is not None:
        added = _extract_added_techniques(report.diffs)
        await _run_auto_kql(auto_kql, added)


# ─────────────────────────────────────────
# 워커 자동 배선 팩토리 (main() 진입점)
# ─────────────────────────────────────────


def _build_publisher(settings: Settings) -> object | None:
    """`github_token` 있으면 GitHubRulePublisher, 없으면 None."""
    if not settings.github_token.get_secret_value():
        return None
    try:
        from tools.rule_publisher import GitHubRulePublisher

        return GitHubRulePublisher(settings)
    except Exception as exc:  # noqa: BLE001 — 배선 실패 시 skip
        _logger.warning("publisher 배선 실패: %s", exc)
        return None


def _build_threat_landscape(settings: Settings) -> ThreatLandscapeAgent | None:
    """feed URL 이 하나라도 있으면 ThreatLandscapeAgent 자동 배선."""
    try:
        from tools.atlas_feed import AtlasFeed
        from tools.cisa_kev_feed import CisaKevFeed
        from tools.feed_base import FeedTool
        from tools.graph_yaml_patch import GraphYamlPatchTool
        from tools.mitre_stix_feed import MitreStixFeed
    except ImportError as exc:
        _logger.warning("threat_landscape: 모듈 미존재 — 워커 비활성: %s", exc)
        return None

    feeds: list[FeedTool] = []
    if settings.attack_feed_url:
        feeds.append(MitreStixFeed(settings))
    if settings.atlas_feed_url:
        feeds.append(AtlasFeed(settings))
    if settings.kev_feed_url:
        feeds.append(CisaKevFeed(settings))
    if not feeds:
        _logger.info("threat_landscape: feed URL 미설정 — 워커 비활성")
        return None
    patcher = GraphYamlPatchTool(settings)
    publisher = _build_publisher(settings)
    return ThreatLandscapeAgent(
        settings,
        feeds=feeds,
        patcher=patcher,
        publisher=publisher,  # type: ignore[arg-type]
    )


def _build_auto_kql(settings: Settings) -> AutoKqlRuleAgent | None:
    """`auto_kql_enabled` 이고 LLM 가용 시 워커 배선.

    `auto_kql_enabled` 설정 자체가 없으면(A-2 PR 미머지 상태) 자동 비활성.
    """
    if not getattr(settings, "auto_kql_enabled", False):
        return None
    try:
        from agents.auto_kql_rule_agent import AutoKqlRuleAgent as _Agent
    except ImportError:
        _logger.warning("auto_kql: 모듈 미존재 — 워커 비활성")
        return None
    from core.llm import get_llm_client

    try:
        llm = get_llm_client(settings)
    except Exception as exc:  # noqa: BLE001
        _logger.warning("auto_kql: LLM 배선 실패 — 워커 비활성: %s", exc)
        return None
    publisher = _build_publisher(settings)
    return _Agent(settings, llm=llm, publisher=publisher)


async def main(interval_seconds: float | None = None) -> None:
    """헬스 서버 기동 후 학습 루프를 주기 실행한다(blocking).

    워커는 settings 기반 자동 배선:
    - `outcome_probe` — 시뮬 소스가 별도 프로세스라 자동 배선 대상 X (외부 주입).
    - `threat_landscape` — 하나 이상의 feed URL 이 있으면 자동 활성.
    - `auto_kql` — `AUTO_KQL_ENABLED=true` + LLM 가용 시 자동 활성.
    """
    settings = get_settings()
    interval = interval_seconds if interval_seconds is not None else 30.0
    serve_in_background(port=8080)

    threat = _build_threat_landscape(settings)
    auto_kql = _build_auto_kql(settings)
    last_refresh: list[float] = [0.0]
    _logger.info(
        "경험/학습 워커 기동: interval=%.0fs, threat=%s, auto_kql=%s",
        interval,
        threat is not None,
        auto_kql is not None,
    )
    while True:
        try:
            await run_cycle(
                threat_landscape=threat,
                auto_kql=auto_kql,
                last_landscape_refresh=last_refresh,
                settings=settings,
            )
        except Exception as exc:  # noqa: BLE001 - 사이클 실패가 워커를 죽이지 않게
            _logger.warning("learning 사이클 실패(계속): %s", exc)
        await asyncio.sleep(interval)


if __name__ == "__main__":
    asyncio.run(main())
