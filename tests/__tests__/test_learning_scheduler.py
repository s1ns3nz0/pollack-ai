"""Learning worker 스케줄러 통합 — 3 워커 조정.

_StubKql 은 AutoKqlRuleAgent 인터페이스 duck-typed — main 에 A-2 미머지 시에도
동작하도록 상속 없이 `.run_for(list[str])` 만 구현.
"""

from __future__ import annotations

import pytest

from app.learning import _extract_added_techniques, run_cycle
from core.models import LandscapeDiff, WorkerReport


class _StubOutcome:
    def __init__(self) -> None:
        self.calls = 0

    async def run(self) -> WorkerReport:
        self.calls += 1
        return WorkerReport(cycle_at="t", auto_applied=2, errors=[])


class _StubThreat:
    def __init__(self, diffs: list[LandscapeDiff] | None = None) -> None:
        self.calls = 0
        self._diffs = diffs or []

    async def run(self) -> WorkerReport:
        self.calls += 1
        return WorkerReport(
            cycle_at="t", diffs=self._diffs, auto_applied=1, pr_urls=[], errors=[]
        )


class _StubKql:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    async def run_for(self, added: list[str]) -> WorkerReport:
        self.calls.append(added)
        return WorkerReport(cycle_at="t", auto_applied=len(added))


class _FailingThreat:
    async def run(self) -> WorkerReport:
        raise RuntimeError("boom")


class _FailingOutcome:
    async def run(self) -> WorkerReport:
        raise RuntimeError("outcome boom")


class TestExtractAddedTechniques:
    def test_attack_only(self) -> None:
        diffs = [LandscapeDiff(source="attack", added=["T1", "T2"])]
        assert _extract_added_techniques(diffs) == ["T1", "T2"]

    def test_kev_excluded(self) -> None:
        diffs = [
            LandscapeDiff(source="attack", added=["T1"]),
            LandscapeDiff(source="kev", added=["CVE-2024-1"]),
        ]
        assert _extract_added_techniques(diffs) == ["T1"]

    def test_duplicates_removed(self) -> None:
        diffs = [
            LandscapeDiff(source="attack", added=["T1", "T2"]),
            LandscapeDiff(source="atlas", added=["T2", "T3"]),
        ]
        assert _extract_added_techniques(diffs) == ["T1", "T2", "T3"]

    def test_empty(self) -> None:
        assert _extract_added_techniques([]) == []


class TestRunCycle:
    @pytest.mark.asyncio
    async def test_all_none_returns_quickly(self) -> None:
        await run_cycle()

    @pytest.mark.asyncio
    async def test_outcome_only_invoked(self) -> None:
        probe = _StubOutcome()
        await run_cycle(outcome_probe=probe)
        assert probe.calls == 1

    @pytest.mark.asyncio
    async def test_landscape_gated_by_refresh_hours(self) -> None:
        # last_refresh 매우 최근 → skip
        threat = _StubThreat()
        import time as _t

        recent = [_t.time()]
        await run_cycle(threat_landscape=threat, last_landscape_refresh=recent)
        assert threat.calls == 0

    @pytest.mark.asyncio
    async def test_landscape_runs_when_stale(self) -> None:
        threat = _StubThreat(diffs=[LandscapeDiff(source="attack", added=["T9999"])])
        # last_refresh 오래 전 → 실행
        await run_cycle(threat_landscape=threat, last_landscape_refresh=[0.0])
        assert threat.calls == 1

    @pytest.mark.asyncio
    async def test_auto_kql_receives_added_after_threat(self) -> None:
        threat = _StubThreat(diffs=[LandscapeDiff(source="attack", added=["T1", "T2"])])
        kql = _StubKql()
        await run_cycle(
            threat_landscape=threat,
            auto_kql=kql,
            last_landscape_refresh=[0.0],
        )
        assert kql.calls == [["T1", "T2"]]

    @pytest.mark.asyncio
    async def test_auto_kql_skipped_when_no_added(self) -> None:
        threat = _StubThreat(diffs=[])
        kql = _StubKql()
        await run_cycle(
            threat_landscape=threat,
            auto_kql=kql,
            last_landscape_refresh=[0.0],
        )
        assert kql.calls == []

    @pytest.mark.asyncio
    async def test_auto_kql_skipped_when_threat_none(self) -> None:
        kql = _StubKql()
        await run_cycle(auto_kql=kql)
        assert kql.calls == []

    @pytest.mark.asyncio
    async def test_outcome_failure_isolated_from_threat(self) -> None:
        threat = _StubThreat(diffs=[])
        await run_cycle(
            outcome_probe=_FailingOutcome(),
            threat_landscape=threat,
            last_landscape_refresh=[0.0],
        )
        # threat 는 여전히 호출됨
        assert threat.calls == 1

    @pytest.mark.asyncio
    async def test_threat_failure_skips_auto_kql(self) -> None:
        # threat 실패 시 report 없음 → auto_kql 호출 안 됨
        kql = _StubKql()
        await run_cycle(
            threat_landscape=_FailingThreat(),
            auto_kql=kql,
            last_landscape_refresh=[0.0],
        )
        assert kql.calls == []

    @pytest.mark.asyncio
    async def test_all_three_wired_together(self) -> None:
        probe = _StubOutcome()
        threat = _StubThreat(diffs=[LandscapeDiff(source="attack", added=["T7"])])
        kql = _StubKql()
        await run_cycle(
            outcome_probe=probe,
            threat_landscape=threat,
            auto_kql=kql,
            last_landscape_refresh=[0.0],
        )
        assert probe.calls == 1
        assert threat.calls == 1
        assert kql.calls == [["T7"]]
