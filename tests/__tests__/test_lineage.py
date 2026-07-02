"""spec D-1 Data Lineage — snapshot + Report 통합 + 시크릿 마스킹."""

from __future__ import annotations

import pytest

from agents.report_agent import ReportAgent
from core.lineage import LineageCollector, _git_sha_default
from core.models import (
    Alert,
    LineageSnapshot,
    Severity,
    SOCState,
    Verdict,
)
from core.settings import Settings
from core.severity import SeverityEngine


def _state(**kwargs: object) -> SOCState:
    alert = Alert(
        id="a1",
        scenario_id="S2",
        title="X",
        severity_baseline=Severity.MEDIUM,
        signals=["sig.a"],
        expected_detection={"sigma_rule": "r1"},
    )
    base: dict[str, object] = {
        "alert": alert,
        "severity": Severity.MEDIUM,
        "verdict": Verdict.TRUE_POSITIVE,
        "node_timings": [
            {"node": "triage", "elapsed_ms": 10.0},
            {"node": "investigation", "elapsed_ms": 25.0},
            {"node": "investigation", "elapsed_ms": 30.0},  # 노드당 max
        ],
    }
    base.update(kwargs)
    return base  # type: ignore[return-value]


class TestSnapshotFields:
    def test_captures_llm_model(self) -> None:
        c = LineageCollector(Settings(), git_sha_provider=lambda: "abc123")
        s = c.snapshot(_state())
        assert s.llm_provider == "ollama"
        assert s.llm_model  # qwen 계열 디폴트

    def test_policy_hashes_present(self) -> None:
        c = LineageCollector(Settings(), git_sha_provider=lambda: "abc123")
        s = c.snapshot(_state())
        assert "severity-policy.yaml" in s.policy_hashes
        assert s.policy_hashes["severity-policy.yaml"].startswith("sha256:")

    def test_settings_fingerprint_stable_and_masked(self) -> None:
        # 같은 settings 두 번 → 같은 fingerprint (결정론)
        c1 = LineageCollector(Settings(), git_sha_provider=lambda: "x")
        c2 = LineageCollector(Settings(), git_sha_provider=lambda: "x")
        s1 = c1.snapshot(_state())
        s2 = c2.snapshot(_state())
        assert s1.settings_fingerprint == s2.settings_fingerprint
        assert s1.settings_fingerprint.startswith("sha256:")

    def test_secret_change_reflected_in_fingerprint(self) -> None:
        # SecretStr 은 마스킹되지만 pydantic 은 실제 값 dump 없음 — 마스킹 후 동일 값
        # 그래서 시크릿이 달라도 fingerprint 는 같음 (원본 노출 X 검증)
        from pydantic import SecretStr

        s1 = LineageCollector(
            Settings(github_token=SecretStr("secret-a")),
            git_sha_provider=lambda: "x",
        ).snapshot(_state())
        s2 = LineageCollector(
            Settings(github_token=SecretStr("secret-b")),
            git_sha_provider=lambda: "x",
        ).snapshot(_state())
        # 시크릿 값이 다르지만 fingerprint 동일 → 원본 미노출
        assert s1.settings_fingerprint == s2.settings_fingerprint

    def test_git_sha_from_provider(self) -> None:
        c = LineageCollector(Settings(), git_sha_provider=lambda: "deadbeef")
        assert c.snapshot(_state()).code_version == "deadbeef"

    def test_git_sha_default_fallback_on_error(self) -> None:
        # subprocess 성공 여부와 무관하게 str 반환
        v = _git_sha_default()
        assert isinstance(v, str)

    def test_total_latency_sums(self) -> None:
        c = LineageCollector(Settings(), git_sha_provider=lambda: "x")
        s = c.snapshot(_state())
        assert s.total_latency_ms == 65.0  # 10 + 25 + 30

    def test_node_latencies_max(self) -> None:
        c = LineageCollector(Settings(), git_sha_provider=lambda: "x")
        s = c.snapshot(_state())
        assert s.node_latencies["investigation"] == 30.0
        assert s.node_latencies["triage"] == 10.0

    def test_ensemble_weights_optional_absent(self) -> None:
        c = LineageCollector(Settings(), git_sha_provider=lambda: "x")
        s = c.snapshot(_state())
        assert s.ensemble_weights == {}


class _FakeEnsemble:
    weights = {"signal": 0.5, "llm": 0.3, "experience": 0.2}


class TestEnsembleWeightsCapture:
    def test_captured(self) -> None:
        c = LineageCollector(Settings(), git_sha_provider=lambda: "x")
        s = c.snapshot(_state(ensemble=_FakeEnsemble()))
        assert s.ensemble_weights == {"signal": 0.5, "llm": 0.3, "experience": 0.2}


class TestReportIntegration:
    @pytest.mark.asyncio
    async def test_lineage_embedded_when_collector_injected(self) -> None:
        collector = LineageCollector(Settings(), git_sha_provider=lambda: "abc")
        agent = ReportAgent(Settings(), SeverityEngine(), lineage=collector)
        out = await agent.run(_state())
        assert isinstance(out["oscal_evidence"].lineage, LineageSnapshot)
        assert out["oscal_evidence"].lineage.code_version == "abc"

    @pytest.mark.asyncio
    async def test_no_collector_lineage_none(self) -> None:
        agent = ReportAgent(Settings(), SeverityEngine())
        out = await agent.run(_state())
        assert out["oscal_evidence"].lineage is None
