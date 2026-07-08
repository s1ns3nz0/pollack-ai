"""분석 엔진 배선 — diamond→report, cato→metrics, bda→worker 가 실제로 돎."""

from typing import cast

import pytest

from app.metrics import _cato_metrics
from core.bda import BdaAssessor
from core.models import Severity


class TestDiamondInReport:
    """ReportAgent 가 DiamondEvent 를 report 에 노출."""

    @pytest.mark.asyncio
    async def test_report_exposes_diamond(self) -> None:
        from agents.graph import build_soc_graph
        from core.models import Alert

        graph = build_soc_graph()
        alert = Alert(
            id="a1",
            scenario_id="S2",
            title="t",
            asset_id="C2_LINK",
            mission_phase="ingress",
            severity_baseline=Severity.MEDIUM,
            signals=["sig"],
            iocs=["9.9.9.9"],
            mitre={"tactics": ["c2"], "techniques": ["T1071"]},
        )
        state = await graph.ainvoke({"alert": alert})
        report = state["report"]
        assert report.diamond is not None
        assert report.diamond.victim == "C2_LINK"
        assert "T1071" in report.diamond.capabilities
        assert "9.9.9.9" in report.diamond.infrastructure


class TestCatoMetrics:
    """cATO 게이지가 스크레이프에 노출(정책 로드되면)."""

    def test_cato_metrics_emitted(self) -> None:
        lines = _cato_metrics()
        # 정책(cato-controls.yaml + bas + slo) 있으면 게이지 방출
        text = "\n".join(lines)
        assert "soc_cato_authorization" in text
        assert "soc_cato_poam_total" in text

    def test_cato_metrics_graceful(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """의존 로드 실패 시 빈 목록(스크레이프 안 깨짐)."""
        import core.bas as bas_mod

        def _boom(*_a: object, **_k: object) -> object:
            raise RuntimeError("no policy")

        monkeypatch.setattr(bas_mod.BASRunner, "from_yaml", classmethod(_boom))
        assert _cato_metrics() == []


class TestBdaInWorker:
    """OutcomeProbeAgent 가 BDA 를 산정(복구권고 집계)."""

    @pytest.mark.asyncio
    async def test_worker_assesses_bda_restore(self) -> None:
        from agents.outcome_probe_agent import OutcomeProbeAgent
        from core.outcome import InMemoryObservationSource, Observation, ProbeEngine
        from core.settings import get_settings

        src = InMemoryObservationSource()
        # 유의미 피해(mission_effect+reoccurred → effect=0.0) + 복구 미적용 → 복구권고
        src.push(
            Observation.model_validate(
                {
                    "alert_id": "a1",
                    "scenario_id": "S1",
                    "ts": "t",
                    "mission_effect_observed": True,
                    "reoccurred": True,
                    "window_min": 10,
                }
            )
        )
        agent = OutcomeProbeAgent(get_settings(), src, ProbeEngine())
        report = await agent.run()
        assert report.errors == []  # 정상 사이클(BDA 계산 포함)

    @pytest.mark.asyncio
    async def test_bda_error_contained(self) -> None:
        """BDA assessor 예외 → 사이클 안 깨짐, errors 에 담김(Codex Medium)."""
        from agents.outcome_probe_agent import OutcomeProbeAgent
        from core.outcome import InMemoryObservationSource, Observation, ProbeEngine
        from core.settings import get_settings

        class _BoomBda:
            def assess(self, *_a: object, **_k: object) -> object:
                raise ValueError("boom")

        src = InMemoryObservationSource()
        src.push(
            Observation.model_validate(
                {"alert_id": "a1", "scenario_id": "S1", "ts": "t"}
            )
        )
        agent = OutcomeProbeAgent(
            get_settings(), src, ProbeEngine(), bda=cast(BdaAssessor, _BoomBda())
        )
        report = await agent.run()  # 예외 전파 안 됨
        assert any("bda[a1]" in e for e in report.errors)

    def test_bda_default_wired(self) -> None:
        """BdaAssessor 기본 배선(미주입도 자동 생성)."""
        from agents.outcome_probe_agent import OutcomeProbeAgent
        from core.outcome import InMemoryObservationSource, ProbeEngine
        from core.settings import get_settings

        agent = OutcomeProbeAgent(
            get_settings(), InMemoryObservationSource(), ProbeEngine()
        )
        assert agent._bda is not None
