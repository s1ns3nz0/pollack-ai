"""골든 픽스처(issue #83) — detection fixture -> response runbook trace 결정론 검증.

fixture -> tactic -> CACAO playbook 선택, fixture -> asset_id -> mission_continuity
(graceful degradation resilience) 두 체인을 실제 컴포넌트(ResponseAgent/ReportAgent)로
검증한다. issue #83의 pseudo-flow는 `response.mission_continuity`를 가정했으나 실제로는
`report.mission_continuity`(agents/report_agent.py, core/degradation.py)에 있다 —
"실제 detection-side 매핑을 쓸 것"이라는 issue 안내에 따라 실제 컴포넌트 배선을 따랐다.

Spec: https://github.com/s1ns3nz0/pollack-ai/issues/83
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agents.report_agent import ReportAgent
from agents.response_agent import ResponseAgent
from core.cacao import CacaoPlaybook, load_playbooks
from core.degradation import DegradationAssessor, DegradationMatrix
from core.models import Alert, Severity, SOCState, Verdict
from core.settings import Settings
from core.severity import SeverityEngine
from tools.coverage import CoverageMatrix

_FIXTURES_DIR = Path(__file__).resolve().parents[2] / "benchmarks" / "eval_scenarios"

# issue #83 "Initial Golden Fixtures To Cover" 5건 — 전부 실제 dah-sentinel-content
# 배포 룰(S1~S126 신번호)과 CACAO 카탈로그/degradation-matrix 실측으로 매핑됨.
_GOLDEN_FIXTURES = [
    "S1-GNSS-SPOOF.yaml",
    "S24-DATALINK-C2-TAKEOVER.yaml",
    "S33-FIRMWARE-SUPPLY-CHAIN-TAMPER.yaml",
    "S117-BLOS-SATCOM-MITM.yaml",
    "S89-RAG-POISONING.yaml",
]

_REQUIRED_FIELDS = (
    "fixture_id",
    "scenario_id",
    "title",
    "asset_id",
    "expected_tactic",
    "expected_techniques",
    "expected_detection",
    "expected_cacao_playbook_id",
    "expected_resilience_level",
    "expected_fallback_contains",
    "expected_report_evidence",
)


def _load_fixture(name: str) -> dict[str, object]:
    return yaml.safe_load((_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def _alert_from_fixture(fx: dict[str, object]) -> Alert:
    telemetry = fx.get("telemetry", {})
    return Alert(
        id=str(fx["fixture_id"]),
        scenario_id=str(fx["scenario_id"]),
        title=str(fx["title"]),
        asset_id=str(fx["asset_id"]),
        severity_baseline=Severity(str(fx["severity_baseline"])),
        signals=list(telemetry.get("signals", [])) if isinstance(telemetry, dict) else [],
        defense_playbook=dict(fx.get("defense_playbook", {}) or {}),
    )


@pytest.fixture(scope="module")
def catalog() -> list[CacaoPlaybook]:
    return load_playbooks()


@pytest.fixture(scope="module")
def degradation() -> DegradationAssessor:
    return DegradationAssessor(DegradationMatrix.from_yaml())


class TestFixtureContract:
    """acceptance criteria — 필수 필드 + 참조 무결성(tactic/playbook/asset 실재)."""

    @pytest.mark.parametrize("name", _GOLDEN_FIXTURES)
    def test_required_fields_present(self, name: str) -> None:
        fx = _load_fixture(name)
        missing = [k for k in _REQUIRED_FIELDS if k not in fx]
        assert not missing, f"{name} missing required fields: {missing}"

    @pytest.mark.parametrize("name", _GOLDEN_FIXTURES)
    def test_expected_tactic_exists_in_attack_coverage(self, name: str) -> None:
        fx = _load_fixture(name)
        tactic_names = {t.name for t in CoverageMatrix.from_yaml().tactics}
        assert fx["expected_tactic"] in tactic_names

    @pytest.mark.parametrize("name", _GOLDEN_FIXTURES)
    def test_expected_playbook_exists_in_catalog(
        self, name: str, catalog: list[CacaoPlaybook]
    ) -> None:
        fx = _load_fixture(name)
        assert fx["expected_cacao_playbook_id"] in {pb.id for pb in catalog}

    @pytest.mark.parametrize("name", _GOLDEN_FIXTURES)
    def test_asset_id_exists_in_degradation_matrix(
        self, name: str, degradation: DegradationAssessor
    ) -> None:
        fx = _load_fixture(name)
        probe = Alert(
            id="probe",
            scenario_id="probe",
            title="probe",
            asset_id=str(fx["asset_id"]),
            severity_baseline=Severity.HIGH,
        )
        assert degradation.assess(probe, Verdict.TRUE_POSITIVE) is not None


class TestFixtureToCacaoPlaybookTrace:
    """fixture -> tactic -> CACAO playbook 선택 결정론 검증."""

    @pytest.mark.parametrize("name", _GOLDEN_FIXTURES)
    @pytest.mark.asyncio
    async def test_selected_playbook_matches_expected(
        self, name: str, catalog: list[CacaoPlaybook]
    ) -> None:
        fx = _load_fixture(name)
        alert = _alert_from_fixture(fx)
        agent = ResponseAgent(
            Settings(),
            SeverityEngine(),
            playbooks=catalog,
            scenario_tactic={fx["scenario_id"]: fx["expected_tactic"]},
        )
        state: SOCState = {
            "alert": alert,
            "severity": Severity.HIGH,
            "verdict": Verdict.TRUE_POSITIVE,
        }
        out = await agent.run(state)
        assert out["response"].cacao_playbook_id == fx["expected_cacao_playbook_id"]


class TestFixtureToResilienceTrace:
    """fixture -> asset_id -> mission_continuity(response resilience) 결정론 검증."""

    @pytest.mark.parametrize("name", _GOLDEN_FIXTURES)
    @pytest.mark.asyncio
    async def test_mission_continuity_matches_expected(
        self, name: str, degradation: DegradationAssessor
    ) -> None:
        fx = _load_fixture(name)
        alert = _alert_from_fixture(fx)
        agent = ReportAgent(Settings(), SeverityEngine(), degradation=degradation)
        state: SOCState = {
            "alert": alert,
            "severity": Severity.HIGH,
            "verdict": Verdict.TRUE_POSITIVE,
        }
        out = await agent.run(state)
        mc = out["report"].mission_continuity

        assert mc is not None
        assert mc.level == fx["expected_resilience_level"]
        assert fx["expected_fallback_contains"] in mc.fallback
        assert fx["expected_report_evidence"] in mc.capability_lost
