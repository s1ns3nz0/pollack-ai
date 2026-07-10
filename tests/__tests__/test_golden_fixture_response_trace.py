"""골든 픽스처(issue #83) — detection fixture -> response runbook trace 결정론 검증.

fixture -> tactic -> CACAO playbook 선택, fixture -> asset_id -> mission_continuity
(graceful degradation resilience) 두 체인을 실제 컴포넌트(ResponseAgent/ReportAgent)로
검증한다. issue #83의 pseudo-flow는 `response.mission_continuity`를 가정했으나 실제로는
`report.mission_continuity`(agents/report_agent.py, core/degradation.py)에 있다 —
"실제 detection-side 매핑을 쓸 것"이라는 issue 안내에 따라 실제 컴포넌트 배선을 따랐다.

Spec: https://github.com/s1ns3nz0/pollack-ai/issues/83
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml

from agents.report_agent import ReportAgent
from agents.response_agent import ResponseAgent
from core.cacao import CacaoPlaybook, load_playbooks, scenario_tactic_map
from core.degradation import DegradationAssessor, DegradationMatrix
from core.models import Alert, Severity, SOCState, Verdict
from core.runbook import load_runbooks
from core.settings import Settings
from core.severity import SeverityEngine
from tools.coverage import CoverageMatrix

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FIXTURES_DIR = _REPO_ROOT / "benchmarks" / "eval_scenarios"
_MANIFEST_PATH = _REPO_ROOT / "sentinel" / "rule_manifest.json"

# benchmarks/eval_scenarios 의 모든 golden fixture 를 response trace 로 검증한다.
_GOLDEN_FIXTURES = sorted(p.name for p in _FIXTURES_DIR.glob("*.yaml"))

_REQUIRED_FIELDS = (
    "fixture_id",
    "scenario_id",
    "title",
    "asset_id",
    "expected_tactic",
    "expected_techniques",
    "expected_detection",
    "expected_cacao_playbook_id",
    "expected_runbook_id",
    "expected_resilience_level",
    "expected_fallback_contains",
    "expected_report_evidence",
)


def _load_fixture(name: str) -> dict[str, object]:
    data = yaml.safe_load((_FIXTURES_DIR / name).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _alert_from_fixture(fx: dict[str, object]) -> Alert:
    telemetry = fx.get("telemetry", {})
    playbook = fx.get("defense_playbook") or {}
    return Alert(
        id=str(fx["fixture_id"]),
        scenario_id=str(fx["scenario_id"]),
        title=str(fx["title"]),
        asset_id=str(fx["asset_id"]),
        severity_baseline=Severity(str(fx["severity_baseline"])),
        signals=(
            list(telemetry.get("signals", [])) if isinstance(telemetry, dict) else []
        ),
        defense_playbook=playbook if isinstance(playbook, dict) else {},
    )


def _load_manifest() -> dict[str, dict[str, list[str]]]:
    """`sentinel/rule_manifest.json` 의 rules 맵(파일명 -> tactics/techniques) 반환.

    Returns:
        룰 파일명을 tactics/techniques 리스트에 매핑한 딕셔너리.

    Raises:
        AssertionError: 매니페스트가 없거나 구조가 예상과 다를 때.
    """
    assert _MANIFEST_PATH.exists(), (
        f"룰 매니페스트 없음: {_MANIFEST_PATH} — "
        "`python scripts/sync_rule_manifest.py` 로 생성"
    )
    data = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    rules = data.get("rules")
    assert isinstance(rules, dict)
    return {
        str(name): {
            "tactics": [str(t) for t in entry.get("tactics", [])],
            "techniques": [str(t) for t in entry.get("techniques", [])],
        }
        for name, entry in rules.items()
        if isinstance(entry, dict)
    }


def _technique_covered(fixture_tech: str, rule_techs: list[str]) -> bool:
    """fixture 기법이 룰 기법 집합에 부모-자식(prefix) 관점으로 커버되는지.

    ATT&CK 하위기법(`T1565.001`)은 부모(`T1565`)만 선언한 룰로도 커버로 본다.
    반대로 fixture 가 부모만 선언하고 룰이 하위기법만 가진 경우도 커버로 인정한다.

    Args:
        fixture_tech: fixture 의 `expected_techniques` 항목 하나.
        rule_techs: 대응 Sentinel 룰의 `techniques` 목록.

    Returns:
        커버되면 True.
    """
    for rt in rule_techs:
        if fixture_tech == rt:
            return True
        if fixture_tech.startswith(f"{rt}."):
            return True
        if rt.startswith(f"{fixture_tech}."):
            return True
    return False


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

    @pytest.mark.parametrize("name", _GOLDEN_FIXTURES)
    def test_sentinel_rule_exists_in_manifest(self, name: str) -> None:
        """fixture 가 가리키는 sentinel_rule 이 dah-sentinel-content 카탈로그에 실재."""
        fx = _load_fixture(name)
        detection = fx.get("expected_detection")
        assert isinstance(detection, dict), f"{name}: expected_detection 누락/형식오류"
        rule = detection.get("sentinel_rule")
        assert isinstance(rule, str) and rule, f"{name}: sentinel_rule 누락"
        manifest = _load_manifest()
        assert rule in manifest, (
            f"{name}: sentinel_rule '{rule}' 이 룰 매니페스트에 없음 — "
            "dah-sentinel-content 에 룰이 있는지 확인 후 "
            "`python scripts/sync_rule_manifest.py` 재실행"
        )

    @pytest.mark.parametrize("name", _GOLDEN_FIXTURES)
    def test_expected_techniques_consistent_with_rule(self, name: str) -> None:
        """fixture 의 expected_techniques 가 실제 룰 techniques 와 정합(부모-자식 허용).

        오배선(엉뚱한 실존 룰을 가리키는) 방지 — fixture 기법과 룰 기법이
        전혀 겹치지 않으면 잘못된 매핑으로 간주하고 실패시킨다.
        """
        fx = _load_fixture(name)
        detection = fx.get("expected_detection")
        assert isinstance(detection, dict)
        rule = str(detection["sentinel_rule"])
        manifest = _load_manifest()
        assert rule in manifest
        rule_techs = manifest[rule]["techniques"]
        fixture_techs = fx.get("expected_techniques") or []
        assert isinstance(fixture_techs, list)

        uncovered = [
            str(t) for t in fixture_techs if not _technique_covered(str(t), rule_techs)
        ]
        assert not uncovered, (
            f"{name}: expected_techniques {uncovered} 가 룰 '{rule}' 의 "
            f"techniques {rule_techs} 로 커버되지 않음 (오배선 의심)"
        )


class TestManifestDrift:
    """룰 매니페스트가 dah-sentinel-content 실물과 어긋나지 않는지(로컬 옵트인)."""

    @pytest.mark.skipif(
        not os.environ.get("DAH_SENTINEL_PATH"),
        reason="DAH_SENTINEL_PATH 미설정 — CI hermetic 실행에서는 드리프트 검사 생략",
    )
    def test_manifest_matches_source_repo(self) -> None:
        """env 로 소스 레포가 주어지면 재생성본과 커밋본이 일치해야 한다."""
        from scripts.sync_rule_manifest import build_manifest

        source = Path(os.environ["DAH_SENTINEL_PATH"])
        regenerated = build_manifest(source)
        committed = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))

        assert regenerated["rules"] == committed["rules"], (
            "룰 매니페스트가 소스 레포와 어긋남 — "
            "`python scripts/sync_rule_manifest.py` 로 갱신 후 커밋"
        )


class TestFixtureToCacaoPlaybookTrace:
    """fixture -> tactic -> CACAO playbook 선택 결정론 검증."""

    @pytest.mark.parametrize("name", _GOLDEN_FIXTURES)
    @pytest.mark.asyncio
    async def test_selected_playbook_matches_expected(
        self, name: str, catalog: list[CacaoPlaybook]
    ) -> None:
        fx = _load_fixture(name)
        alert = _alert_from_fixture(fx)
        # 실제 production 맵(scenario_tactic_map)을 사용해야 fixture→맵→PB 체인이
        # 검증된다 — fixture 의 expected_tactic 을 주입하면 순환 검증이 된다.
        real_map = scenario_tactic_map()
        assert real_map.get(str(fx["scenario_id"])) == fx["expected_tactic"]
        agent = ResponseAgent(
            Settings(),
            SeverityEngine(),
            playbooks=catalog,
            scenario_tactic=real_map,
            runbooks=load_runbooks(),
        )
        state: SOCState = {
            "alert": alert,
            "severity": Severity.HIGH,
            "verdict": Verdict.TRUE_POSITIVE,
        }
        out = await agent.run(state)
        assert out["response"].cacao_playbook_id == fx["expected_cacao_playbook_id"]
        assert out["response"].runbook_id == fx["expected_runbook_id"]
        assert out["response"].runbook_status == "resolved"


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
        assert str(fx["expected_fallback_contains"]) in mc.fallback
        assert str(fx["expected_report_evidence"]) in mc.capability_lost
