"""run_kpi 오프라인 폴백 단위 테스트 — projects/ 부재 시 eval_scenarios 전환."""

from pathlib import Path

import pytest

from benchmarks.run_kpi import (
    evidence_ratios,
    llm_runtime,
    load_tp_alerts,
    resolve_eval_source,
)
from core.models import OscalEvidence, Verdict

_SCN_YAML = """\
scenario_id: S1-GNSS-SPOOF
title: GNSS 스푸핑 (EKF 잔차 급증)
severity_baseline: h
target_asset:
  tier: t1
mission_context:
  phase: on_station
telemetry:
  signals:
    - "PosHorizVariance 0.06 (정상 0.007 대비 7배)"
expected_detection:
  rule: EKF-RESIDUAL-SPIKE
defense_playbook:
  playbook_id: PB-GNSS-01
"""


class TestResolveEvalSource:
    """평가셋 소스 자동 결정 테스트."""

    def test_prefers_live_projects_dir(self, tmp_path: Path) -> None:
        """projects/ 시나리오가 있으면 live 모드 + 해당 경로."""
        live = tmp_path / "projects" / "dah2026" / "scenarios"
        live.mkdir(parents=True)
        (live / "S1-GNSS-SPOOF.yaml").write_text(_SCN_YAML, encoding="utf-8")
        offline = tmp_path / "benchmarks" / "eval_scenarios"
        offline.mkdir(parents=True)

        scen_dir, mode = resolve_eval_source(tmp_path)

        assert scen_dir == live
        assert mode == "live"

    def test_falls_back_to_offline_eval_scenarios(self, tmp_path: Path) -> None:
        """projects/ 없으면 benchmarks/eval_scenarios + offline 모드."""
        offline = tmp_path / "benchmarks" / "eval_scenarios"
        offline.mkdir(parents=True)
        (offline / "S1-GNSS-SPOOF.yaml").write_text(_SCN_YAML, encoding="utf-8")

        scen_dir, mode = resolve_eval_source(tmp_path)

        assert scen_dir == offline
        assert mode == "offline"

    def test_raises_when_no_scenarios_anywhere(self, tmp_path: Path) -> None:
        """양쪽 다 시나리오 없으면 명시적 오류 — 빈 평가셋 무의미."""
        with pytest.raises(FileNotFoundError):
            resolve_eval_source(tmp_path)


class TestLoadTpAlerts:
    """시나리오 YAML → 정탐 Alert 변환 테스트."""

    def test_parses_yaml_into_tp_alert(self, tmp_path: Path) -> None:
        """필드 매핑 + ground_truth=TRUE_POSITIVE 확인."""
        (tmp_path / "S1-GNSS-SPOOF.yaml").write_text(_SCN_YAML, encoding="utf-8")

        alerts = load_tp_alerts(tmp_path)

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.id == "KPI-TP-S1-GNSS-SPOOF"
        assert alert.scenario_id == "S1-GNSS-SPOOF"
        assert alert.severity_baseline.value == "h"
        assert alert.signals == ["PosHorizVariance 0.06 (정상 0.007 대비 7배)"]
        assert alert.expected_detection == {"rule": "EKF-RESIDUAL-SPIKE"}
        assert alert.ground_truth == Verdict.TRUE_POSITIVE

    def test_sorts_by_scenario_number(self, tmp_path: Path) -> None:
        """S2 < S10 숫자 정렬 확인 (사전순이면 S10 이 S2 앞에 옴)."""
        for sid in ("S10-EXFIL", "S2-FW-TAMPER"):
            body = _SCN_YAML.replace("S1-GNSS-SPOOF", sid)
            (tmp_path / f"{sid}.yaml").write_text(body, encoding="utf-8")

        alerts = load_tp_alerts(tmp_path)

        assert [a.scenario_id for a in alerts] == ["S2-FW-TAMPER", "S10-EXFIL"]


class TestEvidenceRatios:
    """KPI evidence 산식은 stub OSCAL 을 완성 증거로 세지 않는다."""

    def test_stub_evidence_is_present_but_not_mapped(self) -> None:
        evidence = [
            OscalEvidence(
                evidence_level="summary",
                implementation_status="stub",
                alert_id="a1",
                scenario_id="S1",
            )
        ]

        ratios = evidence_ratios(evidence, total=1)

        assert ratios["present"] == 1.0
        assert ratios["mapped"] == 0.0

    def test_mapped_evidence_counts_as_mapped(self) -> None:
        evidence = [
            OscalEvidence(
                evidence_level="summary",
                implementation_status="mapped",
                alert_id="a1",
                scenario_id="S1",
                control_refs=["NIST-IR-4"],
            )
        ]

        ratios = evidence_ratios(evidence, total=1)

        assert ratios["present"] == 1.0
        assert ratios["mapped"] == 1.0


class TestLlmRuntime:
    """LLM 런타임 표기는 기본 결정론과 요청 실패 폴백을 구분한다."""

    def test_default_deterministic_is_not_labeled_fallback(self) -> None:
        runtime = llm_runtime(requested=False, available=False)

        assert runtime["llm"] == "deterministic"
        assert runtime["llm_requested"] is False
        assert runtime["degraded"] == []

    def test_requested_but_unavailable_is_degraded_fallback(self) -> None:
        runtime = llm_runtime(requested=True, available=False)

        assert runtime["llm"] == "deterministic-fallback"
        assert runtime["llm_requested"] is True
        assert runtime["degraded"] == ["llm-unavailable"]

    def test_requested_and_available_is_live(self) -> None:
        runtime = llm_runtime(requested=True, available=True)

        assert runtime["llm"] == "live"
        assert runtime["degraded"] == []
