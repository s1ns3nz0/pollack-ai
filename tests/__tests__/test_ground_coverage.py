"""지상 세그먼트 방어 커버리지 — blind KPI·계측 백로그·정직성 불변식."""

import pytest

from core.exceptions import CoverageDataError
from tools.coverage import (
    DEFAULT_COVERAGE_PATH,
    CoverageMatrix,
    GroundEvidence,
    GroundRemediation,
    GroundSegmentCoverage,
    GroundSurface,
)


class TestReport:
    def test_all_fourteen_blind(self) -> None:
        """기본 데이터 — 14개 surface 전부 구조적 사각(covered_by 비어있음)."""
        r = GroundSegmentCoverage.from_yaml().ground_report()
        assert r.total_surfaces == 14
        assert r.blind == 14 and r.covered == 0
        assert r.coverage_pct == 0.0

    def test_blind_by_segment(self) -> None:
        r = GroundSegmentCoverage.from_yaml().ground_report()
        assert r.blind_by_segment == {
            "gcs_app": 4,
            "companion_ros": 3,
            "datalink": 3,
            "fleet_cloud": 4,
        }

    def test_backlog_sorted_by_unblocks(self) -> None:
        """계측 백로그 — 해소 수 내림차순, 다수 해소 로그원이 앞."""
        r = GroundSegmentCoverage.from_yaml().ground_report()
        top = r.backlog[0]
        assert top.unblocks == 3 and top.remediation in {
            "gcs_app_telemetry",
            "ros_audit",
        }
        assert [b.unblocks for b in r.backlog] == sorted(
            (b.unblocks for b in r.backlog), reverse=True
        )
        # blind surface 총합 == 백로그 해소 수 총합(누락 없음).
        assert sum(b.unblocks for b in r.backlog) == 14

    def test_new_techniques_parent_sub_split(self) -> None:
        """신규기법 — 완전신규 vs 부모가 항공에 있는 서브 분리(M3)."""
        nt = GroundSegmentCoverage.from_yaml().new_techniques()
        assert set(nt.exact_new) == {"T1203", "T0857", "T0855", "T1557"}
        assert set(nt.subtechnique_of_covered) == {"T1195.002", "T1565.001"}
        # 항공에 이미 있는 기법(T1190/T1565/T0831/T1059/T1195)은 어느 버킷에도 없음.
        both = set(nt.exact_new) | set(nt.subtechnique_of_covered)
        assert both.isdisjoint({"T1190", "T1565", "T0831", "T1059", "T1195"})

    def test_blind_kill_chains_never_detectable(self) -> None:
        """L5 — blind 킬체인 C19/C20 은 항상 detectable=False(데이터로 못 덮음)."""
        r = GroundSegmentCoverage.from_yaml().ground_report()
        ids = {c.id for c in r.blind_kill_chains}
        assert ids == {"C19", "C20"}
        assert all(not c.detectable for c in r.blind_kill_chains)


class TestNoInflation:
    def test_airborne_report_unchanged_by_ground(self) -> None:
        """H2 — 지상 모듈이 항공 KPI(total/pct)에 절대 안 섞임."""
        before = CoverageMatrix.from_yaml().report()
        GroundSegmentCoverage.from_yaml().ground_report()  # 부작용 없어야
        after = CoverageMatrix.from_yaml().report()
        assert before.total == after.total
        assert before.coverage_pct == after.coverage_pct
        assert before.addressable_pct == after.addressable_pct

    def test_ground_yaml_rejects_airborne_file(self) -> None:
        """H2 — tactics 키 있는 항공 파일을 지상 로더로 적재하면 거부."""
        with pytest.raises(CoverageDataError):
            GroundSegmentCoverage.from_yaml(DEFAULT_COVERAGE_PATH)


class TestEvidenceGate:
    def _cov(self, surfaces: list[GroundSurface]) -> GroundSegmentCoverage:
        rem = {
            "impl": GroundRemediation(id="impl", implemented=True),
            "todo": GroundRemediation(id="todo", implemented=False),
        }
        return GroundSegmentCoverage(surfaces, rem)

    def test_covered_by_flips_when_implemented(self) -> None:
        """근거(구현 remediation) 있으면 covered 로 전환."""
        s = GroundSurface(
            scenario="S1",
            segment="x",
            remediation="impl",
            covered_by=[GroundEvidence(remediation="impl", source_table="T_CL")],
        )
        assert not s.blind
        r = self._cov([s]).ground_report(CoverageMatrix.from_yaml())
        assert r.covered == 1 and r.blind == 0

    def test_postload_mutation_cannot_inflate(self) -> None:
        """High — 적재 후 미구현 근거를 append 해도 런타임 게이트가 blind 로 유지."""
        s = GroundSurface(scenario="S1", segment="x", remediation="todo")
        cov = self._cov([s])
        s.covered_by.append(GroundEvidence(remediation="todo"))  # 미구현
        r = cov.ground_report(CoverageMatrix.from_yaml())
        assert r.covered == 0 and r.blind == 1
        # 미지 remediation 도 마찬가지.
        s.covered_by[:] = [GroundEvidence(remediation="ghost")]
        assert cov.ground_report(CoverageMatrix.from_yaml()).blind == 1

    def test_placeholder_evidence_rejected(self, tmp_path: object) -> None:
        """M4 — 미구현 remediation 을 근거로 위장하면 CoverageDataError."""
        p = tmp_path / "g.yaml"  # type: ignore[operator]
        p.write_text(
            "remediations:\n  todo: {implemented: false}\n"
            "surfaces:\n  - {scenario: S1, remediation: todo, "
            "covered_by: [{remediation: todo}]}\n",
            encoding="utf-8",
        )
        with pytest.raises(CoverageDataError):
            GroundSegmentCoverage.from_yaml(str(p))


class TestGraceful:
    def test_missing_policy_raises(self) -> None:
        with pytest.raises(CoverageDataError):
            GroundSegmentCoverage.from_yaml("/tmp/__no_ground__.yaml")
