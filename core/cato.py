"""cATO — 지속 인가(Continuous ATO) 합성 엔진(NIST 800-37 RMF / DoD DevSecOps).

기존 방어 검증 신호(BAS 탐지 커버리지·SLO 위반·SBOM 무결성)를 NIST 800-53 통제
갭으로 환산해 **POA&M**(Plan of Action & Milestones) 을 산출하고, 갭 심각도에 따라
지속 인가 태세(authorized/conditional/at_risk)를 판정한다. "컴플라이언스 증거가
파이프라인에서 자동 생성"(팀 선언) 을 인가 판정까지 확장 — OSCAL 이 *증거*라면
cATO 는 그 증거의 *지속 인가 판정*이다.

전 과정 결정론·정책구동(cato-controls.yaml). LLM 무관.

Spec: docs/superpowers/specs/2026-07-08-cato-poam-design.md
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel
import yaml

from core.bas import BASReport
from core.exceptions import PolicyError
from core.models import CatoStatus, PoamItem, SbomFinding
from core.monitoring import SloBreach

_POLICY = Path(__file__).resolve().parent / "policy" / "cato-controls.yaml"

# SBOM issue → POA&M 심각도(변조/취약=고, 미등록=중).
_SBOM_SEVERITY = {"tampered": "high", "vulnerable": "high", "unregistered": "medium"}
_SEV_RANK = {"low": 1, "medium": 2, "high": 3}


class ControlMapping(BaseModel):
    """cato-controls.yaml 통제 매핑 한 건."""

    id: str
    family: str = ""
    source: str = ""  # "bas" | "slo" | "sbom"
    severity: str = "medium"  # 소스가 자체 severity 없을 때 기본


class CatoControls:
    """cato-controls.yaml 로더 — 통제↔신호 매핑 + BAS 탐지 하한."""

    def __init__(
        self, controls: list[ControlMapping], bas_detection_floor: float
    ) -> None:
        self._controls = controls
        self.bas_detection_floor = bas_detection_floor

    def by_source(self, source: str) -> ControlMapping | None:
        """소스 신호에 매핑된 통제(첫 매칭)."""
        return next((c for c in self._controls if c.source == source), None)

    @property
    def count(self) -> int:
        """정의된 통제 수."""
        return len(self._controls)

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> CatoControls:
        """cato-controls.yaml 을 적재한다.

        Raises:
            PolicyError: 파일 부재/파싱 실패/구조 불일치/빈 통제 시.
        """
        p = Path(path) if path is not None else _POLICY
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise PolicyError(f"cATO 통제 적재 실패: {exc}") from exc
        if not isinstance(raw, dict):
            raise PolicyError("cATO 통제 구조 오류(최상위 dict 아님).")
        cato = raw.get("cato")
        if not isinstance(cato, dict):
            raise PolicyError("cATO 통제 구조 오류(cato 섹션 없음).")
        floor = cato.get("bas_detection_floor", 0.8)
        try:
            floor_f = float(floor)
        except (TypeError, ValueError) as exc:
            raise PolicyError(f"bas_detection_floor 형식 오류: {exc}") from exc
        controls = [
            ControlMapping.model_validate(c)
            for c in (cato.get("controls") or [])
            if isinstance(c, dict) and c.get("id")
        ]
        if not controls:
            raise PolicyError("cATO 통제가 비어있음.")
        return cls(controls, floor_f)


class CatoAssessor:
    """방어 검증 신호 → POA&M + 지속 인가 판정(결정론).

    Args:
        controls: 통제↔신호 매핑 정책.
    """

    def __init__(self, controls: CatoControls) -> None:
        self._controls = controls

    def assess(
        self,
        bas: BASReport | None = None,
        slo_breaches: list[SloBreach] | None = None,
        sbom_findings: list[SbomFinding] | None = None,
    ) -> CatoStatus:
        """신호를 통제 갭으로 환산해 POA&M + 인가태세를 산출한다.

        Args:
            bas: BAS 검증 결과(탐지 커버리지). None 이면 해당 통제 skip.
            slo_breaches: SLO 위반 목록. None/빈 이면 갭 없음.
            sbom_findings: SBOM 무결성 위험. None/빈 이면 갭 없음.

        Returns:
            POA&M 집계 + authorization 판정을 담은 CatoStatus.
        """
        poam: list[PoamItem] = []
        poam.extend(self._bas_gap(bas))
        poam.extend(self._slo_gaps(slo_breaches or []))
        poam.extend(self._sbom_gaps(sbom_findings or []))

        authorization = self._authorize(poam)
        rationale = [f"통제 {self._controls.count}건 평가, POA&M {len(poam)}건"]
        rationale.append(f"인가태세={authorization}")
        return CatoStatus(
            authorization=authorization,
            poam=poam,
            controls_evaluated=self._controls.count,
            rationale=rationale,
        )

    def _bas_gap(self, bas: BASReport | None) -> list[PoamItem]:
        if bas is None:
            return []
        ctrl = self._controls.by_source("bas")
        if ctrl is None or bas.detection_ratio >= self._controls.bas_detection_floor:
            return []
        return [
            PoamItem(
                control_id=ctrl.id,
                family=ctrl.family,
                severity=ctrl.severity,
                source="bas",
                gap=(
                    f"BAS 탐지 커버리지 {bas.detection_ratio:.0%} < "
                    f"하한 {self._controls.bas_detection_floor:.0%} "
                    f"(미탐 {len(bas.gaps)}건)"
                ),
            )
        ]

    def _slo_gaps(self, breaches: list[SloBreach]) -> list[PoamItem]:
        ctrl = self._controls.by_source("slo")
        if ctrl is None:
            return []
        return [
            PoamItem(
                control_id=ctrl.id,
                family=ctrl.family,
                severity=b.severity if b.severity in _SEV_RANK else ctrl.severity,
                source="slo",
                gap=f"SLO 위반 {b.metric}: {b.message}",
            )
            for b in breaches
        ]

    def _sbom_gaps(self, findings: list[SbomFinding]) -> list[PoamItem]:
        ctrl = self._controls.by_source("sbom")
        if ctrl is None:
            return []
        return [
            PoamItem(
                control_id=ctrl.id,
                family=ctrl.family,
                severity=_SBOM_SEVERITY.get(f.issue, ctrl.severity),
                source="sbom",
                gap=f"SBOM {f.issue}: {f.component} {f.detail}".strip(),
            )
            for f in findings
        ]

    @staticmethod
    def _authorize(poam: list[PoamItem]) -> str:
        """POA&M 최고 심각도 → 인가태세(고=at_risk / 중·저=conditional / 무=ok)."""
        if not poam:
            return "authorized"
        worst = max(_SEV_RANK.get(p.severity, 2) for p in poam)
        if worst >= _SEV_RANK["high"]:
            return "at_risk"
        return "conditional"
