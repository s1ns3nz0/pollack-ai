"""ZTMM self-attested 통제 매핑 — CISA Zero Trust Maturity Model 2.0.

플랫폼 통제를 ZTMM 5 기둥 + 3 교차역량 × 4 성숙도에 매핑한다. **측정이 아니라
self-attested 선언**이라(근거 없이 advanced/optimal 주장 = 씨어터, Codex Crit) 각 성숙도
주장에 **근거(evidence)를 강제**한다:

  - declared advanced/optimal 인데 evidence=self_attested → effective 를 initial 로 cap
    + `unverified_maturity_claim` finding(근거 없는 고등급 봉쇄).
  - verified_runtime/implemented_static(control_ref 감사 가능) → declared 인정.

단일 "overall" 없음(H1) — 기둥/교차역량별 matrix + 보수 rollup 은 minimum_effective.
정직 라벨: measurement_status="not_measured"(overclaim 방지). 정적 — 호출자 1회 캐시.

Spec: docs/superpowers/specs/2026-07-09-zero-trust-maturity-design.md
"""

from __future__ import annotations

from pathlib import Path

from core.models import ZtAttestation, ZtMapping
from core.policy_loader import load_policy_mapping, require_list

_POLICY = Path(__file__).resolve().parent / "policy" / "zt-maturity.yaml"

_MATURITY_ORDER = {"traditional": 0, "initial": 1, "advanced": 2, "optimal": 3}
_ORDER_NAME = ["traditional", "initial", "advanced", "optimal"]
_VERIFIED_EVIDENCE = frozenset({"verified_runtime", "implemented_static"})


def _rank(maturity: str) -> int:
    """성숙도 순서값(미지값 → traditional=0)."""
    return _MATURITY_ORDER.get(maturity.strip().lower(), 0)


def _effective(declared: str, evidence: str) -> str:
    """근거검증 후 실효 성숙도 — 근거 없는 advanced/optimal 은 initial 로 cap(Crit)."""
    if _rank(declared) >= _MATURITY_ORDER["advanced"] and evidence not in (
        _VERIFIED_EVIDENCE
    ):
        return "initial"
    return declared.strip().lower() if declared.strip() else "traditional"


class ZtAssessor:
    """ZTMM self-attested 매핑 산정(결정론·읽기전용·evidence-gated)."""

    def __init__(self, attestations: list[ZtAttestation]) -> None:
        self._attestations = attestations

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> ZtAssessor:
        """zt-maturity.yaml 을 적재한다(공유 로더로 graceful).

        Args:
            path: 정책 경로. 생략 시 기본 zt-maturity.yaml.

        Returns:
            로드된 ZtAssessor.

        Raises:
            PolicyError: 파일 부재/파싱 실패/구조 불일치 시.
        """
        raw = load_policy_mapping(path, _POLICY, label="ZTMM 매핑")
        out: list[ZtAttestation] = []
        for item in require_list(raw.get("maturity"), label="ZTMM maturity"):
            if not isinstance(item, dict):
                continue
            declared = str(item.get("declared", "traditional"))
            evidence = str(item.get("evidence", "self_attested"))
            out.append(
                ZtAttestation(
                    name=str(item.get("name", "")),
                    kind=(
                        "cross_cutting"
                        if str(item.get("kind", "")) == "cross_cutting"
                        else "pillar"
                    ),
                    declared=declared,
                    effective=_effective(declared, evidence),
                    control_ref=str(item.get("control_ref", "")),
                    evidence=evidence,
                )
            )
        return cls(out)

    def assess(self) -> ZtMapping:
        """self-attested 매핑 산정 — 기둥별 matrix + 근거검증 findings(overall 없음).

        Returns:
            ZtMapping(capabilities·minimum_declared·minimum_effective·findings).
        """
        if not self._attestations:
            return ZtMapping(findings=["ztmm_no_capabilities"])
        findings: list[str] = []
        for a in self._attestations:
            # 근거 없는 고등급 주장 — effective 가 declared 아래로 cap 됨(씨어터).
            if _rank(a.effective) < _rank(a.declared):
                findings.append(
                    f"unverified_maturity_claim: {a.name} 선언 {a.declared} 이나 근거"
                    f"({a.evidence}) 미검증 → 실효 {a.effective}"
                )
        min_decl = min(_rank(a.declared) for a in self._attestations)
        min_eff = min(_rank(a.effective) for a in self._attestations)
        return ZtMapping(
            capabilities=self._attestations,
            minimum_declared=_ORDER_NAME[min_decl],
            minimum_effective=_ORDER_NAME[min_eff],
            findings=findings,
        )


def load_zt_mapping() -> ZtMapping:
    """기본 정책으로 ZTMM 매핑 산정 — 실패 시 degraded(관측가능, AIBOM M-b 교훈)."""
    from core.exceptions import SOCPlatformError

    try:
        return ZtAssessor.from_yaml().assess()
    except SOCPlatformError:
        return ZtMapping(findings=["ztmm_assessment_unavailable"])
