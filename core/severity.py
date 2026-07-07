"""심각도 정책 엔진.

심각도 = f(공격 영향[baseline], 자산 tier, 임무 단계, 외부 사이버 태세). 규칙은
`core/policy/severity-policy.yaml` 에 외부화 → 코드 수정 없이 튜닝('추후 조정 가능').
심각도 판정권은 LLM 이 아니라 이 엔진(정책)이 갖는다 — 인젝션 내성의 구조적 보장.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from core.exceptions import PolicyError
from core.models import Alert, Severity

POLICY_DIR = Path(__file__).resolve().parent / "policy"
_POSTURE_RANK = {"normal": 0, "elevated": 1, "high": 2}


def _as_dict(value: object, *, where: str) -> dict[str, object]:
    """value 가 dict 가 아니면 PolicyError. mypy-안전한 정책 접근용."""
    if not isinstance(value, dict):
        raise PolicyError(f"정책 형식 오류: {where} 는 매핑이어야 함")
    return {str(k): v for k, v in value.items()}


def _as_int(value: object) -> int:
    return value if isinstance(value, int) else 0


def load_yaml(path: Path) -> dict[str, object]:
    """정책 YAML 을 dict 로 로드한다.

    Args:
        path: 정책 파일 경로.

    Returns:
        최상위 매핑.

    Raises:
        PolicyError: 파일이 매핑이 아닐 때.
    """
    with path.open(encoding="utf-8") as f:
        loaded: object = yaml.safe_load(f)
    return _as_dict(loaded, where=str(path))


class SeverityEngine:
    """`severity-policy.yaml` 의 rule-based 심각도 산정을 구현한다."""

    def __init__(
        self,
        policy: dict[str, object] | None = None,
        assets: dict[str, object] | None = None,
    ) -> None:
        self.policy = policy or load_yaml(POLICY_DIR / "severity-policy.yaml")
        self.assets = assets or load_yaml(POLICY_DIR / "asset-tiers.yaml")

        scoring = _as_dict(self.policy["scoring"], where="scoring")
        self.ordinal: dict[str, int] = {
            str(k): _as_int(v)
            for k, v in _as_dict(scoring["ordinal"], where="ordinal").items()
        }
        self.inv: dict[int, str] = {v: k for k, v in self.ordinal.items()}
        self.tier_mod = _as_dict(
            scoring.get("asset_tier_modifier", {}), where="tier_mod"
        )
        self.phase_mod = _as_dict(
            scoring.get("mission_phase_modifier", {}), where="phase_mod"
        )
        self.posture_mod = _as_dict(
            scoring.get("posture_modifier", {}), where="posture_mod"
        )
        lock = self.posture_mod.get("lock_no_downgrade_at")
        self.lock_at: str | None = lock if isinstance(lock, str) else None

        clamp = scoring.get("clamp", ["i", "h"])
        lo, hi = clamp if isinstance(clamp, list) and len(clamp) == 2 else ["i", "h"]
        self.clamp_lo = self.ordinal[str(lo)]
        self.clamp_hi = self.ordinal[str(hi)]

        dyn = self.policy.get("dynamics", {})
        self.dynamics = _as_dict(dyn, where="dynamics") if isinstance(dyn, dict) else {}

    def compute(self, alert: Alert) -> tuple[Severity, list[str]]:
        """경보의 심각도 등급과 산정 근거를 반환한다.

        Args:
            alert: 입력 경보.

        Returns:
            (등급, 근거 문자열 목록).
        """
        baseline = str(alert.severity_baseline)
        base_n = self.ordinal[baseline]
        d_tier = _as_int(self.tier_mod.get(alert.asset_tier, 0))
        d_phase = _as_int(self.phase_mod.get(alert.mission_phase, 0))
        d_posture = _as_int(self.posture_mod.get(alert.posture, 0))

        total = base_n + d_tier + d_phase + d_posture
        rationale = [
            f"baseline={baseline}({base_n})",
            f"asset[{alert.asset_tier}]={d_tier:+d}",
            f"phase[{alert.mission_phase}]={d_phase:+d}",
            f"posture[{alert.posture}]={d_posture:+d}",
        ]

        locked = bool(
            self.lock_at
            and _POSTURE_RANK.get(alert.posture, 0)
            >= _POSTURE_RANK.get(self.lock_at, 99)
        )

        total = self._apply_dynamics(alert, total, rationale, locked=locked)

        if locked and total < base_n:
            total = base_n
            rationale.append(
                f"posture>={self.lock_at} → no-downgrade lock(baseline 유지)"
            )

        total = max(self.clamp_lo, min(self.clamp_hi, total))
        level = Severity(self.inv[total])
        rationale.append(f"=> {level}")
        return level, rationale

    def _apply_dynamics(
        self, alert: Alert, total: int, rationale: list[str], *, locked: bool
    ) -> int:
        """dynamics 규칙(런타임 신호 기반)을 적용한다.

        posture lock 활성 시 de-escalation(하향)은 적용하지 않는다(명세 준수).
        """
        for raw in self._rules("escalation"):
            rule = _as_dict(raw, where="escalation rule")
            name = rule.get("rule")
            if name == "dwelling_time_exceeds":
                thr = rule.get("threshold_min")
                if isinstance(thr, int) and alert.dwelling_min >= thr:
                    inc = _as_int(rule.get("action", 0))
                    total += inc
                    rationale.append(
                        f"dyn[dwelling {alert.dwelling_min}m≥{thr}]={inc:+d}"
                    )
            elif name == "lateral_correlation" and alert.lateral_correlation:
                floor = self.ordinal.get(str(rule.get("value", "m")), 0)
                if total < floor:
                    total = floor
                    rationale.append(
                        f"dyn[lateral_correlation]→min {rule.get('value')}"
                    )
            elif name == "prediction_match" and alert.prediction_match:
                inc = _as_int(rule.get("action", 0))
                total += inc
                rationale.append(f"dyn[prediction_match]={inc:+d}")
            elif name == "kill_chain_advanced" and alert.kill_chain_advanced:
                inc = _as_int(rule.get("action", 0))
                total += inc
                rationale.append(f"dyn[kill_chain_advanced]={inc:+d}")

        for raw in self._rules("de_escalation"):
            rule = _as_dict(raw, where="de_escalation rule")
            if rule.get("rule") == "no_effect_sustained" and alert.no_effect_sustained:
                if locked:
                    rationale.append("dyn[no_effect_sustained] skipped(posture lock)")
                    continue
                dec = _as_int(rule.get("action", 0))
                total += dec
                rationale.append(f"dyn[no_effect_sustained]={dec:+d}")
        return total

    def _rules(self, key: str) -> list[object]:
        rules = self.dynamics.get(key, [])
        return rules if isinstance(rules, list) else []

    def level_meta(self, level: Severity) -> dict[str, object]:
        """등급별 메타(HITL/자동대응/OSCAL 증거 수준)를 반환한다."""
        levels = _as_dict(self.policy["levels"], where="levels")
        return _as_dict(levels[str(level)], where=f"levels.{level}")
