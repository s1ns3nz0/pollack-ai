"""인과 추론 — 신호→영향 체인 결정론 매핑(spec A1).

`core/policy/causal-rules.yaml` 에 정의된 룰을 alert.signals 와 매칭해 CausalChain
을 빌드한다. LLM 은 step.explanation 채울 때만 사용(선택). 인과 자체는 결정론 —
LLM 인젝션이 인과를 왜곡할 수 없다.

Spec: docs/superpowers/specs/2026-06-30-causal-reasoning-design.md
"""

from __future__ import annotations

from pathlib import Path

import yaml

from core.exceptions import LLMError, PolicyError
from core.llm import LLMClient
from core.models import Alert, CausalChain, CausalStep, InvestigationResult
from utils.logging import get_logger

_EXPLAIN_SYS = (
    "당신은 SOC 분석가다. 주어진 인과 단계(signal→effect→next_step)를 한 문장 한국어로"
    " 평이하게 설명하라. 컨텍스트 밖 추측 금지."
)


def _explain_user(alert: Alert, step: CausalStep) -> str:
    return (
        f"경보: {alert.title}\n"
        f"단계: {step.signal} → {step.effect} → {step.next_step or '(끝)'}\n"
        f"매핑: {step.mitre_technique}"
    )


class CausalReasoner:
    """결정론 인과 룰 기반 체인 빌더.

    LLM 주입 + `explain=True` 시 각 step.explanation 을 LLM 으로 채운다.
    실패한 step 은 explanation 빈값 (체인 자체는 보존).
    """

    def __init__(
        self,
        rules_path: Path,
        llm: LLMClient | None = None,
        explain: bool = False,
    ) -> None:
        self._rules = self._load(rules_path)
        self._llm = llm
        self._explain = explain
        self._logger = get_logger("CausalReasoner")

    @staticmethod
    def _load(path: Path) -> list[dict[str, object]]:
        if not path.exists():
            return []
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise PolicyError(f"causal rules: 루트가 매핑이 아님: {path}")
        rules = data.get("rules", [])
        if not isinstance(rules, list):
            raise PolicyError(f"causal rules: rules 가 리스트가 아님: {path}")
        return [r for r in rules if isinstance(r, dict)]

    async def build_chain(
        self, alert: Alert, inv: InvestigationResult | None = None
    ) -> CausalChain:
        """alert.signals 와 매칭되는 첫 룰의 chain 빌드.

        멀티 룰 매칭은 후속 사이클 — 본 spec 은 첫 매칭만 사용한다.
        """
        del inv
        signals = set(alert.signals)
        for rule in self._rules:
            triggers = rule.get("when_signal", [])
            if not isinstance(triggers, list):
                continue
            trigger_set = {str(t) for t in triggers}
            if not (trigger_set & signals):
                continue
            chain_raw = rule.get("chain", [])
            if not isinstance(chain_raw, list):
                continue
            steps: list[CausalStep] = []
            for s in chain_raw:
                if not isinstance(s, dict):
                    continue
                try:
                    steps.append(
                        CausalStep(
                            signal=str(s.get("signal", "")),
                            effect=str(s.get("effect", "")),
                            next_step=str(s.get("next_step", "")),
                            mitre_technique=str(s.get("mitre_technique", "")),
                        )
                    )
                except Exception:  # noqa: BLE001,S112 - pydantic 검증 graceful skip
                    continue
            if self._explain and self._llm is not None:
                for step in steps:
                    try:
                        step.explanation = await self._llm.acomplete(
                            _EXPLAIN_SYS, _explain_user(alert, step)
                        )
                    except LLMError as exc:
                        self._logger.warning("causal LLM 설명 실패: %s", exc)
            rule_id = str(rule.get("id", ""))
            return CausalChain(steps=steps, basis_rules=[rule_id] if rule_id else [])
        return CausalChain()
