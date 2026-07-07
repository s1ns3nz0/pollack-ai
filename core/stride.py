"""UAV STRIDE 위협 모델 — 공격을 6 유형으로 분류 + 완화 매핑 + BAS 커버리지 연계.

UAV 전용 STRIDE 모델(2025 IET, "Enhanced Cybersecurity Framework for UAS")의
결정론 구현. alert 를 STRIDE 6 유형(Spoofing/Tampering/Repudiation/Info
Disclosure/DoS/Elevation of Privilege)으로 분류하고 각 유형의 완화책을 제시한다.
분류는 alert.mitre.stride 명시 태그 우선, 없으면 tactic 으로 추론한다.

BAS 의 by_stride 커버리지와 연계 — "어느 위협 유형에 방어 공백이 있나" 를 산출해
STRIDE 관점의 방어 성숙도를 노출한다. LLM 무관, 전 과정 결정론.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field
import yaml

from core.exceptions import PolicyError
from core.models import Alert, StrideThreat

_POLICY = Path(__file__).resolve().parent / "policy" / "stride-model.yaml"


class StrideCategory(BaseModel):
    """STRIDE 카테고리 정의 한 건."""

    code: str
    name: str
    desc: str = ""
    mitigation: str = ""
    tactics: list[str] = Field(default_factory=list)


class StrideModel:
    """stride-model.yaml 로더 — STRIDE 6 카테고리 정의."""

    def __init__(self, categories: dict[str, StrideCategory]) -> None:
        self._categories = categories

    @property
    def category_count(self) -> int:
        """정의된 카테고리 수."""
        return len(self._categories)

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> StrideModel:
        """stride-model.yaml 을 적재한다.

        Args:
            path: 정책 경로. 생략 시 기본 stride-model.yaml.

        Returns:
            로드된 StrideModel.

        Raises:
            PolicyError: 파일 부재/파싱 실패/구조 불일치 시.
        """
        p = Path(path) if path is not None else _POLICY
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise PolicyError(f"STRIDE 모델 적재 실패: {exc}") from exc
        if not isinstance(raw, dict):
            raise PolicyError("STRIDE 모델 구조 오류(최상위 dict 아님).")
        categories: dict[str, StrideCategory] = {}
        raw_cats = raw.get("categories", {})
        if isinstance(raw_cats, dict):
            for code, cell in raw_cats.items():
                if not isinstance(cell, dict):
                    continue
                categories[str(code)] = StrideCategory(
                    code=str(code),
                    name=str(cell.get("name", "")),
                    desc=str(cell.get("desc", "")),
                    mitigation=str(cell.get("mitigation", "")),
                    tactics=[str(t) for t in cell.get("tactics", []) or []],
                )
        if not categories:
            raise PolicyError("STRIDE 모델에 카테고리가 없음.")
        return cls(categories)

    def category(self, code: str) -> StrideCategory | None:
        """STRIDE 코드의 카테고리 정의를 반환한다(미정의면 None)."""
        return self._categories.get(code)

    def codes(self) -> list[str]:
        """정의된 STRIDE 코드 목록."""
        return list(self._categories)

    def codes_for_tactic(self, tactic: str) -> list[str]:
        """tactic 이 해당하는 STRIDE 코드 목록(추론용)."""
        return [c.code for c in self._categories.values() if tactic in c.tactics]


class StrideClassifier:
    """alert → STRIDE 위협 분류 + BAS 커버리지 연계.

    Args:
        model: STRIDE 카테고리 정의 모델.
    """

    def __init__(self, model: StrideModel) -> None:
        self._model = model

    def classify(self, alert: Alert) -> list[StrideThreat]:
        """alert 를 STRIDE 위협 유형으로 분류한다.

        alert.mitre.stride 명시 태그 우선, 없으면 tactic 으로 추론한다.

        Args:
            alert: 대상 알람.

        Returns:
            STRIDE 위협 목록(정의 순서, 중복 제거). 분류 불가 시 빈 리스트.
        """
        codes = self._resolve_codes(alert)
        out: list[StrideThreat] = []
        for code in self._model.codes():
            if code not in codes:
                continue
            cat = self._model.category(code)
            if cat is None:
                continue
            out.append(
                StrideThreat(code=cat.code, name=cat.name, mitigation=cat.mitigation)
            )
        return out

    def coverage(self, bas_report: object) -> dict[str, float]:
        """BAS 검증 결과로 STRIDE 유형별 방어 커버리지를 산출한다.

        Args:
            bas_report: BASReport(by_stride 를 가진 객체).

        Returns:
            STRIDE 코드 → 탐지 비율(BAS by_stride 기반).
        """
        by_stride = getattr(bas_report, "by_stride", {})
        return {
            code: stat.ratio
            for code, stat in by_stride.items()
            if code in set(self._model.codes())
        }

    def _resolve_codes(self, alert: Alert) -> set[str]:
        """명시 stride 태그 또는 tactic 추론으로 STRIDE 코드 집합을 구한다."""
        raw = alert.mitre.get("stride")
        if isinstance(raw, list) and raw:
            return {str(c) for c in raw}
        tactics_raw = alert.mitre.get("tactics", [])
        tactics = [str(t) for t in tactics_raw] if isinstance(tactics_raw, list) else []
        codes: set[str] = set()
        for tactic in tactics:
            codes.update(self._model.codes_for_tactic(tactic))
        return codes
