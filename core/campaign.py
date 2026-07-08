"""캠페인 체인 탐지 — 시나리오 시퀀스 상관(2층 Campaign Incident).

"단일 룰은 누구나 만든다. 창의성은 전술 간 시간 상관관계에서 나온다"(황준식).
개별 시나리오(1층 Alert)의 관측 순서가 알려진 캠페인 패턴(`campaign-chains.yaml`,
Notion C1~C7)과 일치하면 진행 중 캠페인으로 식별한다. actor 의 관측 시나리오
이력을 캠페인 시퀀스와 순서보존 prefix subsequence 대조해 진행도 + 다음 예상
시나리오를 산출한다.

우리 예측 폐루프(SequencePredictor: technique n-gram)의 상위 레이어 — 캠페인은
알려진 시퀀스 템플릿, 예측기는 관측 빈도 학습. 둘이 상보적으로 '다음 수' 를 좁힌다.
LLM 무관, 전 과정 결정론.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from core.exceptions import PolicyError
from core.models import CampaignMatch
from core.policy_loader import load_policy_mapping, require_list, validate_models

_POLICY = Path(__file__).resolve().parent / "policy" / "campaign-chains.yaml"

# 캠페인 확정 최소 매칭 단계 — 1개만으론 여러 체인 시작과 겹쳐 오탐.
_MIN_MATCH = 2


class CampaignChain(BaseModel):
    """캠페인 체인 정의 한 건."""

    id: str
    name: str = ""
    sequence: list[str] = Field(default_factory=list)
    connect_key: str = ""
    connect_type: str = ""
    severity: str = ""


class CampaignChains:
    """campaign-chains.yaml 로더 — C1~C7 시나리오 시퀀스."""

    def __init__(self, chains: list[CampaignChain]) -> None:
        self._chains = chains

    @property
    def count(self) -> int:
        """로드된 캠페인 체인 수."""
        return len(self._chains)

    def all(self) -> list[CampaignChain]:
        """전체 캠페인 체인."""
        return list(self._chains)

    def chain(self, chain_id: str) -> CampaignChain | None:
        """id 로 캠페인 체인을 반환한다(없으면 None)."""
        return next((c for c in self._chains if c.id == chain_id), None)

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> CampaignChains:
        """campaign-chains.yaml 을 적재한다.

        Args:
            path: 정책 경로. 생략 시 기본 campaign-chains.yaml.

        Returns:
            로드된 CampaignChains.

        Raises:
            PolicyError: 파일 부재/파싱 실패/구조 불일치 시.
        """
        raw = load_policy_mapping(path, _POLICY, label="캠페인 체인")
        chains = validate_models(
            require_list(raw.get("chains"), label="캠페인 체인 chains"),
            CampaignChain,
            label="캠페인 체인",
        )
        if not chains:
            raise PolicyError("캠페인 체인이 비어있음.")
        return cls(chains)


def _prefix_match_len(sequence: list[str], history: list[str]) -> int:
    """시퀀스가 history 안에서 순서보존 매칭된 prefix 길이를 반환한다.

    캠페인은 시간 상관이므로 중간에 무관 시나리오가 껴도 순서만 보존되면 매칭한다
    (subsequence). 시퀀스 앞에서부터 history 를 스캔하며 이어지는 최장 prefix 를 센다.

    Args:
        sequence: 캠페인 시나리오 순서.
        history: 관측 시나리오 이력(시간순).

    Returns:
        매칭된 prefix 단계 수(0~len(sequence)).
    """
    idx = 0
    for scenario in history:
        if idx < len(sequence) and scenario == sequence[idx]:
            idx += 1
    return idx


class CampaignDetector:
    """관측 시나리오 이력 → 진행 중 캠페인 매칭(결정론).

    Args:
        chains: 캠페인 체인 정의.
        min_match: 캠페인 확정 최소 매칭 단계(기본 2 — 오탐 방지).
    """

    def __init__(self, chains: CampaignChains, min_match: int = _MIN_MATCH) -> None:
        self._chains = chains
        self._min_match = min_match

    def detect(self, scenario_history: list[str]) -> list[CampaignMatch]:
        """관측 시나리오 이력에서 진행 중 캠페인을 식별한다.

        Args:
            scenario_history: 관측 시나리오 id 이력(시간순, 예: ["S6","S13"]).

        Returns:
            매칭된 캠페인 목록(matched 내림차순). 확정 미달이면 빈 리스트.
        """
        seen = set(scenario_history)
        matches: list[CampaignMatch] = []
        for chain in self._chains.all():
            matched = _prefix_match_len(chain.sequence, scenario_history)
            if matched < self._min_match:
                continue
            total = len(chain.sequence)
            next_expected = chain.sequence[matched] if matched < total else ""
            # out-of-order 방지: 다음 예상이 이미 관측됐으면 거짓 예측 — 억제.
            # (subsequence 매칭은 종단 단계가 순서 어긋나게 먼저 나와도 진행으로
            #  세므로, 이미 본 시나리오를 "다음"으로 내놓지 않는다.)
            if next_expected in seen:
                next_expected = ""
            matches.append(
                CampaignMatch(
                    chain_id=chain.id,
                    name=chain.name,
                    matched=matched,
                    total=total,
                    next_expected=next_expected,
                    severity=chain.severity,
                )
            )
        matches.sort(key=lambda m: -m.matched)
        return matches
