"""모든 SOC Agent 의 베이스 클래스."""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.models import SOCState, WorkerReport
from core.settings import Settings
from utils.logging import get_logger


class BaseSOCAgent(ABC):
    """6-에이전트 SOC 파이프라인의 공통 베이스.

    각 에이전트는 `run(state)` 에서 자신의 산출물 + `trace` 항목을 담은 부분
    상태를 반환한다(LangGraph 가 병합).
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._logger = get_logger(self.__class__.__name__)

    @abstractmethod
    async def run(self, state: SOCState) -> SOCState:
        """에이전트 메인 실행 로직.

        Args:
            state: 현재 LangGraph 상태.

        Returns:
            병합할 부분 상태(자신의 산출물 + trace).
        """
        ...


class BaseWorkerAgent(ABC):
    """Deployment B (learning worker) 주기 사이클 에이전트 베이스(spec T1).

    `BaseSOCAgent.run(state)` 와 시그너처가 다르다 — alert state 무관 + 주기 트리거.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._logger = get_logger(self.__class__.__name__)

    @abstractmethod
    async def run(self) -> WorkerReport:
        """주기 사이클 실행. 보고서 반환."""
        ...
