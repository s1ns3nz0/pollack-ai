"""RAGAS 분석 품질 자동 측정(spec D1).

Investigation 의 summary + similar_cases 에 대한 faithfulness / answer_relevancy /
context_relevancy 를 *비동기* 측정한다. 핫패스 SLO 보존을 위해 fire-and-forget
패턴: Investigation 노드가 `asyncio.create_task` 로 던지고 결과를 기다리지 않는다.

RAGAS / datasets 미설치 시 ImportError → None 반환 (graceful). 추론 실패도 동일.

Spec: docs/superpowers/specs/2026-06-30-ragas-quality-metrics-design.md
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from core.models import Alert, RagasResult, RetrievedChunk
from core.settings import Settings
from utils.logging import get_logger


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class RagasEvaluator:
    """RAGAS 라이브러리 어댑터 + 비동기 측정 + Prometheus 게이지 갱신.

    의존 라이브러리는 lazy import — 미설치/실패 시 None 반환.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings()
        self._semaphore = asyncio.Semaphore(2)
        self._logger = get_logger("RagasEvaluator")

    async def aevaluate(
        self,
        alert: Alert,
        summary: str,
        contexts: list[RetrievedChunk],
    ) -> RagasResult | None:
        """RAGAS 3 메트릭 측정. 미설치/장애/빈 입력 시 None."""
        if not summary or not contexts:
            return None
        async with self._semaphore:
            try:
                ragas_evaluate, faith, ans_rel, ctx_rel, dataset_cls = (
                    self._lazy_import()
                )
            except ImportError as exc:
                self._logger.warning("ragas 미설치 — 측정 생략: %s", exc)
                return None
            question = f"{alert.title}: {' '.join(alert.signals)}"
            data = dataset_cls.from_dict(  # type: ignore[attr-defined]
                {
                    "question": [question],
                    "answer": [summary],
                    "contexts": [[c.text for c in contexts]],
                }
            )
            try:
                loop = asyncio.get_event_loop()
                scores = await loop.run_in_executor(
                    None,
                    lambda: ragas_evaluate(  # type: ignore[operator]
                        data, metrics=[faith, ans_rel, ctx_rel]
                    ),
                )
            except Exception as exc:  # noqa: BLE001 - RAGAS 내부 변동성
                self._logger.warning("ragas 측정 실패: %s", exc)
                return None
            try:
                return RagasResult(
                    faithfulness=float(scores["faithfulness"]),
                    answer_relevancy=float(scores["answer_relevancy"]),
                    context_relevancy=float(scores["context_relevancy"]),
                    evaluated_at=_now_iso(),
                    n_contexts=len(contexts),
                )
            except (KeyError, TypeError, ValueError) as exc:
                self._logger.warning("ragas 결과 파싱 실패: %s", exc)
                return None

    @staticmethod
    def _lazy_import() -> tuple[object, object, object, object, object]:
        from datasets import Dataset
        from ragas import evaluate
        from ragas.metrics import (
            answer_relevancy,
            context_relevancy,
            faithfulness,
        )

        return evaluate, faithfulness, answer_relevancy, context_relevancy, Dataset
