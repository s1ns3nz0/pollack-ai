"""[2] Investigation Agent — RAG 유사사례 검색 + 신호 상관 + 출처 검증.

RAG 는 `RagflowRetrievalTool`(또는 동일 시그니처의 리트리버)로 주입한다. 검색
컨텍스트는 출처 가드레일(신뢰 출처 `kb/` 만 채택) 통과분만 사용한다. LLM 이 주입되면
신뢰 컨텍스트를 근거로 상관분석 요약을 생성하고, 실패/미주입 시 결정론적 요약으로
폴백한다(파이프라인 안전).
"""

from __future__ import annotations

import re
from typing import Protocol, runtime_checkable

from agents.base import BaseSOCAgent
from core.exceptions import LLMError, SOCPlatformError
from core.experience import MemoryReadGate, RecallPurpose
from core.llm import LLMClient
from core.models import (
    Alert,
    InvestigationResult,
    RetrievedChunk,
    SandboxReport,
    SOCState,
    ThreatIntelFinding,
    TiVerdict,
)
from core.settings import Settings

_HASH_RE = re.compile(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}")

_SUMMARY_SYSTEM = (
    "당신은 UAV 보안관제(SOC) 분석가다. 주어진 경보와 신뢰 지식베이스 컨텍스트만"
    " 근거로, 의심 공격과 핵심 근거를 3문장 이내 한국어로 요약하라. 컨텍스트에 없는"
    " 내용은 지어내지 마라."
)


def _confidence(trusted: list[RetrievedChunk], rag_degraded: bool) -> float:
    """분석 신뢰도(0.0~1.0)를 결정론적으로 산정한다.

    신뢰 컨텍스트(`kb/`)의 검색 점수 상위 3건 평균과 커버리지(건수)를 결합한다.
    LLM 자체평가가 아니라 검색 근거에서 도출하므로 KPI 검증(레드팀 라벨 대조)이
    가능하다.

    Args:
        trusted: 출처 검증을 통과한 신뢰 컨텍스트 청크.
        rag_degraded: RAG 검색이 강등(빈 컨텍스트)됐는지 여부.

    Returns:
        0.0~1.0 신뢰도. 근거 없으면 낮게(강등 0.2 / 미히트 0.3) 보수 산정.
    """
    if not trusted:
        return 0.2 if rag_degraded else 0.3
    top = sorted((c.score for c in trusted), reverse=True)[:3]
    mean_score = sum(top) / len(top)
    coverage = min(len(trusted), 3) / 3.0
    return round(min(1.0, 0.4 + 0.4 * mean_score + 0.2 * coverage), 3)


@runtime_checkable
class ContextRetriever(Protocol):
    """Investigation 이 의존하는 RAG 리트리버 계약."""

    async def aretrieve(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        """질의에 대한 컨텍스트 청크를 반환한다."""
        ...


@runtime_checkable
class ThreatIntelTool(Protocol):
    """Investigation 이 의존하는 외부 위협 인텔(TI) 조회 계약."""

    async def alookup(self, indicators: list[str]) -> list[ThreatIntelFinding]:
        """IOC 목록의 평판을 조회해 반환한다."""
        ...


@runtime_checkable
class SandboxDetonator(Protocol):
    """Investigation 이 의존하는 샌드박스 디토네이션 계약."""

    async def adetonate(self, artifact: str) -> SandboxReport:
        """아티팩트(해시)를 분석해 행위 기반 보고서를 반환한다."""
        ...


class InvestigationAgent(BaseSOCAgent):
    """RAG 유사사례 + 외부 TI + 신호 상관 분석 Agent."""

    def __init__(
        self,
        settings: Settings,
        retriever: ContextRetriever | None,
        llm: LLMClient | None = None,
        ti: ThreatIntelTool | None = None,
        experience: MemoryReadGate | None = None,
        sandbox: SandboxDetonator | None = None,
    ) -> None:
        super().__init__(settings)
        self._retriever = retriever
        self._llm = llm
        self._ti = ti
        self._experience = experience
        self._sandbox = sandbox

    async def run(self, state: SOCState) -> SOCState:
        """유사사례 검색 + 출처 검증 + (LLM) 상관분석 요약.

        Args:
            state: `alert` 를 포함한 현재 상태.

        Returns:
            investigation 결과 + (미신뢰 컨텍스트 격리 시) 가드레일 플래그.
        """
        alert = state["alert"]
        query = f"{alert.scenario_id} {alert.title} {' '.join(alert.signals)}"

        chunks: list[RetrievedChunk] = []
        rag_degraded = False
        if self._retriever is not None:
            try:
                chunks = await self._retriever.aretrieve(query, k=5)
            except SOCPlatformError as exc:
                # RAG 장애가 SOC 전체를 막지 않도록 빈 컨텍스트로 강등(대응 계속).
                rag_degraded = True
                self._logger.warning(
                    "investigation RAG 검색 실패, 빈 컨텍스트로 계속: %s", exc
                )

        trusted = [c for c in chunks if c.source.startswith("kb/")]
        dropped = len(chunks) - len(trusted)
        summary = await self._summarize(alert.title, alert.signals, trusted)
        confidence = _confidence(trusted, rag_degraded)

        # 샌드박스 디토네이션: 경보의 해시 IOC 를 터뜨려 행위 기반 판정 + IOC 추출.
        sandbox_reports = await self._detonate(alert.iocs)
        extracted = [
            ioc
            for r in sandbox_reports
            if r.verdict == TiVerdict.MALICIOUS
            for ioc in r.extracted_iocs
        ]
        if any(r.verdict == TiVerdict.MALICIOUS for r in sandbox_reports):
            confidence = round(
                min(1.0, confidence + 0.2), 3
            )  # 악성 디토네이션 = 강근거

        # 외부 TI 보강: 경보 IOC + 디토네이션 추출 IOC 평판 조회(장애 시 빈 결과 강등).
        ti_indicators = list(dict.fromkeys([*alert.iocs, *extracted]))
        ti_findings = await self._lookup_ti(ti_indicators)
        if any(f.verdict == TiVerdict.MALICIOUS for f in ti_findings):
            confidence = round(min(1.0, confidence + 0.2), 3)  # 악성 IOC = 강한 근거

        # 경험메모리(exp/) 자문: 과거 정탐 회상으로 탐지 강화(안전 방향).
        # 신종(룰부재 X·근거부족) TP 를 1회 학습 후 잡게 하는 자가발전 레버.
        exp_corroboration = await self._recall_experience(alert.scenario_id)
        if exp_corroboration:
            confidence = round(min(1.0, confidence + 0.2), 3)  # 과거 정탐 = 보강 근거

        # 맥락 FP 억제 자문(위험 방향): 신뢰 과거 오탐 중 *동일 신호패턴*만 집계.
        suppression = await self._recall_suppression(alert)

        self._logger.info(
            "investigation: alert=%s hits=%d trusted=%d degraded=%s ti=%d sb=%d "
            "exp=%d sup=%d conf=%.2f",
            alert.id,
            len(chunks),
            len(trusted),
            rag_degraded,
            len(ti_findings),
            len(sandbox_reports),
            exp_corroboration,
            suppression,
            confidence,
        )

        result: SOCState = {
            "investigation": InvestigationResult(
                matched_signals=alert.signals,
                mitre=alert.mitre,
                similar_cases=trusted,
                summary=summary,
                confidence=confidence,
                ti_findings=ti_findings,
                experience_corroboration=exp_corroboration,
                suppression_corroboration=suppression,
                sandbox_reports=sandbox_reports,
            ),
            "trace": ["investigation"],
        }
        flags: list[str] = []
        if rag_degraded:
            flags.append("RAG 검색 불가 — 빈 컨텍스트로 강등(대응 계속)")
        if dropped:
            flags.append(f"미신뢰 컨텍스트 {dropped}건 격리")
        if flags:
            result["guardrail_flags"] = flags
        return result

    async def _recall_experience(self, scenario_id: str) -> int:
        """exp/ 에서 과거 정탐을 회상해 보강 근거 수를 반환(자문).

        미주입/장애 시 0 으로 강등한다(메모리 없이도 대응 계속 — 핫패스 안전).
        탐지 강화(DETECTION) 방향만 사용하므로 오염돼도 억제(FN)로 이어지지 않는다.

        Args:
            scenario_id: 회상 대상 시나리오 식별자.

        Returns:
            서명·신뢰 검증을 통과한 과거 정탐 레코드 수.
        """
        if self._experience is None:
            return 0
        try:
            hits = await self._experience.recall(scenario_id, RecallPurpose.DETECTION)
        except SOCPlatformError as exc:
            self._logger.warning("investigation 경험 회상 실패, 무시하고 계속: %s", exc)
            return 0
        return len(hits)

    async def _recall_suppression(self, alert: Alert) -> int:
        """동일 신호패턴의 신뢰 과거 오탐(맥락 FP)을 회상해 억제 근거 수를 반환.

        위험 방향(TP→FP 억제)이므로 *좁게* 집계한다: 신뢰 출처(ReadGate 가
        env_verified/redgt_offline 만 회상)이면서, 과거 오탐의 신호 집합이 현재 경보
        신호의 *부분집합*인 경우만 센다 → 시나리오 전체가 아니라 동일 패턴만 억제,
        진짜 공격(다른 신호)은 묻히지 않는다. 미주입/장애 시 0(억제 안 함).

        Args:
            alert: 현재 경보(시나리오·신호 비교 대상).

        Returns:
            동일 패턴 신뢰 과거 오탐 수.
        """
        if self._experience is None:
            return 0
        try:
            hits = await self._experience.recall(
                alert.scenario_id, RecallPurpose.SUPPRESSION
            )
        except SOCPlatformError as exc:
            self._logger.warning("investigation 억제 회상 실패, 무시하고 계속: %s", exc)
            return 0
        current = set(alert.signals)
        return sum(1 for h in hits if h.signals and set(h.signals) <= current)

    async def _detonate(self, iocs: list[str]) -> list[SandboxReport]:
        """경보의 *해시* IOC 를 샌드박스로 디토네이트. 미주입/해시없음/장애 시 빈 결과.

        해시 형식 IOC 만 추려 분석한다(IP/도메인은 TI 담당). 장애는 무시하고 계속
        (핫패스 안전 — RAG/TI 와 동일 graceful degrade).

        Args:
            iocs: 경보 IOC 목록.

        Returns:
            디토네이션 보고서 목록(악성 시 confidence 보강·IOC 추출에 사용).
        """
        if self._sandbox is None:
            return []
        hashes = [i for i in iocs if _HASH_RE.fullmatch(i)]
        reports: list[SandboxReport] = []
        for artifact in hashes:
            try:
                reports.append(await self._sandbox.adetonate(artifact))
            except SOCPlatformError as exc:
                self._logger.warning(
                    "investigation 샌드박스 분석 실패, 무시하고 계속: %s", exc
                )
        return reports

    async def _lookup_ti(self, iocs: list[str]) -> list[ThreatIntelFinding]:
        """경보 IOC 를 외부 TI 로 조회. 미주입/IOC 없음/장애 시 빈 결과(대응 계속)."""
        if self._ti is None or not iocs:
            return []
        try:
            return await self._ti.alookup(iocs)
        except SOCPlatformError as exc:
            self._logger.warning("investigation TI 조회 실패, 무시하고 계속: %s", exc)
            return []

    async def _summarize(
        self, title: str, signals: list[str], trusted: list[RetrievedChunk]
    ) -> str:
        """LLM 으로 상관분석 요약 생성. 미주입/오류 시 결정론적 폴백."""
        fallback = f"{title} 상관분석: 신뢰 사례 {len(trusted)}건"
        if self._llm is None:
            return fallback
        context = "\n\n".join(f"[{c.source}] {c.text[:500]}" for c in trusted[:5])
        user = (
            f"경보: {title}\n탐지 신호: {', '.join(signals)}\n\n"
            f"신뢰 컨텍스트:\n{context if context else '(없음)'}"
        )
        try:
            return await self._llm.acomplete(_SUMMARY_SYSTEM, user)
        except LLMError as exc:
            self._logger.warning("investigation 요약 LLM 실패, 폴백: %s", exc)
            return fallback
