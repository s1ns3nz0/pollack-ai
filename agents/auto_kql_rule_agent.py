"""AutoKqlRuleAgent — 신규 technique → KQL draft PR(spec A-2).

T1 이 준 `LandscapeDiff.added` 리스트를 받아 LLM 으로 KQL draft 생성 → 검증 →
`RulePullRequest` 페이로드 → `RulePublisher.apublish`. 자동 머지 없음 — 항상 운영자
검토 필수.

Spec: docs/superpowers/specs/2026-07-02-auto-kql-rule-suggester-design.md
"""

from __future__ import annotations

from datetime import UTC, datetime
import re

from agents.base import BaseWorkerAgent
from core.exceptions import LLMError, SOCPlatformError
from core.kql_validator import KqlValidator
from core.llm import LLMClient
from core.models import RulePullRequest, WorkerReport
from core.settings import Settings
from tools.rule_publisher import RulePublisher

_SYS = (
    "당신은 Azure Sentinel KQL 룰 저자다. 주어진 MITRE ATT&CK technique 에 매칭되는"
    " KQL 탐지 룰 draft 를 작성하라. 반드시 아래 형식만 출력:\n"
    "```kql\n<KQL 룰 본문>\n```\n"
    "external_table/externaldata/http_get 함수 사용 금지."
    " SecurityEvent · Syslog · SigninLogs 등 표준 테이블만 참조."
)

# info-string 관용(``` 뒤 공백/kql/부가텍스트 허용): ```kql, ``` kql 제목, ```KQL 등.
_RE_KQL = re.compile(r"```[ \t]*kql[^\n]*\n(.*?)\n```", re.DOTALL | re.IGNORECASE)
_RE_ANY = re.compile(r"```[^\n]*\n(.*?)\n```", re.DOTALL)


def parse_kql(text: str) -> str | None:
    """LLM 출력에서 KQL 코드블록 추출.

    ```kql 태그 블록을 우선(설명·표 등 다른 블록 오선택 방지, Codex). 없을 때만
    태그 없는 단일 블록으로 폴백.
    """
    m = _RE_KQL.search(text)
    if m is not None:
        return m.group(1).strip()
    m = _RE_ANY.search(text)
    return m.group(1).strip() if m else None


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _user_prompt(tid: str) -> str:
    return (
        f"Technique: {tid}\n\n"
        f"위 technique 를 탐지하는 Azure Sentinel KQL 룰 초안을 작성하시오."
    )


class AutoKqlRuleAgent(BaseWorkerAgent):
    """T1 신규 technique → KQL draft PR.

    Args:
        settings: 전역 설정.
        llm: 필수 — draft 생성.
        validator: KqlValidator. 미주입 시 디폴트 생성.
        publisher: PR 발행기. 미주입 시 proposed 만.
        max_techniques: 사이클당 처리 상한. 미주입 시 settings.auto_kql_max_techniques.
    """

    def __init__(
        self,
        settings: Settings,
        llm: LLMClient,
        validator: KqlValidator | None = None,
        publisher: RulePublisher | None = None,
        max_techniques: int | None = None,
    ) -> None:
        super().__init__(settings)
        self._llm = llm
        self._validator = validator or KqlValidator()
        self._publisher = publisher
        self._max_techniques = (
            settings.auto_kql_max_techniques
            if max_techniques is None
            else max(1, max_techniques)
        )

    async def run(self) -> WorkerReport:
        """no-op — 호출자가 run_for(added_techs) 를 직접 호출."""
        return WorkerReport(cycle_at=_now_iso())

    async def run_for(self, added_techs: list[str]) -> WorkerReport:
        """신규 technique 목록에 대해 KQL draft PR 생성."""
        applied = 0
        errors: list[str] = []
        pr_urls: list[str] = []
        for tid in added_techs[: self._max_techniques]:
            raw = await self._call_llm(tid, errors)
            if raw is None:
                continue
            kql = parse_kql(raw)
            if kql is None:
                errors.append(f"{tid} 파싱 실패")
                continue
            ok, reason = self._validator.check(kql)
            if not ok:
                errors.append(f"{tid} 검증 실패: {reason}")
                continue
            pr = self._build_pr(tid, kql)
            if self._publisher is None:
                # publisher 없으면 발행 산출물 없음 — applied 미집계(가시성, Codex).
                errors.append(f"{tid} 미발행: publisher 없음(draft only)")
                continue
            try:
                pr = await self._publisher.apublish(pr)
            except SOCPlatformError as exc:
                errors.append(f"{tid} PR 실패: {exc}")
                continue
            if pr.url:
                pr_urls.append(pr.url)
            applied += 1
        self._logger.info(
            "auto_kql: processed=%d applied=%d errors=%d",
            len(added_techs),
            applied,
            len(errors),
        )
        return WorkerReport(
            cycle_at=_now_iso(),
            auto_applied=applied,
            pr_urls=pr_urls,
            errors=errors,
        )

    async def _call_llm(self, tid: str, errors: list[str]) -> str | None:
        try:
            return await self._llm.acomplete(_SYS, _user_prompt(tid))
        except LLMError as exc:
            errors.append(f"{tid} LLM 실패: {exc}")
            return None

    def _build_pr(self, tid: str, kql: str) -> RulePullRequest:
        ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        branch = f"feat/auto-kql-{tid.lower().replace('.', '-')}-{ts}"
        body = (
            "**⚠ LLM 자동 생성 초안 — 운영자 검토 필수.**\n\n"
            f"- Technique: `{tid}`\n"
            "- 회귀 게이트(`benchmarks/`) 통과 후 머지.\n"
            "- 위험 함수 자동 검증 통과(external_table/http_get 등 차단).\n\n"
            "```kql\n"
            f"{kql}\n"
            "```\n"
        )
        return RulePullRequest(
            repo=self._settings.sentinel_content_repo,
            branch=branch,
            path=f"Analytics/{tid}.kql",
            title=f"feat(analytics): {tid} 신규 KQL 룰 초안 (auto-suggest)",
            body=body,
            file_content=kql,
            base_branch=self._settings.rule_base_branch,
        )
