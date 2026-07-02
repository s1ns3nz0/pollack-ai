"""spec A-2 Auto KQL Rule Suggester — validator + agent + PR 페이로드."""

from __future__ import annotations

import pytest

from agents.auto_kql_rule_agent import AutoKqlRuleAgent, parse_kql
from core.exceptions import LLMError, SOCPlatformError
from core.kql_validator import KqlValidator
from core.models import RulePullRequest
from core.settings import Settings


class TestParseKql:
    def test_valid_block(self) -> None:
        text = (
            "요약: 아래 룰을 사용하세요.\n"
            "```kql\n"
            "SecurityEvent | where EventID == 4625\n"
            "```\n"
            "끝."
        )
        assert parse_kql(text) == "SecurityEvent | where EventID == 4625"

    def test_block_without_kql_tag(self) -> None:
        assert parse_kql("```\nA | B\n```") == "A | B"

    def test_no_block_returns_none(self) -> None:
        assert parse_kql("문자만") is None


class TestKqlValidator:
    def test_accepts_minimal(self) -> None:
        ok, reason = KqlValidator().check("SecurityEvent | where EventID == 4625")
        assert ok and reason == "ok"

    def test_rejects_empty(self) -> None:
        ok, reason = KqlValidator().check("")
        assert not ok and reason == "empty"

    def test_rejects_too_long(self) -> None:
        big = "SecurityEvent | " + ("x" * 9000)
        ok, reason = KqlValidator().check(big)
        assert not ok and reason == "too_long"

    def test_rejects_no_pipe(self) -> None:
        ok, reason = KqlValidator().check("SecurityEvent")
        assert not ok and reason == "no_pipe"

    def test_rejects_external_table(self) -> None:
        ok, reason = KqlValidator().check("external_table('x') | project a")
        assert not ok and "blocked_fn" in reason

    def test_rejects_externaldata(self) -> None:
        ok, reason = KqlValidator().check(
            "externaldata(a:string) [@'http://x'] | project a"
        )
        assert not ok and "blocked_fn" in reason

    def test_rejects_httpget(self) -> None:
        ok, reason = KqlValidator().check("SecurityEvent | project http_get('x')")
        assert not ok and "blocked_fn" in reason

    def test_rejects_cluster(self) -> None:
        ok, reason = KqlValidator().check("cluster('x').database('y') | take 1")
        assert not ok


class _FakeLLM:
    def __init__(self, out: str = "```kql\nSecurityEvent | where EventID == 4625\n```"):
        self._out = out
        self.calls = 0

    async def acomplete(self, system: str, user: str) -> str:
        self.calls += 1
        return self._out


class _FailingLLM:
    async def acomplete(self, system: str, user: str) -> str:
        raise LLMError("simulated")


class _StubPublisher:
    def __init__(self) -> None:
        self.published: list[RulePullRequest] = []

    async def apublish(self, pr: RulePullRequest) -> RulePullRequest:
        self.published.append(pr)
        return pr.model_copy(
            update={"status": "opened", "url": f"https://pr/{len(self.published)}"}
        )


class _FailingPublisher:
    async def apublish(self, pr: RulePullRequest) -> RulePullRequest:
        raise SOCPlatformError("publish fail")


class TestAgentFlow:
    @pytest.mark.asyncio
    async def test_processes_and_publishes(self) -> None:
        pub = _StubPublisher()
        agent = AutoKqlRuleAgent(Settings(), _FakeLLM(), publisher=pub)
        report = await agent.run_for(["T1059", "T1078", "T1021"])
        assert report.auto_applied == 3
        assert len(pub.published) == 3
        assert len(report.pr_urls) == 3
        # PR 페이로드 형식 확인
        pr = pub.published[0]
        assert pr.path.endswith(".kql")
        assert "auto-suggest" in pr.title

    @pytest.mark.asyncio
    async def test_respects_max_techniques(self) -> None:
        pub = _StubPublisher()
        agent = AutoKqlRuleAgent(
            Settings(), _FakeLLM(), publisher=pub, max_techniques=2
        )
        report = await agent.run_for([f"T{i}" for i in range(10)])
        assert report.auto_applied == 2

    @pytest.mark.asyncio
    async def test_llm_failure_records_error_continues(self) -> None:
        agent = AutoKqlRuleAgent(Settings(), _FailingLLM(), publisher=_StubPublisher())
        report = await agent.run_for(["T1", "T2"])
        assert report.auto_applied == 0
        assert len(report.errors) == 2

    @pytest.mark.asyncio
    async def test_validation_failure_skips(self) -> None:
        # LLM 이 위험 함수 포함한 KQL 반환 → skip
        bad_llm = _FakeLLM("```kql\nexternal_table('x') | take 1\n```")
        agent = AutoKqlRuleAgent(Settings(), bad_llm, publisher=_StubPublisher())
        report = await agent.run_for(["T1"])
        assert report.auto_applied == 0
        assert any("blocked_fn" in e for e in report.errors)

    @pytest.mark.asyncio
    async def test_parse_failure_skips(self) -> None:
        # LLM 이 코드블록 없음
        weird_llm = _FakeLLM("설명만 있고 코드 없음")
        agent = AutoKqlRuleAgent(Settings(), weird_llm, publisher=_StubPublisher())
        report = await agent.run_for(["T1"])
        assert report.auto_applied == 0
        assert any("파싱 실패" in e for e in report.errors)

    @pytest.mark.asyncio
    async def test_publisher_failure_records_error(self) -> None:
        agent = AutoKqlRuleAgent(Settings(), _FakeLLM(), publisher=_FailingPublisher())
        report = await agent.run_for(["T1"])
        assert report.auto_applied == 0
        assert any("PR 실패" in e for e in report.errors)

    @pytest.mark.asyncio
    async def test_no_publisher_still_applied(self) -> None:
        agent = AutoKqlRuleAgent(Settings(), _FakeLLM(), publisher=None)
        report = await agent.run_for(["T1"])
        assert report.auto_applied == 1
        assert report.pr_urls == []

    @pytest.mark.asyncio
    async def test_run_no_op_returns_empty_report(self) -> None:
        agent = AutoKqlRuleAgent(Settings(), _FakeLLM())
        report = await agent.run()
        assert report.auto_applied == 0
