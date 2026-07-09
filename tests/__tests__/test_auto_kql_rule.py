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
        assert not ok and "blocked" in reason

    def test_rejects_externaldata(self) -> None:
        ok, reason = KqlValidator().check(
            "externaldata(a:string) [@'http://x'] | project a"
        )
        assert not ok and "blocked" in reason

    def test_rejects_httpget(self) -> None:
        ok, reason = KqlValidator().check("SecurityEvent | project http_get('x')")
        assert not ok and "blocked" in reason

    def test_rejects_cluster(self) -> None:
        ok, reason = KqlValidator().check("cluster('x').database('y') | take 1")
        assert not ok

    def test_rejects_cluster_with_space(self) -> None:
        """공백 삽입 회피 — cluster ( 도 차단(Codex)."""
        ok, reason = KqlValidator().check("SecurityEvent | where cluster ('x')")
        assert not ok and "cluster" in reason

    def test_rejects_management_command(self) -> None:
        """선행 `.` 관리 명령(.create/.alter 등) 차단."""
        ok, reason = KqlValidator().check(".create table Foo | project a")
        assert not ok and reason == "management_command"

    def test_rejects_evaluate_plugin(self) -> None:
        """evaluate 플러그인(임의 실행/유출) 차단."""
        ok, reason = KqlValidator().check("SecurityEvent | evaluate bag_unpack(x)")
        assert not ok and "evaluate" in reason

    def test_comment_evasion_blocked(self) -> None:
        """주석 삽입으로 위험함수 은닉 회피 — 주석 제거 후 검출."""
        ok, _ = KqlValidator().check("SecurityEvent | where external_table //ok\n('x')")
        assert not ok

    def test_url_in_string_not_treated_as_comment(self) -> None:
        """문자열 내 http:// 의 // 를 주석으로 오인해 파이프 훼손하지 않음."""
        ok, reason = KqlValidator().check(
            "SecurityEvent | where Url == 'http://x/a' | take 1"
        )
        assert ok and reason == "ok"

    def test_blocked_after_url_not_hidden(self) -> None:
        """URL 의 // 뒤에 오는 위험구문이 주석제거로 은닉되지 않음(Codex 재검토)."""
        ok, reason = KqlValidator().check(
            "SecurityEvent | where Url == 'http://x' | evaluate bag_unpack(y)"
        )
        assert not ok and "evaluate" in reason


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
        assert any("blocked" in e for e in report.errors)

    @pytest.mark.asyncio
    async def test_parse_failure_skips(self) -> None:
        # LLM 이 코드블록 없음
        weird_llm = _FakeLLM("설명만 있고 코드 없음")
        agent = AutoKqlRuleAgent(Settings(), weird_llm, publisher=_StubPublisher())
        report = await agent.run_for(["T1"])
        assert report.auto_applied == 0
        assert any("파싱 실패" in e for e in report.errors)

    @pytest.mark.asyncio
    async def test_parses_fence_with_trailing_info(self) -> None:
        """```kql 뒤 부가 텍스트/공백 있는 펜스도 추출(Codex 재검토)."""
        llm = _FakeLLM("```kql T1059 rule\nSecurityEvent | where EventID == 1\n```")
        agent = AutoKqlRuleAgent(Settings(), llm, publisher=_StubPublisher())
        report = await agent.run_for(["T1059"])
        assert report.auto_applied == 1

    @pytest.mark.asyncio
    async def test_publisher_failure_records_error(self) -> None:
        agent = AutoKqlRuleAgent(Settings(), _FakeLLM(), publisher=_FailingPublisher())
        report = await agent.run_for(["T1"])
        assert report.auto_applied == 0
        assert any("PR 실패" in e for e in report.errors)

    @pytest.mark.asyncio
    async def test_no_publisher_not_applied(self) -> None:
        """publisher 없으면 발행 산출물 없음 — applied 0 + 미발행 기록(Codex)."""
        agent = AutoKqlRuleAgent(Settings(), _FakeLLM(), publisher=None)
        report = await agent.run_for(["T1"])
        assert report.auto_applied == 0
        assert report.pr_urls == []
        assert any("미발행" in e for e in report.errors)

    @pytest.mark.asyncio
    async def test_run_no_op_returns_empty_report(self) -> None:
        agent = AutoKqlRuleAgent(Settings(), _FakeLLM())
        report = await agent.run()
        assert report.auto_applied == 0
