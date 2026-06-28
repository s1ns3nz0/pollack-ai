"""RulePublisher — CSV apply 로직 + GitHubRulePublisher 4단계 PR 흐름.

GitHub API 는 httpx.MockTransport 로 모사(네트워크 없음). CSV 멱등 추가/수정과
PR 흐름·검증 실패 거동을 확인한다.
"""

import base64
import json

import httpx
from pydantic import SecretStr
import pytest

from core.exceptions import RulePublishError
from core.models import RulePullRequest, WatchlistUpdate
from core.settings import Settings
from tools.rule_publisher import (
    GitHubRulePublisher,
    StubRulePublisher,
    apply_watchlist,
)


def _add(value: str = "UAV-07") -> WatchlistUpdate:
    return WatchlistUpdate(
        watchlist="GNSS_Exception_List",
        search_key="UAVId_s",
        update_type="B",
        action="add",
        entry={
            "UAVId_s": value,
            "added_by": "rule_update_agent",
            "reason": "정상 RF간섭 구역",
            "source_alert": "FP-1",
        },
        reason="예외 추가",
    )


def _modify(value: str = "0.65") -> WatchlistUpdate:
    return WatchlistUpdate(
        watchlist="UAV_Threshold_List",
        search_key="ThresholdKey",
        update_type="C",
        action="modify",
        entry={
            "ThresholdKey": "MaxJamIndicator",
            "Value": value,
            "modified_by": "rule_update_agent",
            "reason": "오탐 임계 상향",
            "source_alert": "FP-2",
        },
        reason="임계값 조정",
    )


class TestApplyWatchlist:
    """순수 CSV 적용 로직 — 멱등·메타 제외·수정."""

    def test_add_appends_row_without_provenance_columns(self) -> None:
        existing = "UAVId_s,MaxPosResidual_d\nUAV-01,5\n"
        text, changed = apply_watchlist(existing, _add("UAV-07"))
        assert changed is True
        assert "UAV-07" in text
        assert "added_by" not in text  # 감사 메타는 CSV 에 안 들어감
        assert "source_alert" not in text

    def test_add_is_idempotent(self) -> None:
        existing = "UAVId_s,MaxPosResidual_d\nUAV-07,5\n"
        text, changed = apply_watchlist(existing, _add("UAV-07"))
        assert changed is False
        assert text == existing

    def test_modify_updates_matching_value(self) -> None:
        existing = "ThresholdKey,Value\nMaxJamIndicator,0.5\nMaxRttMs_SATCOM,5000\n"
        text, changed = apply_watchlist(existing, _modify("0.65"))
        assert changed is True
        assert "MaxJamIndicator,0.65" in text
        assert "MaxRttMs_SATCOM,5000" in text  # 다른 행 불변

    def test_modify_noop_when_already_set(self) -> None:
        existing = "ThresholdKey,Value\nMaxJamIndicator,0.65\n"
        _text, changed = apply_watchlist(existing, _modify("0.65"))
        assert changed is False

    def test_new_file_creates_header(self) -> None:
        text, changed = apply_watchlist(None, _add("UAV-07"))
        assert changed is True
        assert text.splitlines()[0] == "UAVId_s"
        assert "UAV-07" in text


class _FakeGitHub:
    """상태 보유 GitHub API 목 — 호출 기록 + PUT 본문 캡처."""

    def __init__(self, csv_text: str | None, file_exists: bool = True) -> None:
        self.csv_text = csv_text
        self.file_exists = file_exists
        self.calls: list[tuple[str, str]] = []
        self.put_content: str | None = None
        self.pr_created = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        if request.method == "GET" and "/git/ref/heads/" in path:
            return httpx.Response(200, json={"object": {"sha": "basesha"}})
        if request.method == "GET" and "/contents/" in path:
            if not self.file_exists or self.csv_text is None:
                return httpx.Response(404, json={"message": "Not Found"})
            enc = base64.b64encode(self.csv_text.encode()).decode()
            return httpx.Response(200, json={"content": enc, "sha": "filesha"})
        if request.method == "POST" and path.endswith("/git/refs"):
            return httpx.Response(201, json={"ref": "refs/heads/x"})
        if request.method == "PUT" and "/contents/" in path:
            body = json.loads(request.content)
            self.put_content = base64.b64decode(body["content"]).decode()
            return httpx.Response(200, json={"content": {}})
        if request.method == "POST" and path.endswith("/pulls"):
            self.pr_created = True
            return httpx.Response(
                201, json={"html_url": "https://github.com/s1ns3nz0/x/pull/1"}
            )
        return httpx.Response(500, json={"path": path})


def _publisher(fake: _FakeGitHub) -> GitHubRulePublisher:
    settings = Settings(github_token=SecretStr("tok"))

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(fake.handler))

    return GitHubRulePublisher(settings=settings, client_factory=factory)


def _pr(wl: WatchlistUpdate) -> RulePullRequest:
    return RulePullRequest(
        repo="s1ns3nz0/dah-sentinel-content",
        branch="feat/watchlist/gnss_exception_list-fp-1",
        path=f"Watchlists/{wl.watchlist}.csv",
        title="chore(watchlist): add",
        base_branch="main",
        watchlist_update=wl,
    )


class TestGitHubPublisher:
    """4단계 PR 흐름 — 모사 트랜스포트."""

    @pytest.mark.asyncio
    async def test_add_opens_pr_with_committed_row(self) -> None:
        fake = _FakeGitHub("UAVId_s,MaxPosResidual_d\nUAV-01,5\n")
        out = await _publisher(fake).apublish(_pr(_add("UAV-07")))
        assert out.status == "opened"
        assert out.url == "https://github.com/s1ns3nz0/x/pull/1"
        assert fake.put_content is not None and "UAV-07" in fake.put_content
        assert fake.pr_created is True

    @pytest.mark.asyncio
    async def test_modify_commits_updated_value(self) -> None:
        fake = _FakeGitHub("ThresholdKey,Value\nMaxJamIndicator,0.5\n")
        pr = _pr(_modify("0.65"))
        out = await _publisher(fake).apublish(pr)
        assert out.status == "opened"
        assert fake.put_content is not None
        assert "MaxJamIndicator,0.65" in fake.put_content

    @pytest.mark.asyncio
    async def test_idempotent_add_skips_commit_and_pr(self) -> None:
        fake = _FakeGitHub("UAVId_s,MaxPosResidual_d\nUAV-07,5\n")
        out = await _publisher(fake).apublish(_pr(_add("UAV-07")))
        assert out.status == "unchanged"
        assert fake.put_content is None
        assert fake.pr_created is False

    @pytest.mark.asyncio
    async def test_new_file_path_commits(self) -> None:
        fake = _FakeGitHub(None, file_exists=False)
        out = await _publisher(fake).apublish(_pr(_add("UAV-07")))
        assert out.status == "opened"
        assert fake.put_content is not None and "UAV-07" in fake.put_content

    @pytest.mark.asyncio
    async def test_existing_pr_returns_url(self) -> None:
        class _FakeExistingPr(_FakeGitHub):
            def handler(self, request: httpx.Request) -> httpx.Response:
                path = request.url.path
                if request.method == "POST" and path.endswith("/pulls"):
                    self.calls.append((request.method, path))
                    return httpx.Response(422, json={"message": "exists"})
                if request.method == "GET" and path.endswith("/pulls"):
                    return httpx.Response(
                        200,
                        json=[{"html_url": "https://github.com/s/x/pull/9"}],
                    )
                return super().handler(request)

        fake = _FakeExistingPr("UAVId_s\nUAV-01\n")
        out = await _publisher(fake).apublish(_pr(_add("UAV-07")))
        assert out.status == "opened"
        assert out.url == "https://github.com/s/x/pull/9"


class TestPublisherGuards:
    """발행 전제 검증."""

    @pytest.mark.asyncio
    async def test_missing_token_raises(self) -> None:
        pub = GitHubRulePublisher(settings=Settings())  # 토큰 빈값
        with pytest.raises(RulePublishError):
            await pub.apublish(_pr(_add()))

    @pytest.mark.asyncio
    async def test_no_watchlist_update_raises(self) -> None:
        pub = GitHubRulePublisher(settings=Settings(github_token=SecretStr("t")))
        pr = RulePullRequest(
            repo="r", branch="b", path="p", title="t", watchlist_update=None
        )
        with pytest.raises(RulePublishError):
            await pub.apublish(pr)

    @pytest.mark.asyncio
    async def test_stub_publisher_marks_proposed(self) -> None:
        out = await StubRulePublisher().apublish(_pr(_add()))
        assert out.status == "proposed"
        assert out.url
