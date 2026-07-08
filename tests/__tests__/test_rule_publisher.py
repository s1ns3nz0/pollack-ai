"""RulePublisher — CSV/ARM-JSON apply 로직 + GitHubRulePublisher PR 흐름.

저장소 워치리스트는 ARM 템플릿 JSON(rawContent 내장 CSV). GitHub API 는
httpx.MockTransport 로 모사(네트워크 없음). 멱등 추가/수정·SearchKey 검증·PR 흐름을
확인한다.
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
    apply_watchlist_json,
)


def _add(
    value: str = "gnss-ex-003", columns: dict[str, str] | None = None
) -> WatchlistUpdate:
    entry = {
        "ZoneId": value,
        "added_by": "rule_update_agent",
        "reason": "정상 RF간섭 구역",
        "source_alert": "FP-1",
    }
    entry.update(columns or {})
    return WatchlistUpdate(
        watchlist="GNSS_Exception_List",
        search_key="ZoneId",
        update_type="B",
        action="add",
        entry=entry,
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


def _arm_json(items_key: str, header: str, rows: list[str]) -> str:
    """워치리스트 ARM 템플릿 JSON(rawContent 내장 CSV) 텍스트를 만든다."""
    raw = "\r\n".join([header, *rows])
    doc = {
        "resources": [
            {
                "properties": {
                    "displayName": "wl",
                    "itemsSearchKey": items_key,
                    "contentType": "Text/Csv",
                    "rawContent": raw,
                }
            }
        ]
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def _raw_of(json_text: str) -> str:
    raw = json.loads(json_text)["resources"][0]["properties"]["rawContent"]
    assert isinstance(raw, str)
    return raw


class TestApplyWatchlist:
    """순수 CSV 적용 로직 — 멱등·메타 제외·수정."""

    def test_add_appends_row_without_provenance_columns(self) -> None:
        existing = "ZoneId,MinLat\r\ngnss-ex-001,36.68"
        text, changed = apply_watchlist(existing, _add("gnss-ex-003"))
        assert changed is True
        assert "gnss-ex-003" in text
        assert "added_by" not in text  # 감사 메타는 CSV 에 안 들어감
        assert "source_alert" not in text

    def test_add_is_idempotent(self) -> None:
        existing = "ZoneId,MinLat\r\ngnss-ex-003,36.68"
        text, changed = apply_watchlist(existing, _add("gnss-ex-003"))
        assert changed is False
        assert text == existing

    def test_modify_updates_matching_value(self) -> None:
        existing = "ThresholdKey,Value\r\nMaxJamIndicator,0.5\r\nMaxRttMs_SATCOM,5000"
        text, changed = apply_watchlist(existing, _modify("0.65"))
        assert changed is True
        assert "MaxJamIndicator,0.65" in text
        assert "MaxRttMs_SATCOM,5000" in text  # 다른 행 불변


class TestApplyWatchlistJson:
    """ARM 템플릿 JSON 의 rawContent 적용 + SearchKey 검증."""

    def test_add_updates_rawcontent(self) -> None:
        jt = _arm_json("ZoneId", "ZoneId,MinLat,MaxLat", ["gnss-ex-001,36.68,36.72"])
        new, changed = apply_watchlist_json(jt, _add("gnss-ex-003"))
        assert changed is True
        raw = _raw_of(new)
        assert "gnss-ex-003" in raw
        assert "\r\n" in raw  # 줄 구분 보존
        assert "added_by" not in raw

    def test_idempotent(self) -> None:
        jt = _arm_json("ZoneId", "ZoneId,MinLat", ["gnss-ex-003,36.70"])
        new, changed = apply_watchlist_json(jt, _add("gnss-ex-003"))
        assert changed is False
        assert new == jt

    def test_searchkey_mismatch_raises(self) -> None:
        jt = _arm_json("UAVId_s", "UAVId_s,Max", ["uav-1,0.1"])  # 힌트는 ZoneId
        with pytest.raises(RulePublishError):
            apply_watchlist_json(jt, _add("gnss-ex-003"))

    def test_modify_value_in_json(self) -> None:
        jt = _arm_json("ThresholdKey", "ThresholdKey,Value", ["MaxJamIndicator,0.5"])
        new, changed = apply_watchlist_json(jt, _modify("0.65"))
        assert changed is True
        assert "MaxJamIndicator,0.65" in _raw_of(new)

    def test_bad_json_raises(self) -> None:
        with pytest.raises(RulePublishError):
            apply_watchlist_json("{not json", _add())


class _FakeGitHub:
    """상태 보유 GitHub API 목 — 호출 기록 + PUT 본문 캡처."""

    def __init__(self, file_json: str | None, file_exists: bool = True) -> None:
        self.file_json = file_json
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
            if not self.file_exists or self.file_json is None:
                return httpx.Response(404, json={"message": "Not Found"})
            enc = base64.b64encode(self.file_json.encode()).decode()
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
        branch=f"fix/watchlist/{wl.watchlist.lower()}-fp-1",
        path=f"Watchlists/{wl.watchlist}.json",
        title="fix(watchlist): add",
        base_branch="main",
        watchlist_update=wl,
    )


class TestGitHubPublisher:
    """ARM-JSON PR 흐름 — 모사 트랜스포트."""

    @pytest.mark.asyncio
    async def test_add_opens_pr_with_committed_row(self) -> None:
        fake = _FakeGitHub(
            _arm_json("ZoneId", "ZoneId,MinLat,MaxLat", ["gnss-ex-001,36.68,36.72"])
        )
        out = await _publisher(fake).apublish(_pr(_add("gnss-ex-003")))
        assert out.status == "opened"
        assert out.url == "https://github.com/s1ns3nz0/x/pull/1"
        assert fake.put_content is not None
        assert "gnss-ex-003" in _raw_of(fake.put_content)
        assert fake.pr_created is True

    @pytest.mark.asyncio
    async def test_modify_commits_updated_value(self) -> None:
        fake = _FakeGitHub(
            _arm_json("ThresholdKey", "ThresholdKey,Value", ["MaxJamIndicator,0.5"])
        )
        out = await _publisher(fake).apublish(_pr(_modify("0.65")))
        assert out.status == "opened"
        assert fake.put_content is not None
        assert "MaxJamIndicator,0.65" in _raw_of(fake.put_content)

    @pytest.mark.asyncio
    async def test_idempotent_add_skips_commit_and_pr(self) -> None:
        fake = _FakeGitHub(_arm_json("ZoneId", "ZoneId,MinLat", ["gnss-ex-003,36.70"]))
        out = await _publisher(fake).apublish(_pr(_add("gnss-ex-003")))
        assert out.status == "unchanged"
        assert fake.put_content is None
        assert fake.pr_created is False

    @pytest.mark.asyncio
    async def test_missing_watchlist_file_raises(self) -> None:
        fake = _FakeGitHub(None, file_exists=False)
        with pytest.raises(RulePublishError):
            await _publisher(fake).apublish(_pr(_add("gnss-ex-003")))

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
                        200, json=[{"html_url": "https://github.com/s/x/pull/9"}]
                    )
                return super().handler(request)

        fake = _FakeExistingPr(_arm_json("ZoneId", "ZoneId,MinLat", ["a,1"]))
        out = await _publisher(fake).apublish(_pr(_add("gnss-ex-003")))
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
