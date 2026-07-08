"""spec T1 Threat Landscape — feeds + patch + agent + 통합."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from agents.threat_landscape_agent import ThreatLandscapeAgent
from core.exceptions import SOCPlatformError
from core.models import FeedSnapshot, LandscapeDiff
from core.settings import Settings
from tools.atlas_feed import AtlasFeed
from tools.cisa_kev_feed import CisaKevFeed
from tools.feed_base import fetch_with_retry
from tools.graph_yaml_patch import GraphYamlPatchTool
from tools.mitre_stix_feed import MitreStixFeed


@pytest.mark.asyncio
async def test_fetch_with_retry_https_only() -> None:
    with pytest.raises(SOCPlatformError):
        await fetch_with_retry("http://insecure.example.com")


@pytest.mark.asyncio
async def test_fetch_with_retry_success() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"hello")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        body, digest = await fetch_with_retry(
            "https://example.com/feed.json", client=client
        )
        assert body == b"hello"
        assert len(digest) == 64


class TestMitreStixFeed:
    @pytest.mark.asyncio
    async def test_parses_techniques(self) -> None:
        payload = json.dumps(
            {
                "modified": "2026-06-30",
                "objects": [
                    {
                        "type": "attack-pattern",
                        "external_references": [
                            {"source_name": "mitre-attack", "external_id": "T1059"}
                        ],
                    },
                    {
                        "type": "attack-pattern",
                        "external_references": [
                            {"source_name": "mitre-attack", "external_id": "T1021"}
                        ],
                    },
                    {"type": "malware"},  # 무시
                ],
            }
        ).encode()

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=payload)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            feed = MitreStixFeed(Settings(), client=c)
            snap = await feed.afetch()
            assert snap.source == "attack"
            assert "T1059" in snap.techniques
            assert "T1021" in snap.techniques


class TestCisaKevFeed:
    @pytest.mark.asyncio
    async def test_parses_cves(self) -> None:
        payload = json.dumps(
            {
                "dateReleased": "2026-06-30",
                "vulnerabilities": [
                    {"cveID": "CVE-2024-1234"},
                    {"cveID": "CVE-2025-9999"},
                ],
            }
        ).encode()

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=payload)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            feed = CisaKevFeed(Settings(), client=c)
            snap = await feed.afetch()
            assert "CVE-2024-1234" in snap.cves
            assert "CVE-2025-9999" in snap.cves


class TestAtlasFeed:
    @pytest.mark.asyncio
    async def test_parses_yaml(self) -> None:
        body = b"techniques:\n  - id: AML.T0051\n  - id: AML.T0010\n"

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=body)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            feed = AtlasFeed(Settings(), client=c)
            snap = await feed.afetch()
            assert "AML.T0051" in snap.techniques


class TestGraphYamlPatchTool:
    def test_compute_diff_attack(self, tmp_path: Path) -> None:
        graph_path = tmp_path / "graph.yaml"
        graph_path.write_text(
            "techniques:\n  - id: T1059\n  - id: T1021\n", encoding="utf-8"
        )
        patcher = GraphYamlPatchTool(Settings(), graph_path=graph_path)
        snap = FeedSnapshot(
            source="attack",
            techniques=["T1059", "T9999"],  # T9999 신규, T1021 누락
        )
        diff = patcher.compute_diff(snap)
        assert "T9999" in diff.added
        assert "T1021" in diff.removed

    def test_apply_added_appends(self, tmp_path: Path) -> None:
        graph_path = tmp_path / "graph.yaml"
        graph_path.write_text("techniques: []\n", encoding="utf-8")
        patcher = GraphYamlPatchTool(Settings(), graph_path=graph_path)
        diff = LandscapeDiff(source="attack", added=["T1000", "T1001"])
        n = patcher.apply_added(diff)
        assert n == 2
        # 재로드 → 포함 확인
        assert "T1000" in patcher._current_techs()  # noqa: SLF001

    def test_kev_diff_only_cves(self, tmp_path: Path) -> None:
        patcher = GraphYamlPatchTool(Settings(), graph_path=tmp_path / "g.yaml")
        snap = FeedSnapshot(source="kev", cves=["CVE-1", "CVE-2"])
        diff = patcher.compute_diff(snap)
        assert diff.kev_new == ["CVE-1", "CVE-2"]
        assert not diff.added and not diff.removed


class _StubFeed:
    def __init__(
        self,
        source: str,
        techniques: list[str] | None = None,
        cves: list[str] | None = None,
        fail: bool = False,
    ) -> None:
        self.source = source
        self._techs = techniques or []
        self._cves = cves or []
        self._fail = fail

    async def afetch(self) -> FeedSnapshot:
        if self._fail:
            raise SOCPlatformError(f"stub fail: {self.source}")
        return FeedSnapshot(source=self.source, techniques=self._techs, cves=self._cves)


class TestThreatLandscapeAgent:
    @pytest.mark.asyncio
    async def test_cycle_with_mixed_feeds(self, tmp_path: Path) -> None:
        graph_path = tmp_path / "graph.yaml"
        graph_path.write_text("techniques:\n  - id: T1059\n", encoding="utf-8")
        patcher = GraphYamlPatchTool(Settings(), graph_path=graph_path)
        captured: list[str] = []

        async def invalidate(cves: list[str]) -> None:
            captured.extend(cves)

        agent = ThreatLandscapeAgent(
            Settings(),
            feeds=[
                _StubFeed("attack", techniques=["T1059", "T8888"]),
                _StubFeed("kev", cves=["CVE-2024-9999"]),
                _StubFeed("atlas", fail=True),
            ],
            patcher=patcher,
            vuln_cache_invalidator=invalidate,
        )
        report = await agent.run()
        # attack: T8888 신규 자동
        assert report.auto_applied >= 1
        # kev: 무효화 호출됨
        assert "CVE-2024-9999" in captured
        # atlas: 에러 기록
        assert any("atlas" in e for e in report.errors)

    @pytest.mark.asyncio
    async def test_added_cap_forces_pr(self, tmp_path: Path) -> None:
        graph_path = tmp_path / "graph.yaml"
        graph_path.write_text("techniques: []\n", encoding="utf-8")
        patcher = GraphYamlPatchTool(Settings(), graph_path=graph_path)
        large = [f"T{i}" for i in range(5000, 5200)]  # 200건
        agent = ThreatLandscapeAgent(
            Settings(feed_added_cap=100),
            feeds=[_StubFeed("attack", techniques=large)],
            patcher=patcher,
            publisher=None,  # PR proposed 모드
        )
        report = await agent.run()
        # added=200 > cap=100 → 자동적용 0 + PR 시도(publisher None → url 빈값)
        assert report.auto_applied == 0
