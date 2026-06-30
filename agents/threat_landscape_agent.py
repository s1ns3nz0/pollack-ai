"""ThreatLandscapeAgent — 위협 피드 주기 갱신(spec T1).

Deployment B (learning worker) 의 새 사이클. ATT&CK/ATLAS/EMB3D/CISA KEV 피드를
주기 fetch → graph yaml diff → 신규 자동 적용 / 변경·삭제 PR → coverage 재계산.

핫패스 영향 0 (BaseWorkerAgent — alert state 무관).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from agents.base import BaseWorkerAgent
from core.exceptions import SOCPlatformError
from core.models import LandscapeDiff, WorkerReport
from core.settings import Settings
from tools.feed_base import FeedTool
from tools.graph_yaml_patch import GraphYamlPatchTool
from tools.rule_publisher import RulePublisher


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class ThreatLandscapeAgent(BaseWorkerAgent):
    """주기 위협 피드 갱신 에이전트.

    Args:
        settings: 전역 설정.
        feeds: 피드 어댑터 목록. 비면 사이클은 빈 보고서 반환.
        patcher: graph yaml 패치 도구.
        publisher: PR 발행기. 미주입 시 PR `proposed` 상태로만 산출.
        vuln_cache_invalidator: KEV 신규 CVE 캐시 무효화 hook(선택).
        added_cap: 자동 적용 상한(초과 시 PR 강제).
    """

    def __init__(
        self,
        settings: Settings,
        feeds: list[FeedTool],
        patcher: GraphYamlPatchTool,
        publisher: RulePublisher | None = None,
        vuln_cache_invalidator: Callable[[list[str]], Awaitable[None]] | None = None,
        added_cap: int | None = None,
    ) -> None:
        super().__init__(settings)
        self._feeds = feeds
        self._patcher = patcher
        self._publisher = publisher
        self._invalidate = vuln_cache_invalidator
        self._added_cap = added_cap or settings.feed_added_cap

    async def run(self) -> WorkerReport:
        diffs: list[LandscapeDiff] = []
        errors: list[str] = []
        for feed in self._feeds:
            try:
                snap = await feed.afetch()
            except SOCPlatformError as exc:
                errors.append(f"{feed.source}: {exc}")
                self._logger.warning("feed 실패: %s", exc)
                continue
            try:
                diffs.append(self._patcher.compute_diff(snap))
            except SOCPlatformError as exc:
                errors.append(f"{feed.source} diff: {exc}")

        auto = 0
        pr_urls: list[str] = []
        for diff in diffs:
            if diff.kev_new and self._invalidate is not None:
                try:
                    await self._invalidate(diff.kev_new)
                except SOCPlatformError as exc:
                    errors.append(f"kev invalidate: {exc}")
            if diff.added:
                if len(diff.added) > self._added_cap:
                    pr = self._patcher.build_pr(diff, reason="added_cap_exceeded")
                    pr_urls.append(await self._publish(pr))
                else:
                    auto += self._patcher.apply_added(diff)
            if diff.changed or diff.removed:
                pr = self._patcher.build_pr(diff)
                pr_urls.append(await self._publish(pr))

        # coverage 재계산(spec T1 §8). reload 미구현 시 graceful.
        try:
            from tools.coverage import CoverageMatrix

            reload_fn = getattr(CoverageMatrix, "reload", None)
            if callable(reload_fn):
                reload_fn()
        except Exception as exc:  # noqa: BLE001 — 메트릭 모듈 결합 최소화
            self._logger.warning("coverage reload 실패: %s", exc)

        return WorkerReport(
            cycle_at=_now_iso(),
            diffs=diffs,
            auto_applied=auto,
            pr_urls=[u for u in pr_urls if u],
            errors=errors,
        )

    async def _publish(self, pr_payload: object) -> str:
        """PR 발행 (publisher 미주입 시 proposed — URL 빈값)."""
        if self._publisher is None:
            return ""
        try:
            pr = await self._publisher.apublish(pr_payload)  # type: ignore[arg-type]
            return getattr(pr, "url", "") or ""
        except SOCPlatformError as exc:
            self._logger.warning("PR 발행 실패: %s", exc)
            return ""
