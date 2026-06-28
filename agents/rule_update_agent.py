"""[4a] Rule Update Agent (오탐) — Watch List 전용 수정 + PR 발행.

원칙(팀 합의): **KQL 룰은 절대 건드리지 않는다.** 오탐 발생 시 KQL 이 읽는 Watch
List 값만 추가/수정한다. 유형은 A(화이트리스트)/B(예외)/C(임계값) 세 가지다.

경보의 `expected_detection.remediation` 힌트(watchlist/search_key/type/...)로부터
`WatchlistUpdate` 와 외부 룰 저장소 PR 페이로드를 구성하고, 발행기(`RulePublisher`)가
주입되면 PR 을 올린다. 변경은 회귀 게이트(benchmarks: 알려진 TP 무손실) 통과 후
머지하도록 본문에 명시한다.
"""

from __future__ import annotations

from agents.base import BaseSOCAgent
from core.coerce import opt_str
from core.exceptions import SOCPlatformError
from core.models import (
    Alert,
    RulePullRequest,
    RuleUpdateResult,
    SOCState,
    WatchlistUpdate,
)
from core.settings import Settings
from tools.rule_publisher import RulePublisher


class RuleUpdateAgent(BaseSOCAgent):
    """오탐 → Watch List 수정 제안 + (선택) PR 발행 Agent.

    Args:
        settings: 전역 설정(룰 저장소·브랜치 접두 등).
        publisher: Watch List PR 발행기(미지정 시 proposed 상태로만 산출).
    """

    def __init__(
        self, settings: Settings, publisher: RulePublisher | None = None
    ) -> None:
        super().__init__(settings)
        self._publisher = publisher

    async def run(self, state: SOCState) -> SOCState:
        """오탐 → Watch List 변경 제안 + PR 페이로드 구성(필요 시 발행).

        Args:
            state: verdict=false_positive 인 상태.

        Returns:
            rule_update 산출물(Watch List 변경·PR 포함)이 담긴 부분 상태.
        """
        alert = state["alert"]
        rule = (
            opt_str(alert.expected_detection.get("sentinel_rule"))
            or opt_str(alert.expected_detection.get("sigma_rule"))
            or "unknown"
        )
        watchlist_update = self._build_watchlist_update(alert)
        if watchlist_update is None:
            self._logger.info(
                "rule_update: alert=%s rule=%s (remediation 미지정 — 검토 필요)",
                alert.id,
                rule,
            )
            return {
                "rule_update": RuleUpdateResult(
                    target_rule=rule,
                    proposal=(
                        f"오탐 패턴 검토 필요: '{alert.title}' "
                        "(Watch List remediation 미지정)"
                    ),
                    pr_status="no_remediation",
                    reason=f"verdict=false_positive (alert {alert.id})",
                ),
                "trace": ["rule_update"],
            }

        pr = self._build_pr(alert, watchlist_update)
        if self._publisher is not None:
            pr = await self._publish(pr)
        self._logger.info(
            "rule_update: alert=%s watchlist=%s action=%s status=%s",
            alert.id,
            watchlist_update.watchlist,
            watchlist_update.action,
            pr.status,
        )
        return {
            "rule_update": RuleUpdateResult(
                target_rule=rule,
                proposal=(
                    f"Watch List '{watchlist_update.watchlist}' "
                    f"{watchlist_update.action} (KQL 불변)"
                ),
                pr_status=pr.status,
                reason=watchlist_update.reason,
                watchlist_update=watchlist_update,
                pull_request=pr,
            ),
            "trace": ["rule_update"],
        }

    def _build_watchlist_update(self, alert: Alert) -> WatchlistUpdate | None:
        """경보 remediation 힌트로부터 Watch List 변경을 구성. 없으면 None.

        Type C(임계값)는 기존 값 modify, A/B(화이트리스트/예외)는 신규 행 add.
        """
        remediation = alert.expected_detection.get("remediation")
        if not isinstance(remediation, dict):
            return None
        watchlist = opt_str(remediation.get("watchlist"))
        search_key = opt_str(remediation.get("search_key"))
        if not watchlist or not search_key:
            return None
        update_type = opt_str(remediation.get("type")) or "B"

        if update_type == "C":
            column = opt_str(remediation.get("column")) or search_key
            value = opt_str(remediation.get("threshold")) or ""
            return WatchlistUpdate(
                watchlist=watchlist,
                search_key=search_key,
                update_type="C",
                action="modify",
                entry={
                    search_key: column,
                    "Value": value,
                    "modified_by": "rule_update_agent",
                    "reason": alert.title,
                    "source_alert": alert.id,
                },
                reason=f"임계값 조정 — {column}={value} (FP {alert.id})",
            )

        value = opt_str(remediation.get("value")) or alert.asset_id or alert.asset_tier
        kind = "화이트리스트 정상항목" if update_type == "A" else "예외"
        entry: dict[str, str] = {
            search_key: value,
            "added_by": "rule_update_agent",
            "reason": alert.title,
            "source_alert": alert.id,
        }
        # 추가 데이터 컬럼(예: GNSS 잔차 임계) — 예외 한정(전체 화이트리스트 방지).
        extra = remediation.get("columns")
        if isinstance(extra, dict):
            for col, col_val in extra.items():
                entry[str(col)] = str(col_val)
        return WatchlistUpdate(
            watchlist=watchlist,
            search_key=search_key,
            update_type=update_type,
            action="add",
            entry=entry,
            reason=f"{kind} 추가 — {search_key}={value} (FP {alert.id})",
        )

    def _build_pr(
        self, alert: Alert, watchlist_update: WatchlistUpdate
    ) -> RulePullRequest:
        """Watch List 변경을 담은 외부 저장소 PR 페이로드를 구성한다."""
        wl = watchlist_update
        prefix = self._settings.rule_branch_prefix
        branch = f"{prefix}/{wl.watchlist}-{alert.id}".lower()
        path = f"Watchlists/{wl.watchlist}.json"
        title = f"fix(watchlist): {wl.watchlist} {wl.action} (FP {alert.id})"
        body = (
            "오탐(FP) 자동 개선 — **Watch List 전용 변경(KQL 불변)**.\n\n"
            f"- Watch List: `{wl.watchlist}` (Type {wl.update_type})\n"
            f"- Action: {wl.action} / SearchKey: `{wl.search_key}`\n"
            f"- Entry: `{wl.entry}`\n"
            f"- 근거: {wl.reason}\n\n"
            "⚠ 회귀 게이트: 머지 전 `benchmarks` 통과 필수(알려진 TP 무손실)."
        )
        return RulePullRequest(
            repo=self._settings.sentinel_content_repo,
            branch=branch,
            path=path,
            title=title,
            body=body,
            base_branch=self._settings.rule_base_branch,
            watchlist_update=wl,
        )

    async def _publish(self, pr: RulePullRequest) -> RulePullRequest:
        """발행기로 PR 을 올린다. 장애 시 failed 로 표시(파이프라인 계속)."""
        if self._publisher is None:
            return pr
        try:
            return await self._publisher.apublish(pr)
        except SOCPlatformError as exc:
            self._logger.warning("rule_update PR 발행 실패, failed 표시: %s", exc)
            return pr.model_copy(update={"status": "failed"})
