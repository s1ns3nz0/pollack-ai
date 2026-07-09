"""ActiveHuntAgent - bounded read-only Sentinel KQL hunts."""

from __future__ import annotations

from agents.base import BaseSOCAgent
from core.active_hunt import ActiveHuntPlanner, HuntQuery
from core.models import ActiveHuntFinding, InvestigationResult, MissionRisk, SOCState
from core.settings import Settings
from tools.sentinel_query_tool import SentinelQueryClient


class ActiveHuntAgent(BaseSOCAgent):
    """Run policy-approved active hunt KQL templates and return evidence findings.

    Args:
        settings: Global application settings.
        planner: Active hunt query planner.
        client: Read-only Sentinel query client.
        cpcon_level: Current global CPCON level.
    """

    def __init__(
        self,
        settings: Settings,
        planner: ActiveHuntPlanner,
        client: SentinelQueryClient,
        cpcon_level: int,
    ) -> None:
        """Initialize the agent dependencies.

        Args:
            settings: Global application settings.
            planner: Active hunt query planner.
            client: Read-only Sentinel query client.
            cpcon_level: Current global CPCON level.
        """
        super().__init__(settings)
        self._planner = planner
        self._client = client
        self._cpcon_level = cpcon_level

    async def run(self, state: SOCState) -> SOCState:
        """Execute active hunt queries and return partial state.

        Args:
            state: Current LangGraph SOC state.

        Returns:
            SOCState: Partial state containing active hunt findings and trace.

        Raises:
            None.
        """
        if not self._settings.active_hunt_enabled:
            return {"active_hunt_findings": [], "trace": ["active_hunt"]}

        alert = state["alert"]
        investigation: InvestigationResult | None = state.get("investigation")
        mission_risk: MissionRisk | None = state.get("mission_risk")
        predictions = investigation.predictions if investigation is not None else []
        plan = self._planner.plan(
            alert=alert,
            predictions=predictions,
            mission_risk=mission_risk,
            cpcon_level=self._cpcon_level,
        )

        findings: list[ActiveHuntFinding] = list(plan.unavailable_findings)
        for query in plan.queries:
            findings.append(await self._run_query(query))

        self._logger.info(
            "active_hunt: alert=%s queries=%d matched=%d",
            alert.id,
            len(plan.queries),
            sum(1 for finding in findings if finding.matched),
        )
        return {"active_hunt_findings": findings, "trace": ["active_hunt"]}

    async def _run_query(self, query: HuntQuery) -> ActiveHuntFinding:
        """Run one planned query and convert the result to a finding.

        Args:
            query: Rendered policy-approved hunt query.

        Returns:
            ActiveHuntFinding: Normalized finding for the query outcome.

        Raises:
            None.
        """
        try:
            result = await self._client.aquery(query.kql, query.timeout_seconds)
        except Exception as exc:
            return ActiveHuntFinding(
                direction=query.direction,
                technique=query.technique,
                tactic=query.tactic,
                query_id=query.query_id,
                time_window=query.time_window,
                rationale=query.rationale,
                error=str(exc),
            )

        return ActiveHuntFinding(
            direction=query.direction,
            technique=query.technique,
            tactic=query.tactic,
            query_id=query.query_id,
            matched=result.row_count > 0,
            row_count=result.row_count,
            time_window=query.time_window,
            rationale=query.rationale,
            sample=result.rows[: query.row_limit],
            error=result.error,
        )
