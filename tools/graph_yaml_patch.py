"""mitre_attack_graph.yaml diff/patch + PR 페이로드 빌드(spec T1).

신규 추가는 자동 적용(상한 `feed_added_cap` 초과 시 PR), 변경·삭제는 항상 PR.
`RulePublisher` 와 페어 — PR 페이로드 형식은 `RulePullRequest`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import yaml

from core.models import FeedSnapshot, LandscapeDiff, RulePullRequest
from core.settings import Settings
from utils.logging import get_logger


class GraphYamlPatchTool:
    """mitre_attack_graph.yaml 갱신 도구.

    동작:
    - `compute_diff(snap)` → 현재 yaml 의 techniques 와 snap.techniques 비교.
    - `apply_added(diff)` → 신규 항목 yaml 에 추가 (상한 가드 호출자 책임).
    - `build_pr(diff)` → `RulePullRequest` 페이로드 생성 (RulePublisher 가 발행).
    """

    def __init__(
        self,
        settings: Settings,
        graph_path: Path | None = None,
    ) -> None:
        self._settings = settings
        self._path = graph_path or (
            Path(__file__).resolve().parents[1] / "data" / "mitre_attack_graph.yaml"
        )
        self._logger = get_logger("GraphYamlPatchTool")

    def _load(self) -> dict[str, object]:
        if not self._path.exists():
            return {"techniques": []}
        with self._path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {"techniques": []}

    def _save(self, data: dict[str, object]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)

    def _current_techs(self) -> set[str]:
        data = self._load()
        techs = data.get("techniques", [])
        if not isinstance(techs, list):
            return set()
        out: set[str] = set()
        for entry in techs:
            if isinstance(entry, dict):
                tid = entry.get("id") or entry.get("technique")
                if isinstance(tid, str):
                    out.add(tid)
            elif isinstance(entry, str):
                out.add(entry)
        return out

    def compute_diff(self, snap: FeedSnapshot) -> LandscapeDiff:
        """현재 yaml 과 snap 비교 — added/removed 만 산정(변경 차후)."""
        if snap.source == "kev":
            # KEV 는 yaml 갱신 대상 아님 — kev_new 만 수집(저장은 vuln_tool 무효화).
            return LandscapeDiff(source=snap.source, kev_new=snap.cves)
        current = self._current_techs()
        latest = set(snap.techniques)
        added = sorted(latest - current)
        removed = sorted(current - latest)
        return LandscapeDiff(source=snap.source, added=added, removed=removed)

    def apply_added(self, diff: LandscapeDiff) -> int:
        """diff.added 만 yaml 에 추가. 반환: 적용 건수."""
        if not diff.added or diff.source == "kev":
            return 0
        data = self._load()
        techs = data.setdefault("techniques", [])
        if not isinstance(techs, list):
            return 0
        existing = self._current_techs()
        applied = 0
        for tid in diff.added:
            if tid in existing:
                continue
            techs.append({"id": tid, "source": diff.source})
            applied += 1
        if applied:
            self._save(data)
        return applied

    def build_pr(self, diff: LandscapeDiff, reason: str = "") -> RulePullRequest:
        """변경/삭제 또는 cap 초과 시 PR 페이로드 빌드."""
        ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        branch = f"chore/threat-landscape-{diff.source}-{ts}"
        body_lines = [
            f"위협 피드 변경 자동 PR(spec T1) — source={diff.source}",
            "",
            f"- added: {len(diff.added)}",
            f"- changed: {len(diff.changed)}",
            f"- removed: {len(diff.removed)}",
        ]
        if reason:
            body_lines.append(f"\n사유: {reason}")
        body_lines.append("\n⚠ 회귀 게이트(`benchmarks/`) 통과 후 머지.")
        return RulePullRequest(
            repo=self._settings.sentinel_content_repo,
            branch=branch,
            path="data/mitre_attack_graph.yaml",
            title=(
                f"chore(threat-landscape): {diff.source} 갱신"
                f" (+{len(diff.added)} ~{len(diff.changed)} -{len(diff.removed)})"
            ),
            body="\n".join(body_lines),
            base_branch=self._settings.rule_base_branch,
        )
