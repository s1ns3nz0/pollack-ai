"""데이터 라인리지 스냅샷 수집(spec D-1).

Report 노드가 일괄 수집 → OscalEvidence.lineage 임베드. 방산 재현성(NIST SP
800-53 AU/CM/SI) 감사 추적. 시크릿은 pydantic SecretStr 자동 마스킹으로 노출 X.

Spec: docs/superpowers/specs/2026-07-02-data-lineage-design.md
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
import hashlib
import json

from core.models import LineageSnapshot, SOCState
from core.settings import Settings
from core.severity import POLICY_DIR

_POLICY_FILES = ("severity-policy.yaml", "asset-tiers.yaml", "causal-rules.yaml")


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _git_sha_default() -> str:
    """subprocess timeout 2초. 실패 시 "unknown"."""
    try:
        import subprocess  # noqa: S404 — read-only git rev-parse

        r = subprocess.run(  # noqa: S603, S607 — 고정 인자만, shell=False
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
        return r.stdout.strip() if r.returncode == 0 else "unknown"
    except Exception:  # noqa: BLE001 — 어떤 실패든 graceful
        return "unknown"


class LineageCollector:
    """라인리지 스냅샷 수집기.

    Args:
        settings: 전역 설정 — llm_provider/model + fingerprint 대상.
        git_sha_provider: 테스트 주입용. 미주입 시 subprocess.
    """

    def __init__(
        self,
        settings: Settings,
        git_sha_provider: Callable[[], str] | None = None,
    ) -> None:
        self._settings = settings
        self._git_sha_provider = git_sha_provider or _git_sha_default

    def snapshot(self, state: SOCState) -> LineageSnapshot:
        """state 에서 라인리지 스냅샷을 조립."""
        return LineageSnapshot(
            captured_at=_now_iso(),
            code_version=self._git_sha_provider(),
            llm_provider=self._settings.llm_provider,
            llm_model=self._settings.ollama_chat_model,
            policy_hashes=self._policy_hashes(),
            settings_fingerprint=self._settings_fp(),
            ensemble_weights=self._weights(state),
            total_latency_ms=self._total_latency(state),
            node_latencies=self._node_latencies(state),
        )

    def _policy_hashes(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for name in _POLICY_FILES:
            path = POLICY_DIR / name
            if path.exists():
                h = hashlib.sha256(path.read_bytes()).hexdigest()
                out[name] = f"sha256:{h[:16]}"
        return out

    def _settings_fp(self) -> str:
        """비밀 자동 마스킹 후 SHA-256 (앞 16자)."""
        # pydantic SecretStr 은 model_dump(mode='json') 시 '**********' 반환.
        data = self._settings.model_dump(mode="json")
        canonical = json.dumps(data, sort_keys=True, ensure_ascii=False)
        return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()[:16]

    def _weights(self, state: SOCState) -> dict[str, float]:
        ensemble = state.get("ensemble")
        if ensemble is None:
            return {}
        weights = getattr(ensemble, "weights", None)
        if isinstance(weights, dict):
            return {str(k): float(v) for k, v in weights.items()}
        return {}

    def _total_latency(self, state: SOCState) -> float:
        total = 0.0
        for t in state.get("node_timings", []):
            elapsed = t.get("elapsed_ms")
            if isinstance(elapsed, (int, float)):
                total += float(elapsed)
        return round(total, 3)

    def _node_latencies(self, state: SOCState) -> dict[str, float]:
        out: dict[str, float] = {}
        for t in state.get("node_timings", []):
            node = t.get("node")
            elapsed = t.get("elapsed_ms")
            if isinstance(node, str) and isinstance(elapsed, (int, float)):
                out[node] = max(out.get(node, 0.0), float(elapsed))
        return out
