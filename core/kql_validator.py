"""KQL 룰 최소 문법·위험 함수 검증(spec A-2).

LLM 이 생성한 KQL draft 를 화이트리스트 스켈레톤(파이프 필수) + 위험 함수
블랙리스트 기준으로 검증한다. 인젝션 표면(external_table 데이터 유출 등) 차단.

Spec: docs/superpowers/specs/2026-07-02-auto-kql-rule-suggester-design.md
"""

from __future__ import annotations

_BLOCKED_FNS: frozenset[str] = frozenset(
    {
        "external_table",
        "externaldata",
        "http_get",
        "http_request",
        "invoke_",
        "cluster(",
        "database(",
    }
)


class KqlValidator:
    """LLM 이 생성한 KQL draft 최소 검증기.

    거부 사유는 문자열로 반환한다 — 호출자가 로그/PR body 에 사용 가능.
    """

    def __init__(self, max_length: int = 8000) -> None:
        self._max_length = max_length

    def check(self, kql: str) -> tuple[bool, str]:
        """(OK 여부, 사유). OK 는 (True, 'ok')."""
        text = kql.strip()
        if not text:
            return False, "empty"
        if len(text) > self._max_length:
            return False, "too_long"
        if "|" not in text:
            return False, "no_pipe"
        low = text.lower()
        for fn in _BLOCKED_FNS:
            if fn in low:
                return False, f"blocked_fn: {fn}"
        return True, "ok"
