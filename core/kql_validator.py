"""KQL 룰 최소 문법·위험 구문 검증(spec A-2).

LLM 이 생성한 KQL draft 를 화이트리스트 스켈레톤(파이프 필수) + 위험 구문
블랙리스트로 검증한다. 인젝션/유출 표면 차단: 크로스 클러스터·DB 호출
(external_table/externaldata/cluster()/database()), 원격 fetch(http_*),
관리 명령(선행 `.` 커맨드), 플러그인 실행(evaluate). 전(全) 검사 전에 주석을
제거해 `cluster //x\n(` 류 회피를 봉쇄한다.

**심층방어 주의**: 이 검증기는 최후 방어선이 아니다 — draft 는 항상 proposed PR +
운영자 검토를 거친다. 여기선 명백히 위험한 구문만 사전 차단(정규 KQL 파서 아님).

Spec: docs/superpowers/specs/2026-07-02-auto-kql-rule-suggester-design.md
"""

from __future__ import annotations

import re

# 위험 구문(정규화·주석제거·소문자 후 검사). 공백/개행 삽입 회피 대비 정규식.
_BLOCKED_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("external_table", re.compile(r"external_table\s*\(")),
    ("externaldata", re.compile(r"externaldata\b")),
    ("cluster()", re.compile(r"\bcluster\s*\(")),
    ("database()", re.compile(r"\bdatabase\s*\(")),
    ("http_get", re.compile(r"http_get\b")),
    ("http_request", re.compile(r"http_request\b")),
    ("invoke_", re.compile(r"\binvoke_")),
    ("evaluate_plugin", re.compile(r"\bevaluate\b")),
)
_COMMENT_RE = re.compile(r"//[^\n]*")


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
        if "|" not in text:  # 파이프는 원문 기준(문자열 내 // URL 훼손 방지).
            return False, "no_pipe"
        # 위험구문은 원문 ∪ 주석제거본 양쪽에서 검사한다.
        #  - 원문(raw): 문자열 내 URL(http://) 뒤에 오는 토큰이 주석 제거로 사라지는
        #    회피 차단(예: '...://x' | evaluate → raw 에 evaluate 존재).
        #  - 주석제거본(stripped): 토큰을 주석으로 쪼갠 회피 차단(cluster //x\n( 등).
        low_raw = text.lower()
        stripped = _COMMENT_RE.sub("", text)
        low_stripped = stripped.lower()
        # 관리 명령(.create/.alter/.drop 등)은 어느 줄이든 선행 `.` 로 시작.
        for line in (*text.splitlines(), *stripped.splitlines()):
            if line.strip().startswith("."):
                return False, "management_command"
        for name, pat in _BLOCKED_PATTERNS:
            if pat.search(low_raw) or pat.search(low_stripped):
                return False, f"blocked: {name}"
        return True, "ok"
