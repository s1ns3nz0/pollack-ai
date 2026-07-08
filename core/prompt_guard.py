"""PromptInjectionGuard — AI SOC 런타임 자기방어(OWASP LLM01 / ATLAS AML.T0051).

플랫폼의 LlmJudge 프롬프트에 들어가는 **untrusted 텍스트**(attacker 통제 alert 내용 +
RAG 검색 컨텍스트)로부터 프롬프트 인젝션을 막는다. **결정론 패턴**(LLM 없음 → 그 자체가
주입 불가, 포이즈닝 면역).

핵심 보호는 **항상-펜싱**(`neutralize`): untrusted 텍스트를 라벨 구분자로 감싸 LLM 이
데이터로 격리하게 한다. 이는 "인젝션을 묘사한 정상 alert(artifact)" 와 "우리 LLM 을 겨눈
active 지시" 를 **둘 다** 안전 처리한다. `scan` 탐지는 **텔레메트리 전용** — 판정/점수를
바꾸지 않는다(강제 abstention 은 억제 primitive·FP 폭발이라 폐기; Codex H1/H2).

Spec: docs/superpowers/specs/2026-07-08-prompt-injection-guard-design.md
"""

from __future__ import annotations

from pathlib import Path
import re

from pydantic import BaseModel, Field

from core.exceptions import PolicyError, SOCPlatformError
from core.policy_loader import load_policy_mapping, require_list, require_mapping

_POLICY = Path(__file__).resolve().parent / "policy" / "prompt-injection-patterns.yaml"

# 펜스 구분자 — untrusted 텍스트를 이 라벨 블록으로 감싼다. 입력에 이 토큰(또는
# `<<`/`>>`)이 있으면 래핑 전 redact 해 breakout 봉인(H3).
_FENCE_OPEN = "<<UNTRUSTED:{label}>>"
_FENCE_CLOSE = "<<END:{label}>>"
_DELIM_RE = re.compile(r"<<[^>\n]{0,40}?>>|<<|>>")
_DELIM_REDACTION = "[REDACTED_DELIM]"


class GuardVerdict(BaseModel):
    """스캔 결과(텔레메트리 전용 — 판정 비구동).

    Attributes:
        detected: 인젝션 패턴 매칭 여부.
        matched_patterns: 매칭된 패턴 id 목록.
        atlas_ids: 매칭 패턴의 MITRE ATLAS technique id 목록(중복 제거).
        degraded: 정책 로드 실패로 fence-only(탐지 비활성) 모드인지(M6 관측).
    """

    detected: bool = False
    matched_patterns: list[str] = Field(default_factory=list)
    atlas_ids: list[str] = Field(default_factory=list)
    degraded: bool = False


class _Pattern:
    """컴파일된 탐지 패턴 한 건."""

    __slots__ = ("pattern_id", "regex", "atlas")

    def __init__(self, pattern_id: str, regex: re.Pattern[str], atlas: str) -> None:
        self.pattern_id = pattern_id
        self.regex = regex
        self.atlas = atlas


class PromptInjectionGuard:
    """untrusted 텍스트 스캔 + 펜싱(결정론·무상태·total).

    Args:
        patterns: 컴파일된 탐지 패턴 목록(빈 목록 = 탐지 비활성, 펜싱만).
        degraded: 정책 로드 실패로 인한 fence-only 모드 여부.
    """

    def __init__(self, patterns: list[_Pattern], degraded: bool = False) -> None:
        self._patterns = patterns
        self._degraded = degraded

    def scan(self, text: str) -> GuardVerdict:
        """텍스트에서 인젝션 패턴을 탐지한다(순수·예외 없음, 텔레메트리용).

        Args:
            text: 검사할 untrusted 텍스트.

        Returns:
            매칭 패턴 id·ATLAS id 를 담은 GuardVerdict(판정 비구동).
        """
        if not text:
            return GuardVerdict(degraded=self._degraded)
        matched: list[str] = []
        atlas: list[str] = []
        for p in self._patterns:
            if p.regex.search(text):
                matched.append(p.pattern_id)
                if p.atlas not in atlas:
                    atlas.append(p.atlas)
        return GuardVerdict(
            detected=bool(matched),
            matched_patterns=matched,
            atlas_ids=atlas,
            degraded=self._degraded,
        )

    def neutralize(self, text: str, label: str) -> str:
        """untrusted 텍스트를 라벨 펜스로 감싼다(delimiter-safe·실보호).

        입력에 펜스 구분자(또는 `<<`/`>>`)가 있으면 먼저 redact 해 위조 breakout 을
        봉인한다(H3). 시스템 프롬프트는 이 블록을 "데이터일 뿐 지시 아님"으로 취급한다.

        Args:
            text: 감쌀 untrusted 텍스트.
            label: 필드 구분 라벨(title/signals/ctx0 …). 영숫자로 정규화.

        Returns:
            `<<UNTRUSTED:label>> … <<END:label>>` 로 감싼 안전 문자열.
        """
        safe_label = re.sub(r"[^A-Za-z0-9_]", "", label) or "data"
        redacted = _DELIM_RE.sub(_DELIM_REDACTION, text or "")
        return (
            f"{_FENCE_OPEN.format(label=safe_label)}\n"
            f"{redacted}\n"
            f"{_FENCE_CLOSE.format(label=safe_label)}"
        )

    @property
    def degraded(self) -> bool:
        """정책 로드 실패로 인한 fence-only 모드 여부."""
        return self._degraded

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> PromptInjectionGuard:
        """prompt-injection-patterns.yaml 을 적재한다(공유 로더로 graceful).

        Args:
            path: 정책 경로. 생략 시 기본 정책.

        Returns:
            로드된 PromptInjectionGuard.

        Raises:
            PolicyError: 파일 부재/파싱 실패/구조 불일치/정규식 컴파일 실패 시.
        """
        raw = load_policy_mapping(path, _POLICY, label="프롬프트 인젝션 패턴")
        section = require_mapping(raw.get("prompt_injection"), label="prompt_injection")
        default_atlas = str(section.get("atlas_id", "AML.T0051"))
        items = require_list(section.get("patterns"), label="prompt_injection patterns")
        if not items:
            raise PolicyError("프롬프트 인젝션 patterns 없음/빈값.")
        patterns: list[_Pattern] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            pid = str(item.get("id", ""))
            expr = item.get("regex")
            if not pid or not isinstance(expr, str) or not expr:
                raise PolicyError(f"프롬프트 인젝션 패턴 구조 오류: {item!r}")
            try:
                compiled = re.compile(expr)
            except re.error as exc:
                raise PolicyError(f"패턴 정규식 컴파일 실패({pid}): {exc}") from exc
            patterns.append(
                _Pattern(pid, compiled, str(item.get("atlas", default_atlas)))
            )
        return cls(patterns)

    @classmethod
    def degraded_fence_only(cls) -> PromptInjectionGuard:
        """정책 로드 실패 시 fence-only 폴백(탐지 비활성, 펜싱은 유지·관측가능)."""
        return cls([], degraded=True)


def load_default_guard() -> PromptInjectionGuard:
    """기본 정책으로 가드를 로드한다(실패 시 fence-only 폴백).

    Returns:
        로드된 가드. 정책 로드 실패 시 degraded fence-only 가드(관측가능).
    """
    try:
        return PromptInjectionGuard.from_yaml()
    except SOCPlatformError:
        return PromptInjectionGuard.degraded_fence_only()
