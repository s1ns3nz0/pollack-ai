"""정책/시나리오 dict(`dict[str, object]`)에서 타입 안전하게 값을 추출하는 헬퍼.

YAML 에서 온 `object` 값을 mypy-strict 하에서 안전하게 좁힌다.
"""

from __future__ import annotations


def opt_str(value: object) -> str | None:
    """문자열이면 그대로, None 이면 None, 그 외는 str() 로 변환."""
    if value is None:
        return None
    return value if isinstance(value, str) else str(value)


def str_list(value: object) -> list[str]:
    """리스트면 각 원소를 str 로, 아니면 빈 리스트."""
    if not isinstance(value, list):
        return []
    return [x if isinstance(x, str) else str(x) for x in value]
