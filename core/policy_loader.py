"""정책 YAML 로더 공통 헬퍼 — graceful-degrade 보일러플레이트 단일화.

15+ 개 `from_yaml` 로더가 같은 패턴(파일읽기→safe_load→최상위 dict 검증→항목
model_validate)을 반복했고, 매 신규 로더마다 Codex 가 같은 구멍을 지적했다:
**model_validate/구조검증이 try 밖이면 ValidationError/TypeError 가 graph 의
`except SOCPlatformError` catch 를 우회해 파이프라인을 크래시**시킨다.

이 헬퍼는 파일읽기·파싱·구조검증·모델검증을 전부 `SOCPlatformError` 하위(기본
`PolicyError`, coverage 는 `CoverageDataError`)로 감싸 그 구멍을 원천봉쇄한다.
신규 로더는 이 헬퍼만 쓰면 graceful-degrade 가 구조적으로 보장된다.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError
import yaml

from core.exceptions import PolicyError, SOCPlatformError

_M = TypeVar("_M", bound=BaseModel)


def load_policy_mapping(
    path: str | Path | None,
    default_path: Path,
    *,
    label: str,
    error_cls: type[SOCPlatformError] = PolicyError,
) -> dict[str, object]:
    """정책 YAML 을 읽어 최상위 dict 를 반환한다(모든 실패 → error_cls).

    Args:
        path: 명시 경로(None 이면 default_path).
        default_path: 기본 정책 경로.
        label: 오류 메시지용 정책 이름(예: "COA matrix").
        error_cls: 발생 예외 클래스(SOCPlatformError 하위). 기본 PolicyError.

    Returns:
        최상위 매핑(dict).

    Raises:
        error_cls: 파일 부재/파싱 실패/최상위 비-dict 시.
    """
    p = Path(path) if path is not None else default_path
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise error_cls(f"{label} 적재 실패: {exc}") from exc
    if not isinstance(raw, dict):
        raise error_cls(f"{label} 구조 오류(최상위 dict 아님).")
    return raw


def require_list(
    value: object, *, label: str, error_cls: type[SOCPlatformError] = PolicyError
) -> list[object]:
    """값이 리스트임을 강제한다(None → 빈 리스트, 그 외 비-리스트 → error_cls).

    Raises:
        error_cls: value 가 None/list 가 아닐 때.
    """
    if value is None:
        return []
    if not isinstance(value, list):
        raise error_cls(f"{label} 구조 오류(리스트 아님).")
    return list(value)


def require_mapping(
    value: object, *, label: str, error_cls: type[SOCPlatformError] = PolicyError
) -> dict[str, object]:
    """값이 매핑임을 강제한다(None → 빈 dict, 그 외 비-dict → error_cls).

    Raises:
        error_cls: value 가 None/dict 가 아닐 때.
    """
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise error_cls(f"{label} 구조 오류(매핑 아님).")
    return value


def validate_models(
    items: Iterable[object],
    model: type[_M],
    *,
    label: str,
    error_cls: type[SOCPlatformError] = PolicyError,
    skip_non_dict: bool = True,
) -> list[_M]:
    """항목들을 pydantic model 로 검증한다(ValidationError → error_cls, 구멍 근절).

    Args:
        items: 검증 대상(각 dict 여야 함).
        model: 대상 pydantic 모델.
        label: 오류 메시지용 이름.
        error_cls: 발생 예외 클래스. 기본 PolicyError.
        skip_non_dict: True 면 비-dict 항목 건너뜀, False 면 error_cls.

    Returns:
        검증된 모델 목록.

    Raises:
        error_cls: 의미검증(ValidationError) 실패 또는 비-dict(skip_non_dict=False) 시.
    """
    out: list[_M] = []
    try:
        for item in items:
            if not isinstance(item, dict):
                if skip_non_dict:
                    continue
                raise error_cls(f"{label} 항목이 dict 아님: {item!r}")
            out.append(model.model_validate(item))
    except (ValidationError, TypeError, ValueError) as exc:
        # pydantic v2 는 validator 의 TypeError 를 ValidationError 로 감싸지 않는다 —
        # TypeError/ValueError 도 함께 잡아 graph 크래시 벡터를 완전 봉인(Codex #1).
        raise error_cls(f"{label} 항목 검증 실패: {exc}") from exc
    return out
