"""공유 원시 타입 — Alert(계약)와 나머지 모델이 함께 쓰는 enum/컴포넌트.

core/alert.py 와 core/models.py 가 순환 없이 공유할 수 있도록 여기 둔다
(alert.py → primitives, models.py → primitives + alert. 단방향).
하위호환: core.models 가 이 심볼들을 re-export 하므로 기존 `from core.models import
Severity` 는 그대로 동작.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """심각도 등급(정책 엔진 산정값)."""

    HIGH = "h"
    MEDIUM = "m"
    LOW = "l"
    INFO = "i"


class Verdict(StrEnum):
    """오탐/정탐 판정."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"


class SbomComponent(BaseModel):
    """SBOM 컴포넌트 한 건(관측된 UAV 펌웨어/라이브러리/모델).

    Attributes:
        name: 컴포넌트 식별자.
        version: 관측 버전.
        hash: 관측 서명 해시(승인 해시와 대조).
        cves: 컴포넌트가 선언한 CVE 목록(vuln_tool 로 악용여부 조회).
    """

    name: str
    version: str = ""
    hash: str = ""
    cves: list[str] = Field(default_factory=list)
