"""플랫폼 커스텀 예외 계층.

모든 커스텀 예외는 `SOCPlatformError` 하위로 정의한다.
"""

from __future__ import annotations


class SOCPlatformError(Exception):
    """플랫폼 전체 베이스 예외."""


class RagflowQueryError(SOCPlatformError):
    """RAGFlow 검색 API 연동 오류."""
