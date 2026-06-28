"""플랫폼 커스텀 예외 계층.

모든 커스텀 예외는 `SOCPlatformError` 하위로 정의한다.
"""

from __future__ import annotations


class SOCPlatformError(Exception):
    """플랫폼 전체 베이스 예외."""


class RagflowQueryError(SOCPlatformError):
    """RAGFlow 검색 API 연동 오류."""


class PolicyError(SOCPlatformError):
    """심각도 정책 로드/적용 오류."""


class LLMError(SOCPlatformError):
    """LLM(요약/판정) 호출 오류."""


class ExperienceStoreError(SOCPlatformError):
    """경험메모리(`exp/`) 저장소 읽기/쓰기 오류."""


class ThreatIntelError(SOCPlatformError):
    """외부 위협 인텔(TI) 조회 오류(연동/응답 검증 실패)."""


class SandboxError(SOCPlatformError):
    """샌드박스 디토네이션/분석 오류(연동/응답 검증 실패)."""


class VulnLookupError(SOCPlatformError):
    """취약점(CVE) 컨텍스트 조회 오류(연동/응답 검증 실패)."""
