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


class RulePublishError(SOCPlatformError):
    """탐지룰 저장소(Watch List PR) 발행 오류(연동/응답 검증 실패)."""


class GraphRetrievalError(SOCPlatformError):
    """지식그래프(GraphRAG) 로드/검색 오류."""


class CoverageDataError(SOCPlatformError):
    """ATT&CK 커버리지 매트릭스 로드/검증 오류."""


class PlaybookError(SOCPlatformError):
    """CACAO 플레이북 카탈로그 로드/검증 오류(스키마·정합·no-exec 위반)."""
