"""표준 로거 팩토리.

`print()` 사용을 금지하고 모든 로깅을 `soc.*` 네임스페이스로 일원화한다.
"""

from __future__ import annotations

import logging


def get_logger(name: str) -> logging.Logger:
    """`soc.<name>` 네임스페이스의 표준 로거를 반환한다.

    Args:
        name: 로거 하위 이름. 보통 호출 클래스/모듈 이름.

    Returns:
        `soc.<name>` 이름으로 설정된 로거 인스턴스.
    """
    return logging.getLogger(f"soc.{name}")
