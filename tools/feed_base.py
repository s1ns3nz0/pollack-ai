"""위협 피드 어댑터 공통 인터페이스(spec T1).

`FeedTool` Protocol + 공통 HTTP 헬퍼. HTTPS 강제 + retry + SHA-256 변경 추적.

Spec: docs/superpowers/specs/2026-06-30-threat-landscape-agent-design.md
"""

from __future__ import annotations

import hashlib
from typing import Protocol, runtime_checkable

import httpx

from core.exceptions import SOCPlatformError
from core.models import FeedSnapshot


@runtime_checkable
class FeedTool(Protocol):
    """위협 피드 어댑터 계약."""

    source: str

    async def afetch(self) -> FeedSnapshot:
        """피드를 가져와 FeedSnapshot 으로 반환한다."""
        ...


async def fetch_with_retry(
    url: str,
    *,
    timeout: float = 60.0,
    retries: int = 2,
    user_agent: str = "pollack-ai/1.0",
    client: httpx.AsyncClient | None = None,
) -> tuple[bytes, str]:
    """URL 에서 body 를 가져와 (body, sha256_hex) 반환.

    HTTPS only. 5xx → 지수 backoff retry. 4xx → SOCPlatformError.
    """
    if not url.lower().startswith("https://"):
        raise SOCPlatformError(f"feed: HTTPS only ({url})")
    last_exc: Exception | None = None
    delay = 1.0
    for _attempt in range(retries + 1):
        try:
            if client is None:
                async with httpx.AsyncClient(
                    timeout=timeout, headers={"User-Agent": user_agent}
                ) as c:
                    resp = await c.get(url)
            else:
                resp = await client.get(
                    url, headers={"User-Agent": user_agent}, timeout=timeout
                )
            if 500 <= resp.status_code < 600:
                last_exc = SOCPlatformError(f"feed 5xx {resp.status_code}: {url}")
            else:
                resp.raise_for_status()
                body = resp.content
                digest = hashlib.sha256(body).hexdigest()
                return body, digest
        except (httpx.HTTPError, SOCPlatformError) as exc:
            last_exc = (
                exc
                if not isinstance(exc, SOCPlatformError)
                else SOCPlatformError(str(exc))
            )
        import asyncio

        await asyncio.sleep(delay)
        delay *= 2.0
    raise SOCPlatformError(f"feed 실패: {url}: {last_exc}")
