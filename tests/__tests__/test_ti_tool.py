"""StubThreatIntel — IOC 평판 조회 검증."""

import pytest

from core.models import TiVerdict
from tools.ti_tool import StubThreatIntel


class TestStubThreatIntel:
    """오프라인 결정론 TI 조회."""

    @pytest.mark.asyncio
    async def test_known_malicious(self) -> None:
        """알려진 악성 IOC → MALICIOUS."""
        ti = StubThreatIntel(malicious=frozenset({"bad-hash"}))
        out = await ti.alookup(["bad-hash"])
        assert out[0].verdict == TiVerdict.MALICIOUS
        assert out[0].source == "stub-ti"

    @pytest.mark.asyncio
    async def test_suspicious_and_unknown(self) -> None:
        """의심 집합 → SUSPICIOUS, 미등록 → UNKNOWN."""
        ti = StubThreatIntel(malicious=frozenset(), suspicious=frozenset({"1.2.3.4"}))
        out = {f.indicator: f.verdict for f in await ti.alookup(["1.2.3.4", "8.8.8.8"])}
        assert out["1.2.3.4"] == TiVerdict.SUSPICIOUS
        assert out["8.8.8.8"] == TiVerdict.UNKNOWN

    @pytest.mark.asyncio
    async def test_empty_indicators(self) -> None:
        """빈 IOC 목록 → 빈 결과."""
        assert await StubThreatIntel().alookup([]) == []
