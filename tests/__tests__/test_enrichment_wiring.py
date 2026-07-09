"""외부 enrich(TI/샌드박스/vuln) 기본 배선 — OPSEC 마스터 + per-source 키 게이트."""

from agents.graph import _default_sandbox, _default_ti, _default_vuln
from core.settings import Settings
from tools.sandbox_tool import HybridAnalysisTool
from tools.ti_tool import CompositeThreatIntel
from tools.vuln_tool import BoundedVuln, CompositeVuln


def _settings(**over: object) -> Settings:
    base: dict[str, object] = {
        "external_enrichment_enabled": False,
        "virustotal_api_key": "",
        "greynoise_api_key": "",
        "abuseipdb_api_key": "",
        "threatfox_api_key": "",
        "hybridanalysis_api_key": "",
    }
    base.update(over)
    return Settings(**base)  # type: ignore[arg-type]


class TestMasterGate:
    def test_disabled_yields_none(self) -> None:
        """마스터 off → 키가 있어도 TI/샌드박스/vuln 전부 None(default-deny)."""
        s = _settings(
            external_enrichment_enabled=False,
            virustotal_api_key="k",
            hybridanalysis_api_key="k",
        )
        assert _default_ti(s) is None
        assert _default_sandbox(s) is None
        assert _default_vuln(s) is None

    def test_enabled_no_keys_ti_sandbox_none(self) -> None:
        """마스터 on + 키 없음 → TI/샌드박스는 None(소스 없음)."""
        s = _settings(external_enrichment_enabled=True)
        assert _default_ti(s) is None
        assert _default_sandbox(s) is None


class TestKeyGatedComposite:
    def test_ti_composite_with_key(self) -> None:
        """마스터 on + VT 키 → CompositeThreatIntel 구성."""
        s = _settings(external_enrichment_enabled=True, virustotal_api_key="k")
        assert isinstance(_default_ti(s), CompositeThreatIntel)

    def test_sandbox_with_key(self) -> None:
        """마스터 on + Hybrid Analysis 키 → HybridAnalysisTool."""
        s = _settings(external_enrichment_enabled=True, hybridanalysis_api_key="k")
        assert isinstance(_default_sandbox(s), HybridAnalysisTool)

    def test_vuln_cisa_kev_keyless(self) -> None:
        """마스터 on → vuln 은 CISA KEV(키불요)로 항상 구성(BoundedVuln 래핑)."""
        s = _settings(external_enrichment_enabled=True)
        v = _default_vuln(s)
        # 데드라인 래퍼로 감싼 CompositeVuln(Codex diff High — report-side 도 bounded).
        assert isinstance(v, BoundedVuln)
        assert isinstance(v._inner, CompositeVuln)
        assert v._deadline == s.enrichment_deadline_seconds  # 데드라인 plumbing
