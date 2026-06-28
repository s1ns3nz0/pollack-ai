"""RagflowExperienceStore — 적립/존재/회상 라운드트립 + 서명 보존 + 게이트 통합.

RAGFlow API 는 httpx.MockTransport 로 모사(네트워크 없음). 핵심은 본문 JSON 라운드
트립으로 서명/지문이 보존돼 MemoryReadGate 가 무결성 검증을 통과시키는 것.
"""

import httpx
from pydantic import SecretStr
import pytest

from core.exceptions import ExperienceStoreError
from core.experience import MemoryReadGate, RecallPurpose, Sha256Signer
from core.models import (
    EnvVerdict,
    ExperienceRecord,
    JudgeFeatures,
    Provenance,
    Severity,
    Verdict,
)
from core.settings import Settings
from tools.ragflow_experience import RagflowExperienceStore

_SCEN = "UAV-GNSS-001"


def _signed(
    scenario: str = _SCEN, verdict: Verdict = Verdict.TRUE_POSITIVE
) -> ExperienceRecord:
    env = (
        EnvVerdict.CONFIRMED_TP
        if verdict == Verdict.TRUE_POSITIVE
        else EnvVerdict.CONFIRMED_FP
    )
    rec = ExperienceRecord(
        scenario_id=scenario,
        signals=["GNSS-INS 잔차 급증"],
        asset_tier="T1-Critical",
        verdict=verdict,
        severity=Severity.HIGH,
        judge_features=JudgeFeatures(
            has_signal=True, has_rule=True, corroborated=True, confidence=0.6
        ),
        env_verdict=env,
        provenance=Provenance.ENV_VERIFIED,
    )
    fp = rec.fingerprint()
    return rec.model_copy(
        update={"content_hash": fp, "signature": Sha256Signer().sign(fp)}
    )


class _FakeRagflow:
    """상태 보유 RAGFlow 목 — 업로드 본문 캡처 + retrieval 반환 레코드 보유."""

    def __init__(
        self, records: list[ExperienceRecord] | None = None, code: int = 0
    ) -> None:
        self.records = records or []
        self.code = code
        self.uploaded: bytes | None = None
        self.doc_names: list[str] = [f"{r.content_hash}.json" for r in (records or [])]

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path.endswith("/documents"):
            self.uploaded = request.content
            return httpx.Response(self._http(), json={"code": self.code, "data": {}})
        if request.method == "GET" and path.endswith("/documents"):
            docs = [{"name": n} for n in self.doc_names]
            return httpx.Response(200, json={"code": 0, "data": {"docs": docs}})
        if request.method == "POST" and path.endswith("/retrieval"):
            chunks = [{"content": r.model_dump_json()} for r in self.records]
            return httpx.Response(
                self._http(), json={"code": self.code, "data": {"chunks": chunks}}
            )
        return httpx.Response(404, json={"code": 1, "message": path})

    def _http(self) -> int:
        return 200 if self.code == 0 else 200  # RAGFlow 는 200+code 로 오류 표현


def _store(fake: _FakeRagflow) -> RagflowExperienceStore:
    settings = Settings(
        ragflow_api_token=SecretStr("tok"), ragflow_exp_dataset_id="exp-ds"
    )

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(fake.handler))

    return RagflowExperienceStore(settings=settings, client_factory=factory)


class TestWrite:
    @pytest.mark.asyncio
    async def test_awrite_uploads_record_json(self) -> None:
        fake = _FakeRagflow()
        rec = _signed()
        await _store(fake).awrite(rec)
        assert fake.uploaded is not None
        assert _SCEN.encode() in fake.uploaded  # 멀티파트 본문에 레코드 JSON 포함
        assert rec.content_hash.encode() in fake.uploaded

    @pytest.mark.asyncio
    async def test_unsigned_record_rejected(self) -> None:
        fake = _FakeRagflow()
        rec = _signed().model_copy(update={"content_hash": ""})
        with pytest.raises(ExperienceStoreError):
            await _store(fake).awrite(rec)

    @pytest.mark.asyncio
    async def test_api_error_raises(self) -> None:
        fake = _FakeRagflow(code=1)
        with pytest.raises(ExperienceStoreError):
            await _store(fake).awrite(_signed())


class TestExists:
    @pytest.mark.asyncio
    async def test_true_when_doc_present(self) -> None:
        rec = _signed()
        fake = _FakeRagflow(records=[rec])
        assert await _store(fake).aexists(rec.content_hash) is True

    @pytest.mark.asyncio
    async def test_false_when_absent(self) -> None:
        fake = _FakeRagflow(records=[])
        assert await _store(fake).aexists("deadbeef") is False


class TestQuery:
    @pytest.mark.asyncio
    async def test_roundtrip_preserves_signature(self) -> None:
        rec = _signed()
        fake = _FakeRagflow(records=[rec])
        out = await _store(fake).aquery(_SCEN)
        assert len(out) == 1
        assert out[0].content_hash == rec.content_hash
        assert out[0].signature == rec.signature  # 서명 보존 → 게이트 검증 가능

    @pytest.mark.asyncio
    async def test_filters_other_scenarios(self) -> None:
        rec = _signed(scenario="OTHER")
        fake = _FakeRagflow(records=[rec])
        out = await _store(fake).aquery(_SCEN)
        assert out == []

    @pytest.mark.asyncio
    async def test_skips_unparseable_chunks(self) -> None:
        class _Garbage(_FakeRagflow):
            def handler(self, request: httpx.Request) -> httpx.Response:
                if request.method == "POST" and request.url.path.endswith("/retrieval"):
                    return httpx.Response(
                        200,
                        json={"code": 0, "data": {"chunks": [{"content": "{bad"}]}},
                    )
                return super().handler(request)

        fake = _Garbage()
        assert await _store(fake).aquery(_SCEN) == []


class TestConfigAndGateIntegration:
    @pytest.mark.asyncio
    async def test_missing_config_raises(self) -> None:
        store = RagflowExperienceStore(settings=Settings())  # 토큰/데이터셋 빈값
        with pytest.raises(ExperienceStoreError):
            await store.aquery(_SCEN)

    @pytest.mark.asyncio
    async def test_read_gate_verifies_roundtripped_record(self) -> None:
        """저장소 회상 → 읽기 게이트가 서명 검증 후 채택(통합)."""
        rec = _signed()
        fake = _FakeRagflow(records=[rec])
        gate = MemoryReadGate(_store(fake), signer=Sha256Signer())
        hits = await gate.recall(_SCEN, RecallPurpose.DETECTION)
        assert len(hits) == 1
        assert hits[0].content_hash == rec.content_hash
