"""RagflowExperienceStore 재심 능력 — ascan_suppressions + arevoke (mock httpx).

RAGFlow 실 서버는 이 환경에 없다. httpx.MockTransport 로 요청/응답 계약만
검증한다 — 실 서버 검증은 회사 PC(회사 PC 체크리스트는 커밋 메시지 참고).
"""

import json

import httpx
from pydantic import SecretStr
import pytest

from core.experience import Sha256Signer
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


def _rec(
    *,
    scenario: str = "S2",
    verdict: Verdict = Verdict.FALSE_POSITIVE,
    env: EnvVerdict = EnvVerdict.CONFIRMED_FP,
    revoked: bool = False,
    actor_fp: str = "",
) -> ExperienceRecord:
    rec = ExperienceRecord(
        scenario_id=scenario,
        signals=["명령 시퀀스 불연속"],
        verdict=verdict,
        severity=Severity.LOW,
        judge_features=JudgeFeatures(
            has_signal=True, has_rule=False, corroborated=False, confidence=0.3
        ),
        env_verdict=env,
        provenance=Provenance.ENV_VERIFIED,
        actor_fingerprint=actor_fp,
        revoked=revoked,
    )
    fp = rec.fingerprint()
    return rec.model_copy(
        update={"content_hash": fp, "signature": Sha256Signer().sign(fp)}
    )


class _FakeRagflow:
    """상태 보유 RAGFlow 목 — 문서(id/name/content) 보유 + 삭제/업로드 캡처."""

    def __init__(
        self, records: list[ExperienceRecord] | None = None, code: int = 0
    ) -> None:
        self.code = code
        # doc_id → (name, content_json)
        self.docs: dict[str, tuple[str, str]] = {}
        for i, r in enumerate(records or []):
            self.docs[f"doc-{i}"] = (f"{r.content_hash}.json", r.model_dump_json())
        self.deleted_ids: list[str] = []
        self.uploaded: list[bytes] = []
        self._next = len(self.docs)

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method
        if method == "POST" and path.endswith("/retrieval"):
            chunks = [{"content": c} for _n, c in self.docs.values()]
            return httpx.Response(
                200, json={"code": self.code, "data": {"chunks": chunks}}
            )
        if method == "GET" and path.endswith("/documents"):
            docs = [{"id": i, "name": n} for i, (n, _c) in self.docs.items()]
            return httpx.Response(200, json={"code": 0, "data": {"docs": docs}})
        if method == "DELETE" and path.endswith("/documents"):
            body = json.loads(request.content or b"{}")
            for did in body.get("ids", []):
                self.deleted_ids.append(did)
                self.docs.pop(did, None)
            return httpx.Response(200, json={"code": 0})
        if method == "POST" and path.endswith("/documents"):
            self.uploaded.append(request.content)
            did = f"doc-{self._next}"
            self._next += 1
            self.docs[did] = ("uploaded.json", "")
            return httpx.Response(200, json={"code": self.code, "data": {}})
        return httpx.Response(404, json={"code": 1, "message": path})


def _store(fake: _FakeRagflow) -> RagflowExperienceStore:
    settings = Settings(
        ragflow_api_token=SecretStr("tok"), ragflow_exp_dataset_id="exp-ds"
    )

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(fake.handler))

    return RagflowExperienceStore(settings=settings, client_factory=factory)


class TestScanSuppressions:
    @pytest.mark.asyncio
    async def test_returns_only_confirmed_fp(self) -> None:
        """CONFIRMED_FP 만 스캔 — TP 는 제외."""
        fake = _FakeRagflow(
            records=[
                _rec(env=EnvVerdict.CONFIRMED_FP),
                _rec(
                    scenario="S1",
                    verdict=Verdict.TRUE_POSITIVE,
                    env=EnvVerdict.CONFIRMED_TP,
                ),
            ]
        )
        out = await _store(fake).ascan_suppressions()
        assert len(out) == 1
        assert out[0].env_verdict == EnvVerdict.CONFIRMED_FP

    @pytest.mark.asyncio
    async def test_excludes_already_revoked(self) -> None:
        """이미 revoked 된 FP 는 스캔 제외(재심 대상 아님)."""
        fake = _FakeRagflow(records=[_rec(revoked=True)])
        out = await _store(fake).ascan_suppressions()
        assert out == []

    @pytest.mark.asyncio
    async def test_skips_unparseable(self) -> None:
        """파싱 불가 문서는 graceful skip."""
        fake = _FakeRagflow(records=[_rec()])
        fake.docs["bad"] = ("bad.json", "{not json")
        out = await _store(fake).ascan_suppressions()
        assert len(out) == 1


class TestRevoke:
    @pytest.mark.asyncio
    async def test_revoke_deletes_and_reuploads(self) -> None:
        """arevoke → 기존 문서 삭제 + revoked=True 레코드 재업로드."""
        rec = _rec(actor_fp="fp:x")
        fake = _FakeRagflow(records=[rec])
        store = _store(fake)

        await store.ascan_suppressions()  # 캐시 채움
        ok = await store.arevoke(rec.content_hash, "동일 actor 확정")

        assert ok is True
        assert fake.deleted_ids == ["doc-0"]
        assert fake.uploaded, "갱신 레코드 재업로드"
        uploaded = json.loads(
            fake.uploaded[-1].split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n", 3)[0]
        )
        assert uploaded["revoked"] is True
        assert uploaded["reopened_reason"] == "동일 actor 확정"
        # revoke 는 fingerprint 불포함 → content_hash/서명 보존
        assert uploaded["content_hash"] == rec.content_hash
        assert uploaded["signature"] == rec.signature

    @pytest.mark.asyncio
    async def test_revoke_missing_returns_false(self) -> None:
        """캐시에 없는 지문 revoke 는 False."""
        fake = _FakeRagflow(records=[])
        store = _store(fake)
        await store.ascan_suppressions()
        assert await store.arevoke("deadbeef", "x") is False
