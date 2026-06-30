"""경험메모리(`exp/`) RAGFlow 백엔드 — `ExperienceStore` 계약의 영속 구현.

`InMemoryExperienceStore` 와 동일 계약(aexists/awrite/aquery)을 RAGFlow 의 별도
데이터셋(`ragflow_exp_dataset_id`)으로 영속화한다. 자기개선 루프의 "기억"이 프로세스
재시작/스케일아웃을 넘어 유지되게 한다.

저장 모델: 레코드 1건 = 문서 1건. 문서 본문은 `ExperienceRecord` 의 JSON 직렬화
이며, 파일명은 `<content_hash>.json`(멱등 키). 회상은 RAGFlow `retrieval` 로 후보를
가져와 본문 JSON 을 역직렬화한다 — **서명/지문이 그대로 보존**되므로 읽기 게이트가
무결성·진정성을 검증할 수 있다(서버단 신뢰 가정 없음).

주입형(client_factory)으로 테스트는 `httpx.MockTransport` 로 네트워크 없이 검증한다.
설정 누락/연동 장애는 `ExperienceStoreError` 로 던져 상위에서 graceful degrade 한다.
"""

from __future__ import annotations

import httpx

from core.exceptions import ExperienceStoreError
from core.models import ExperienceRecord
from core.settings import Settings, get_settings
from utils.logging import get_logger

_logger = get_logger("ragflow_experience")


class RagflowExperienceStore:
    """RAGFlow 데이터셋으로 백업되는 경험메모리 저장소.

    Args:
        settings: 전역 설정(RAGFlow 접속 + `ragflow_exp_dataset_id`). 미지정 시 환경.
        client_factory: 비동기 HTTP 클라이언트 팩토리(테스트 주입용).
    """

    def __init__(
        self, settings: Settings | None = None, client_factory: object | None = None
    ) -> None:
        self._settings = settings or get_settings()
        self._client_factory = client_factory

    def _make_client(self) -> httpx.AsyncClient:
        if self._client_factory is not None:
            return self._client_factory()  # type: ignore[operator,no-any-return]
        return httpx.AsyncClient(timeout=self._settings.ragflow_timeout_seconds)

    def _dataset(self) -> str:
        ds = self._settings.ragflow_exp_dataset_id
        token = self._settings.ragflow_api_token.get_secret_value()
        if not ds or not token:
            raise ExperienceStoreError(
                "경험메모리 RAGFlow 설정 누락(RAGFLOW_EXP_DATASET_ID/TOKEN)."
            )
        return ds

    def _headers(self) -> dict[str, str]:
        token = self._settings.ragflow_api_token.get_secret_value()
        return {"Authorization": f"Bearer {token}"}

    def _base(self) -> str:
        return self._settings.ragflow_base_url.rstrip("/")

    @staticmethod
    def _filename(fingerprint: str) -> str:
        return f"{fingerprint}.json"

    async def aexists(self, fingerprint: str) -> bool:
        """해당 지문 문서가 이미 적립돼 있으면 True.

        Raises:
            ExperienceStoreError: 설정 누락 또는 조회 장애 시.
        """
        ds = self._dataset()
        url = f"{self._base()}/api/v1/datasets/{ds}/documents"
        name = self._filename(fingerprint)
        try:
            async with self._make_client() as client:
                resp = await client.get(
                    url, headers=self._headers(), params={"keywords": fingerprint}
                )
                resp.raise_for_status()
                body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ExperienceStoreError(f"경험메모리 존재조회 실패: {exc}") from exc
        for doc in _docs_of(body):
            if doc.get("name") == name:
                return True
        return False

    async def awrite(self, record: ExperienceRecord) -> None:
        """서명·지문이 부여된 레코드를 문서로 업로드한다.

        Raises:
            ExperienceStoreError: 설정 누락, 미서명 레코드, 업로드 장애 시.
        """
        if not record.content_hash:
            raise ExperienceStoreError("미서명 레코드는 적립 불가(content_hash 없음).")
        ds = self._dataset()
        url = f"{self._base()}/api/v1/datasets/{ds}/documents"
        payload = record.model_dump_json().encode("utf-8")
        files = {
            "file": (self._filename(record.content_hash), payload, "application/json")
        }
        try:
            async with self._make_client() as client:
                resp = await client.post(url, headers=self._headers(), files=files)
                resp.raise_for_status()
                body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ExperienceStoreError(f"경험메모리 적립 실패: {exc}") from exc
        if not isinstance(body, dict) or body.get("code") != 0:
            raise ExperienceStoreError(f"경험메모리 적립 거부: {_err_detail(body)}")
        _logger.info(
            "exp write: scenario=%s fp=%s", record.scenario_id, record.content_hash[:12]
        )

    async def aquery(self, scenario_id: str, k: int = 20) -> list[ExperienceRecord]:
        """시나리오 관련 레코드를 최대 k 건 회상한다(미검증 — 신뢰판단은 읽기 게이트).

        Raises:
            ExperienceStoreError: 설정 누락 또는 조회 장애 시.
        """
        ds = self._dataset()
        url = f"{self._base()}/api/v1/retrieval"
        payload: dict[str, object] = {
            "question": scenario_id,
            "dataset_ids": [ds],
            "page": 1,
            "page_size": max(k * 4, 20),
            "similarity_threshold": 0.0,  # 회상은 넓게 — 신뢰필터는 읽기 게이트가 담당
            "vector_similarity_weight": self._settings.ragflow_vector_weight,
            "top_k": self._settings.ragflow_top_k,
        }
        try:
            async with self._make_client() as client:
                resp = await client.post(url, headers=self._headers(), json=payload)
                resp.raise_for_status()
                body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ExperienceStoreError(f"경험메모리 회상 실패: {exc}") from exc
        if not isinstance(body, dict) or body.get("code") != 0:
            raise ExperienceStoreError(f"경험메모리 회상 거부: {_err_detail(body)}")
        return self._parse_records(body, scenario_id, k)

    @staticmethod
    def _parse_records(
        body: dict[str, object], scenario_id: str, k: int
    ) -> list[ExperienceRecord]:
        """retrieval 응답의 청크 본문(JSON)을 ExperienceRecord 로 역직렬화한다.

        파싱 불가/시나리오 불일치 청크는 건너뛴다(서명 검증은 읽기 게이트가 수행).
        """
        records: list[ExperienceRecord] = []
        seen: set[str] = set()
        for content in _chunk_contents(body):
            try:
                record = ExperienceRecord.model_validate_json(content)
            except ValueError:
                continue
            if record.scenario_id != scenario_id:
                continue
            if record.content_hash in seen:
                continue
            seen.add(record.content_hash)
            records.append(record)
            if len(records) >= k:
                break
        return records


def _err_detail(body: object) -> object:
    """RAGFlow 오류 응답에서 메시지(있으면)를 추출한다(로깅용)."""
    return body.get("message") if isinstance(body, dict) else body


def _docs_of(body: object) -> list[dict[str, object]]:
    """RAGFlow documents 응답에서 문서 목록을 안전하게 추출한다."""
    if not isinstance(body, dict):
        return []
    data = body.get("data")
    candidates: object = None
    if isinstance(data, dict):
        candidates = data.get("docs") or data.get("documents")
    elif isinstance(data, list):
        candidates = data
    if not isinstance(candidates, list):
        return []
    return [d for d in candidates if isinstance(d, dict)]


def _chunk_contents(body: dict[str, object]) -> list[str]:
    """retrieval 응답에서 청크 본문 문자열만 추출한다."""
    data = body.get("data")
    if not isinstance(data, dict):
        return []
    chunks = data.get("chunks")
    if not isinstance(chunks, list):
        return []
    out: list[str] = []
    for chunk in chunks:
        if isinstance(chunk, dict):
            content = chunk.get("content")
            if isinstance(content, str):
                out.append(content)
    return out
