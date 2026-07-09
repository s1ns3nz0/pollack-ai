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
from core.models import EnvVerdict, ExperienceRecord
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
        # 재심(cold-case) 캐시 — arevoke 가 갱신 재업로드할 레코드 전체를 보관.
        # ascan_suppressions 가 채운다(ColdCaseReopener 는 scan→revoke 순서 호출).
        self._suppression_cache: dict[str, ExperienceRecord] = {}
        self._last_suppression_scan_complete = True

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

    async def ascan_suppressions(self) -> list[ExperienceRecord]:
        """미revoke 억제(CONFIRMED_FP) 레코드를 반환한다(재심 스캔).

        retrieval 을 넓게(scenario 무관) 긁어 CONFIRMED_FP·미revoke 만 필터한다.
        arevoke 가 갱신 재업로드에 쓸 레코드를 내부 캐시에 보관한다.

        **완전성 주의(Codex Medium)**: RAGFlow 는 청크 CONTENT 를 retrieval 로만
        노출하므로 이 스캔은 top_k 상한의 유사도 랭킹 결과다 — 억제 레코드 수가
        top_k 를 초과하면 저순위 일부가 누락될 수 있다. 반환 수가 상한에 도달하면
        경고 로그로 truncation 을 노출한다(무음 절단 금지). 결정론 완전 열거는
        문서 다운로드 API 필요 → RAGFlow 실검증(회사 PC) 후속. 파이프라인이 실제
        쓰는 InMemoryExperienceStore.ascan_suppressions 는 완전 스캔이다.

        Returns:
            재심 후보 억제 레코드 목록.

        Raises:
            ExperienceStoreError: 설정 누락 또는 조회 장애 시.
        """
        ds = self._dataset()
        url = f"{self._base()}/api/v1/retrieval"
        cap = max(self._settings.ragflow_top_k, 100)
        payload: dict[str, object] = {
            "question": "CONFIRMED_FP suppression 억제",
            "dataset_ids": [ds],
            "page": 1,
            "page_size": cap,
            "similarity_threshold": 0.0,
            "vector_similarity_weight": self._settings.ragflow_vector_weight,
            "top_k": self._settings.ragflow_top_k,
        }
        try:
            async with self._make_client() as client:
                resp = await client.post(url, headers=self._headers(), json=payload)
                resp.raise_for_status()
                body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ExperienceStoreError(f"억제 스캔 실패: {exc}") from exc
        if not isinstance(body, dict) or body.get("code") != 0:
            raise ExperienceStoreError(f"억제 스캔 거부: {_err_detail(body)}")
        out: list[ExperienceRecord] = []
        self._suppression_cache.clear()
        scanned = 0
        for content in _chunk_contents(body):
            scanned += 1
            try:
                record = ExperienceRecord.model_validate_json(content)
            except ValueError:
                continue
            if record.env_verdict != EnvVerdict.CONFIRMED_FP or record.revoked:
                continue
            self._suppression_cache[record.content_hash] = record
            out.append(record)
        if scanned >= cap:
            self._last_suppression_scan_complete = False
            _logger.warning(
                "억제 스캔 상한(%d) 도달 — 저순위 억제 누락 가능(재심 불완전). "
                "완전 열거는 RAGFlow 문서 다운로드 API 필요(후속).",
                cap,
            )
        else:
            self._last_suppression_scan_complete = True
        return out

    @property
    def last_suppression_scan_complete(self) -> bool:
        """마지막 억제 스캔이 RAGFlow retrieval cap 에 잘리지 않았으면 True."""
        return self._last_suppression_scan_complete

    async def arevoke(self, fingerprint: str, reason: str) -> bool:
        """지문 레코드를 revoke — 기존 문서 삭제 후 갱신 레코드 재업로드.

        revoked 는 fingerprint 에 포함되지 않으므로 content_hash·서명이 보존되고
        문서 파일명(`<fp>.json`)도 그대로 유지된다. 갱신 대상 레코드는 직전
        `ascan_suppressions` 캐시에서 가져온다(없으면 False).

        Args:
            fingerprint: revoke 대상 레코드 지문(content_hash).
            reason: 재심 근거(트리거 종류 + 식별자).

        Returns:
            revoke 성공 시 True, 캐시에 없으면 False.

        Raises:
            ExperienceStoreError: 문서 조회/삭제/업로드 장애 시.
        """
        record = self._suppression_cache.get(fingerprint)
        if record is None:
            return False
        doc_id = await self._find_doc_id(self._filename(fingerprint))
        if doc_id is not None:
            await self._delete_doc(doc_id)
        revoked = record.model_copy(update={"revoked": True, "reopened_reason": reason})
        await self.awrite(revoked)
        self._suppression_cache.pop(fingerprint, None)
        _logger.info("exp revoke: fp=%s reason=%s", fingerprint[:12], reason)
        return True

    async def _find_doc_id(self, name: str) -> str | None:
        """문서 이름으로 RAGFlow 문서 id 를 조회한다(없으면 None)."""
        ds = self._dataset()
        url = f"{self._base()}/api/v1/datasets/{ds}/documents"
        try:
            async with self._make_client() as client:
                resp = await client.get(
                    url, headers=self._headers(), params={"keywords": name}
                )
                resp.raise_for_status()
                body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ExperienceStoreError(f"문서 조회 실패: {exc}") from exc
        for doc in _docs_of(body):
            if doc.get("name") == name:
                doc_id = doc.get("id")
                return str(doc_id) if doc_id is not None else None
        return None

    async def _delete_doc(self, doc_id: str) -> None:
        """RAGFlow 문서를 id 로 삭제한다."""
        ds = self._dataset()
        url = f"{self._base()}/api/v1/datasets/{ds}/documents"
        try:
            async with self._make_client() as client:
                resp = await client.request(
                    "DELETE",
                    url,
                    headers=self._headers(),
                    json={"ids": [doc_id]},
                )
                resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise ExperienceStoreError(f"문서 삭제 실패: {exc}") from exc

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
