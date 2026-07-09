"""Watch List 변경 발행기 — 탐지룰 저장소(GitHub)에 PR 생성.

RuleUpdateAgent 가 만든 `RulePullRequest`(Watch List 변경)를 외부 룰 저장소에 올린다.
모든 발행기는 동일 `apublish(pr) -> RulePullRequest` 계약을 따른다(Protocol 주입):

- `StubRulePublisher`   : 오프라인 — PR 생성 없이 proposed 상태 반환(데모/테스트).
- `GitHubRulePublisher` : 실 GitHub API 로 변경·브랜치·커밋·PR 생성(멱등).

`dah-sentinel-content` 저장소의 워치리스트는 **ARM 템플릿 JSON**(`Watchlists/*.json`)
으로 저장되고 CSV 내용은 `properties.rawContent` 문자열에 박혀 있다. 발행기는 그 JSON 을
받아 `rawContent` 안의 행만 추가(A/B)/수정(C)하고 JSON 을 다시 커밋한다. SearchKey 는
JSON 의 `itemsSearchKey`(단일 진실)와 대조해 검증한다.

원칙: KQL 룰은 절대 건드리지 않는다. 변경은 회귀 게이트(benchmarks: 알려진 TP 무손실)
통과 후 머지하도록 PR 본문에 명시한다.
"""

from __future__ import annotations

import base64
import csv
import io
import json
from typing import Protocol, runtime_checkable
from urllib.parse import quote

import httpx

from core.exceptions import RulePublishError
from core.models import RulePullRequest, WatchlistUpdate
from core.settings import Settings, get_settings
from utils.logging import get_logger

_logger = get_logger("rule_publisher")

# CSV 컬럼이 아닌 감사용 메타데이터 키(Watch List 스키마 오염 방지 — 커밋 메시지로만).
_PROVENANCE_KEYS = frozenset({"added_by", "modified_by", "reason", "source_alert"})


@runtime_checkable
class RulePublisher(Protocol):
    """Watch List PR 발행기 계약."""

    async def apublish(self, pr: RulePullRequest) -> RulePullRequest:
        """PR 페이로드를 발행하고 상태/URL 이 채워진 사본을 반환한다."""
        ...


class StubRulePublisher:
    """오프라인 발행기 — 실제 PR 없이 proposed 상태로 반환(데모/테스트)."""

    async def apublish(self, pr: RulePullRequest) -> RulePullRequest:
        """PR 을 발행하지 않고 제안 상태로 표시한다."""
        _logger.info(
            "rule PR(stub): repo=%s branch=%s path=%s", pr.repo, pr.branch, pr.path
        )
        return pr.model_copy(
            update={
                "status": "proposed",
                "url": f"stub://rule-pr/{pr.repo}/{pr.branch}",
            }
        )


def _data_columns(wl: WatchlistUpdate) -> dict[str, str]:
    """Watch List 행에 쓸 실제 데이터 컬럼만 추출(감사 메타 제외)."""
    return {k: v for k, v in wl.entry.items() if k not in _PROVENANCE_KEYS}


def apply_watchlist(existing: str | None, wl: WatchlistUpdate) -> tuple[str, bool]:
    """기존 Watch List CSV 텍스트에 변경을 적용한다.

    add(A/B): SearchKey 값으로 중복 확인 후 신규 행 추가. modify(C): SearchKey 로
    행을 찾아 값 갱신(없으면 추가). 헤더에 없는 데이터 컬럼은 헤더에 더한다.

    Args:
        existing: 기존 CSV 본문(없으면 None — 신규 파일).
        wl: 적용할 Watch List 변경.

    Returns:
        (새 CSV 본문, 실제 변경 여부). 변경 없으면 원본과 False.
    """
    data = _data_columns(wl)
    rows: list[dict[str, str]] = []
    fieldnames: list[str] = []
    if existing:
        reader = csv.DictReader(io.StringIO(existing))
        fieldnames = list(reader.fieldnames or [])
        rows = [{k: (v or "") for k, v in r.items()} for r in reader]
    for col in data:
        if col not in fieldnames:
            fieldnames.append(col)

    key_col = wl.search_key
    key_val = data.get(key_col, "")
    changed = False

    if wl.action == "modify":
        matched = False
        for row in rows:
            if row.get(key_col) == key_val:
                for col, val in data.items():
                    if row.get(col) != val:
                        row[col] = val
                        changed = True
                matched = True
                break
        if not matched:
            rows.append({**{f: "" for f in fieldnames}, **data})
            changed = True
    else:  # add — SearchKey 값 기준 중복 제거(멱등)
        if not any(row.get(key_col) == key_val for row in rows):
            rows.append({**{f: "" for f in fieldnames}, **data})
            changed = True

    if not changed:
        return (existing or "", False)

    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({f: row.get(f, "") for f in fieldnames})
    return (out.getvalue(), True)


def apply_watchlist_json(json_text: str, wl: WatchlistUpdate) -> tuple[str, bool]:
    """ARM 템플릿 워치리스트 JSON 의 `rawContent`(내장 CSV)에 변경을 적용한다.

    `itemsSearchKey` 를 단일 진실로 삼아 힌트의 search_key 와 대조 검증한다(드리프트
    방어). 내장 CSV 는 `\\r\\n` 구분이며, 변경 후 JSON 구조는 그대로 두고 `rawContent`
    값만 교체한다.

    Args:
        json_text: 워치리스트 ARM 템플릿 JSON 본문.
        wl: 적용할 Watch List 변경.

    Returns:
        (새 JSON 본문, 실제 변경 여부).

    Raises:
        RulePublishError: JSON 구조 불일치 또는 SearchKey 불일치 시.
    """
    try:
        doc = json.loads(json_text)
        props = doc["resources"][0]["properties"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise RulePublishError(f"워치리스트 JSON 구조 파싱 실패: {exc}") from exc

    items_key = props.get("itemsSearchKey")
    if items_key != wl.search_key:
        raise RulePublishError(
            f"SearchKey 불일치: 힌트={wl.search_key!r} JSON={items_key!r}"
        )

    raw = props.get("rawContent", "")
    if not isinstance(raw, str):
        raise RulePublishError("rawContent 형식 검증 실패")
    new_raw, changed = apply_watchlist(raw, wl)
    if not changed:
        return (json_text, False)

    # 저장소 스타일에 맞춰 말미 개행 제거(행 사이는 csv.writer 가 \r\n 사용).
    props["rawContent"] = new_raw.rstrip("\r\n")
    return (json.dumps(doc, indent=2, ensure_ascii=False) + "\n", True)


class GitHubRulePublisher:
    """실 GitHub API 로 Watch List CSV 변경 PR 을 생성한다.

    흐름: 베이스 SHA 조회 → 현재 CSV 조회 → 변경 적용(멱등) → 변경 시에만 작업
    브랜치 생성 → 파일 커밋 → PR 오픈. 모든 응답은 형식 검증 후 사용한다.

    Args:
        settings: 전역 설정(repo·토큰·베이스 브랜치 등). 미지정 시 환경 로드.
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
        return httpx.AsyncClient(timeout=self._settings.github_timeout_seconds)

    def _headers(self) -> dict[str, str]:
        token = self._settings.github_token.get_secret_value()
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _api(self, suffix: str, repo: str) -> str:
        return f"{self._settings.github_base_url.rstrip('/')}/repos/{repo}/{suffix}"

    async def apublish(self, pr: RulePullRequest) -> RulePullRequest:
        """Watch List 변경을 PR 로 발행한다.

        Raises:
            RulePublishError: 토큰 미설정·변경 없음·API 응답 검증 실패 시.
        """
        if not self._settings.github_token.get_secret_value():
            raise RulePublishError("GITHUB_TOKEN 미설정 — PR 발행 불가")
        # raw 콘텐츠 PR(예: AutoKQL .kql 신규 파일) — watchlist JSON 경로와 분기.
        if pr.watchlist_update is None:
            if pr.file_content:
                return await self._publish_content(pr)
            raise RulePublishError("watchlist_update/file_content 없음 — 변경 없음")
        try:
            async with self._make_client() as client:
                base_sha = await self._base_sha(client, pr)
                existing, file_sha = await self._get_file(client, pr, pr.base_branch)
                if existing is None:
                    raise RulePublishError(f"워치리스트 JSON 없음: {pr.path}")
                new_text, changed = apply_watchlist_json(existing, pr.watchlist_update)
                if not changed:
                    _logger.info("rule PR: 변경 없음(멱등) repo=%s", pr.repo)
                    return pr.model_copy(update={"status": "unchanged"})
                await self._ensure_branch(client, pr, base_sha)
                await self._put_file(client, pr, new_text, file_sha)
                url = await self._open_pr(client, pr)
        except httpx.HTTPError as exc:
            raise RulePublishError(f"GitHub PR 발행 실패: {exc}") from exc
        _logger.info("rule PR opened: %s", url)
        return pr.model_copy(update={"status": "opened", "url": url})

    async def _publish_content(self, pr: RulePullRequest) -> RulePullRequest:
        """raw 파일 콘텐츠(file_content)를 신규/갱신 PR 로 발행한다.

        watchlist JSON 적용이 아니라 임의 파일(예: KQL 룰)을 create-or-update 한다.
        멱등: 대상 브랜치의 기존 내용과 동일하면 unchanged 반환.

        Raises:
            RulePublishError: API 응답 검증 실패 시.
        """
        try:
            async with self._make_client() as client:
                base_sha = await self._base_sha(client, pr)
                existing, file_sha = await self._get_file(client, pr, pr.base_branch)
                if existing is not None and existing == pr.file_content:
                    _logger.info("content PR: 변경 없음(멱등) repo=%s", pr.repo)
                    return pr.model_copy(update={"status": "unchanged"})
                await self._ensure_branch(client, pr, base_sha)
                _, branch_sha = await self._get_file(client, pr, pr.branch)
                await self._put_file(client, pr, pr.file_content, branch_sha)
                url = await self._open_pr(client, pr)
        except httpx.HTTPError as exc:
            raise RulePublishError(f"GitHub content PR 발행 실패: {exc}") from exc
        _logger.info("content PR opened: %s", url)
        return pr.model_copy(update={"status": "opened", "url": url})

    async def _base_sha(self, client: httpx.AsyncClient, pr: RulePullRequest) -> str:
        url = self._api(f"git/ref/heads/{quote(pr.base_branch)}", pr.repo)
        resp = await client.get(url, headers=self._headers())
        resp.raise_for_status()
        body = resp.json()
        obj = body.get("object") if isinstance(body, dict) else None
        sha = obj.get("sha") if isinstance(obj, dict) else None
        if not isinstance(sha, str):
            raise RulePublishError("베이스 브랜치 SHA 응답 검증 실패")
        return sha

    async def _ensure_branch(
        self, client: httpx.AsyncClient, pr: RulePullRequest, base_sha: str
    ) -> None:
        url = self._api("git/refs", pr.repo)
        resp = await client.post(
            url,
            headers=self._headers(),
            json={"ref": f"refs/heads/{pr.branch}", "sha": base_sha},
        )
        if resp.status_code == 422:  # 이미 존재 — 재사용
            return
        resp.raise_for_status()

    async def _get_file(
        self, client: httpx.AsyncClient, pr: RulePullRequest, ref: str
    ) -> tuple[str | None, str | None]:
        url = self._api(f"contents/{quote(pr.path, safe='/')}", pr.repo)
        resp = await client.get(url, headers=self._headers(), params={"ref": ref})
        if resp.status_code == 404:  # 신규 파일
            return (None, None)
        resp.raise_for_status()
        body = resp.json()
        if not isinstance(body, dict):
            raise RulePublishError("파일 조회 응답 검증 실패")
        raw = body.get("content")
        sha = body.get("sha")
        if not isinstance(sha, str):
            raise RulePublishError("파일 SHA 응답 검증 실패")
        text = base64.b64decode(raw).decode("utf-8") if isinstance(raw, str) else None
        return (text, sha)

    async def _put_file(
        self,
        client: httpx.AsyncClient,
        pr: RulePullRequest,
        text: str,
        file_sha: str | None,
    ) -> None:
        url = self._api(f"contents/{quote(pr.path, safe='/')}", pr.repo)
        payload: dict[str, str] = {
            "message": pr.title,
            "content": base64.b64encode(text.encode("utf-8")).decode("ascii"),
            "branch": pr.branch,
        }
        if file_sha is not None:
            payload["sha"] = file_sha
        resp = await client.put(url, headers=self._headers(), json=payload)
        resp.raise_for_status()

    async def _open_pr(self, client: httpx.AsyncClient, pr: RulePullRequest) -> str:
        url = self._api("pulls", pr.repo)
        resp = await client.post(
            url,
            headers=self._headers(),
            json={
                "title": pr.title,
                "head": pr.branch,
                "base": pr.base_branch,
                "body": pr.body,
            },
        )
        if resp.status_code == 422:  # 동일 head 의 PR 이 이미 열려 있음
            return await self._existing_pr_url(client, pr)
        resp.raise_for_status()
        body = resp.json()
        html_url = body.get("html_url") if isinstance(body, dict) else None
        if not isinstance(html_url, str):
            raise RulePublishError("PR 생성 응답 검증 실패")
        return html_url

    async def _existing_pr_url(
        self, client: httpx.AsyncClient, pr: RulePullRequest
    ) -> str:
        owner = pr.repo.split("/", 1)[0]
        resp = await client.get(
            self._api("pulls", pr.repo),
            headers=self._headers(),
            params={"head": f"{owner}:{pr.branch}", "state": "open"},
        )
        resp.raise_for_status()
        body = resp.json()
        if isinstance(body, list) and body and isinstance(body[0], dict):
            existing = body[0].get("html_url")
            if isinstance(existing, str):
                return existing
        return ""
