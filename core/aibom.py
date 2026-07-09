"""AIBOM — AI Bill of Materials / 모델 출처·거버넌스(SBOM 의 AI 확장).

플랫폼 자기 AI 스택(LLM·임베딩·RAGFlow·GraphRAG·RAGAS 모델)의 **선언 매니페스트**를
승인 목록(`approved-aibom.yaml`)과 대조해 결정론 거버넌스 위험을 판정한다.

  ① unregistered          — 승인 목록에 없는 컴포넌트(shadow·비인가 치환)
  ② untrusted_source      — 승인 소스(레지스트리/URL/제공자) 밖
  ③ unpinned              — 부동 버전(""/"latest"/":latest"/mutable 채널) — 드리프트
  ④ version_mismatch      — 승인 버전과 불일치(다운그레이드/스왑)
  ⑤ tampered              — 양쪽 digest 존재 + 불일치(가중치 포이즌)
  ⑥ integrity_unverifiable— 승인 digest 존재하나 관측 digest 부재(검증 불가)
  ⑦ coverage_gap          — settings 로 기대되나 매니페스트 미선언(under-coverage 방지)

관측 인벤토리는 **신뢰 설정/선언**에서만 온다(untrusted alert 비구동).
정적 posture 라 호출자가 1회 계산·캐시(per-alert 재계산 금지). SBOM 미러.

Spec: docs/superpowers/specs/2026-07-09-aibom-model-provenance-design.md
"""

from __future__ import annotations

from pathlib import Path

from core.models import AibomComponent, AibomFinding
from core.policy_loader import load_policy_mapping, require_list, require_mapping
from core.settings import Settings

_APPROVED_POLICY = Path(__file__).resolve().parent / "policy" / "approved-aibom.yaml"
_MANIFEST_POLICY = Path(__file__).resolve().parent / "policy" / "ai-components.yaml"

# 부동(비고정) 버전 토큰 — 공급망 드리프트 위험.
_MUTABLE_TAGS = frozenset({"", "latest", "main", "stable", "dev", "edge"})


def _is_unpinned(version: str) -> bool:
    """버전이 비고정(부동 태그)인지 판정한다."""
    v = version.strip().lower()
    if v in _MUTABLE_TAGS:
        return True
    # "name:latest" 형태 태그 접미.
    return v.endswith(":latest") or v.endswith(":main") or v.endswith(":stable")


class ApprovedAibom:
    """approved-aibom.yaml 로더 — 승인 컴포넌트 version/digest/source/pinned 기준."""

    def __init__(self, components: dict[str, dict[str, str]]) -> None:
        self._components = components

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> ApprovedAibom:
        """승인 AIBOM YAML 을 적재한다(공유 로더로 graceful).

        Args:
            path: 정책 경로. 생략 시 기본 approved-aibom.yaml.

        Returns:
            로드된 ApprovedAibom.

        Raises:
            PolicyError: 파일 부재/파싱 실패/구조 불일치 시.
        """
        raw = load_policy_mapping(path, _APPROVED_POLICY, label="승인 AIBOM")
        components: dict[str, dict[str, str]] = {}
        for name, cell in require_mapping(
            raw.get("components"), label="AIBOM components"
        ).items():
            if isinstance(cell, dict):
                components[str(name)] = {
                    "version": str(cell.get("version", "")),
                    "digest": str(cell.get("digest", "")),
                    "source": str(cell.get("source", "")),
                }
        return cls(components)

    def approved(self, name: str) -> dict[str, str] | None:
        """컴포넌트 승인 항목을 반환한다(미승인이면 None)."""
        return self._components.get(name)


class AibomInventory:
    """관측 인벤토리 로더 — 선언 매니페스트(ai-components.yaml) 기반."""

    @staticmethod
    def from_manifest(path: str | Path | None = None) -> list[AibomComponent]:
        """AI 컴포넌트 매니페스트를 적재한다(공유 로더로 graceful).

        Args:
            path: 매니페스트 경로. 생략 시 기본 ai-components.yaml.

        Returns:
            선언된 AI 컴포넌트 목록.

        Raises:
            PolicyError: 파일 부재/파싱 실패/구조 불일치 시.
        """
        raw = load_policy_mapping(
            path, _MANIFEST_POLICY, label="AI 컴포넌트 매니페스트"
        )
        out: list[AibomComponent] = []
        for item in require_list(raw.get("components"), label="AIBOM 매니페스트"):
            if isinstance(item, dict):
                out.append(
                    AibomComponent(
                        name=str(item.get("name", "")),
                        component_type=str(item.get("type", "")),
                        version=str(item.get("version", "")),
                        digest=str(item.get("digest", "")),
                        source=str(item.get("source", "")),
                    )
                )
        return out


def expected_component_types(settings: Settings) -> set[str]:
    """settings 로부터 *반드시 선언돼야 할* AI 컴포넌트 유형을 도출한다.

    매니페스트가 이 유형을 누락하면 coverage_gap — silent under-coverage 방지(H1).

    Args:
        settings: 플랫폼 설정.

    Returns:
        기대 유형 집합. chat_llm 항상, 활성 서브시스템(ragas/graphrag/ragflow)별 가산.
    """
    expected = {"chat_llm"}
    if getattr(settings, "ragas_enabled", False):
        expected.add("ragas")
    if getattr(settings, "graph_rag_enabled", False):
        expected.add("graphrag")
    if getattr(settings, "ragflow_base_url", ""):
        # RAGFlow 검색기 활성 → 검색 백엔드 + 임베딩 모델 선언 기대.
        expected.add("ragflow")
        expected.add("embedding")
    if getattr(settings, "ragflow_dataset_id", "") or getattr(
        settings, "ragflow_exp_dataset_id", ""
    ):
        # RAG corpus(dataset) 활성 → poisoning 공급망 거버넌스 대상.
        expected.add("dataset")
    return expected


def settings_datasets(settings: Settings) -> list[AibomComponent]:
    """실행 중 RAG corpus(dataset) 를 관측 컴포넌트로 산출한다(실행값 관측).

    ragflow_dataset_id(검색 KB)·ragflow_exp_dataset_id(경험메모리)를 dataset 으로 —
    선언 매니페스트가 아닌 *실제 설정값*이라 shadow corpus 를 정확히 잡는다.

    Args:
        settings: 플랫폼 설정.

    Returns:
        설정된 dataset 컴포넌트 목록(미설정 시 빈 목록).
    """
    src = str(getattr(settings, "ragflow_base_url", "") or "ragflow")
    out: list[AibomComponent] = []
    for attr in ("ragflow_dataset_id", "ragflow_exp_dataset_id"):
        did = str(getattr(settings, attr, "") or "")
        if did:
            out.append(
                AibomComponent(
                    name=did, component_type="dataset", version=did, source=src
                )
            )
    return out


class AIBOMVerifier:
    """AIBOM 거버넌스 검증기 — 미등록/미신뢰소스/비고정/버전/무결성/coverage.

    Args:
        approved: 승인 AIBOM 기준(컴포넌트별 승인 source 포함).
    """

    def __init__(self, approved: ApprovedAibom) -> None:
        self._approved = approved

    def verify(
        self,
        components: list[AibomComponent],
        expected_types: set[str] | None = None,
    ) -> list[AibomFinding]:
        """선언 컴포넌트를 승인목록/소스/pinned/버전/digest 로 검증한다(동기·결정론).

        Args:
            components: 선언 AI 컴포넌트(매니페스트 산).
            expected_types: 반드시 존재해야 할 유형(미커버 → coverage_gap).

        Returns:
            거버넌스 위험 목록(정상은 미포함).
        """
        findings: list[AibomFinding] = []
        for comp in components:
            findings.extend(self._verify_one(comp))
        findings.extend(self._coverage_gaps(components, expected_types or set()))
        return findings

    def _verify_one(self, comp: AibomComponent) -> list[AibomFinding]:
        """단일 컴포넌트 검증(unregistered stop → source/pinned/version/digest)."""
        entry = self._approved.approved(comp.name)
        if entry is None:
            return [
                AibomFinding(
                    component=comp.name,
                    component_type=comp.component_type,
                    issue="unregistered",
                    detail=f"승인 AIBOM 미등록 AI 컴포넌트({comp.component_type})",
                )
            ]
        out: list[AibomFinding] = []
        if entry["source"] and comp.source != entry["source"]:
            out.append(
                AibomFinding(
                    component=comp.name,
                    component_type=comp.component_type,
                    issue="untrusted_source",
                    detail=(
                        f"소스 불일치 — 선언 {comp.source or '(없음)'} != "
                        f"승인 {entry['source']}"
                    ),
                )
            )
        if _is_unpinned(comp.version):
            out.append(
                AibomFinding(
                    component=comp.name,
                    component_type=comp.component_type,
                    issue="unpinned",
                    detail=f"비고정 버전({comp.version or '(빈값)'}) — 공급망 드리프트",
                )
            )
        if entry["version"] and comp.version != entry["version"]:
            out.append(
                AibomFinding(
                    component=comp.name,
                    component_type=comp.component_type,
                    issue="version_mismatch",
                    detail=(
                        f"버전 불일치 — 선언 {comp.version} != 승인 {entry['version']}"
                    ),
                )
            )
        out.extend(self._verify_digest(comp, entry))
        return out

    @staticmethod
    def _verify_digest(
        comp: AibomComponent, entry: dict[str, str]
    ) -> list[AibomFinding]:
        """무결성 — 양쪽 digest 불일치=tampered, 승인만 존재=integrity_unverifiable."""
        if not entry["digest"]:
            return []
        if not comp.digest:
            return [
                AibomFinding(
                    component=comp.name,
                    component_type=comp.component_type,
                    issue="integrity_unverifiable",
                    detail="관측 digest 부재 — 무결성 검증 불가",
                )
            ]
        if comp.digest != entry["digest"]:
            return [
                AibomFinding(
                    component=comp.name,
                    component_type=comp.component_type,
                    issue="tampered",
                    detail=(
                        f"digest 불일치 — 선언 {comp.digest} != 승인 {entry['digest']}"
                    ),
                )
            ]
        return []

    @staticmethod
    def _coverage_gaps(
        components: list[AibomComponent], expected_types: set[str]
    ) -> list[AibomFinding]:
        """기대 유형 중 매니페스트에 미선언된 것을 coverage_gap 으로 판정한다."""
        declared = {c.component_type for c in components}
        return [
            AibomFinding(
                component=t,
                component_type=t,
                issue="coverage_gap",
                detail=f"기대 AI 컴포넌트({t}) 미선언 — AIBOM 커버리지 공백",
            )
            for t in sorted(expected_types - declared)
        ]
