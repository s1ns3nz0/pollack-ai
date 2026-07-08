# 정책로더 DRY — 공유 헬퍼로 graceful-degrade 버그류 근절

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-08 |
| 상태 | Approved (구현 완료, Codex diff 검증 대기) |
| 작성자 | s1ns3nz0 |
| 근거 | 세션 내내 Codex 가 매 기능 로더에서 같은 구멍 반복 지적(MBCRA/CPCON/cATO 등) |
| base | `feat/wire-analysis-engines`(스택 최상단) |

## 1. 배경 & 동기
15+ 개 `from_yaml` 로더가 동일 패턴(파일읽기→safe_load→최상위 dict 검증→항목
model_validate)을 반복했다. 매 신규 로더마다 Codex 가 **같은 취약점**을 지적:
`model_validate`/구조검증이 try 밖이면 `ValidationError`/`TypeError` 가 graph 의
`except SOCPlatformError` 를 우회해 **파이프라인 크래시**. blacklist 식 개별 대응은
반복·누락 위험. **공유 헬퍼**로 구조적 근절.

## 2. 설계 — `core/policy_loader.py`
| 헬퍼 | 역할 |
|---|---|
| `load_policy_mapping(path, default, label, error_cls)` | 읽기·파싱·최상위 dict 검증 → 실패 전부 error_cls |
| `require_list(value, label, error_cls)` | None→[], 비-리스트→error_cls |
| `require_mapping(value, label, error_cls)` | None→{}, 비-dict→error_cls |
| `validate_models(items, model, label, error_cls)` | **model_validate 를 try 안에서** — ValidationError→error_cls(구멍 근절) |

- `error_cls` 기본 `PolicyError`, coverage 는 `CoverageDataError`(둘 다 SOCPlatformError 하위).

## 3. 마이그레이션 (11 로더)
campaign·bas·monitoring(model_validate 루프 — 잠재 크래시 → validate_models 로 봉인),
coa·degradation·engage·recovery·sbom·stride·terrain·coverage(read 보일러플레이트 → load_policy_mapping).
deception 은 파일별 옵션 로직이 달라 기존 유지(이미 Codex 검증 clean).

## 4. 효과
- 로더당 6~8줄 보일러플레이트 → 1~4줄.
- **신규 로더는 헬퍼만 쓰면 graceful-degrade 구조적 보장** — 반복 버그류 원천봉쇄.
- 타입 강화(dict[str,object] 반환)로 미가드 `.get()` 접근 4곳이 표면화 → require_list/mapping 으로 해소(잠재 버그 제거).

## 5. 테스트 (`tests/__tests__/test_policy_loader.py`)
- 헬퍼 각각(로드·부재·비-dict·잘못된 yaml·custom error_cls·list/mapping 강제).
- validate_models 의미검증 실패→SOCPlatformError 하위(graph catch 보장).
- 마이그레이션 로더 기본 정책 정상 로드 + **잘못된 항목→PolicyError(크래시 아님) 실증**.

## 5.1 Codex diff 검증 반영
- 11 로더 전부 무행동변경 확인(예외타입·빈정책·skip-non-dict 보존).
- **Medium #1**: validate_models 가 ValidationError 만 잡던 걸 (ValidationError,TypeError,
  ValueError)로 확장 — pydantic v2 는 validator TypeError 를 안 감싸므로 완전 봉인.
- Low #2(COA defenses 엄격화)·#3(coverage archetype id str 강제)는 개선/무해 → 수용.

## 6. 롤아웃
1. core/policy_loader.py + 11 로더 마이그레이션.
2. Codex diff 검증 → black/ruff/mypy/pytest(669).
3. 브랜치 `feat/policy-loader-dry`, 커밋 `refactor(policy): from_yaml 공유 헬퍼로 graceful-degrade 버그류 근절`.
