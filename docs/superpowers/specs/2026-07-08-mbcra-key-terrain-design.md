# MBCRA + 사이버 핵심지형(METT-TC / JP 3-12 KT-C)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-08 |
| 상태 | Approved (구현 완료, Codex diff 검증 대기) |
| 작성자 | s1ns3nz0 |
| 관련 ADR | `docs/adr/0002-autonomous-self-improving-blue-soc.md` |
| 근거 | DoD MBCRA(임무기반 사이버 위험평가), JP 3-12 Key Terrain in Cyberspace, Army METT-TC. hackathon 선언 차별점(`docs/hackathon/`) |
| 후속 | ② CPCON 태세 사다리(외부 태세 승수), Troops=coverage-gap 정밀화 |

## 1. 배경 & 동기

팀 선언 차별점(meeting-notes / B-uav-domain)인데 코드 부재였던 3개(METT-TC·cATO·MBCRA)
중 첫 조각. asset-tiers.yaml 은 **정적 tier weight** 일 뿐 — "이 자산이 **어느 임무단계의
핵심지형**인가, 무엇이 이것에 의존하는가" 를 모른다. severity·COA·degradation·recovery 가
전부 asset_tier 를 소비하므로, 자산 criticality 를 **임무관련지형(MRT-C)** 으로 승격하면
전 모듈이 임무맥락을 인지한다.

## 2. 목표 / 비목표
### 목표
- asset-tiers.yaml 에 `key_terrain`(핵심지형 임무단계) + `depends_on`(손상 전파 그래프).
- 읽기전용 `key_terrain` enrich(현 단계 핵심지형 접촉 → severity +1) — decoy_hit 동형.
- **METT-TC 융합 MissionRiskAssessor** → 임무위험 점수(정적 tier 초월).
- report 노출(`SOCReport.mission_risk`). 전 과정 결정론·정책구동.
### 비목표
- severity 코어 로직 변경(dynamics 룰 1개 추가만).
- 외부 태세(CPCON) 승수 — ②의 몫.
- Troops=실시간 coverage-gap 정밀화(현재 tier weight 대리).

## 3. 설계
| 요소 | 구현 |
|---|---|
| 지형 맵 | `core/terrain.py::KeyTerrainMap` — is_key_terrain(asset,phase)·dependents(역방향)·tier_weight |
| enrich | `KeyTerrainDetector.enrich` → `alert.key_terrain`. `_triage_with_match` 4번째 enricher |
| severity | `severity-policy.yaml` dynamics `key_terrain: +1` + `severity.py` 분기 |
| MBCRA | `MissionRiskAssessor.assess` — METT-TC 6요소 융합 → `MissionRisk`(score/factors/rationale) |
| 노출 | `ReportAgent` → `SOCReport.mission_risk` |

### METT-TC 융합 (결정론, alert 기존 신호만)
- **M**ission: mission_phase / **E**nemy: kill_chain_advanced(+2) / **T**errain: 핵심지형(+2)+의존자산수(≤3)
- **T**roops: asset_tier weight / **T**ime: dwelling≥30(+1) / **C**ivil: 지리 컨텍스트(+1)

## 4. 트러스트
- enrich 는 읽기전용 — 정적 정책(asset-tiers.yaml) 기준 판정. alert.asset_id/mission_phase 는
  신뢰 시나리오/sim_bridge 산. 새 외부 조회 없음. severity 격상권은 정책 엔진.

## 5. 테스트 (`tests/__tests__/test_terrain.py`)
- 핵심지형 단계 판정·의존 역방향그래프·빈정책 graceful.
- enrich hit/miss·지원자산 비핵심.
- MissionRisk: 핵심지형 고득점·METT-TC factors 융합·근거.
- 회귀: S8 onboard(PAYLOAD_EOIR/on-station=핵심지형) → +1 격상(HIGH).

## 6. 롤아웃
1. asset-tiers.yaml 확장 + Alert.key_terrain + MissionRisk 모델.
2. core/terrain.py + severity 룰 + graph enrich/assessor 배선 + report.
3. Codex diff 검증 → black/ruff/mypy/pytest(595).
4. 브랜치 `feat/mbcra-key-terrain`, 커밋 `feat(mbcra): 사이버 핵심지형(KT-C) + METT-TC 임무위험`.
