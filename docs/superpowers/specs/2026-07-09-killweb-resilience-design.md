# Mosaic / Kill Web — 단계별 커버리지 breadth 그래프 (결심우위 계층 PR3)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-09 |
| 상태 | 설계(Codex 교차검증 반영) |
| 근거 | Mosaic Warfare / Kill Web(viz 프레이밍) — 단계별 커버리지 breadth. **주의: 센서 독립성·SPOF 제거를 주장하지 않음(기법 수 ≠ 독립 센서)** |
| 선행 | tools/coverage.py(단계별 탐지수), ground_segment_coverage(구조적 사각), terrain |

## 목표 (Codex Critical 반영 — 정직한 재프레이밍)
선형 kill-chain 을 단계별 **커버리지 breadth** 관점으로 재조명 — 각 킬체인 단계(tactic)에
covered ATT&CK **기법이 몇 개**인가. **주의: 기법 수 ≠ 센서/로그원 독립성.** 두 covered
기법이 같은 로그원에 의존할 수 있어 진짜 탐지경로 중복(SPOF-free)을 증명하지 않는다.
따라서 "센서 하나 죽어도 대체" 단정 금지 — coverage breadth 로만 정직히 표현. "mosaic"
은 viz 프레이밍. 선형 chain 데이터모델 불변. 결정론·읽기전용·자문·정적 posture.

## 데이터 모델
`KillWebResilience`(core/models.py, SOCReport 필드 — 요약만, 전체 그래프는 별도 viz):
- `multi_technique_stages: list[str]` — covered 기법 ≥2 단계(breadth 넓음).
- `single_technique_stages: list[str]` — covered 기법 정확히 1(breadth 좁음 —
  독립 센서 여부는 미증명, 단일 커버 기법).
- `uncovered_stages: list[str]` — 현재 covered 0(기법 존재하나 미탐. planned 은 활성
  탐지로 안 셈).
- `empty_stages: list[str]` — 기법 0 단계(분모 제외).
- `blind_surface_count: int` — 지상 세그먼트 구조적 사각(센서 평면 부재).
- `coverage_breadth_ratio: float` — multi / 범위내 비어있지않은 단계.
- `degraded: bool` + `degraded_reason: str` — 정책 로드 실패 관측.
- `rationale: list[str]` — 근거·정직성 주석(기법수≠센서독립 명시).

`KillWebBuilder.to_cytoscape() → dict`(온디맨드 viz — 리포트 미임베드): tactic·technique
노드 + belongs 엣지(coverage matrix order 순, Cytoscape 표준 ioa_graph 동형).

## 산정 로직 (결정론)
`KillWebBuilder.build(matrix: CoverageMatrix, ground)`:
- **CoverageMatrix.tactics 직접 순회**(report().tactics 아님 — .order 필요, Codex High).
- pre-compromise 제외: **order ≤ 2**(Reconnaissance·ResourceDevelopment) — 정찰/자원개발.
  이 단계는 breadth 분모에서 뺌(stage-level, addressable_pct 와 동일 계산 아님 명시).
- 범위내 각 tactic: len(covered) 로 분류 — ≥2 multi, ==1 single, ==0 且 total>0
  uncovered, total==0 empty(분모 제외). (planned 은 covered 로 안 셈 — 활성 탐지 아님.)
- blind_surface_count = ground.blind(정책 실패 시 0).
- coverage_breadth_ratio = len(multi) / max(범위내 비어있지않은 단계 수, 1).
- rationale: single/uncovered 단계 + "기법 수 ≠ 독립 센서" 정직 주석.

## 트러스트
- 결정론·읽기전용·정적 posture(coverage/ground 정책 파생 — per-alert 아님).
- verdict/severity/CAT 불변. **과장 금지** — breadth 낮으면 낮다고, 센서 독립성 미증명
  명시. single_technique 를 "SPOF"로 단정하지 않음.
- coverage/ground 로드 실패 → graceful: 빈 목록 + degraded=True + reason(관측). 크래시 없음.

## 비목표
- 선형 chain/campaign/coverage 교체(불변). 자산 의존성 SPOF(terrain blast-radius —
  후속). 현재 actor 의 web 내 위치 오버레이(PR4 BLUF). 센서 단위 그래뉼러 매핑(데이터
  부재 — 단계 수준 근사).

## 배선
report_agent 로드 시 1회 build·캐시(정적) → SOCReport.kill_web_resilience. metric:
스크레이프 gauge soc_killweb_coverage_breadth_ratio + soc_killweb_single_technique_stage_count
(SPOF 라벨 아님 — 정직, ground gauge 동형).
