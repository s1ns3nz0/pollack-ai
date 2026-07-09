# 의미적 상관 엣지 — AlertCorrelator 정확도 강화 (design)

**날짜**: 2026-07-09
**작성**: 황준식 (analysis lane)
**상태**: design (Codex 교차검증 대기)

## 1. 목적 / intent

`AlertCorrelator`(인제스트 상관기)는 슬라이딩 윈도우 내 **볼륨(storm)·자산개수
(multi_axis)** 만으로 상관 → 무관한 alert 도 같은 창에 있으면 묶이고, **의미적으로
연결된** alert(공유 IOC·자산 의존)이 창을 벗어나면 못 묶는다. 공유-IOC 상관(classic
SIEM)은 완전 부재. 이 기능이 **의미적 상관 엣지**를 추가해 볼륨 클러스터링을 실제
상관 그래프로 격상한다.

## 2. 결정된 설계 (grill 확정)

| 포크 | 결정 |
|---|---|
| 발화 | **가산 신규 `correlated_cluster` 패턴** — 엣지 그래프 연결요소 ≥ cluster_min. 기존 storm/multi_axis 불변 |
| 엣지 | **공유 IOC**(해시/IP, 산열) + **depends_on**(asset 의존, KeyTerrainMap) |
| 트러스트 | escalate-only + IOC shape 산열 + cluster_min; depends_on 은 정책그래프(포이즌 저항) |
| 출력 | S9 재사용 + `pattern="correlated_cluster"`; 전부 core/correlation.py; hotpath/계약 변경 0 |

## 3. 변경 상세 (전부 `core/correlation.py` + settings)

### 3.1 AlertCorrelator
- 생성자에 `terrain: KeyTerrainMap | None = None`(depends_on 엣지용, None 이면 IOC
  엣지만), `cluster_min: int`, `max_alerts: int`(윈도우 하드 상한).
- **윈도우 하드 상한(Codex High — DoS 방지)**: 기존은 시간창 age eviction 만 →
  위조 고속 스트림이 300초 내 N 무한 증가 → O(N²) 페어 폭발. `max_alerts` 로 윈도우
  개수도 캡(초과 시 가장 오래된 것부터 popleft). 저장·compute bounded.
- **IOC 역색인(Codex High)**: 공유-IOC 엣지는 페어와이즈 O(N²) 대신 **IOC→alert_id
  역색인**으로 구성(O(N·k), k=alert당 IOC 수). 같은 IOC 버킷 내 alert 들만 연결.
- `observe(alert, now)`: 윈도우 갱신(age + max_alerts 캡) 후 **기존 storm/multi_axis
  에 더해** 클러스터 판정:
  1. **엣지 그래프**(노드=alert.id):
     - **공유 IOC 엣지**: 산열된 공통 IOC(역색인) 보유 alert 쌍 연결. IOC 는 shape
       검증(md5/sha1/sha256·공개 IP·도메인만 — `IocEgressFilter` 규칙 재사용, 불정·
       사설·내부지표 제외).
     - **depends_on 엣지**: A.asset_id ↔ B.asset_id 의존(`terrain` 조회). 등록 자산만
       엣지(위조 asset_id 는 엣지 0 — 포이즌 저항).
  2. **연결요소**(union-find). 크기 ≥ cluster_min **이고 서로 다른 자산 ≥ 2**(단일자산
     반복 배제)인 요소 있으면 `correlated_cluster` 확정.
- **발화 상태머신(Codex Medium — 정밀 명세)**: 단일 `_fired` bool 대신 **패턴별
  arm/disarm**. `_fired: dict[str, bool]`(pattern→발화됨). observe 는 우선순위
  (`correlated_cluster` > `multi_axis` > `alert_storm`) 순회하며 **탐지됐고 아직
  미발화**인 **최고 우선순위 1건** 반환. 각 패턴은 자기 조건이 False 로 떨어지면
  재무장(disarm). → 발화된 cluster 가 storm/multi_axis 를 굶기지 않음(각자 독립
  arm), 동일 군집 중복발화 없음(fired 유지), observe 는 여전히 최대 1건 반환.

### 3.2 CorrelatedIncident / to_aggregate_alert
- `CorrelatedIncident.pattern` 값에 `"correlated_cluster"` 추가. 필드 재사용
  (member_alert_ids/member_scenarios/distinct_assets). 엣지 근거용 `edge_kinds:
  list[str]`(예 ["shared_ioc","dependency"]) 추가(append-only).
- `to_aggregate_alert`: pattern 이 correlated_cluster 면 signals 에 "의미상관: 공유
  IOC/의존엣지로 N자산 M경보 연결" + baseline HIGH + lateral_correlation=True(다축
  조율과 동급). 기존 집약 시나리오 id(`UAV-SWARM-SATURATION-009`, correlation.py
  하드코딩) 재사용 — bas-scenarios 계약 미변경.
- **네이밍 주의(Codex Medium)**: 이 id 는 bas-scenarios 카탈로그와 **미정렬**(카탈로그
  는 S8-SWARM-SATURATION / S9=SATCOM disable). 단 집약 alert 은 **합성 내부 산출물**
  (카탈로그 시나리오 아님)이라 계약 미저촉. id 불일치는 correlation.py 의 **선재**
  이슈(이 PR 미도입) → 계약 파일 안 건드림. 카탈로그 정렬은 후속(detection 조율).

### 3.3 hotpath / graph
- **변경 없음**. `observe()` 가 correlated_cluster incident 를 반환하면 기존
  `_process_aggregate` 재투입 경로가 그대로 처리(correlation PR#67 배선 재사용).

### 3.4 settings
- `correlation_cluster_min: int = 3`(gt 0 — 연결요소 최소 크기).
- `correlation_window_max_alerts: int = 512`(gt 0 — 윈도우 하드 상한, DoS 방지).
- hotpath `_get_correlator` 가 `terrain=KeyTerrainMap.from_yaml()`(실패 시 None →
  IOC 엣지만) + `cluster_min` + `max_alerts` 주입.

## 4. 트러스트 / 포이즈닝
- **depends_on 엣지**: 정책그래프(asset-tiers) 기반 — 위조 asset_id 는 등록 자산이
  아니면 엣지 0(포이즌 저항). 실 등록 자산 사칭은 escalate-only.
- **공유-IOC 엣지**: wire IOC(공격자 제어) — 공통 IOC 주입으로 가짜 클러스터 가능.
  단 **상관된 alert 는 상관되는 게 맞음**(tautology) + escalate-only(과클러스터=surface,
  은폐 아님) + IOC **shape 산열**(불정지표 엣지 불가) + **cluster_min**(미세 클러스터
  억제). 위조 → 과-surface(alert fatigue), 억제/자율행동 아님.
- **재투입 S9**: correlation PR#67 트러스트 서사 동일 — 가설, escalate-only, 권고전용,
  env-verdict 자동보장 주장 안 함. observe 는 inbound 만(집약 재관측 없음).
- **perf/DoS(Codex High 반영)**: 윈도우는 시간창 + **max_alerts 하드 상한** 이중
  bound → 위조 고속 스트림도 N ≤ max_alerts. 공유-IOC 엣지는 **IOC 역색인**(O(N·k))
  으로 O(N²) 페어 폭발 회피. depends_on 엣지도 자산별 그룹 조회. compute·메모리 상한.

## 5. 테스트 (`tests/__tests__/test_correlation.py` 확장)
- `test_shared_ioc_forms_cluster`: 공통 IOC + 2자산 ≥ cluster_min → correlated_cluster.
- `test_dependency_edge_forms_cluster`: A depends_on B(등록) → 엣지 → 클러스터.
- `test_forged_asset_no_dependency_edge`: 미등록 asset_id → depends_on 엣지 0.
- `test_malformed_ioc_no_edge`: 불정 IOC(사설IP/쓰레기) → 공유엣지 안 생김.
- `test_single_asset_repeat_no_cluster`: 동일 자산 반복 → distinct<2 → 클러스터 아님.
- `test_cluster_min_threshold`: cluster_min 미만 연결요소 → 미발화.
- `test_precedence_cluster_over_storm`: 클러스터+볼륨 동시 → correlated_cluster 반환.
- `test_no_terrain_ioc_only`: terrain=None → depends_on 엣지 없이 IOC 엣지만.
- `test_window_max_alerts_cap`(Codex High): 위조 고속 스트림 → 윈도우 ≤ max_alerts.
- `test_cluster_dedup_no_refire`(Codex Medium): 동일 군집 성장해도 재발화 없음.
- `test_cluster_fired_does_not_starve_storm`(Codex Medium): cluster 발화 후에도 별개
  storm 조건 충족 시 storm 발화 가능(패턴별 arm).
- 기존 storm/multi_axis 테스트 회귀(가산이라 불변).

## 6. 미결 / 후속
- IOC 역색인 최적화는 윈도우 大 시(현 storm_count 소규모라 O(N²) 수용) — 후속.
- 엣지 종류 확장(공유 actor_id·kill-chain 단계) — 후속.
- cluster_min 초기값 튜닝은 운용 피드백.
- 게이트: 스펙→Codex 설계리뷰→반영→구현→black/ruff/mypy/pytest→clean-worktree→
  Codex diff 리뷰→커밋/PR/머지.
