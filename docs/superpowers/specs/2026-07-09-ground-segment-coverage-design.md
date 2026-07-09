# 지상 세그먼트 방어 커버리지 — 구조적 사각(blind spot) 계량 + 계측 백로그

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-09 |
| 상태 | 설계(Codex 교차검증 대기) |
| 근거 | 팀 「UAV ATT&CK 매핑표」 §16 지상 세그먼트 공격면(S86~S99), MITRE ATT&CK Enterprise+ICS |
| 선행 | tools/coverage.py(항공 커버리지 권위), data/attack_coverage.yaml |

## 문제
UAV Sentinel 은 **기체(공중 세그먼트) 텔레메트리 평면(`UAV*_CL`)만** 감시한다. 팀 매핑표
§16 이 새로 추가한 **지상 세그먼트 14개 공격면(S86~S99)** — GCS 앱 · 컴패니언/ROS ·
데이터링크(모뎀/SATCOM/GDT) · 함대/클라우드 백엔드 — 은 전용 로그가 없어 **전부 탐지
불가(구조적 사각)**. 현재 `attack_coverage.yaml` 은 항공 매트릭스만 담아 이 사각을
계량하지 못한다. 항공 커버리지는 "범위내 100%"라 좋아 보이지만 **지상 세그먼트 blind
spot 은 보고서·KPI 어디에도 안 잡힌다** = 정직하지 않은 posture.

## 목표
지상 세그먼트 방어 커버리지를 **별도 스코프**로 계량한다. 결정론·읽기전용·외향 없음.

1. `data/ground_segment_coverage.yaml`(신규): 14개 surface(S86~S99) + remediation(필요
   로그원) + 예시 blind 킬체인(C19/C20). **항공 yaml 과 물리적 분리** — 항공 KPI 분모
   오염 불가.
2. `tools/coverage.py` 확장: `GroundSegmentCoverage` 클래스 + `ground_report()`.
   - `blind_spots()`: 탐지 불가 surface(현재 14/14 전부).
   - `instrumentation_backlog()`: remediation(로그원)→해소 가능 surface 수로 우선순위.
   - `new_techniques()`: 지상 surface 기법 중 **항공 CoverageMatrix 에 없는** 것 파생
     (T1203·T1195.002·T0857·T1565.001·T1557·T0855). 하드코딩 아님 — 교차대조 산출.
3. 정직성 불변식:
   - 지상 surface 는 **항공 `report()` 의 total/covered/pct 에 절대 안 섞임**(별 로더/별 파일).
   - surface 는 `covered_by: list[str]`(로그테이블/룰) 미보유 → blind. 실제 로그 평면이
     생겨 `covered_by` 채워질 때만 covered 로 전환(evidence-gate, zero_trust `_effective` 미러).
   - 현재 전부 blind → ground coverage 0/14. 과장 금지.

## 데이터 모델(surface 14개)
| S | segment | tactic | technique | remediation |
|---|---|---|---|---|
| S86 | gcs_app | Execution | T1203 | gcs_app_telemetry |
| S87 | gcs_app | Execution | T1059 | gcs_app_telemetry |
| S88 | gcs_app | InitialAccess | T1195.002 | gcs_update_integrity |
| S89 | gcs_app | Impact | T1565 | gcs_app_telemetry |
| S90 | companion_ros | InitialAccess | T1190 | ros_audit |
| S91 | companion_ros | Execution | T0855 | ros_audit |
| S92 | companion_ros | Impact | T0831 | ros_audit |
| S93 | datalink | Persistence | T0857 | datalink_fw_attest |
| S94 | datalink | Collection | T1557 | link_frame_integrity |
| S95 | datalink | InitialAccess | T1195 | time_source_integrity |
| S96 | fleet_cloud | InitialAccess | T1190 | fleet_api_audit |
| S97 | fleet_cloud | Impact | T1565.001 | pipeline_integrity |
| S98 | fleet_cloud | Collection | T1557 | stream_integrity |
| S99 | fleet_cloud | Impact | T1565 | fleet_api_audit |

remediation(필요 계측 로그원, backlog 우선순위 = 해소 surface 수):
- gcs_app_telemetry(3): GCS 앱 감사(파서 크래시·플러그인/QML 로드·config/로그 변조)
- ros_audit(3): 컴패니언 ROS/MAVROS 감사(마스터 접근·토픽 퍼블리시·setpoint)
- fleet_api_audit(2): 함대·C4I API 감사(인증·IDOR·주문 검증)
- gcs_update_integrity(1) · datalink_fw_attest(1) · link_frame_integrity(1) ·
  time_source_integrity(1) · pipeline_integrity(1) · stream_integrity(1)

blind 킬체인(예시·탐지 불가·campaign.py 미배선):
- C19: S86(GCS 악성미션)→S92(MAVROS 주입)→S99(C4I 위조명령)
- C20: S96(함대API)→S97(텔레메트리 오염)→S98(영상 하이재킹)

## 비목표
- 지상 로그 평면 실제 구현/적재(다른 레인·sim env). C19/C20 campaign 탐지 배선(텔레메트리
  없어 탐지 불가 — 정직하게 문서화만). SOCReport 배선(fast-follow 후보). 외향 액션.

## 트러스트
- 결정론·읽기전용. 항공/지상 분모 물리 분리. covered 전환은 covered_by(실 로그원) 있을 때만.
- 정책 실패 → CoverageDataError(graceful, 기존 로더 재사용).
