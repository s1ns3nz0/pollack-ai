# Incident Case: GPS 재밍과 스푸핑 구분 (IEEE UAV Attack 실측 기반)

근거 데이터: IEEE UAV Attack Dataset (DOI 10.21227/00dg-0d12)의 라이브 비행 로그
실측 통계. `ieee_uav_attack_gps_signatures.md` 참조.

## 입력 신호 (PX4 vehicle_gps_position 토픽)

- satellites_used, fix_type, jamming_indicator, noise_per_ms, eph, epv, hdop, vdop

## 판별 규칙

### GPS 재밍 (Jamming)
- satellites_used 급감 (정상 11~13 → 재밍 시 최소 4)
- noise_per_ms 상승 (정상 ~114 상한 → 재밍 시 171)
- fix_type 하락 (3 → 0까지 떨어짐, 측위 상실)
- vdop/epv 급등 (vdop 정상 ~1.7 → 재밍 시 30.7), 측위 정밀도 붕괴
- 해석: 위성 신호 수신 자체가 막힘. 가용성 상실(Loss of Availability).

### GPS 스푸핑 (Spoofing)
- satellites_used 정상 유지 (5~11), fix_type 3 유지 — 겉보기 정상
- 그러나 eph 상승 (정상 상한 3.7 → 스푸핑 6.3), hdop 상승 (0.94 → 2.99)
- 위치/속도가 그럴듯하지만 추정기(estimator_innovation)와 불일치
- 해석: "정상처럼 보이는 가짜 위치". 무결성 상실(Loss of Control/View).

## 대응 (IEC 62443 + MITRE)

- 두 공격 모두 GCS 통신 링크는 정상일 수 있음 → 네트워크 장애와 구분.
- MITRE ATT&CK for ICS: Wireless Compromise (T0860).
- failsafe(loiter/RTL/manual) 정책 확인, GPS/IMU/autopilot/GCS 로그 보존.
- 영향받은 UAV-GCS conduit 격리 검토, 동일 운용 zone 내 타 자산 점검.

## 관련 문서

- `ieee_uav_attack_gps_signatures.md`
- `aissou_gps_spoofing_feature_summary.md`
- `incident_case_gps_spoofing_gcs_normal.md`
- `iec62443_uav_response_templates.md`
