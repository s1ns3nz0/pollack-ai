# IEEE UAV Attack Dataset: GPS Spoofing/Jamming 시그니처 (실제 로그 분석)

원천: `raw_data/uav_attack_dataset/` (IEEE DataPort DOI 10.21227/00dg-0d12,
Whelan et al.). PX4 비행 로그(.ulg + uORB 토픽별 CSV)를 시나리오별로 분석 (2026-06).

## 라이브 비행 시나리오 (vehicle_gps_position 토픽 핵심 신호)

각 시나리오 1개 비행, 토픽 CSV 약 60개.

### Benign Flight (정상)
- `satellites_used`: min=11.0, mean=12.125, max=13.0 (n=248)
- `fix_type`: min=3.0, mean=3.0, max=3.0 (n=248)
- `jamming_indicator`: min=8.0, mean=26.0, max=67.0 (n=248)
- `noise_per_ms`: min=96.0, mean=100.319, max=114.0 (n=248)
- `eph`: min=1.739, mean=2.16, max=3.725 (n=248)
- `epv`: min=2.816, mean=3.272, max=5.292 (n=248)
- `hdop`: min=0.77, mean=0.772, max=0.94 (n=248)
- `vdop`: min=1.14, mean=1.317, max=1.68 (n=248)

### GPS Jamming (재밍)
- `satellites_used`: min=4.0, mean=13.616, max=14.0 (n=224)
- `fix_type`: min=0.0, mean=2.987, max=3.0 (n=224)
- `jamming_indicator`: min=11.0, mean=27.156, max=60.0 (n=224)
- `noise_per_ms`: min=99.0, mean=112.54, max=171.0 (n=224)
- `eph`: min=1.049, mean=2.299, max=5.741 (n=224)
- `epv`: min=1.698, mean=3.613, max=9.422 (n=224)
- `hdop`: min=0.71, mean=0.74, max=4.16 (n=224)
- `vdop`: min=1.21, mean=1.364, max=30.7 (n=224)

### GPS Spoofing (스푸핑)
- `satellites_used`: min=5.0, mean=10.732, max=11.0 (n=138)
- `fix_type`: min=3.0, mean=3.0, max=3.0 (n=138)
- `jamming_indicator`: min=10.0, mean=26.819, max=66.0 (n=138)
- `noise_per_ms`: min=100.0, mean=108.297, max=140.0 (n=138)
- `eph`: min=1.574, mean=2.527, max=6.296 (n=138)
- `epv`: min=2.337, mean=3.282, max=7.508 (n=138)
- `hdop`: min=0.84, mean=0.883, max=2.99 (n=138)
- `vdop`: min=1.3, mean=1.333, max=2.39 (n=138)

## 탐지 관점 해석

- **재밍**: `jamming_indicator` 상승, `noise_per_ms` 증가, `satellites_used` 급감,
  `fix_type` 하락 — 위성 수신 자체가 막히는 신호.
- **스푸핑**: `satellites_used`/`fix_type`는 정상처럼 유지되나 위치/속도(eph, epv,
  s_variance)와 추정기 innovation이 비정상 — "정상처럼 보이는 가짜 위치".
- 두 공격 모두 GCS 통신 링크는 정상일 수 있어, 네트워크 장애와 구분이 중요
  (incident_case_gps_spoofing_gcs_normal 참조).

## 시뮬레이션 시나리오 (기체별)

- 기체: PX4-H480-SITL, PX4-PLANE-SITL, PX4-QUAD-HITL, PX4-QUAD-SITL, PX4-TAIL-SITL, PX4-VTOL-SITL
- SITL/HITL 조합으로 동일 공격을 다양한 기체에서 재현.

## SOC 활용 / 로컬 경로

- PX4 추정기 신호(estimator_innovation, estimator_status)와 GPS 토픽을 결합하면
  스푸핑/재밍을 구분하는 탐지 규칙·모델을 만들 수 있다.
- 경로: `raw_data/uav_attack_dataset/extracted/Live GPS Spoofing and Jamming/<시나리오>/`
