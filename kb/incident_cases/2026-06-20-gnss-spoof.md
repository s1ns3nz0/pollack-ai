# 인시던트 2026-06-20 — 안흥 GNSS 스푸핑 (정탐)

S1 룰(EKF 잔차 급증) 알람. UAV-ANHEUNG-07 on-station 중 PosHorizVariance 0.06,
VelocityVariance 0.05 동시 급등(정상 ~0.007의 7배). Red team 주입 확인 → 정탐.

대응: RTB 트리거, 운용자 통보. 교훈: 안흥 RF 간섭 구역은 GNSS_Exception_List 의
ZoneId 예외(위경도 박스)로 분리해 정상 간섭과 공격을 구분.
