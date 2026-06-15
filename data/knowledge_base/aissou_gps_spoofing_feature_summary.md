# Aissou GPS Spoofing Dataset: Feature Summary (실제 데이터 분석)

원천: `raw_data/aissou_gps_spoofing/` (Mendeley z7dj3yyzt8 v3, sha256 검증 완료).
실제 xlsx 3개를 openpyxl로 파싱해 생성 (2026-06).

USRP를 GPS 수신기로 구성해 수집한 정품 GPS 신호에서 8개 병렬 채널의 acquisition/
tracking/navigation 단계 13개 피처를 추출하고, 단순/중간/정교 3종 GPS 스푸핑 공격을
시뮬레이션한 데이터셋이다.

## 파일/시트별 구조

### GPS_Authentic_Data_3D_8_Channels.xlsx — sheet `Sheet1`
- 데이터 행: 159,146
- 컬럼 수: 104
- 헤더 예시: PRN, Carrier_Doppler_hz
- 형태: 8개 병렬 채널 × acquisition/tracking/navigation 단계의 원시 피처 행렬 (정품 신호만). 라벨은 파일 단위(authentic vs authentic+simulated)로 구분되며, 개별 컬럼이 아니라 채널 블록 구조로 배치됨.

### GPS_Data_Simplified_2D_Feature_Map.xlsx — sheet `Sheet1`
- 데이터 행: 510,530
- 컬럼 수: 14
- 헤더 예시: PRN, DO, PD, RX, TOW, CP, EC, LC, PC, PIP, PQP, TCD, CN0, Output
- **라벨 분포(`Output` 컬럼: 0=정품, 1/2/3=스푸핑 3종):**
- `0`: 397825 (77.9%)
- `1`: 36458 (7.1%)
- `2`: 44232 (8.7%)
- `3`: 32015 (6.3%)

### GPS_Dataset_3D_8_Channels_Authentic_and_Simulated.xlsx — sheet `Sheet1`
- 데이터 행: 158,176
- 컬럼 수: 112
- 헤더 예시: PRN, Carrier_Doppler_hz
- 형태: 8개 병렬 채널 × acquisition/tracking/navigation 단계의 원시 피처 행렬 (정품 + 시뮬레이션 스푸핑 혼합). 라벨은 파일 단위(authentic vs authentic+simulated)로 구분되며, 개별 컬럼이 아니라 채널 블록 구조로 배치됨.


## SOC 활용

- 정품 vs 스푸핑 신호의 채널별 피처 차이를 학습해 GPS 스푸핑 탐지기를 만들 수 있다.
- 탐지 양성 → incident case `incident_case_gps_spoofing_gcs_normal` 패턴,
  MITRE ATT&CK for ICS Wireless Compromise(T0860)에 매핑.
- 로컬 경로: `raw_data/aissou_gps_spoofing/extracted/A DATASET .../*.xlsx`
