# Knowledge Base 매니페스트 (데이터 구성도)

RAGFlow KB(`uav_soc_rag`)에 적재되는 원천 문서. 본문은 .gitignore로 제외하고 이 매니페스트만 커밋.
정본: `/gpfs/home/jm00055/pollack-ai/projects/uav_soc_rag_poc/ragflow_ingest/`

## 구성도 (한 KB + 범주 메타데이터)

문서별 메타 `{category, source, scenarios}`. 검색 시 `category`로 범주 한정 가능.

| category | 개수 | source |
|---|---:|---|
| `incident_cases` | 13 | authored |
| `attack_techniques` | 99 | MITRE ATT&CK for ICS |
| `standards` | 3 | IEC 62443 |
| `datasets` | 11 | Aissou/IEEE/NetComm/LIG도메인보고서 |

## 공격 시나리오(S1~S11) ↔ incident_case 커버리지

| 시나리오 | incident_case |
|---|---|
| S1 GPS 스푸핑 | gps_jamming_vs_spoofing, gps_spoofing_gcs_normal |
| S2 C2 하이재킹 | c2_hijack_command_injection, wifi_deauth_network_primary |
| S3 SATCOM MITM | satcom_mitm_integrity |
| S4 펌웨어/공급망 | firmware_supplychain_tamper |
| S5 RAG 포이즈닝 | rag_poisoning_severity_downgrade |
| S6 GCS 침해 | gcs_compromise_lateral |
| S7 UGV 원격조종 탈취 | ugv_teleop_hijack |
| S8 온보드AI 적대공격 | onboard_ai_adversarial_evade |
| S9 군집 포화 | swarm_saturation_alertstorm |
| S10 SATCOM 무력화 | satcom_terminal_takedown |
| S11 모바일 GCS 침해 | mobile_gcs_compromise |

## incident_cases (13) — source: authored

- `incident_case_c2_hijack_command_injection.md` ·scenario S2
- `incident_case_firmware_supplychain_tamper.md` ·scenario S4
- `incident_case_gcs_compromise_lateral.md` ·scenario S6
- `incident_case_gps_jamming_vs_spoofing.md` ·scenario S1
- `incident_case_gps_spoofing_gcs_normal.md` ·scenario S1
- `incident_case_mobile_gcs_compromise.md` ·scenario S11
- `incident_case_onboard_ai_adversarial_evade.md` ·scenario S8
- `incident_case_rag_poisoning_severity_downgrade.md` ·scenario S5
- `incident_case_satcom_mitm_integrity.md` ·scenario S3
- `incident_case_satcom_terminal_takedown.md` ·scenario S10
- `incident_case_swarm_saturation_alertstorm.md` ·scenario S9
- `incident_case_ugv_teleop_hijack.md` ·scenario S7
- `incident_case_wifi_deauth_network_primary.md` ·scenario S2

## attack_techniques (99) — source: MITRE ATT&CK for ICS

(98 기법 + 요약. 목록 생략)

## standards (3) — source: IEC 62443

- `gca_leveraging_isa62443_risk_assessment.pdf`
- `isa_iec_62443_overview.html`
- `iec62443_uav_response_templates.md`

## datasets (11) — source: Aissou / IEEE / UAV NetworkCommunication / LIG 도메인 보고서

- `aissou_gps_spoofing_dataset.md`
- `aissou_gps_spoofing_feature_summary.md`
- `dataset_card_aissou_gps_spoofing.md`
- `dataset_card_uav_attack_dataset.md`
- `ieee_uav_attack_gps_signatures.md`
- `lig_drone_catalog_report.pdf`
- `uav_attack_dataset_metadata.md`
- `uav_networkcommunication_feature_summary.md`
- `uav_networkcommunication_file_manifest.md`
- `uav_networkcommunication_readme.md`
- `uav_ugv_satcom_report.pdf`

