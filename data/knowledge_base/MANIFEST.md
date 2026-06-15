# Knowledge Base 매니페스트 (데이터 구성도)

RAGFlow KB(`uav_soc_rag`)에 적재되는 원천 문서. 본문은 .gitignore로 제외하고 이 매니페스트만 커밋.
정본: `/gpfs/home/jm00055/pollack-ai/projects/uav_soc_rag_poc/ragflow_ingest/`

## 구성도 (한 KB + 범주 메타데이터)

문서별 메타 `{category, source, scenarios}`. 검색 시 `category`로 범주 한정 가능.

| category | 개수 | source |
|---|---:|---|
| `incident_cases` | 8 | authored |
| `attack_techniques` | 99 | MITRE ATT&CK for ICS |
| `standards` | 3 | IEC 62443 |
| `datasets` | 11 | Aissou/IEEE/NetComm/LIG도메인보고서 |

## 공격 시나리오(S1~S6) ↔ incident_case 커버리지

| 시나리오 | incident_case |
|---|---|
| S1 GPS 스푸핑 | gps_spoofing_gcs_normal, gps_jamming_vs_spoofing |
| S2 C2 하이재킹 | c2_hijack_command_injection, wifi_deauth_network_primary |
| S3 SATCOM MITM | satcom_mitm_integrity |
| S4 펌웨어/공급망 | firmware_supplychain_tamper |
| S5 RAG 포이즈닝 | rag_poisoning_severity_downgrade |
| S6 GCS 침해 | gcs_compromise_lateral |

> project_meta(진행 메모)는 검색 노이즈라 KB에서 제외.

## incident_cases (8) — source: authored

- `incident_case_c2_hijack_command_injection.md`  ·scenario S2
- `incident_case_firmware_supplychain_tamper.md`  ·scenario S4
- `incident_case_gcs_compromise_lateral.md`  ·scenario S6
- `incident_case_gps_jamming_vs_spoofing.md`  ·scenario S1
- `incident_case_gps_spoofing_gcs_normal.md`  ·scenario S1
- `incident_case_rag_poisoning_severity_downgrade.md`  ·scenario S5
- `incident_case_satcom_mitm_integrity.md`  ·scenario S3
- `incident_case_wifi_deauth_network_primary.md`  ·scenario S2

## attack_techniques (99) — source: MITRE ATT&CK for ICS

- `activate_firmware_update_mode.md`
- `adversary_in_the_middle.md`
- `automated_collection.md`
- `autorun_image.md`
- `block_command_message.md`
- `block_communications.md`
- `block_operational_technology_message.md`
- `block_reporting_message.md`
- `block_serial_com.md`
- `broadcast_discovery.md`
- `brute_force_i_o.md`
- `change_credential.md`
- `change_operating_mode.md`
- `change_program_state.md`
- `command_line_interface.md`
- `command_message.md`
- `connection_proxy.md`
- `control_device_identification.md`
- `damage_to_property.md`
- `data_destruction.md`
- `data_from_information_repositories.md`
- `data_from_local_system.md`
- `data_historian_compromise.md`
- `default_credentials.md`
- `denial_of_control.md`
- `denial_of_service.md`
- `denial_of_view.md`
- `detect_operating_mode.md`
- `device_restart_shutdown.md`
- `download_all.md`
- `drive_by_compromise.md`
- `engineering_workstation_compromise.md`
- `execution_through_api.md`
- `exploit_public_facing_application.md`
- `exploitation_for_evasion.md`
- `exploitation_for_privilege_escalation.md`
- `exploitation_of_remote_services.md`
- `external_remote_services.md`
- `hardcoded_credentials.md`
- `hooking.md`
- `i_o_image.md`
- `i_o_module_discovery.md`
- `insecure_credentials.md`
- `internet_accessible_device.md`
- `lateral_tool_transfer.md`
- `location_identification.md`
- `loss_of_availability.md`
- `loss_of_control.md`
- `loss_of_productivity_and_revenue.md`
- `loss_of_protection.md`
- `loss_of_safety.md`
- `loss_of_view.md`
- `manipulate_i_o_image.md`
- `manipulation_of_control.md`
- `manipulation_of_view.md`
- `mitre_ics_filtered_summary.md`
- `modify_alarm_settings.md`
- `modify_control_logic.md`
- `modify_controller_tasking.md`
- `modify_firmware.md`
- `modify_parameter.md`
- `modify_program.md`
- `module_firmware.md`
- `monitor_process_state.md`
- `multicast_discovery.md`
- `native_api.md`
- `network_service_scanning.md`
- `online_edit.md`
- `point_tag_identification.md`
- `port_scan.md`
- `program_append.md`
- `program_download.md`
- `program_upload.md`
- `project_file_infection.md`
- `remote_services.md`
- `remote_system_discovery.md`
- `remote_system_information_discovery.md`
- `replication_through_removable_media.md`
- `reporting_message.md`
- `rogue_master.md`
- `role_identification.md`
- `rootkit.md`
- `screen_capture.md`
- `serial_com.md`
- `serial_connection_enumeration.md`
- `service_stop.md`
- `spoof_reporting_message.md`
- `standard_application_layer_protocol.md`
- `supply_chain_compromise.md`
- `system_binary_proxy_execution.md`
- `system_firmware.md`
- `theft_of_operational_information.md`
- `transient_cyber_asset.md`
- `unauthorized_command_message.md`
- `unauthorized_message.md`
- `valid_accounts.md`
- `wi_fi.md`
- `wireless_compromise.md`
- `wireless_sniffing.md`

## standards (3) — source: IEC 62443

- `gca_leveraging_isa62443_risk_assessment.pdf`
- `iec62443_uav_response_templates.md`
- `isa_iec_62443_overview.html`

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
