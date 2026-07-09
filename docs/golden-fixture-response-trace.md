# Golden Fixture → Detection → Response Runbook Trace

> issue [#83](https://github.com/s1ns3nz0/pollack-ai/issues/83) — golden fixture가 단순 탐지
> 입력으로 끝나지 않고 response runbook(CACAO 플레이북 선택 + graceful degradation)까지
> 결정론으로 추적 가능함을 보이는 표.

각 골든 픽스처(`benchmarks/eval_scenarios/*.yaml`)는 실제 dah-sentinel-content 배포 룰
(S1~S126 신번호)과 `core/policy/cacao-playbooks.yaml` / `core/policy/degradation-matrix.yaml`
을 실측 대조해 `expected_*` 필드를 채운다. 검증 테스트:
`tests/__tests__/test_golden_fixture_response_trace.py`.

| Fixture | scenario_id | Expected tactic | Expected CACAO PB | Expected resilience | Expected report evidence |
| --- | --- | --- | --- | --- | --- |
| S1 GNSS spoof | `S1-GNSS-SPOOFING` | Collection | `playbook--uav-coll-0001` | `GNSS=SUSTAINED` | "위성항법 정확도" |
| S21 lateral movement | `S21-LATERAL-MOVEMENT` | LateralMovement | `playbook--uav-lm-0001` | `GCS=SUSTAINED` | "1차 지상통제소 지휘" |
| S24 C2 jamming/takeover | `S24-DATALINK-C2-TAKEOVER` | CommandAndControl | `playbook--uav-c2-0001` | `C2_LINK=MINIMAL` | "실시간 지상 지휘통제" |
| S33 firmware supply chain tamper | `S33-FIRMWARE-SUPPLY-CHAIN-TAMPER` | InitialAccess | `playbook--uav-ia-0001` | `AUTOPILOT=ABORT` | "비행제어" |
| S42 GCS QML plugin injection | `S42-GCS-QML-PLUGIN-INJECTION` | Execution | `playbook--uav-exec-0001` | `GCS=SUSTAINED` | "1차 지상통제소 지휘" |
| S88 adversarial patch attack | `S88-ADVERSARIAL-PATCH-ATTACK` | StealthEvasion | `playbook--uav-stealth-0001` | `PAYLOAD_EOIR=SUSTAINED` | "EO/IR 표적인식 신뢰도" |
| S89 RAG poisoning | `S89-RAG-POISONING-ORIENT-DECEPTION` | StealthEvasion | `playbook--uav-stealth-0001` | `AI_SOC=SUSTAINED` | "AI SOC 자동 판정" |
| S100 swarm saturation | `S100-SWARM-SATURATION-SOC-OVERLOAD` | Impact | `playbook--uav-impact-0001` | `AI_SOC=SUSTAINED` | "AI SOC 자동 판정" |
| S117 BLOS SATCOM MITM | `S117-BLOS-AUTONOMY-COMMAND-FORGE` | Collection | `playbook--uav-coll-0001` | `SATCOM=SUSTAINED` | "위성 데이터링크" |

## 실측 기준

`expected_tactic` 은 production 배선 그대로 — `core/cacao.py scenario_tactic_map()`
(bas-scenarios.yaml `tactics[0]`, Enterprise 명명은 UAV ATT&CK 로 정규화:
DefenseEvasion→StealthEvasion) — 을 따르고, `expected_cacao_playbook_id` 는
CACAO 카탈로그(`core/policy/cacao-playbooks.yaml`)의 exact-match
선택 결과다. 검증 테스트가 fixture 값 주입이 아닌 실제 `scenario_tactic_map()` 으로
동일 체인을 재현하므로, 이 표의 값은 fixture·production 양쪽과 결정론으로 일치한다.

또한 issue pseudo-flow는 `response.mission_continuity`를 가정했으나, 실제로는
`report.mission_continuity`(`agents/report_agent.py` + `core/degradation.py`)에서
산출된다 — CACAO 선택(`ResponseAgent`)과 graceful degradation(`ReportAgent`)은 별개
컴포넌트다. 테스트는 실제 배선을 그대로 따른다.
