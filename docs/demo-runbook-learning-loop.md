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
| S1 GNSS spoof | `S1-GNSS-SPOOFING` | Impact | `playbook--uav-impact-0001` | `GNSS=SUSTAINED` | "위성항법 정확도" |
| S24 C2 jamming/takeover | `S24-DATALINK-C2-TAKEOVER` | InhibitResponseFunction | `playbook--uav-irf-0001` | `C2_LINK=MINIMAL` | "실시간 지상 지휘통제" |
| S33 firmware supply chain tamper | `S33-FIRMWARE-SUPPLY-CHAIN-TAMPER` | Impact | `playbook--uav-impact-0001` | `AUTOPILOT=ABORT` | "비행제어" |
| S117 BLOS SATCOM MITM | `S117-BLOS-AUTONOMY-COMMAND-FORGE` | Impact | `playbook--uav-impact-0001` | `SATCOM=SUSTAINED` | "위성 데이터링크" |
| S89 RAG poisoning | `S89-RAG-POISONING-ORIENT-DECEPTION` | Impact | `playbook--uav-impact-0001` | `AI_SOC=SUSTAINED` | "AI SOC 자동 판정" |

## 실측과 issue 제안표의 차이

issue #83의 예시표는 일부 항목에서 `playbook--uav-c2-0001`/`playbook--uav-persist-0001`/
`playbook--uav-coll-0001`/`playbook--uav-exfil-0001`을 후보로 제시했으나, 실제
`core/policy/cacao-playbooks.yaml`에는 **3개 플레이북만 존재**한다 —
`playbook--uav-impact-0001`(Impact) · `playbook--uav-ipc-0001`(ImpairProcessControl) ·
`playbook--uav-irf-0001`(InhibitResponseFunction). 각 시나리오의 실제 `tactics[]`(dah
AnalyticsRules JSON, 복수 전술 보유)를 대조해 이 3개 중 실제로 매칭되는 전술을
`expected_tactic`으로 채택했다 — S24만 InhibitResponseFunction, 나머지 4건은 Impact.

또한 issue pseudo-flow는 `response.mission_continuity`를 가정했으나, 실제로는
`report.mission_continuity`(`agents/report_agent.py` + `core/degradation.py`)에서
산출된다 — CACAO 선택(`ResponseAgent`)과 graceful degradation(`ReportAgent`)은 별개
컴포넌트다. 테스트는 실제 배선을 그대로 따른다.
