# 황준식 lane — 진행 상황 (Notion 미러)

> 회사 PC에서 Notion 접근이 막혀 있어서, Notion "황준식 과업" 페이지 내용을 이 파일로 미러링합니다.
> **앞으로는 이 파일을 최신화**합니다. (Notion 원본과 동일 내용)
> 최종 상태: **RAG·방어 6-에이전트 실제 구현 완료** (RAGFlow + 실 LangGraph, 팀 CI 통과). 프로토타입 45 tests passed.
> 상세 핸드오프/이관 가이드는 프로토타입의 `HANDOFF.md`, `WORK-HISTORY.md`, `RAG_DEFENSE_STATUS.md` 참고.

마지막 갱신: 2026-06-17

---

## 지금 어디까지 됐나요

큰 항목만 상태로 먼저 보시면 이 정도예요.

| 항목 | 상태 | 보면 되는 곳 |
|---|---|---|
| Agent E2E 테스트 | 됨 (45 passed) | `run_demo.py` · `tests/` |
| 심각도 정책 h/m/l/i | 됨 | `policy/` · `policy_loader.py` |
| 심각도 동적조정(dynamics) | 됨 (엔진 구동) | `severity-policy.yaml` · `policy_loader.py` |
| UAV/UGV 공격 시나리오 | 됨 (S1~S11) | `scenarios/` |
| 레드팀 매핑(PyRIT/Garak) | 매핑 됨 / 실행은 다른 PC | `redteam/` · `scenarios/*.yaml` |
| MITRE/ATLAS/EMB3D 추적 | 됨 | `tracking/coverage-matrix.md` |
| RAG 검색(RAGFlow) | ✅ 실제 구현 — KB 126 docs | `tools/ragflow_tool.py` |
| 방어 6-에이전트 SOC | ✅ 실 LangGraph·async, CI 통과 | `agents/` |
| 에이전트 LLM 추론 | mock — Azure OpenAI 교체 예정(별도 lane) | — |
| OSCAL 통제 매핑 | 협업 대기 | `core/oscal.py` (stub) |

---

## 공격 시나리오 한눈에

팀이 공통으로 쓰는 YAML 한 포맷으로 정리했어요. 이 한 장이 SOC·RAG·PyRIT·Garak·Sentinel·심각도까지 전부 먹는 게 핵심인 거 같아요. 아래 표에 시나리오별로 공격 흐름부터 탐지·대응·레드팀까지 묶어놨습니다.

처음 6개(S1~S6)에서, 러우전쟁·이스라엘·홍해 실전 분석을 반영해 **UGV·온보드AI·군집포화·SATCOM무력화·모바일GCS 5개(S7~S11)를 추가**했어요(총 11개). 안내서가 명시한 UAV/UGV/위성통신을 다 덮고, "Defense AI" 주제에 맞춰 공격받는 AI(S8)와 방어하는 AI(S5)를 양쪽 다 다룹니다. 기존 S2는 광케이블(재밍 내성) 변형, S4는 공급망(페이저 모델 + 확인된 무허가 라디오 PoC)으로 보강했고요.

| 시나리오 · 자산(Tier) | 공격 흐름(kill chain) | MITRE 매핑 | 탐지 신호 → Sigma 룰 | 심각도 | 방어 플레이북 / 레드팀 |
|---|---|---|---|---|---|
| **S1** GPS/GNSS 스푸핑 · GNSS(T1) | 정찰→EW 위치선점→위조 GNSS 주입→위치 drift→항로 이탈 | ICS T0830·T0856·T0831·T0815 / EMB3D 센서변조(category) | GNSS-INS 잔차 급증 + C/N0 비정상 상승 → `uav_gps_spoof_residual.yml` | h | PB-NAV-RTB-01 (INS 페일오버·RTB) / 레드팀 SEV-DOWNGRADE-01 |
| **S2** C2 재밍·하이재킹 · C2_LINK(T1) | 정찰→C2 재밍→세션 하이재킹→위조명령 주입→통제권 탈취 | ICS T0814·T0855·T0831·T0813 / EMB3D 약한인증(category) | 지상국 미발신 명령 수신 / 명령 시퀀스 불연속 → `uav_c2_unauthorized_cmd.yml` | h | PB-C2-FAILSAFE-02 (명령인증·대체링크·페일세이프) / 레드팀 SEV-DOWNGRADE-01 |
| **S3** SATCOM MITM · SATCOM(T2) | 정찰→SATCOM 가로채기→MITM 위치선점→데이터 변조·유출 | ICS T0830·T0856·T0832 | MAC 검증 실패율↑ / 페이로드 체크섬 불일치 → `uav_satcom_integrity_fail.yml` | m (방첩 상향 시 h) | PB-LINK-INTEG-03 (무결성 격리·키 롤오버·대체링크) / 레드팀 FP-FORCE-02 |
| **S4** 펌웨어·공급망 변조 · AUTOPILOT(T1) | 공급망 임플란트→펌웨어 변조→배포→트리거→제어로직 변조 | ICS T0862·T0857·T0843·T0889 / EMB3D 펌웨어변조·시큐어부트부재(category) | 서명·해시 불일치 / SBOM 미등록 컴포넌트 → `uav_fw_signature_mismatch.yml` | h | PB-FW-INTEG-04 (비행금지 게이트·재이미징·SBOM 재검증) / 레드팀 SEV-DOWNGRADE-01 |
| **S5** RAG 포이즈닝 ⚠️제안 · AI_SOC(T0) | KB 접근→오염문서 주입→검색 트리거→심각도 오판→대응 무력화 | ATLAS AML.T0051.001·T0020·RAGPoison·T0054 | 정책 기대등급-에이전트 판정 괴리 / 미서명 컨텍스트 검색 → `aisoc_severity_anomaly.yml` | h (메타위협·항상 유지) | PB-AISOC-GUARD-05 (출처검증·정책하한·HITL) / 레드팀 핵심 표적 |
| **S6** GCS 침해·횡적확산 · GCS(T1) | 초기침투→유효계정 탈취→GCS 장악→다수기체 재지정→횡적확산 | ICS T0822·T0859·T0855·T0866·T0867 | 비정상 로그인 / 단시간 다수기체 재지정 / 내부망 횡적연결 → `gcs_mass_retasking.yml` | h | PB-GCS-CONTAIN-06 (세션격리·2차승인·자격증명 회전) / 레드팀 PLAYBOOK-MISFIRE-03 |
| **S7** UGV 원격조종 탈취·노획 · UGV_TELEOP(T1) | 정찰→재밍/센서 스푸핑→기동불능→지상 노획→자격증명 탈취 | ICS T0814·T0855·T0831·T0859 / ATLAS T0043 / EMB3D 센서·물리추출(category) | 제어두절+IMU 노획징후 / 탈취 자격증명 재사용 → `ugv_teleop_hijack_capture.yml` | h | PB-UGV-CONTAIN-07 (원격 zeroize·자격증명 회전·안전정지) / 레드팀 SEV-DOWNGRADE-01 |
| **S8** 온보드 표적인식 AI 적대적 공격 · PAYLOAD_EOIR(T2) | 모델 정찰→적대적 패치/디코이/dazzling→인식 회피→임무 무력화 | ATLAS T0015·T0043·T0020 / EMB3D EO·IR 센서(category) | 센서간 표적 불일치 / 탐지 신뢰도 이상분포 → `onboard_ai_adversarial_evade.yml` | m (무장유도 연계 시 h) | PB-ONBOARDAI-08 (센서융합 게이트·HITL·robust 모델) / 레드팀 FP-FORCE-02 |
| **S9** 군집 포화·SOC 과부하 · AI_SOC(T0) | 대량/근접발사→다축 동시침해→경보 폭주→운용자·탐지 포화 | ICS T0814·T0855 / ATLAS T0029(category) | 경보 레이트 이상 + 다축 상관 클러스터 → `swarm_saturation_alertstorm.yml` | h | PB-SWARM-AGGREGATE-09 (경보 집약·lateral 에스컬레이션·게이트 완화) / 레드팀 SEV-DOWNGRADE-01 |
| **S10** SATCOM 단말/관리망 무력화 · SATCOM(T2) | 관리망 침투→유효계정→악성 업데이트→모뎀 무력화→운용망 고립 | ICS T0814·T0809·T0857·T0822·T0859 / EMB3D 모뎀 펌웨어(category) | 다수 단말 동시 접속실패 + 관리채널 이상 → `satcom_terminal_mass_failure.yml` | h | PB-SATCOM-FAILOVER-10 (망 이중화·무결성검증·로컬 자율) / 레드팀 SEV-DOWNGRADE-01 |
| **S11** 모바일/전술 GCS 침해 · GCS(T1) | 악성앱/임플란트→임무·자격증명 유출→위조임무 업로드→GCS 확산 | ICS T0822·T0859·T0855·T0867 / ATT&CK Mobile | 비인가 앱 + 임무파일 비정상 접근 + 세션토큰 재사용 → `mobile_gcs_compromise.yml` | h | PB-MOBILEGCS-CONTAIN-11 (MDM·앱서명·권한분리) / 레드팀 SEV-DOWNGRADE-01 |

> 실전 앵커: S7=우크라 전로봇 합동공격(2024-12), S8=재밍내성 AI 종말유도(Skynode S 등), S9=Shahed 군집·Operation Spiderweb, S10=KA-SAT/Viasat(2022, AcidRain), S11=Infamous Chisel(2023). 상세 출처·검증 플래그는 `docs/hackathon/references.md`.

---

## 심각도는 이렇게 잡았어요

등급은 h/m/l/i 네 단계예요. UAV 기준으로 h는 임무 실패·기체 통제권 상실급, m은 부분 저하라 이중화로 버티는 수준, l은 비핵심 기능 저하, i는 영향 없는 정찰·스캔 정도로 봤습니다.

결정 하나만 짚자면, 심각도를 LLM한테 판단시키지 않았어요. 자산 중요도(GNSS·C2·GCS는 T1, AI SOC는 T0), 임무 단계, 외부 사이버 태세를 전부 `severity-policy.yaml`에 규칙으로 빼두고 엔진은 계산만 합니다. 이렇게 한 이유는 두 가지인데요, 나중에 기준이 바뀌어도 코드 말고 YAML만 고치면 되고, 레드팀이 프롬프트 인젝션으로 등급을 깎으려 해도 정책 하한이 막아주거든요.

여기에 동적 조정도 얹었어요. 위협이 30분 넘게 머물면 한 단계 올리고, GCS·C2 같은 상위 자산이 뚫리면 거기 묶인 기체 등급을 끌어올립니다. 반대로 한참 무영향이면 한 단계 내리는데, 태세가 올라가 있을 때(elevated 이상)는 하향 자체를 막아서 baseline 밑으로는 안 내려가게 해뒀어요.

---

## MITRE는 뭘 쓰나요 (차량 MITRE 질문 답)

찾아보니 자동차 전용 ATT&CK 매트릭스는 따로 없더라고요. 그래서 이렇게 나눴어요. 통신·제어·공급망 같은 운영기술(OT)은 **ATT&CK for ICS**, 우리 방어 AI를 노리는 공격은 **ATLAS**, 비행제어기·센서·펌웨어 같은 임베디드는 **MITRE EMB3D**로요. UAV/UGV는 결국 임베디드라 EMB3D가 정답이고, 이게 보고서 차별점도 되는 거 같아요. 공격↔방어 매핑은 `coverage-matrix.md`에서 계속 추적합니다.

이번 확장에서 ATLAS는 방어 AI(S5)뿐 아니라 **공격 대상 기체의 온보드 표적인식 AI(S8)**까지 매핑해서 '공격받는 AI·방어하는 AI 양쪽'을 다루게 됐고, 모바일 GCS(S11)는 ATT&CK Mobile을 병행으로 넣었어요. EMB3D는 가짜 TID 대신 카테고리명(펌웨어변조·시큐어부트부재·센서변조·물리추출)으로 적고, 제출 직전에 emb3d.mitre.org에서 실제 번호만 채웁니다.

---

## 아직 남은 것

- RAG flow는 RAGFlow(로컬 ollama: bge-m3 임베딩 / qwen2.5:14b)로 **실제 구현 완료** — `tools/ragflow_tool.py`. 에이전트 LLM 추론만 아직 mock → Azure OpenAI 교체 예정(별도 lane)
- S1·S4·S7·S8·S10의 EMB3D는 카테고리명으로 적어뒀고, 제출 전 emb3d.mitre.org에서 실제 TID만 채우면 돼요
- dynamics 신호(체류시간·횡적상관)는 탐지 파이프라인이 실제로 채워줘야 합니다
- OSCAL 통제 ID 매핑은 인프라·컴플라이언스 담당과 같이 해야 해요
- Sigma 룰 11개 실제 구현은 김수지님 핸드오프로 넘어갑니다
- 러우전쟁 등 실전 참고문헌은 `docs/hackathon/references.md`로 정리해뒀어요 (검증 플래그 포함 — Spiderweb·적대적패치·DJI는 "보도/잠재"로, KA-SAT·Infamous Chisel은 안전 인용)
