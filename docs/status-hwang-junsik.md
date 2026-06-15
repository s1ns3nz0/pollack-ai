# 황준식 lane — 진행 상황 (Notion 미러)

> 회사 PC에서 Notion 접근이 막혀 있어서, Notion "황준식 과업" 페이지 내용을 이 파일로 미러링합니다.
> **앞으로는 이 파일을 최신화**합니다. (Notion 원본과 동일 내용)
> 최종 상태: **27 tests passed**, `python run_demo.py` 기본 콘솔에서 정상 동작.
> 상세 핸드오프/이관 가이드는 프로토타입의 `HANDOFF.md`, `WORK-HISTORY.md` 참고.

마지막 갱신: 2026-06-15

---

## 지금 어디까지 됐나요

큰 항목만 상태로 먼저 보시면 이 정도예요.

| 항목 | 상태 | 보면 되는 곳 |
|---|---|---|
| Agent E2E 테스트 | 됨 (27 passed) | `run_demo.py` · `tests/` |
| 심각도 정책 h/m/l/i | 됨 | `policy/` · `policy_loader.py` |
| 심각도 동적조정(dynamics) | 됨 (엔진 구동) | `severity-policy.yaml` · `policy_loader.py` |
| UAV 공격 시나리오 | 됨 (S1~S6) | `scenarios/` |
| 레드팀 매핑(PyRIT/Garak) | 매핑 됨 / 실행은 다른 PC | `redteam/` · `scenarios/*.yaml` |
| MITRE/ATLAS/EMB3D 추적 | 됨 | `tracking/coverage-matrix.md` |
| RAG flow | 다른 PC (이 repo는 mock) | `interfaces.py` |
| OSCAL 통제 매핑 | 협업 대기 | `oscal.py` (stub) |

---

## 공격 시나리오 한눈에

팀이 공통으로 쓰는 YAML 한 포맷으로 정리했어요. 이 한 장이 SOC·RAG·PyRIT·Garak·Sentinel·심각도까지 전부 먹는 게 핵심인 거 같아요. 아래 표에 시나리오별로 공격 흐름부터 탐지·대응·레드팀까지 묶어놨습니다.

| 시나리오 · 자산(Tier) | 공격 흐름(kill chain) | MITRE 매핑 | 탐지 신호 → Sigma 룰 | 심각도 | 방어 플레이북 / 레드팀 |
|---|---|---|---|---|---|
| **S1** GPS/GNSS 스푸핑 · GNSS(T1) | 정찰→EW 위치선점→위조 GNSS 주입→위치 drift→항로 이탈 | ICS T0830·T0856·T0831·T0815 / EMB3D 센서변조(verify) | GNSS-INS 잔차 급증 + C/N0 비정상 상승 → `uav_gps_spoof_residual.yml` | h | PB-NAV-RTB-01 (INS 페일오버·RTB) / 레드팀 SEV-DOWNGRADE-01 |
| **S2** C2 재밍·하이재킹 · C2_LINK(T1) | 정찰→C2 재밍→세션 하이재킹→위조명령 주입→통제권 탈취 | ICS T0814·T0855·T0831·T0813 / EMB3D 약한인증(verify) | 지상국 미발신 명령 수신 / 명령 시퀀스 불연속 → `uav_c2_unauthorized_cmd.yml` | h | PB-C2-FAILSAFE-02 (명령인증·대체링크·페일세이프) / 레드팀 SEV-DOWNGRADE-01 |
| **S3** SATCOM MITM · SATCOM(T2) | 정찰→SATCOM 가로채기→MITM 위치선점→데이터 변조·유출 | ICS T0830·T0856·T0832 | MAC 검증 실패율↑ / 페이로드 체크섬 불일치 → `uav_satcom_integrity_fail.yml` | m (방첩 상향 시 h) | PB-LINK-INTEG-03 (무결성 격리·키 롤오버·대체링크) / 레드팀 FP-FORCE-02 |
| **S4** 펌웨어·공급망 변조 · AUTOPILOT(T1) | 공급망 임플란트→펌웨어 변조→배포→트리거→제어로직 변조 | ICS T0862·T0857·T0843·T0889 / EMB3D 펌웨어변조·시큐어부트부재(verify) | 서명·해시 불일치 / SBOM 미등록 컴포넌트 → `uav_fw_signature_mismatch.yml` | h | PB-FW-INTEG-04 (비행금지 게이트·재이미징·SBOM 재검증) / 레드팀 SEV-DOWNGRADE-01 |
| **S5** RAG 포이즈닝 ⚠️제안 · AI_SOC(T0) | KB 접근→오염문서 주입→검색 트리거→심각도 오판→대응 무력화 | ATLAS AML.T0051.001·T0020·RAGPoison·T0054 | 정책 기대등급-에이전트 판정 괴리 / 미서명 컨텍스트 검색 → `aisoc_severity_anomaly.yml` | h (메타위협·항상 유지) | PB-AISOC-GUARD-05 (출처검증·정책하한·HITL) / 레드팀 핵심 표적 |
| **S6** GCS 침해·횡적확산 · GCS(T1) | 초기침투→유효계정 탈취→GCS 장악→다수기체 재지정→횡적확산 | ICS T0822·T0859·T0855·T0866·T0867 | 비정상 로그인 / 단시간 다수기체 재지정 / 내부망 횡적연결 → `gcs_mass_retasking.yml` | h | PB-GCS-CONTAIN-06 (세션격리·2차승인·자격증명 회전) / 레드팀 PLAYBOOK-MISFIRE-03 |

---

## 심각도는 이렇게 잡았어요

등급은 h/m/l/i 네 단계예요. UAV 기준으로 h는 임무 실패·기체 통제권 상실급, m은 부분 저하라 이중화로 버티는 수준, l은 비핵심 기능 저하, i는 영향 없는 정찰·스캔 정도로 봤습니다.

결정 하나만 짚자면, 심각도를 LLM한테 판단시키지 않았어요. 자산 중요도(GNSS·C2·GCS는 T1, AI SOC는 T0), 임무 단계, 외부 사이버 태세를 전부 `severity-policy.yaml`에 규칙으로 빼두고 엔진은 계산만 합니다. 이렇게 한 이유는 두 가지인데요, 나중에 기준이 바뀌어도 코드 말고 YAML만 고치면 되고, 레드팀이 프롬프트 인젝션으로 등급을 깎으려 해도 정책 하한이 막아주거든요.

여기에 동적 조정도 얹었어요. 위협이 30분 넘게 머물면 한 단계 올리고, GCS·C2 같은 상위 자산이 뚫리면 거기 묶인 기체 등급을 끌어올립니다. 반대로 한참 무영향이면 한 단계 내리는데, 태세가 올라가 있을 때(elevated 이상)는 하향 자체를 막아서 baseline 밑으로는 안 내려가게 해뒀어요.

---

## MITRE는 뭘 쓰나요 (차량 MITRE 질문 답)

찾아보니 자동차 전용 ATT&CK 매트릭스는 따로 없더라고요. 그래서 이렇게 나눴어요. 통신·제어·공급망 같은 운영기술(OT)은 **ATT&CK for ICS**, 우리 방어 AI를 노리는 공격은 **ATLAS**, 비행제어기·센서·펌웨어 같은 임베디드는 **MITRE EMB3D**로요. UAV/UGV는 결국 임베디드라 EMB3D가 정답이고, 이게 보고서 차별점도 되는 거 같아요. 공격↔방어 매핑은 `coverage-matrix.md`에서 계속 추적합니다.

---

## 아직 남은 것

- RAG flow는 다른 PC에 있어요 — 이 repo는 mock으로 격리해뒀고 나중에 연결할 예정입니다
- S1·S4의 EMB3D TID 정확한 번호 확정이 필요해요 (emb3d.mitre.org)
- dynamics 신호(체류시간·횡적상관)는 탐지 파이프라인이 실제로 채워줘야 합니다
- OSCAL 통제 ID 매핑은 인프라·컴플라이언스 담당과 같이 해야 해요
- Sigma 룰 6개 실제 구현은 김수지님 핸드오프로 넘어갑니다
