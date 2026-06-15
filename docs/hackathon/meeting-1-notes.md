# 1차 미팅 회의록

> Notion 미러 — 자동 추출. 원본: LIG D&A Hackathon

# blue team soc

각 기능별로 kpi, framework 기준으로 운영할 거고 어떻게 얼마나 충족할 건지도 
4단계 (h, m, l, i)
- h: dd
- m
- l
- i:
추후에 심각도 조정 가능
자산의 중요도까지 > 

failover > 
- 일단 돌아와라 
uav, ugv 환경 받아보고 생각하자
(외부 상황 정보 → )

Sentinel 탐지 Alert
↓
[1] Triage Agent : kpi(우선 순위 분류, dwelling time, 
↓
[2] Investigation Agent
↓
[3] Validation Agent (오탐/정탐 판단)
↓
┌───────────────┐
↓               ↓
[4a] Rule Update   [4b] Response Agent
Agent               (플레이북)
(오탐)              (정탐)
↓               ↓
[5] Report Agent + OSCAL 아카이빙

물리적 타격
- uav 환경을 

# 개요

좋아, 컨셉 위주로 브리핑할게.

---

## 프로젝트 한 줄 요약

**"UAV/UGV 공격 시나리오 기반 방어 AI 플랫폼"**
Azure + AKS 위에서 돌아가는 Agentic AI SOC + SSDLC 자동화 플랫폼

---

## 팀 구성

| 인원 | 강점 | 역할 |
|---|---|---|
| 황준식 | 정보장교 + AI Agent 경험 | LangGraph Agent + 시나리오 |
| 김수지 | Microsoft Sentinel 전문가 | SOC + 탐지 로직 |
| 김동언 | 모의해킹 + CSP | 보안 테스트 파이프라인 |
| 너 | OSCAL + DevSecOps + k8s | 전체 인프라 + 컴플라이언스 |

---

## 핵심 차별점

**1. SSDLC + AI SOC 통합**
단순 SOC 툴이 아니라 개발 단계부터 운영까지 end-to-end 보안 자동화
**2. 방산 특화**
- METT+TC 기반 임무 맥락 반영
- cATO MbCRA 임무 기반 위험 평가
- ATCIS/MIMS 모사 연동
**3. OSCAL 자동화**
컴플라이언스 증거가 파이프라인에서 자동 생성
**4. Detection as Code**
위협 모델링 → Red Teaming → Sigma Rule 자동 생성 → Sentinel 배포까지 자동화

---

## 플랫폼 구조 3개 레이어

### 레이어 1: SSDLC 파이프라인

```
개발 단계 보안 자동화
├── STRIDE GPT (위협 모델링)
├── CodeQL + Semgrep (코드 보안)
├── Trivy + SBOM (공급망 보안)
├── DAST - ZAP + Nuclei (API 보안)
├── PyRIT + Garak (AI Red Teaming)
└── OSCAL 컴플라이언스 게이트
```

### 레이어 2: AI SOC (핵심)

```
운영 단계 위협 탐지/대응
├── Triage Agent
├── Investigation Agent
├── Validation Agent (오탐/정탐)
├── Rule Update Agent (오탐 시)
├── Response Agent (정탐 시)
└── Report Agent
```

### 레이어 3: 인프라

```
AKS + kagent
├── Resilience (HPA + 자동복구)
├── OTel 분산 트레이싱 자동화
└── GitOps 기반 Agent 관리
```

---

## 핵심 기술 스택

**AI/Agent**
- LangGraph (Agent 오케스트레이션)
- kagent (K8s 네이티브 Agent 운영)
- Azure OpenAI GPT-4o-mini/GPT-5-nano
- GraphRAG (지식 베이스 + 연관 분석)
- RAG (UAV 도메인 지식 주입)
**보안**
- Microsoft Sentinel (SIEM)
- Sigma Rules + Detection as Code
- MITRE ATT&CK for ICS + ATLAS
- OWASP API Top 10 + LLM Top 10
- PyRIT + Garak (AI Red Teaming)
**컴플라이언스**
- OSCAL (자동 증거 아카이빙)
- NIST AI RMF
- SSDF SP 800-218
- IEC 62443
- cATO MbCRA + METT+TC
**인프라**
- Azure + AKS
- CycloneDX (SBOM + AI-BOM)
- CISA KEV + NVD (TI 자동 업데이트) - 백로그/ 애저 네이티브로 기능 있음, 보고서에만 컨셉으로 넣기??
- Grafana + Loki (모니터링)

---

## 자동화 핵심 흐름

### SSDLC 자동화

```
코드 푸시
→ 위협 모델링 (STRIDE GPT)
→ MITRE TTP 자동 추출
→ PyRIT 공격 시나리오 자동 생성
→ 탐지 실패 TTP → Sigma Rule 자동 생성
→ Sentinel 자동 배포
→ OSCAL 증거 자동 아카이빙
```

### AI SOC 자동화

```
Sentinel Alert
→ GraphRAG 유사 사례 검색
→ TI + 샌드박스 분석
→ 오탐/정탐 판단 (Human-in-the-Loop)
→ 오탐: Rule 자동 수정 + GitHub PR
→ 정탐: 플레이북 실행
→ OSCAL 증거 아카이빙
```

---

## LLMOps / AgentOps

```
평가
├── RAGAS (RAG 품질)
└── LLM-as-a-Judge (황준식 루브릭)

모니터링
├── kagent OTel (자동)
└── Azure Monitor + Grafana

피드백 루프
├── 오탐 이력 → RAG 지식 베이스 업데이트
└── 황준식 Human 검토 → 루브릭 개선
```

---

## 개발 전략

**MVP (1~2주차)**
- 시나리오 2개
- LangGraph Triage + Response Agent
- AKS 기본 배포
- Sentinel 탐지 룰 2개
- OSCAL 통제항목 3~5개
**보강 (3주차)**
- 시나리오 5~7개 확장
- Investigation + Validation + Rule Update Agent 추가
- GraphRAG 연동
- PyRIT + DAST 추가
- Resilience 구성
**마무리 (4주차)**
- 전체 통합 테스트
- 데모 시나리오 구성
- 보고서 작성
- 발표 준비

---

## Azure 선택 이유

- Sentinel 생태계 가장 성숙 (Detection as Code)
- Azure OpenAI 네이티브 연동
- 한국 리전 데이터 주권 확보
- 김수지 Sentinel 실무 경험 즉시 투입

---

## 킥오프 때 결정해야 할 것

- Azure OpenAI Service만 vs Azure AI Foundry
- kagent 채택 여부
- GraphRAG vs 일반 RAG
- 시나리오 MVP 범위
- 모델 선택 (GPT-4o-mini vs GPT-5-nano)

---

일요일 킥오프 때 이 내용 기반으로 팀이랑 얘기하면 방향 빠르게 잡힐 거야. 잘 돼라 ㅋㅋㅋ

1. 양진수
  - kagent 공부하고 azure 에 배포 테스트
  - 최대한 빨리 github 프로젝트 만들고, 들어갈 테스트 도구, 내용 정리하기
1. 황준식
  1. agent 설계 end to end로 테스트
  1. 데이터는 rag flow로 만들어 놨음
  1. uav 공격 시나리오 공유해주기
1. 김수지
  1. 탐지 시나리오를 탐지룰로 바꾸기 +
  1. 센티넬 설정 <> iac 
  1. 계정 초대 넣기
  1. agent 별 kpi 정리하고
1. 김동언
  1. pyRIT + garak 좀 보고 시나리오 어떻게 적용할지 > mitre 정보를 caldera 로 테스트 + 탐지룰 연동을 어떻게 시킬지(json 상하차) + 어떻게 하면 효율적으로 적용

  환경 나오면은 임시로 원격 미팅한 번 해야될 수도 있음

  2주차차 모임(다음주 일요일) > 각자 뭘 들고 올 거냐는 추가 미팅 후에 정리하지만, 위에 내용은 무조건 다 들고오기
