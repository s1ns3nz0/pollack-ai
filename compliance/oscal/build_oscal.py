#!/usr/bin/env python3
"""UAV AI SOC — NIST AI RMF 1.0 → OSCAL 1.1.2 생성기 (단일 소스).

AI RMF 72개 서브카테고리(NIST AI 100-1 원문)를 OSCAL catalog 으로 만들고,
플랫폼 통제 매핑·구현현황을 profile / component-definition / SSP / POA&M 으로
생성한다. 대시보드용 data.js 도 함께 emit 한다.

상태값(OSCAL implementation-status): implemented | partial | planned
실행: python build_oscal.py <출력디렉토리>
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

OSCAL_VERSION = "1.1.2"
NS = uuid.UUID("6f3a9c2e-0000-5000-a000-554156534f43")  # 안정적 uuid5 네임스페이스
NOW = datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def u(seed: str) -> str:
    """식별자 기반 안정적 UUID (재실행 시 동일)."""
    return str(uuid.uuid5(NS, seed))


# ─────────────────────────────────────────────────────────────────────────
# 1. AI RMF Core — 함수 / 카테고리 / 서브카테고리 (NIST AI 100-1, Tables 1–4 원문)
# ─────────────────────────────────────────────────────────────────────────
FUNCTIONS = {
    "GOVERN": "조직 전반에 AI 리스크의 매핑·측정·관리를 위한 문화·책임·정책·감독을 확립하는 교차기능.",
    "MAP": "AI 시스템의 맥락을 설정하고 리스크와 영향을 식별하는 범위설정 기능.",
    "MEASURE": "정량·정성 도구로 AI 리스크를 분석·평가·벤치마크·모니터링하는 기능.",
    "MANAGE": "우선순위화된 리스크에 자원을 배분해 대응·복구·소통하는 기능.",
}

CATEGORIES = {
    "GOVERN 1": "Policies, processes, procedures, and practices across the organization related to the mapping, measuring, and managing of AI risks are in place, transparent, and implemented effectively.",
    "GOVERN 2": "Accountability structures are in place so that the appropriate teams and individuals are empowered, responsible, and trained for mapping, measuring, and managing AI risks.",
    "GOVERN 3": "Workforce diversity, equity, inclusion, and accessibility processes are prioritized in the mapping, measuring, and managing of AI risks throughout the lifecycle.",
    "GOVERN 4": "Organizational teams are committed to a culture that considers and communicates AI risk.",
    "GOVERN 5": "Processes are in place for robust engagement with relevant AI actors.",
    "GOVERN 6": "Policies and procedures are in place to address AI risks and benefits arising from third-party software and data and other supply chain issues.",
    "MAP 1": "Context is established and understood.",
    "MAP 2": "Categorization of the AI system is performed.",
    "MAP 3": "AI capabilities, targeted usage, goals, and expected benefits and costs compared with appropriate benchmarks are understood.",
    "MAP 4": "Risks and benefits are mapped for all components of the AI system including third-party software and data.",
    "MAP 5": "Impacts to individuals, groups, communities, organizations, and society are characterized.",
    "MEASURE 1": "Appropriate methods and metrics are identified and applied.",
    "MEASURE 2": "AI systems are evaluated for trustworthy characteristics.",
    "MEASURE 3": "Mechanisms for tracking identified AI risks over time are in place.",
    "MEASURE 4": "Feedback about efficacy of measurement is gathered and assessed.",
    "MANAGE 1": "AI risks based on assessments and other analytical output from the MAP and MEASURE functions are prioritized, responded to, and managed.",
    "MANAGE 2": "Strategies to maximize AI benefits and minimize negative impacts are planned, prepared, implemented, documented, and informed by input from relevant AI actors.",
    "MANAGE 3": "AI risks and benefits from third-party entities are managed.",
    "MANAGE 4": "Risk treatments, including response and recovery, and communication plans for the identified and measured AI risks are documented and monitored regularly.",
}

# 서브카테고리 원문 (NIST AI 100-1)
SUBCATS: dict[str, str] = {
    "GOVERN 1.1": "Legal and regulatory requirements involving AI are understood, managed, and documented.",
    "GOVERN 1.2": "The characteristics of trustworthy AI are integrated into organizational policies, processes, procedures, and practices.",
    "GOVERN 1.3": "Processes, procedures, and practices are in place to determine the needed level of risk management activities based on the organization's risk tolerance.",
    "GOVERN 1.4": "The risk management process and its outcomes are established through transparent policies, procedures, and other controls based on organizational risk priorities.",
    "GOVERN 1.5": "Ongoing monitoring and periodic review of the risk management process and its outcomes are planned and organizational roles and responsibilities clearly defined, including determining the frequency of periodic review.",
    "GOVERN 1.6": "Mechanisms are in place to inventory AI systems and are resourced according to organizational risk priorities.",
    "GOVERN 1.7": "Processes and procedures are in place for decommissioning and phasing out AI systems safely and in a manner that does not increase risks or decrease the organization's trustworthiness.",
    "GOVERN 2.1": "Roles and responsibilities and lines of communication related to mapping, measuring, and managing AI risks are documented and are clear to individuals and teams throughout the organization.",
    "GOVERN 2.2": "The organization's personnel and partners receive AI risk management training to enable them to perform their duties and responsibilities consistent with related policies, procedures, and agreements.",
    "GOVERN 2.3": "Executive leadership of the organization takes responsibility for decisions about risks associated with AI system development and deployment.",
    "GOVERN 3.1": "Decision-making related to mapping, measuring, and managing AI risks throughout the lifecycle is informed by a diverse team (e.g., diversity of demographics, disciplines, experience, expertise, and backgrounds).",
    "GOVERN 3.2": "Policies and procedures are in place to define and differentiate roles and responsibilities for human-AI configurations and oversight of AI systems.",
    "GOVERN 4.1": "Organizational policies and practices are in place to foster a critical thinking and safety-first mindset in the design, development, deployment, and uses of AI systems to minimize potential negative impacts.",
    "GOVERN 4.2": "Organizational teams document the risks and potential impacts of the AI technology they design, develop, deploy, evaluate, and use, and they communicate about the impacts more broadly.",
    "GOVERN 4.3": "Organizational practices are in place to enable AI testing, identification of incidents, and information sharing.",
    "GOVERN 5.1": "Organizational policies and practices are in place to collect, consider, prioritize, and integrate feedback from those external to the team that developed or deployed the AI system regarding the potential individual and societal impacts related to AI risks.",
    "GOVERN 5.2": "Mechanisms are established to enable the team that developed or deployed AI systems to regularly incorporate adjudicated feedback from relevant AI actors into system design and implementation.",
    "GOVERN 6.1": "Policies and procedures are in place that address AI risks associated with third-party entities, including risks of infringement of a third-party's intellectual property or other rights.",
    "GOVERN 6.2": "Contingency processes are in place to handle failures or incidents in third-party data or AI systems deemed to be high-risk.",
    "MAP 1.1": "Intended purposes, potentially beneficial uses, context-specific laws, norms and expectations, and prospective settings in which the AI system will be deployed are understood and documented. Considerations include: the specific set or types of users along with their expectations; potential positive and negative impacts of system uses to individuals, communities, organizations, society, and the planet; assumptions and related limitations about AI system purposes, uses, and risks across the development or product AI lifecycle; and related TEVV and system metrics.",
    "MAP 1.2": "Interdisciplinary AI actors, competencies, skills, and capacities for establishing context reflect demographic diversity and broad domain and user experience expertise, and their participation is documented. Opportunities for interdisciplinary collaboration are prioritized.",
    "MAP 1.3": "The organization's mission and relevant goals for AI technology are understood and documented.",
    "MAP 1.4": "The business value or context of business use has been clearly defined or – in the case of assessing existing AI systems – re-evaluated.",
    "MAP 1.5": "Organizational risk tolerances are determined and documented.",
    "MAP 1.6": 'System requirements (e.g., "the system shall respect the privacy of its users") are elicited from and understood by relevant AI actors. Design decisions take socio-technical implications into account to address AI risks.',
    "MAP 2.1": "The specific tasks and methods used to implement the tasks that the AI system will support are defined (e.g., classifiers, generative models, recommenders).",
    "MAP 2.2": "Information about the AI system's knowledge limits and how system output may be utilized and overseen by humans is documented. Documentation provides sufficient information to assist relevant AI actors when making decisions and taking subsequent actions.",
    "MAP 2.3": "Scientific integrity and TEVV considerations are identified and documented, including those related to experimental design, data collection and selection (e.g., availability, representativeness, suitability), system trustworthiness, and construct validation.",
    "MAP 3.1": "Potential benefits of intended AI system functionality and performance are examined and documented.",
    "MAP 3.2": "Potential costs, including non-monetary costs, which result from expected or realized AI errors or system functionality and trustworthiness – as connected to organizational risk tolerance – are examined and documented.",
    "MAP 3.3": "Targeted application scope is specified and documented based on the system's capability, established context, and AI system categorization.",
    "MAP 3.4": "Processes for operator and practitioner proficiency with AI system performance and trustworthiness – and relevant technical standards and certifications – are defined, assessed, and documented.",
    "MAP 3.5": "Processes for human oversight are defined, assessed, and documented in accordance with organizational policies from the GOVERN function.",
    "MAP 4.1": "Approaches for mapping AI technology and legal risks of its components – including the use of third-party data or software – are in place, followed, and documented, as are risks of infringement of a third party's intellectual property or other rights.",
    "MAP 4.2": "Internal risk controls for components of the AI system, including third-party AI technologies, are identified and documented.",
    "MAP 5.1": "Likelihood and magnitude of each identified impact (both potentially beneficial and harmful) based on expected use, past uses of AI systems in similar contexts, public incident reports, feedback from those external to the team that developed or deployed the AI system, or other data are identified and documented.",
    "MAP 5.2": "Practices and personnel for supporting regular engagement with relevant AI actors and integrating feedback about positive, negative, and unanticipated impacts are in place and documented.",
    "MEASURE 1.1": "Approaches and metrics for measurement of AI risks enumerated during the MAP function are selected for implementation starting with the most significant AI risks. The risks or trustworthiness characteristics that will not – or cannot – be measured are properly documented.",
    "MEASURE 1.2": "Appropriateness of AI metrics and effectiveness of existing controls are regularly assessed and updated, including reports of errors and potential impacts on affected communities.",
    "MEASURE 1.3": "Internal experts who did not serve as front-line developers for the system and/or independent assessors are involved in regular assessments and updates. Domain experts, users, AI actors external to the team that developed or deployed the AI system, and affected communities are consulted in support of assessments as necessary per organizational risk tolerance.",
    "MEASURE 2.1": "Test sets, metrics, and details about the tools used during TEVV are documented.",
    "MEASURE 2.2": "Evaluations involving human subjects meet applicable requirements (including human subject protection) and are representative of the relevant population.",
    "MEASURE 2.3": "AI system performance or assurance criteria are measured qualitatively or quantitatively and demonstrated for conditions similar to deployment setting(s). Measures are documented.",
    "MEASURE 2.4": "The functionality and behavior of the AI system and its components – as identified in the MAP function – are monitored when in production.",
    "MEASURE 2.5": "The AI system to be deployed is demonstrated to be valid and reliable. Limitations of the generalizability beyond the conditions under which the technology was developed are documented.",
    "MEASURE 2.6": "The AI system is evaluated regularly for safety risks – as identified in the MAP function. The AI system to be deployed is demonstrated to be safe, its residual negative risk does not exceed the risk tolerance, and it can fail safely, particularly if made to operate beyond its knowledge limits. Safety metrics reflect system reliability and robustness, real-time monitoring, and response times for AI system failures.",
    "MEASURE 2.7": "AI system security and resilience – as identified in the MAP function – are evaluated and documented.",
    "MEASURE 2.8": "Risks associated with transparency and accountability – as identified in the MAP function – are examined and documented.",
    "MEASURE 2.9": "The AI model is explained, validated, and documented, and AI system output is interpreted within its context – as identified in the MAP function – to inform responsible use and governance.",
    "MEASURE 2.10": "Privacy risk of the AI system – as identified in the MAP function – is examined and documented.",
    "MEASURE 2.11": "Fairness and bias – as identified in the MAP function – are evaluated and results are documented.",
    "MEASURE 2.12": "Environmental impact and sustainability of AI model training and management activities – as identified in the MAP function – are assessed and documented.",
    "MEASURE 2.13": "Effectiveness of the employed TEVV metrics and processes in the MEASURE function are evaluated and documented.",
    "MEASURE 3.1": "Approaches, personnel, and documentation are in place to regularly identify and track existing, unanticipated, and emergent AI risks based on factors such as intended and actual performance in deployed contexts.",
    "MEASURE 3.2": "Risk tracking approaches are considered for settings where AI risks are difficult to assess using currently available measurement techniques or where metrics are not yet available.",
    "MEASURE 3.3": "Feedback processes for end users and impacted communities to report problems and appeal system outcomes are established and integrated into AI system evaluation metrics.",
    "MEASURE 4.1": "Measurement approaches for identifying AI risks are connected to deployment context(s) and informed through consultation with domain experts and other end users. Approaches are documented.",
    "MEASURE 4.2": "Measurement results regarding AI system trustworthiness in deployment context(s) and across the AI lifecycle are informed by input from domain experts and relevant AI actors to validate whether the system is performing consistently as intended. Results are documented.",
    "MEASURE 4.3": "Measurable performance improvements or declines based on consultations with relevant AI actors, including affected communities, and field data about context-relevant risks and trustworthiness characteristics are identified and documented.",
    "MANAGE 1.1": "A determination is made as to whether the AI system achieves its intended purposes and stated objectives and whether its development or deployment should proceed.",
    "MANAGE 1.2": "Treatment of documented AI risks is prioritized based on impact, likelihood, and available resources or methods.",
    "MANAGE 1.3": "Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.",
    "MANAGE 1.4": "Negative residual risks (defined as the sum of all unmitigated risks) to both downstream acquirers of AI systems and end users are documented.",
    "MANAGE 2.1": "Resources required to manage AI risks are taken into account – along with viable non-AI alternative systems, approaches, or methods – to reduce the magnitude or likelihood of potential impacts.",
    "MANAGE 2.2": "Mechanisms are in place and applied to sustain the value of deployed AI systems.",
    "MANAGE 2.3": "Procedures are followed to respond to and recover from a previously unknown risk when it is identified.",
    "MANAGE 2.4": "Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.",
    "MANAGE 3.1": "AI risks and benefits from third-party resources are regularly monitored, and risk controls are applied and documented.",
    "MANAGE 3.2": "Pre-trained models which are used for development are monitored as part of AI system regular monitoring and maintenance.",
    "MANAGE 4.1": "Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and other relevant AI actors, appeal and override, decommissioning, incident response, recovery, and change management.",
    "MANAGE 4.2": "Measurable activities for continual improvements are integrated into AI system updates and include regular engagement with interested parties, including relevant AI actors.",
    "MANAGE 4.3": "Incidents and errors are communicated to relevant AI actors, including affected communities. Processes for tracking, responding to, and recovering from incidents and errors are followed and documented.",
}


def cid(label: str) -> str:
    """'GOVERN 1.1' → 'govern-1.1' (OSCAL control id)."""
    fn, num = label.split(" ")
    return f"{fn.lower()}-{num}"


# ─────────────────────────────────────────────────────────────────────────
# 2. 플랫폼 통제 컴포넌트
# ─────────────────────────────────────────────────────────────────────────
COMPONENTS = {
    "cicd": (
        "CI/CD Pipeline (GitHub Actions)",
        "service",
        "lint(black/ruff/mypy)→test(pytest)→CodeQL→dependency-review CI 게이트. .github/workflows/ci.yml.",
    ),
    "airedteam": (
        "AI Red Team Gate (PyRIT/ATLAS)",
        "service",
        "AI 시스템 적대 견고성 게이트. benchmarks/run_atlas_redteam.py, run_redteam_skeleton.py, check_gates.py. 트랙 A(PR 차단)+B(나이틀리).",
    ),
    "supplychain": (
        "Supply Chain Integrity",
        "service",
        "SBOM(Syft)·서명(cosign)·SLSA provenance·Actions SHA 핀·OIDC. SCA(dependency-review/Trivy).",
    ),
    "deploy": (
        "Deployment & GitOps (AKS/ArgoCD)",
        "service",
        "ArgoCD GitOps, AKS 트랙 A/B, Argo Rollouts Canary 자동 분석/롤백. deploy/.",
    ),
    "observability": (
        "Observability (Prometheus/Grafana)",
        "service",
        "DORA + AI-SOC 메트릭(agent latency, 토큰비용, RAGAS faithfulness/relevancy, 트리아지 정확도). deploy/monitoring/.",
    ),
    "guardrails": (
        "Runtime Defense Guardrails",
        "software",
        "정책 등급 하한, MemoryReadGate 출처(서명)검증, RAG 포이즌 폐기. core/experience.py, agents/.",
    ),
    "governance": (
        "Governance & Policy",
        "policy",
        "CLAUDE.md, .claude/rules/python-conventions.md, docs/adr/, CI/CD 하네스, CODEOWNERS(계획).",
    ),
    "incident": (
        "Incident Response",
        "process",
        "장애 사후분석(타임라인→RCA→영향→재발방지) + 배포 실패/롤백 알림. incident-postmortem 하네스.",
    ),
}

# ─────────────────────────────────────────────────────────────────────────
# 3. 통제 매핑 — (서브카테고리, 상태, 컴포넌트들, 서술, 증거, trustworthy)
#    상태: implemented | partial | planned
# ─────────────────────────────────────────────────────────────────────────
M = list[tuple]
MAPPINGS: M = [
    # GOVERN
    (
        "GOVERN 1.1",
        "partial",
        ["governance"],
        "방산 컨텍스트의 법·규제(공급망 SSDF/800-204D) 요건을 보안 스킬에 매핑. 정식 법규 인벤토리는 미완.",
        ["docs/", ".claude/skills/pipeline-security-gates/skill.md"],
        ["accountable-transparent"],
    ),
    (
        "GOVERN 1.2",
        "partial",
        ["governance"],
        "trustworthy AI 특성을 코딩/보안 규약에 부분 통합. 전사 정책 문서화는 진행 중.",
        ["CLAUDE.md", ".claude/rules/python-conventions.md"],
        ["accountable-transparent"],
    ),
    (
        "GOVERN 1.4",
        "partial",
        ["governance", "cicd"],
        "리스크 관리 프로세스를 게이트(품질/보안/AI레드팀)와 ADR로 투명화. 리스크 우선순위 정책은 부분.",
        ["docs/adr/", ".claude/HARNESS.md"],
        ["accountable-transparent"],
    ),
    (
        "GOVERN 1.6",
        "planned",
        ["governance"],
        "AI 시스템(에이전트/모델) 인벤토리 메커니즘 미구축. POA&M 항목.",
        [],
        ["accountable-transparent"],
    ),
    (
        "GOVERN 2.1",
        "partial",
        ["governance"],
        "하네스 에이전트별 역할 정의로 책임 경계 명확화. CODEOWNERS·승인 권한 매트릭스는 계획.",
        [".claude/agents/"],
        ["accountable-transparent"],
    ),
    (
        "GOVERN 4.3",
        "implemented",
        ["airedteam", "incident", "cicd"],
        "AI 테스트(레드팀 캠페인)·인시던트 식별(사후분석)·정보공유(SBOM/리포트) 관행 확립.",
        ["benchmarks/run_atlas_redteam.py", ".claude/agents/ai-redteam-engineer.md"],
        ["secure-resilient", "safe"],
    ),
    (
        "GOVERN 6.1",
        "implemented",
        ["supplychain"],
        "서드파티 SW/데이터 공급망 리스크를 SCA·SBOM·라이선스 검사로 통제.",
        [".claude/skills/pipeline-security-gates/skill.md", ".github/workflows/ci.yml"],
        ["secure-resilient"],
    ),
    (
        "GOVERN 6.2",
        "partial",
        ["supplychain", "incident"],
        "서드파티 장애 대비 롤백/대체 경로 일부. 고위험 third-party 모델 비상계획은 부분.",
        ["deploy/argocd/"],
        ["secure-resilient"],
    ),
    # MAP
    (
        "MAP 1.1",
        "partial",
        ["governance"],
        "방산 UAV SOC 의도/맥락/사용자를 문서로 정의. 정식 영향분석은 부분.",
        ["README.md", "docs/"],
        ["valid-reliable"],
    ),
    (
        "MAP 2.1",
        "implemented",
        ["governance"],
        "LangGraph 에이전트 태스크/방법(트리아지·조사·대응) 정의·문서화.",
        ["agents/", "docs/adr/0002-autonomous-self-improving-blue-soc.md"],
        ["valid-reliable"],
    ),
    (
        "MAP 3.5",
        "partial",
        ["deploy", "guardrails"],
        "human oversight = prod 수동 승인 게이트 + 정책 하한. 절차 정식 평가는 부분.",
        ["deploy/", ".claude/skills/deployment-strategies/skill.md"],
        ["accountable-transparent"],
    ),
    (
        "MAP 4.1",
        "partial",
        ["supplychain"],
        "서드파티 데이터/SW 기술·법적 리스크 매핑(SCA/라이선스). 정식 문서화 진행.",
        [".github/workflows/ci.yml"],
        ["secure-resilient"],
    ),
    (
        "MAP 4.2",
        "implemented",
        ["airedteam", "guardrails"],
        "서드파티 AI(LLM/RAG) 포함 컴포넌트 내부 통제 식별: 게이트·가드레일·출처검증.",
        ["core/experience.py", "benchmarks/run_redteam_skeleton.py"],
        ["secure-resilient"],
    ),
    (
        "MAP 5.1",
        "partial",
        ["airedteam"],
        "공격 시나리오(S1~S11, ATT&CK/ATLAS)로 영향 가능성·규모 일부 특성화.",
        ["data/mitre_attack_graph.yaml", "notion-kanban/"],
        ["safe"],
    ),
    # MEASURE
    (
        "MEASURE 1.1",
        "implemented",
        ["airedteam", "observability"],
        "AI 리스크 측정 지표(공격성공률·FP재발률·RAGAS) 선정·구현, 최우선 리스크부터.",
        ["benchmarks/", "docs/benchmarks-ci.md"],
        ["valid-reliable", "secure-resilient"],
    ),
    (
        "MEASURE 1.2",
        "partial",
        ["observability"],
        "지표 적절성/통제 효과를 벤치 추세로 평가. 정기 갱신 절차는 부분.",
        ["benchmarks/run_kpi.py"],
        ["valid-reliable"],
    ),
    (
        "MEASURE 2.1",
        "implemented",
        ["cicd", "airedteam"],
        "테스트셋·지표·도구(PyRIT/Garak/pytest)를 TEVV로 문서화.",
        ["benchmarks/README.md", ".claude/skills/ai-red-teaming/skill.md"],
        ["valid-reliable"],
    ),
    (
        "MEASURE 2.3",
        "implemented",
        ["cicd", "observability"],
        "성능/보증 기준을 정량 측정(라우팅 정확도·Recall@5·MRR), 배포 유사 조건에서.",
        ["benchmarks/run_benchmarks.py"],
        ["valid-reliable"],
    ),
    (
        "MEASURE 2.4",
        "implemented",
        ["observability"],
        "프로덕션에서 시스템 기능·행동 모니터링(Prometheus ServiceMonitor + Grafana).",
        [
            "deploy/monitoring/servicemonitor.yaml",
            "deploy/monitoring/grafana-dashboard.yaml",
        ],
        ["valid-reliable"],
    ),
    (
        "MEASURE 2.5",
        "partial",
        ["cicd"],
        "유효성·신뢰성 데모(벤치)와 일반화 한계 일부 문서화. LLM 연동 RAGAS 확대 진행.",
        ["benchmarks/"],
        ["valid-reliable"],
    ),
    (
        "MEASURE 2.6",
        "partial",
        ["guardrails", "airedteam"],
        "안전 평가: 정책 하한으로 fail-safe(등급 미하향), 잔여 리스크 추적. 정기 안전평가 정식화는 부분.",
        ["benchmarks/run_redteam_skeleton.py", "core/experience.py"],
        ["safe"],
    ),
    (
        "MEASURE 2.7",
        "implemented",
        ["airedteam", "supplychain"],
        "보안·복원력 평가·문서화: ATLAS 적대 벤치(robust vs naive) + 공급망 무결성.",
        ["benchmarks/run_atlas_redteam.py", "benchmarks/results/atlas_redteam.json"],
        ["secure-resilient"],
    ),
    (
        "MEASURE 2.9",
        "partial",
        ["guardrails"],
        "트리아지 판정 근거·검증(결정론 judge)으로 설명/해석 일부. 정식 모델 설명서는 부분.",
        ["agents/validation_agent.py"],
        ["explainable-interpretable"],
    ),
    (
        "MEASURE 3.1",
        "implemented",
        ["observability", "airedteam"],
        "기존/신규/돌발 리스크를 정기 추적: 나이틀리 레드팀 캠페인 + Grafana 시계열.",
        ["docs/benchmarks-ci.md"],
        ["secure-resilient"],
    ),
    (
        "MEASURE 3.2",
        "partial",
        ["airedteam"],
        "측정 곤란 영역(T0015 미믹리)을 게이트 아닌 추세 감시로 추적.",
        ["benchmarks/run_atlas_redteam.py"],
        ["secure-resilient"],
    ),
    (
        "MEASURE 4.1",
        "partial",
        ["observability"],
        "측정 접근을 배포 맥락에 연결. 도메인 전문가 협의 정식화는 부분.",
        ["docs/benchmarks-ci.md"],
        ["valid-reliable"],
    ),
    (
        "MEASURE 4.2",
        "partial",
        ["observability"],
        "신뢰성 측정 결과를 LLM-as-Judge 등으로 검증. 전문가 입력 정식 절차는 부분.",
        ["benchmarks/run_kpi.py"],
        ["valid-reliable"],
    ),
    # MANAGE
    (
        "MANAGE 1.2",
        "partial",
        ["airedteam", "cicd"],
        "문서화된 리스크를 게이트 차단정책(CVSS/임계)으로 우선순위화. 통합 리스크 레지스터는 계획.",
        ["docs/benchmarks-ci.md"],
        ["secure-resilient"],
    ),
    (
        "MANAGE 1.3",
        "implemented",
        ["cicd", "airedteam"],
        "고우선 리스크 대응을 게이트 차단 + POA&M으로 계획·문서화(완화/회피).",
        ["benchmarks/check_gates.py"],
        ["secure-resilient"],
    ),
    (
        "MANAGE 2.3",
        "partial",
        ["deploy", "incident"],
        "미지의 리스크 대응/복구를 자동 롤백·사후분석으로. 정식 절차 문서화는 부분.",
        ["deploy/argocd/", ".claude/agents/pipeline-reviewer.md"],
        ["secure-resilient"],
    ),
    (
        "MANAGE 2.4",
        "implemented",
        ["deploy", "guardrails"],
        "이상 행동 시스템 비활성화: Argo Rollouts 자동 중단/롤백, 정책 하한으로 강등 차단.",
        ["deploy/argocd/", ".claude/skills/deployment-strategies/skill.md"],
        ["safe", "secure-resilient"],
    ),
    (
        "MANAGE 3.1",
        "implemented",
        ["supplychain"],
        "서드파티 리스크 정기 모니터링: dependency-review, Trivy, Dependabot SHA 갱신.",
        [".github/workflows/ci.yml"],
        ["secure-resilient"],
    ),
    (
        "MANAGE 3.2",
        "partial",
        ["observability", "supplychain"],
        "사전학습 모델(Azure OpenAI) 버전/행동 모니터링 일부. 정식 모델 모니터링 계획.",
        ["deploy/monitoring/"],
        ["valid-reliable"],
    ),
    (
        "MANAGE 4.1",
        "implemented",
        ["observability", "incident"],
        "배포 후 모니터링 계획 구현: 메트릭·알림·인시던트 대응·변경관리(GitOps).",
        ["deploy/monitoring/", "deploy/argocd/"],
        ["valid-reliable", "safe"],
    ),
    (
        "MANAGE 4.3",
        "implemented",
        ["incident", "observability"],
        "인시던트/오류 소통·추적: 사후분석 하네스 + Slack/PagerDuty 알림, 추적·복구 절차.",
        [".claude/agents/monitoring-specialist.md"],
        ["safe"],
    ),
]

TRUSTWORTHY = {
    "valid-reliable": "Valid and reliable",
    "safe": "Safe",
    "secure-resilient": "Secure and resilient",
    "accountable-transparent": "Accountable and transparent",
    "explainable-interpretable": "Explainable and interpretable",
    "privacy-enhanced": "Privacy-enhanced",
    "fair": "Fair with harmful bias managed",
}
STATUS_OSCAL = {
    "implemented": "implemented",
    "partial": "partial",
    "planned": "planned",
}


# ─────────────────────────────────────────────────────────────────────────
# 4. OSCAL 빌더
# ─────────────────────────────────────────────────────────────────────────
def metadata(title: str, seed: str) -> dict:
    return {
        "title": title,
        "last-modified": NOW,
        "version": "1.0.0",
        "oscal-version": OSCAL_VERSION,
        "roles": [{"id": "owner", "title": "UAV AI SOC Platform Team"}],
        "parties": [
            {
                "uuid": u("party-soc-team"),
                "type": "organization",
                "name": "UAV AI SOC Platform Team",
            }
        ],
    }


def build_catalog() -> dict:
    groups = []
    for fn, fdesc in FUNCTIONS.items():
        cat_groups = []
        cats = [c for c in CATEGORIES if c.startswith(fn + " ")]
        for cat in cats:
            controls = []
            subs = [s for s in SUBCATS if s.startswith(cat + ".")]
            # 숫자 정렬
            subs.sort(key=lambda s: int(s.split(".")[1]))
            for sub in subs:
                controls.append(
                    {
                        "id": cid(sub),
                        "title": sub,
                        "parts": [
                            {
                                "id": cid(sub) + "_smt",
                                "name": "statement",
                                "prose": SUBCATS[sub],
                            }
                        ],
                    }
                )
            cat_groups.append(
                {
                    "id": cid(cat),
                    "title": cat,
                    "parts": [
                        {
                            "id": cid(cat) + "_smt",
                            "name": "statement",
                            "prose": CATEGORIES[cat],
                        }
                    ],
                    "controls": controls,
                }
            )
        groups.append(
            {
                "id": fn.lower(),
                "title": fn,
                "parts": [
                    {"id": fn.lower() + "_smt", "name": "overview", "prose": fdesc}
                ],
                "groups": cat_groups,
            }
        )
    return {
        "catalog": {
            "uuid": u("catalog"),
            "metadata": metadata("NIST AI RMF 1.0 — OSCAL Control Catalog", "catalog"),
            "groups": groups,
            "back-matter": {
                "resources": [
                    {
                        "uuid": u("res-airmf"),
                        "title": "NIST AI 100-1 — Artificial Intelligence Risk Management Framework (AI RMF 1.0)",
                        "rlinks": [
                            {
                                "href": "https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf",
                                "media-type": "application/pdf",
                            }
                        ],
                    }
                ]
            },
        }
    }


def mapped_ids() -> list[str]:
    return [m[0] for m in MAPPINGS]


def build_profile() -> dict:
    ids = [cid(x) for x in mapped_ids()]
    return {
        "profile": {
            "uuid": u("profile"),
            "metadata": metadata(
                "UAV AI SOC — NIST AI RMF Tailored Profile", "profile"
            ),
            "imports": [
                {
                    "href": "../catalog/nist-ai-rmf-catalog.json",
                    "include-controls": [{"with-ids": ids}],
                }
            ],
            "merge": {"as-is": True},
        }
    }


def build_component_definition() -> dict:
    # 컴포넌트별 통제 역매핑
    by_comp: dict[str, list[tuple]] = {k: [] for k in COMPONENTS}
    for sub, status, comps, narr, evi, tw in MAPPINGS:
        for c in comps:
            by_comp[c].append((sub, status, narr, tw))
    components = []
    for key, (title, ctype, desc) in COMPONENTS.items():
        impls = []
        if by_comp[key]:
            reqs = []
            for sub, status, narr, tw in by_comp[key]:
                reqs.append(
                    {
                        "uuid": u(f"compreq-{key}-{sub}"),
                        "control-id": cid(sub),
                        "description": narr,
                        "props": [
                            {
                                "name": "implementation-status",
                                "value": STATUS_OSCAL[status],
                            }
                        ],
                    }
                )
            impls.append(
                {
                    "uuid": u(f"compimpl-{key}"),
                    "source": "../profile/uav-soc-ai-rmf-profile.json",
                    "description": f"{title} 가 충족하는 AI RMF 통제.",
                    "implemented-requirements": reqs,
                }
            )
        components.append(
            {
                "uuid": u(f"comp-{key}"),
                "type": ctype,
                "title": title,
                "description": desc,
                **({"control-implementations": impls} if impls else {}),
            }
        )
    return {
        "component-definition": {
            "uuid": u("compdef"),
            "metadata": metadata(
                "UAV AI SOC — Platform Components (AI RMF Implementation)", "compdef"
            ),
            "components": components,
        }
    }


def build_ssp() -> dict:
    comp_uuid = {k: u(f"comp-{k}") for k in COMPONENTS}
    # this-system 컴포넌트 필수
    sys_components = [
        {
            "uuid": u("comp-this-system"),
            "type": "this-system",
            "title": "UAV AI SOC Platform",
            "description": "방산 UAV 보안 SaaS — LangGraph 멀티에이전트 + Azure Sentinel AI SOC.",
            "status": {"state": "operational"},
        }
    ]
    for key, (title, ctype, desc) in COMPONENTS.items():
        sys_components.append(
            {
                "uuid": comp_uuid[key],
                "type": ctype,
                "title": title,
                "description": desc,
                "status": {"state": "operational"},
            }
        )
    impl_reqs = []
    for sub, status, comps, narr, evi, tw in MAPPINGS:
        by_components = [
            {
                "component-uuid": comp_uuid[c],
                "uuid": u(f"bc-{sub}-{c}"),
                "description": narr,
            }
            for c in comps
        ]
        props = [{"name": "implementation-status", "value": STATUS_OSCAL[status]}]
        for t in tw:
            props.append(
                {
                    "name": "trustworthy-characteristic",
                    "value": t,
                    "ns": "https://uav-ai-soc/ns/airmf",
                }
            )
        links = [{"href": "#" + u("res-" + e), "rel": "reference"} for e in evi]
        impl_reqs.append(
            {
                "uuid": u(f"ir-{sub}"),
                "control-id": cid(sub),
                "props": props,
                "statements": [
                    {
                        "statement-id": cid(sub) + "_smt",
                        "uuid": u(f"stmt-{sub}"),
                        "by-components": by_components,
                    }
                ],
                **({"links": links} if links else {}),
            }
        )
    # back-matter 증거 리소스
    evidences = sorted({e for m in MAPPINGS for e in m[4]})
    resources = [
        {
            "uuid": u("res-" + e),
            "title": e,
            "rlinks": [{"href": e}],
        }
        for e in evidences
    ]
    return {
        "system-security-plan": {
            "uuid": u("ssp"),
            "metadata": metadata("UAV AI SOC — System Security Plan (AI RMF)", "ssp"),
            "import-profile": {"href": "../profile/uav-soc-ai-rmf-profile.json"},
            "system-characteristics": {
                "system-ids": [{"id": "uav-ai-soc"}],
                "system-name": "UAV AI SOC Platform",
                "description": "방산 UAV 보안 SaaS. LangGraph 멀티에이전트 + Azure Sentinel + GraphRAG, AKS/ArgoCD 배포.",
                "security-sensitivity-level": "high",
                "system-information": {
                    "information-types": [
                        {
                            "uuid": u("info-soc"),
                            "title": "Security operations & threat intelligence",
                            "description": "UAV 위협 탐지·트리아지·대응 데이터.",
                        }
                    ]
                },
                "security-impact-level": {
                    "security-objective-confidentiality": "high",
                    "security-objective-integrity": "high",
                    "security-objective-availability": "high",
                },
                "status": {"state": "operational"},
                "authorization-boundary": {
                    "description": "AKS 클러스터 + GitHub Actions CI/CD + ArgoCD GitOps 범위."
                },
            },
            "system-implementation": {
                "users": [
                    {
                        "uuid": u("user-soc-analyst"),
                        "title": "SOC Analyst / Platform Operator",
                        "role-ids": ["owner"],
                    }
                ],
                "components": sys_components,
            },
            "control-implementation": {
                "description": "AI RMF 맞춤 프로파일에 대한 구현 현황. 상태 prop = implemented/partial/planned.",
                "implemented-requirements": impl_reqs,
            },
        }
    }


def build_poam() -> dict:
    items = []
    for sub, status, comps, narr, evi, tw in MAPPINGS:
        if status == "implemented":
            continue
        risk = "높음" if status == "planned" else "중간"
        milestones = (
            "정식 절차/문서 수립 → 게이트화/자동화 → 정기 검토 등록"
            if status == "partial"
            else "설계 → 구현 → 게이트/모니터링 통합"
        )
        items.append(
            {
                "uuid": u(f"poam-{sub}"),
                "title": f"[{sub}] {SUBCATS[sub][:60]}…",
                "description": f"현황({status}): {narr}  | 잔여 리스크: {risk}",
                "props": [
                    {"name": "implementation-status", "value": STATUS_OSCAL[status]},
                    {"name": "risk", "value": risk},
                ],
                "related-observations": [{"observation-uuid": u(f"obs-{sub}")}],
                "remediation-tracking": {
                    "tracking-entries": [
                        {
                            "uuid": u(f"track-{sub}"),
                            "date-time-stamp": NOW,
                            "title": "초기 등록",
                            "description": milestones,
                        }
                    ]
                },
            }
        )
    observations = []
    for sub, status, comps, narr, evi, tw in MAPPINGS:
        if status == "implemented":
            continue
        observations.append(
            {
                "uuid": u(f"obs-{sub}"),
                "description": f"{sub} 구현 갭({status}).",
                "methods": ["EXAMINE"],
                "collected": NOW,
            }
        )
    return {
        "plan-of-action-and-milestones": {
            "uuid": u("poam"),
            "metadata": metadata("UAV AI SOC — POA&M (AI RMF Gaps)", "poam"),
            "import-ssp": {"href": "../ssp/uav-soc-ssp.json"},
            "observations": observations,
            "poam-items": items,
        }
    }


# ─────────────────────────────────────────────────────────────────────────
# 5. 대시보드 데이터
# ─────────────────────────────────────────────────────────────────────────
def build_dashboard_data() -> dict:
    mp = {m[0]: m for m in MAPPINGS}
    controls = []
    for sub, statement in SUBCATS.items():
        fn = sub.split(" ")[0]
        cat = sub.rsplit(".", 1)[0]
        if sub in mp:
            _, status, comps, narr, evi, tw = mp[sub]
            controls.append(
                {
                    "id": cid(sub),
                    "label": sub,
                    "function": fn,
                    "category": cat,
                    "title": statement,
                    "status": status,
                    "components": [COMPONENTS[c][0] for c in comps],
                    "narrative": narr,
                    "evidence": evi,
                    "trustworthy": [TRUSTWORTHY[t] for t in tw],
                }
            )
        else:
            controls.append(
                {
                    "id": cid(sub),
                    "label": sub,
                    "function": fn,
                    "category": cat,
                    "title": statement,
                    "status": "not-addressed",
                    "components": [],
                    "narrative": "",
                    "evidence": [],
                    "trustworthy": [],
                }
            )
    summary = {"total": len(SUBCATS)}
    for st in ["implemented", "partial", "planned", "not-addressed"]:
        summary[st] = sum(1 for c in controls if c["status"] == st)
    summary["in_profile"] = len(MAPPINGS)
    by_fn = {}
    for fn in FUNCTIONS:
        fc = [c for c in controls if c["function"] == fn]
        by_fn[fn] = {
            "total": len(fc),
            "implemented": sum(1 for c in fc if c["status"] == "implemented"),
            "partial": sum(1 for c in fc if c["status"] == "partial"),
            "planned": sum(1 for c in fc if c["status"] == "planned"),
        }
    return {
        "generated": NOW,
        "oscal_version": OSCAL_VERSION,
        "summary": summary,
        "by_function": by_fn,
        "controls": controls,
    }


# ─────────────────────────────────────────────────────────────────────────
def write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  ✓ {path}")


def main() -> None:
    out = Path(sys.argv[1]).resolve()
    print(f"OSCAL 생성 → {out}")
    write_json(out / "catalog" / "nist-ai-rmf-catalog.json", build_catalog())
    write_json(out / "profile" / "uav-soc-ai-rmf-profile.json", build_profile())
    write_json(
        out / "component-definition" / "uav-soc-components.json",
        build_component_definition(),
    )
    write_json(out / "ssp" / "uav-soc-ssp.json", build_ssp())
    write_json(out / "poam" / "uav-soc-poam.json", build_poam())
    data = build_dashboard_data()
    dpath = out / "dashboard" / "data.js"
    dpath.parent.mkdir(parents=True, exist_ok=True)
    dpath.write_text(
        "window.OSCAL_DATA = " + json.dumps(data, ensure_ascii=False, indent=2) + ";",
        encoding="utf-8",
    )
    print(f"  ✓ {dpath}")
    print(
        f"\n요약: 전체 {data['summary']['total']}개 / 프로파일 {data['summary']['in_profile']}개 "
        f"(구현 {data['summary']['implemented']}, 부분 {data['summary']['partial']}, "
        f"계획 {data['summary']['planned']})"
    )


if __name__ == "__main__":
    main()
