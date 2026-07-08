window.OSCAL_DATA = {
  "generated": "2026-06-28T14:34:55+00:00",
  "oscal_version": "1.1.2",
  "summary": {
    "total": 72,
    "implemented": 15,
    "partial": 19,
    "planned": 1,
    "not-addressed": 37,
    "in_profile": 35
  },
  "by_function": {
    "GOVERN": {
      "total": 19,
      "implemented": 2,
      "partial": 5,
      "planned": 1
    },
    "MAP": {
      "total": 18,
      "implemented": 2,
      "partial": 4,
      "planned": 0
    },
    "MEASURE": {
      "total": 22,
      "implemented": 6,
      "partial": 7,
      "planned": 0
    },
    "MANAGE": {
      "total": 13,
      "implemented": 5,
      "partial": 3,
      "planned": 0
    }
  },
  "controls": [
    {
      "id": "govern-1.1",
      "label": "GOVERN 1.1",
      "function": "GOVERN",
      "category": "GOVERN 1",
      "title": "Legal and regulatory requirements involving AI are understood, managed, and documented.",
      "status": "partial",
      "components": [
        "Governance & Policy"
      ],
      "narrative": "방산 컨텍스트의 법·규제(공급망 SSDF/800-204D) 요건을 보안 스킬에 매핑. 정식 법규 인벤토리는 미완.",
      "evidence": [
        "docs/",
        ".claude/skills/pipeline-security-gates/skill.md"
      ],
      "trustworthy": [
        "Accountable and transparent"
      ]
    },
    {
      "id": "govern-1.2",
      "label": "GOVERN 1.2",
      "function": "GOVERN",
      "category": "GOVERN 1",
      "title": "The characteristics of trustworthy AI are integrated into organizational policies, processes, procedures, and practices.",
      "status": "partial",
      "components": [
        "Governance & Policy"
      ],
      "narrative": "trustworthy AI 특성을 코딩/보안 규약에 부분 통합. 전사 정책 문서화는 진행 중.",
      "evidence": [
        "CLAUDE.md",
        ".claude/rules/python-conventions.md"
      ],
      "trustworthy": [
        "Accountable and transparent"
      ]
    },
    {
      "id": "govern-1.3",
      "label": "GOVERN 1.3",
      "function": "GOVERN",
      "category": "GOVERN 1",
      "title": "Processes, procedures, and practices are in place to determine the needed level of risk management activities based on the organization's risk tolerance.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "govern-1.4",
      "label": "GOVERN 1.4",
      "function": "GOVERN",
      "category": "GOVERN 1",
      "title": "The risk management process and its outcomes are established through transparent policies, procedures, and other controls based on organizational risk priorities.",
      "status": "partial",
      "components": [
        "Governance & Policy",
        "CI/CD Pipeline (GitHub Actions)"
      ],
      "narrative": "리스크 관리 프로세스를 게이트(품질/보안/AI레드팀)와 ADR로 투명화. 리스크 우선순위 정책은 부분.",
      "evidence": [
        "docs/adr/",
        ".claude/HARNESS.md"
      ],
      "trustworthy": [
        "Accountable and transparent"
      ]
    },
    {
      "id": "govern-1.5",
      "label": "GOVERN 1.5",
      "function": "GOVERN",
      "category": "GOVERN 1",
      "title": "Ongoing monitoring and periodic review of the risk management process and its outcomes are planned and organizational roles and responsibilities clearly defined, including determining the frequency of periodic review.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "govern-1.6",
      "label": "GOVERN 1.6",
      "function": "GOVERN",
      "category": "GOVERN 1",
      "title": "Mechanisms are in place to inventory AI systems and are resourced according to organizational risk priorities.",
      "status": "planned",
      "components": [
        "Governance & Policy"
      ],
      "narrative": "AI 시스템(에이전트/모델) 인벤토리 메커니즘 미구축. POA&M 항목.",
      "evidence": [],
      "trustworthy": [
        "Accountable and transparent"
      ]
    },
    {
      "id": "govern-1.7",
      "label": "GOVERN 1.7",
      "function": "GOVERN",
      "category": "GOVERN 1",
      "title": "Processes and procedures are in place for decommissioning and phasing out AI systems safely and in a manner that does not increase risks or decrease the organization's trustworthiness.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "govern-2.1",
      "label": "GOVERN 2.1",
      "function": "GOVERN",
      "category": "GOVERN 2",
      "title": "Roles and responsibilities and lines of communication related to mapping, measuring, and managing AI risks are documented and are clear to individuals and teams throughout the organization.",
      "status": "partial",
      "components": [
        "Governance & Policy"
      ],
      "narrative": "하네스 에이전트별 역할 정의로 책임 경계 명확화. CODEOWNERS·승인 권한 매트릭스는 계획.",
      "evidence": [
        ".claude/agents/"
      ],
      "trustworthy": [
        "Accountable and transparent"
      ]
    },
    {
      "id": "govern-2.2",
      "label": "GOVERN 2.2",
      "function": "GOVERN",
      "category": "GOVERN 2",
      "title": "The organization's personnel and partners receive AI risk management training to enable them to perform their duties and responsibilities consistent with related policies, procedures, and agreements.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "govern-2.3",
      "label": "GOVERN 2.3",
      "function": "GOVERN",
      "category": "GOVERN 2",
      "title": "Executive leadership of the organization takes responsibility for decisions about risks associated with AI system development and deployment.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "govern-3.1",
      "label": "GOVERN 3.1",
      "function": "GOVERN",
      "category": "GOVERN 3",
      "title": "Decision-making related to mapping, measuring, and managing AI risks throughout the lifecycle is informed by a diverse team (e.g., diversity of demographics, disciplines, experience, expertise, and backgrounds).",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "govern-3.2",
      "label": "GOVERN 3.2",
      "function": "GOVERN",
      "category": "GOVERN 3",
      "title": "Policies and procedures are in place to define and differentiate roles and responsibilities for human-AI configurations and oversight of AI systems.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "govern-4.1",
      "label": "GOVERN 4.1",
      "function": "GOVERN",
      "category": "GOVERN 4",
      "title": "Organizational policies and practices are in place to foster a critical thinking and safety-first mindset in the design, development, deployment, and uses of AI systems to minimize potential negative impacts.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "govern-4.2",
      "label": "GOVERN 4.2",
      "function": "GOVERN",
      "category": "GOVERN 4",
      "title": "Organizational teams document the risks and potential impacts of the AI technology they design, develop, deploy, evaluate, and use, and they communicate about the impacts more broadly.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "govern-4.3",
      "label": "GOVERN 4.3",
      "function": "GOVERN",
      "category": "GOVERN 4",
      "title": "Organizational practices are in place to enable AI testing, identification of incidents, and information sharing.",
      "status": "implemented",
      "components": [
        "AI Red Team Gate (PyRIT/ATLAS)",
        "Incident Response",
        "CI/CD Pipeline (GitHub Actions)"
      ],
      "narrative": "AI 테스트(레드팀 캠페인)·인시던트 식별(사후분석)·정보공유(SBOM/리포트) 관행 확립.",
      "evidence": [
        "benchmarks/run_atlas_redteam.py",
        ".claude/agents/ai-redteam-engineer.md"
      ],
      "trustworthy": [
        "Secure and resilient",
        "Safe"
      ]
    },
    {
      "id": "govern-5.1",
      "label": "GOVERN 5.1",
      "function": "GOVERN",
      "category": "GOVERN 5",
      "title": "Organizational policies and practices are in place to collect, consider, prioritize, and integrate feedback from those external to the team that developed or deployed the AI system regarding the potential individual and societal impacts related to AI risks.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "govern-5.2",
      "label": "GOVERN 5.2",
      "function": "GOVERN",
      "category": "GOVERN 5",
      "title": "Mechanisms are established to enable the team that developed or deployed AI systems to regularly incorporate adjudicated feedback from relevant AI actors into system design and implementation.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "govern-6.1",
      "label": "GOVERN 6.1",
      "function": "GOVERN",
      "category": "GOVERN 6",
      "title": "Policies and procedures are in place that address AI risks associated with third-party entities, including risks of infringement of a third-party's intellectual property or other rights.",
      "status": "implemented",
      "components": [
        "Supply Chain Integrity"
      ],
      "narrative": "서드파티 SW/데이터 공급망 리스크를 SCA·SBOM·라이선스 검사로 통제.",
      "evidence": [
        ".claude/skills/pipeline-security-gates/skill.md",
        ".github/workflows/ci.yml"
      ],
      "trustworthy": [
        "Secure and resilient"
      ]
    },
    {
      "id": "govern-6.2",
      "label": "GOVERN 6.2",
      "function": "GOVERN",
      "category": "GOVERN 6",
      "title": "Contingency processes are in place to handle failures or incidents in third-party data or AI systems deemed to be high-risk.",
      "status": "partial",
      "components": [
        "Supply Chain Integrity",
        "Incident Response"
      ],
      "narrative": "서드파티 장애 대비 롤백/대체 경로 일부. 고위험 third-party 모델 비상계획은 부분.",
      "evidence": [
        "deploy/argocd/"
      ],
      "trustworthy": [
        "Secure and resilient"
      ]
    },
    {
      "id": "map-1.1",
      "label": "MAP 1.1",
      "function": "MAP",
      "category": "MAP 1",
      "title": "Intended purposes, potentially beneficial uses, context-specific laws, norms and expectations, and prospective settings in which the AI system will be deployed are understood and documented. Considerations include: the specific set or types of users along with their expectations; potential positive and negative impacts of system uses to individuals, communities, organizations, society, and the planet; assumptions and related limitations about AI system purposes, uses, and risks across the development or product AI lifecycle; and related TEVV and system metrics.",
      "status": "partial",
      "components": [
        "Governance & Policy"
      ],
      "narrative": "방산 UAV SOC 의도/맥락/사용자를 문서로 정의. 정식 영향분석은 부분.",
      "evidence": [
        "README.md",
        "docs/"
      ],
      "trustworthy": [
        "Valid and reliable"
      ]
    },
    {
      "id": "map-1.2",
      "label": "MAP 1.2",
      "function": "MAP",
      "category": "MAP 1",
      "title": "Interdisciplinary AI actors, competencies, skills, and capacities for establishing context reflect demographic diversity and broad domain and user experience expertise, and their participation is documented. Opportunities for interdisciplinary collaboration are prioritized.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "map-1.3",
      "label": "MAP 1.3",
      "function": "MAP",
      "category": "MAP 1",
      "title": "The organization's mission and relevant goals for AI technology are understood and documented.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "map-1.4",
      "label": "MAP 1.4",
      "function": "MAP",
      "category": "MAP 1",
      "title": "The business value or context of business use has been clearly defined or – in the case of assessing existing AI systems – re-evaluated.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "map-1.5",
      "label": "MAP 1.5",
      "function": "MAP",
      "category": "MAP 1",
      "title": "Organizational risk tolerances are determined and documented.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "map-1.6",
      "label": "MAP 1.6",
      "function": "MAP",
      "category": "MAP 1",
      "title": "System requirements (e.g., \"the system shall respect the privacy of its users\") are elicited from and understood by relevant AI actors. Design decisions take socio-technical implications into account to address AI risks.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "map-2.1",
      "label": "MAP 2.1",
      "function": "MAP",
      "category": "MAP 2",
      "title": "The specific tasks and methods used to implement the tasks that the AI system will support are defined (e.g., classifiers, generative models, recommenders).",
      "status": "implemented",
      "components": [
        "Governance & Policy"
      ],
      "narrative": "LangGraph 에이전트 태스크/방법(트리아지·조사·대응) 정의·문서화.",
      "evidence": [
        "agents/",
        "docs/adr/0002-autonomous-self-improving-blue-soc.md"
      ],
      "trustworthy": [
        "Valid and reliable"
      ]
    },
    {
      "id": "map-2.2",
      "label": "MAP 2.2",
      "function": "MAP",
      "category": "MAP 2",
      "title": "Information about the AI system's knowledge limits and how system output may be utilized and overseen by humans is documented. Documentation provides sufficient information to assist relevant AI actors when making decisions and taking subsequent actions.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "map-2.3",
      "label": "MAP 2.3",
      "function": "MAP",
      "category": "MAP 2",
      "title": "Scientific integrity and TEVV considerations are identified and documented, including those related to experimental design, data collection and selection (e.g., availability, representativeness, suitability), system trustworthiness, and construct validation.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "map-3.1",
      "label": "MAP 3.1",
      "function": "MAP",
      "category": "MAP 3",
      "title": "Potential benefits of intended AI system functionality and performance are examined and documented.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "map-3.2",
      "label": "MAP 3.2",
      "function": "MAP",
      "category": "MAP 3",
      "title": "Potential costs, including non-monetary costs, which result from expected or realized AI errors or system functionality and trustworthiness – as connected to organizational risk tolerance – are examined and documented.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "map-3.3",
      "label": "MAP 3.3",
      "function": "MAP",
      "category": "MAP 3",
      "title": "Targeted application scope is specified and documented based on the system's capability, established context, and AI system categorization.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "map-3.4",
      "label": "MAP 3.4",
      "function": "MAP",
      "category": "MAP 3",
      "title": "Processes for operator and practitioner proficiency with AI system performance and trustworthiness – and relevant technical standards and certifications – are defined, assessed, and documented.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "map-3.5",
      "label": "MAP 3.5",
      "function": "MAP",
      "category": "MAP 3",
      "title": "Processes for human oversight are defined, assessed, and documented in accordance with organizational policies from the GOVERN function.",
      "status": "partial",
      "components": [
        "Deployment & GitOps (AKS/ArgoCD)",
        "Runtime Defense Guardrails"
      ],
      "narrative": "human oversight = prod 수동 승인 게이트 + 정책 하한. 절차 정식 평가는 부분.",
      "evidence": [
        "deploy/",
        ".claude/skills/deployment-strategies/skill.md"
      ],
      "trustworthy": [
        "Accountable and transparent"
      ]
    },
    {
      "id": "map-4.1",
      "label": "MAP 4.1",
      "function": "MAP",
      "category": "MAP 4",
      "title": "Approaches for mapping AI technology and legal risks of its components – including the use of third-party data or software – are in place, followed, and documented, as are risks of infringement of a third party's intellectual property or other rights.",
      "status": "partial",
      "components": [
        "Supply Chain Integrity"
      ],
      "narrative": "서드파티 데이터/SW 기술·법적 리스크 매핑(SCA/라이선스). 정식 문서화 진행.",
      "evidence": [
        ".github/workflows/ci.yml"
      ],
      "trustworthy": [
        "Secure and resilient"
      ]
    },
    {
      "id": "map-4.2",
      "label": "MAP 4.2",
      "function": "MAP",
      "category": "MAP 4",
      "title": "Internal risk controls for components of the AI system, including third-party AI technologies, are identified and documented.",
      "status": "implemented",
      "components": [
        "AI Red Team Gate (PyRIT/ATLAS)",
        "Runtime Defense Guardrails"
      ],
      "narrative": "서드파티 AI(LLM/RAG) 포함 컴포넌트 내부 통제 식별: 게이트·가드레일·출처검증.",
      "evidence": [
        "core/experience.py",
        "benchmarks/run_redteam_skeleton.py"
      ],
      "trustworthy": [
        "Secure and resilient"
      ]
    },
    {
      "id": "map-5.1",
      "label": "MAP 5.1",
      "function": "MAP",
      "category": "MAP 5",
      "title": "Likelihood and magnitude of each identified impact (both potentially beneficial and harmful) based on expected use, past uses of AI systems in similar contexts, public incident reports, feedback from those external to the team that developed or deployed the AI system, or other data are identified and documented.",
      "status": "partial",
      "components": [
        "AI Red Team Gate (PyRIT/ATLAS)"
      ],
      "narrative": "공격 시나리오(S1~S11, ATT&CK/ATLAS)로 영향 가능성·규모 일부 특성화.",
      "evidence": [
        "data/mitre_attack_graph.yaml",
        "notion-kanban/"
      ],
      "trustworthy": [
        "Safe"
      ]
    },
    {
      "id": "map-5.2",
      "label": "MAP 5.2",
      "function": "MAP",
      "category": "MAP 5",
      "title": "Practices and personnel for supporting regular engagement with relevant AI actors and integrating feedback about positive, negative, and unanticipated impacts are in place and documented.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "measure-1.1",
      "label": "MEASURE 1.1",
      "function": "MEASURE",
      "category": "MEASURE 1",
      "title": "Approaches and metrics for measurement of AI risks enumerated during the MAP function are selected for implementation starting with the most significant AI risks. The risks or trustworthiness characteristics that will not – or cannot – be measured are properly documented.",
      "status": "implemented",
      "components": [
        "AI Red Team Gate (PyRIT/ATLAS)",
        "Observability (Prometheus/Grafana)"
      ],
      "narrative": "AI 리스크 측정 지표(공격성공률·FP재발률·RAGAS) 선정·구현, 최우선 리스크부터.",
      "evidence": [
        "benchmarks/",
        "docs/benchmarks-ci.md"
      ],
      "trustworthy": [
        "Valid and reliable",
        "Secure and resilient"
      ]
    },
    {
      "id": "measure-1.2",
      "label": "MEASURE 1.2",
      "function": "MEASURE",
      "category": "MEASURE 1",
      "title": "Appropriateness of AI metrics and effectiveness of existing controls are regularly assessed and updated, including reports of errors and potential impacts on affected communities.",
      "status": "partial",
      "components": [
        "Observability (Prometheus/Grafana)"
      ],
      "narrative": "지표 적절성/통제 효과를 벤치 추세로 평가. 정기 갱신 절차는 부분.",
      "evidence": [
        "benchmarks/run_kpi.py"
      ],
      "trustworthy": [
        "Valid and reliable"
      ]
    },
    {
      "id": "measure-1.3",
      "label": "MEASURE 1.3",
      "function": "MEASURE",
      "category": "MEASURE 1",
      "title": "Internal experts who did not serve as front-line developers for the system and/or independent assessors are involved in regular assessments and updates. Domain experts, users, AI actors external to the team that developed or deployed the AI system, and affected communities are consulted in support of assessments as necessary per organizational risk tolerance.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "measure-2.1",
      "label": "MEASURE 2.1",
      "function": "MEASURE",
      "category": "MEASURE 2",
      "title": "Test sets, metrics, and details about the tools used during TEVV are documented.",
      "status": "implemented",
      "components": [
        "CI/CD Pipeline (GitHub Actions)",
        "AI Red Team Gate (PyRIT/ATLAS)"
      ],
      "narrative": "테스트셋·지표·도구(PyRIT/Garak/pytest)를 TEVV로 문서화.",
      "evidence": [
        "benchmarks/README.md",
        ".claude/skills/ai-red-teaming/skill.md"
      ],
      "trustworthy": [
        "Valid and reliable"
      ]
    },
    {
      "id": "measure-2.2",
      "label": "MEASURE 2.2",
      "function": "MEASURE",
      "category": "MEASURE 2",
      "title": "Evaluations involving human subjects meet applicable requirements (including human subject protection) and are representative of the relevant population.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "measure-2.3",
      "label": "MEASURE 2.3",
      "function": "MEASURE",
      "category": "MEASURE 2",
      "title": "AI system performance or assurance criteria are measured qualitatively or quantitatively and demonstrated for conditions similar to deployment setting(s). Measures are documented.",
      "status": "implemented",
      "components": [
        "CI/CD Pipeline (GitHub Actions)",
        "Observability (Prometheus/Grafana)"
      ],
      "narrative": "성능/보증 기준을 정량 측정(라우팅 정확도·Recall@5·MRR), 배포 유사 조건에서.",
      "evidence": [
        "benchmarks/run_benchmarks.py"
      ],
      "trustworthy": [
        "Valid and reliable"
      ]
    },
    {
      "id": "measure-2.4",
      "label": "MEASURE 2.4",
      "function": "MEASURE",
      "category": "MEASURE 2",
      "title": "The functionality and behavior of the AI system and its components – as identified in the MAP function – are monitored when in production.",
      "status": "implemented",
      "components": [
        "Observability (Prometheus/Grafana)"
      ],
      "narrative": "프로덕션에서 시스템 기능·행동 모니터링(Prometheus ServiceMonitor + Grafana).",
      "evidence": [
        "deploy/monitoring/servicemonitor.yaml",
        "deploy/monitoring/grafana-dashboard.yaml"
      ],
      "trustworthy": [
        "Valid and reliable"
      ]
    },
    {
      "id": "measure-2.5",
      "label": "MEASURE 2.5",
      "function": "MEASURE",
      "category": "MEASURE 2",
      "title": "The AI system to be deployed is demonstrated to be valid and reliable. Limitations of the generalizability beyond the conditions under which the technology was developed are documented.",
      "status": "partial",
      "components": [
        "CI/CD Pipeline (GitHub Actions)"
      ],
      "narrative": "유효성·신뢰성 데모(벤치)와 일반화 한계 일부 문서화. LLM 연동 RAGAS 확대 진행.",
      "evidence": [
        "benchmarks/"
      ],
      "trustworthy": [
        "Valid and reliable"
      ]
    },
    {
      "id": "measure-2.6",
      "label": "MEASURE 2.6",
      "function": "MEASURE",
      "category": "MEASURE 2",
      "title": "The AI system is evaluated regularly for safety risks – as identified in the MAP function. The AI system to be deployed is demonstrated to be safe, its residual negative risk does not exceed the risk tolerance, and it can fail safely, particularly if made to operate beyond its knowledge limits. Safety metrics reflect system reliability and robustness, real-time monitoring, and response times for AI system failures.",
      "status": "partial",
      "components": [
        "Runtime Defense Guardrails",
        "AI Red Team Gate (PyRIT/ATLAS)"
      ],
      "narrative": "안전 평가: 정책 하한으로 fail-safe(등급 미하향), 잔여 리스크 추적. 정기 안전평가 정식화는 부분.",
      "evidence": [
        "benchmarks/run_redteam_skeleton.py",
        "core/experience.py"
      ],
      "trustworthy": [
        "Safe"
      ]
    },
    {
      "id": "measure-2.7",
      "label": "MEASURE 2.7",
      "function": "MEASURE",
      "category": "MEASURE 2",
      "title": "AI system security and resilience – as identified in the MAP function – are evaluated and documented.",
      "status": "implemented",
      "components": [
        "AI Red Team Gate (PyRIT/ATLAS)",
        "Supply Chain Integrity"
      ],
      "narrative": "보안·복원력 평가·문서화: ATLAS 적대 벤치(robust vs naive) + 공급망 무결성.",
      "evidence": [
        "benchmarks/run_atlas_redteam.py",
        "benchmarks/results/atlas_redteam.json"
      ],
      "trustworthy": [
        "Secure and resilient"
      ]
    },
    {
      "id": "measure-2.8",
      "label": "MEASURE 2.8",
      "function": "MEASURE",
      "category": "MEASURE 2",
      "title": "Risks associated with transparency and accountability – as identified in the MAP function – are examined and documented.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "measure-2.9",
      "label": "MEASURE 2.9",
      "function": "MEASURE",
      "category": "MEASURE 2",
      "title": "The AI model is explained, validated, and documented, and AI system output is interpreted within its context – as identified in the MAP function – to inform responsible use and governance.",
      "status": "partial",
      "components": [
        "Runtime Defense Guardrails"
      ],
      "narrative": "트리아지 판정 근거·검증(결정론 judge)으로 설명/해석 일부. 정식 모델 설명서는 부분.",
      "evidence": [
        "agents/validation_agent.py"
      ],
      "trustworthy": [
        "Explainable and interpretable"
      ]
    },
    {
      "id": "measure-2.10",
      "label": "MEASURE 2.10",
      "function": "MEASURE",
      "category": "MEASURE 2",
      "title": "Privacy risk of the AI system – as identified in the MAP function – is examined and documented.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "measure-2.11",
      "label": "MEASURE 2.11",
      "function": "MEASURE",
      "category": "MEASURE 2",
      "title": "Fairness and bias – as identified in the MAP function – are evaluated and results are documented.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "measure-2.12",
      "label": "MEASURE 2.12",
      "function": "MEASURE",
      "category": "MEASURE 2",
      "title": "Environmental impact and sustainability of AI model training and management activities – as identified in the MAP function – are assessed and documented.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "measure-2.13",
      "label": "MEASURE 2.13",
      "function": "MEASURE",
      "category": "MEASURE 2",
      "title": "Effectiveness of the employed TEVV metrics and processes in the MEASURE function are evaluated and documented.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "measure-3.1",
      "label": "MEASURE 3.1",
      "function": "MEASURE",
      "category": "MEASURE 3",
      "title": "Approaches, personnel, and documentation are in place to regularly identify and track existing, unanticipated, and emergent AI risks based on factors such as intended and actual performance in deployed contexts.",
      "status": "implemented",
      "components": [
        "Observability (Prometheus/Grafana)",
        "AI Red Team Gate (PyRIT/ATLAS)"
      ],
      "narrative": "기존/신규/돌발 리스크를 정기 추적: 나이틀리 레드팀 캠페인 + Grafana 시계열.",
      "evidence": [
        "docs/benchmarks-ci.md"
      ],
      "trustworthy": [
        "Secure and resilient"
      ]
    },
    {
      "id": "measure-3.2",
      "label": "MEASURE 3.2",
      "function": "MEASURE",
      "category": "MEASURE 3",
      "title": "Risk tracking approaches are considered for settings where AI risks are difficult to assess using currently available measurement techniques or where metrics are not yet available.",
      "status": "partial",
      "components": [
        "AI Red Team Gate (PyRIT/ATLAS)"
      ],
      "narrative": "측정 곤란 영역(T0015 미믹리)을 게이트 아닌 추세 감시로 추적.",
      "evidence": [
        "benchmarks/run_atlas_redteam.py"
      ],
      "trustworthy": [
        "Secure and resilient"
      ]
    },
    {
      "id": "measure-3.3",
      "label": "MEASURE 3.3",
      "function": "MEASURE",
      "category": "MEASURE 3",
      "title": "Feedback processes for end users and impacted communities to report problems and appeal system outcomes are established and integrated into AI system evaluation metrics.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "measure-4.1",
      "label": "MEASURE 4.1",
      "function": "MEASURE",
      "category": "MEASURE 4",
      "title": "Measurement approaches for identifying AI risks are connected to deployment context(s) and informed through consultation with domain experts and other end users. Approaches are documented.",
      "status": "partial",
      "components": [
        "Observability (Prometheus/Grafana)"
      ],
      "narrative": "측정 접근을 배포 맥락에 연결. 도메인 전문가 협의 정식화는 부분.",
      "evidence": [
        "docs/benchmarks-ci.md"
      ],
      "trustworthy": [
        "Valid and reliable"
      ]
    },
    {
      "id": "measure-4.2",
      "label": "MEASURE 4.2",
      "function": "MEASURE",
      "category": "MEASURE 4",
      "title": "Measurement results regarding AI system trustworthiness in deployment context(s) and across the AI lifecycle are informed by input from domain experts and relevant AI actors to validate whether the system is performing consistently as intended. Results are documented.",
      "status": "partial",
      "components": [
        "Observability (Prometheus/Grafana)"
      ],
      "narrative": "신뢰성 측정 결과를 LLM-as-Judge 등으로 검증. 전문가 입력 정식 절차는 부분.",
      "evidence": [
        "benchmarks/run_kpi.py"
      ],
      "trustworthy": [
        "Valid and reliable"
      ]
    },
    {
      "id": "measure-4.3",
      "label": "MEASURE 4.3",
      "function": "MEASURE",
      "category": "MEASURE 4",
      "title": "Measurable performance improvements or declines based on consultations with relevant AI actors, including affected communities, and field data about context-relevant risks and trustworthiness characteristics are identified and documented.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "manage-1.1",
      "label": "MANAGE 1.1",
      "function": "MANAGE",
      "category": "MANAGE 1",
      "title": "A determination is made as to whether the AI system achieves its intended purposes and stated objectives and whether its development or deployment should proceed.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "manage-1.2",
      "label": "MANAGE 1.2",
      "function": "MANAGE",
      "category": "MANAGE 1",
      "title": "Treatment of documented AI risks is prioritized based on impact, likelihood, and available resources or methods.",
      "status": "partial",
      "components": [
        "AI Red Team Gate (PyRIT/ATLAS)",
        "CI/CD Pipeline (GitHub Actions)"
      ],
      "narrative": "문서화된 리스크를 게이트 차단정책(CVSS/임계)으로 우선순위화. 통합 리스크 레지스터는 계획.",
      "evidence": [
        "docs/benchmarks-ci.md"
      ],
      "trustworthy": [
        "Secure and resilient"
      ]
    },
    {
      "id": "manage-1.3",
      "label": "MANAGE 1.3",
      "function": "MANAGE",
      "category": "MANAGE 1",
      "title": "Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.",
      "status": "implemented",
      "components": [
        "CI/CD Pipeline (GitHub Actions)",
        "AI Red Team Gate (PyRIT/ATLAS)"
      ],
      "narrative": "고우선 리스크 대응을 게이트 차단 + POA&M으로 계획·문서화(완화/회피).",
      "evidence": [
        "benchmarks/check_gates.py"
      ],
      "trustworthy": [
        "Secure and resilient"
      ]
    },
    {
      "id": "manage-1.4",
      "label": "MANAGE 1.4",
      "function": "MANAGE",
      "category": "MANAGE 1",
      "title": "Negative residual risks (defined as the sum of all unmitigated risks) to both downstream acquirers of AI systems and end users are documented.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "manage-2.1",
      "label": "MANAGE 2.1",
      "function": "MANAGE",
      "category": "MANAGE 2",
      "title": "Resources required to manage AI risks are taken into account – along with viable non-AI alternative systems, approaches, or methods – to reduce the magnitude or likelihood of potential impacts.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "manage-2.2",
      "label": "MANAGE 2.2",
      "function": "MANAGE",
      "category": "MANAGE 2",
      "title": "Mechanisms are in place and applied to sustain the value of deployed AI systems.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "manage-2.3",
      "label": "MANAGE 2.3",
      "function": "MANAGE",
      "category": "MANAGE 2",
      "title": "Procedures are followed to respond to and recover from a previously unknown risk when it is identified.",
      "status": "partial",
      "components": [
        "Deployment & GitOps (AKS/ArgoCD)",
        "Incident Response"
      ],
      "narrative": "미지의 리스크 대응/복구를 자동 롤백·사후분석으로. 정식 절차 문서화는 부분.",
      "evidence": [
        "deploy/argocd/",
        ".claude/agents/pipeline-reviewer.md"
      ],
      "trustworthy": [
        "Secure and resilient"
      ]
    },
    {
      "id": "manage-2.4",
      "label": "MANAGE 2.4",
      "function": "MANAGE",
      "category": "MANAGE 2",
      "title": "Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.",
      "status": "implemented",
      "components": [
        "Deployment & GitOps (AKS/ArgoCD)",
        "Runtime Defense Guardrails"
      ],
      "narrative": "이상 행동 시스템 비활성화: Argo Rollouts 자동 중단/롤백, 정책 하한으로 강등 차단.",
      "evidence": [
        "deploy/argocd/",
        ".claude/skills/deployment-strategies/skill.md"
      ],
      "trustworthy": [
        "Safe",
        "Secure and resilient"
      ]
    },
    {
      "id": "manage-3.1",
      "label": "MANAGE 3.1",
      "function": "MANAGE",
      "category": "MANAGE 3",
      "title": "AI risks and benefits from third-party resources are regularly monitored, and risk controls are applied and documented.",
      "status": "implemented",
      "components": [
        "Supply Chain Integrity"
      ],
      "narrative": "서드파티 리스크 정기 모니터링: dependency-review, Trivy, Dependabot SHA 갱신.",
      "evidence": [
        ".github/workflows/ci.yml"
      ],
      "trustworthy": [
        "Secure and resilient"
      ]
    },
    {
      "id": "manage-3.2",
      "label": "MANAGE 3.2",
      "function": "MANAGE",
      "category": "MANAGE 3",
      "title": "Pre-trained models which are used for development are monitored as part of AI system regular monitoring and maintenance.",
      "status": "partial",
      "components": [
        "Observability (Prometheus/Grafana)",
        "Supply Chain Integrity"
      ],
      "narrative": "사전학습 모델(Azure OpenAI) 버전/행동 모니터링 일부. 정식 모델 모니터링 계획.",
      "evidence": [
        "deploy/monitoring/"
      ],
      "trustworthy": [
        "Valid and reliable"
      ]
    },
    {
      "id": "manage-4.1",
      "label": "MANAGE 4.1",
      "function": "MANAGE",
      "category": "MANAGE 4",
      "title": "Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and other relevant AI actors, appeal and override, decommissioning, incident response, recovery, and change management.",
      "status": "implemented",
      "components": [
        "Observability (Prometheus/Grafana)",
        "Incident Response"
      ],
      "narrative": "배포 후 모니터링 계획 구현: 메트릭·알림·인시던트 대응·변경관리(GitOps).",
      "evidence": [
        "deploy/monitoring/",
        "deploy/argocd/"
      ],
      "trustworthy": [
        "Valid and reliable",
        "Safe"
      ]
    },
    {
      "id": "manage-4.2",
      "label": "MANAGE 4.2",
      "function": "MANAGE",
      "category": "MANAGE 4",
      "title": "Measurable activities for continual improvements are integrated into AI system updates and include regular engagement with interested parties, including relevant AI actors.",
      "status": "not-addressed",
      "components": [],
      "narrative": "",
      "evidence": [],
      "trustworthy": []
    },
    {
      "id": "manage-4.3",
      "label": "MANAGE 4.3",
      "function": "MANAGE",
      "category": "MANAGE 4",
      "title": "Incidents and errors are communicated to relevant AI actors, including affected communities. Processes for tracking, responding to, and recovering from incidents and errors are followed and documented.",
      "status": "implemented",
      "components": [
        "Incident Response",
        "Observability (Prometheus/Grafana)"
      ],
      "narrative": "인시던트/오류 소통·추적: 사후분석 하네스 + Slack/PagerDuty 알림, 추적·복구 절차.",
      "evidence": [
        ".claude/agents/monitoring-specialist.md"
      ],
      "trustworthy": [
        "Safe"
      ]
    }
  ]
};