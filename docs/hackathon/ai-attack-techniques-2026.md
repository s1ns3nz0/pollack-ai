# AI 대상 최신 공격기법 정리 (2024~2026) — 레드팀 공유용

> 팀원 공유용 리서치 메모. 실제 공개된 CVE/논문/사고 사례만 모음 (가상 시나리오 아님).
> 정리 기준: 이름·시점·핵심 메커니즘·우리 프로젝트(pollack-ai) 연관성·출처.

---

## 1. Zero-click 탈취형

### EchoLeak (CVE-2025-32711)
- **시점**: 2025.6 공개 (Aim Security)
- **대상**: Microsoft 365 Copilot
- **메커니즘**: 사용자 상호작용 없이(zero-click) 이메일 하나로 데이터 탈취. HTML 주석/흰색-on-흰색 텍스트로 숨긴 프롬프트를 이메일에 심어두면 Copilot LLM이 이를 파싱·보존. XPIA(Cross Prompt Injection Attempt) 분류기 우회 + 마크다운 참조링크로 링크 검열 회피 + 자동로딩 이미지 + Teams 프록시 악용을 체이닝해 신뢰경계를 넘어 전권 상승. CVSS 9.3.
- **왜 중요한가**: "프롬프트 인젝션 → 실제 프로덕션 시스템에서 데이터 탈취까지 간" 첫 실증 사례. S5(RAG 포이즈닝) 위협모델이 이론이 아니라는 근거로 인용 가능.
- [arXiv 논문](https://arxiv.org/html/2509.10540v1) · [Sentra 분석](https://sentra.io/blog/copilot-echoleak-prompt-injection) · [HackTheBox 분석](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability)

---

## 2. C2 / 지속성(Persistence)형

### ZombAI
- **시점**: 2024.10
- **대상**: ChatGPT
- **메커니즘**: ChatGPT 메모리에 "주기적으로 이 GitHub 이슈를 재확인해 명령을 실행하라"는 지시를 심음. 공격자는 이슈 본문만 갈아끼우면 언제든 새 명령 하달 — 합법 플랫폼(GitHub)이 C2 서버가 된 사례.

### Reprompt
- **시점**: 2026.1
- **대상**: Microsoft Copilot
- **메커니즘**: 세션 지속성 + 체인요청으로 공격자 서버에서 계속 새 프롬프트를 페치, 추론 시점에 세션을 동적으로 재작업(retask).

### SesameOp (MITRE ATLAS AML.CS0042)
- **시점**: 2026
- **메커니즘**: OpenAI Assistants API 자체를 C2 채널로 악용하는 신종 백도어 기법. 정상 API 트래픽처럼 보여서 네트워크 탐지 회피.

- **왜 중요한가**: 셋 다 "합법 플랫폼/API를 dead-drop C2로 쓴다"는 동일 패턴 — `threat_landscape_agent`처럼 주기적으로 외부 소스를 재조회하는 워커가 있다면 구조적으로 동일한 지속성 벡터가 성립 가능한지 점검할 가치 있음.
- [The Promptware Kill Chain (arXiv, 위 셋을 킬체인으로 정리)](https://arxiv.org/abs/2601.09625) · [Security Boulevard 요약](https://securityboulevard.com/2026/02/the-promptware-kill-chain/)

---

## 3. 자기복제/전파(Worm)형

### Morris II / ComPromptMized
- **시점**: 2024.3 (Cornell Tech·테크니온·Intuit)
- **메커니즘**: 최초의 GenAI 웜 개념증명. 적대적 자기복제 프롬프트를 입력(텍스트/이미지)에 심으면, 이를 처리한 에이전트가 (1) 프롬프트를 출력에 복제하고 (2) 연결된 다른 에이전트로 전파. 이메일 비서 대상 스팸·개인정보 탈취 시나리오로 실증. Gemini Pro/GPT-4/LLaVA 전부에서 성공.
- **왜 중요한가**: 6-에이전트 파이프라인처럼 LLM이 체인으로 연결된 구조에서 "한 에이전트의 오염이 몇 단계까지 전파되나"를 측정하는 지표를 만들 근거.
- [arXiv 논문](https://arxiv.org/abs/2403.02817) · [Schneier on Security 요약](https://www.schneier.com/blog/archives/2024/03/llm-prompt-injection-worm.html)

---

## 4. 공급망(Supply Chain)형

### MCP Tool Poisoning — "the mother of all AI supply chains"
- **시점**: 2026.5 공개 (OX Security)
- **메커니즘**: MCP 서버/패키지에 실려오는 툴 설명(tool description) 자체를 오염 — 사용자에겐 안 보이고 AI만 읽는 메타데이터라서 매 호출마다 조용히, 모든 세션·사용자에 걸쳐 작동. Python/TS/Java/Rust MCP 구현 전반의 구조적 취약점. 최대 약 20만 개 취약 MCP 인스턴스 발견.
- **후속**: 2026.7 Microsoft가 "포이즈닝된 MCP 툴 설명이 에이전트의 데이터 유출로 이어질 수 있다"고 별도 경고.

### LiteLLM PyPI 백도어
- **시점**: 2026.3
- **메커니즘**: 많은 에이전트 프레임워크가 쓰는 게이트웨이 패키지 LiteLLM의 백도어 버전이 PyPI에 약 3시간 게시돼 약 4.7만 회 다운로드. 자율 공격봇이 번들됨.

### Rules File Backdoor
- **메커니즘**: AI IDE 설정파일(예: `.cursorrules` 류)에 숨긴 지시를 심는 공급망 공격 — 코딩 에이전트가 그 룰파일을 신뢰된 컨텍스트로 읽는다는 가정을 악용.

- **왜 중요한가**: `_workspace`에서 하고 있는 공급망 보안 하드닝(builder 부트스트랩, cosign) 작업이 컨테이너/바이너리 무결성엔 강한데, **MCP/패키지 메타데이터 레벨 오염**은 지금 스코프 밖이에요 — 만약 pollack-ai가 MCP를 붙이게 되면(지난번 CVE MCP Server 추천 등) 이 계열이 새로운 공격표면이 됩니다.
- [MCP Tool Poisoning — ITECS](https://itecsonline.com/post/mcp-tool-poisoning-enterprise-ai-agent-security-2026) · [Microsoft 경고 — Security Boulevard](https://securityboulevard.com/2026/07/microsoft-warns-poisoned-mcp-tool-descriptions-can-make-ai-agents-leak-data/) · [TechRepublic](https://www.techrepublic.com/article/news-microsoft-mcp-tool-risk/)

---

## 5. 메모리 오염(Memory Poisoning)형

- **메커니즘**: 세션 1에서 에이전트 메모리/RAG를 오염시켜두면, 세션 10에서도 그 오염된 컨텍스트가 계속 판단에 영향을 줌 — 즉시 발현이 아니라 지연발현(sleeper) 패턴. Gemini/Azure/Bedrock 실사고 사례 존재.
- **관련 연구**: "Plant, Persist, Trigger" — LLM 에이전트 대상 sleeper attack 정식 연구.
- **왜 중요한가**: `core/experience.py`(ExperienceRecord)·`core/actors.py`(ActorProfile) 같은 장기 저장 메모리 구조가 있는데, "한 번 오염되면 몇 사이클 뒤에 터지나"는 지금 S5가 안 보는 각도예요.
- [From Untrusted Input to Trusted Memory (arXiv)](https://arxiv.org/pdf/2606.04329) · [Plant, Persist, Trigger (arXiv)](https://arxiv.org/pdf/2605.28201)

---

## 6. 물리세계(OT/사이버-물리) 연계 — UAV 팀이 제일 눈여겨볼 것

### Dragos 리포트 — 최초의 "AI 보조" OT 공격 확인 사례
- **시점**: 2026.4
- **메커니즘**: 공격자가 상용 AI 모델을 이용해 멕시코 상수도 시설의 제어시스템 경계를 자율적으로 탐색·돌파. AI가 순수 텍스트/데이터 유출을 넘어 **실제 산업제어시스템(ICS) 침투를 보조한 첫 확인 사례**.
- **왜 중요한가**: UAV도 OT/임베디드 제어시스템이라 이 사례가 제일 직접적인 유사 위협모델이에요. "AI가 정찰뿐 아니라 실시간으로 ICS 경계를 우회하는 데 쓰였다"는 게 S1~S11 시나리오의 "AI 보조 공격자" 가정에 실증 근거를 더해줍니다.
- 검색 키워드로 원문 리포트 확인 권장(Dragos 자체 발간 리포트, 공개 뉴스 커버리지로만 확인됨)

---

## 7. 참고 — 통합 프레임워크

- **The Promptware Kill Chain** (2026): 프롬프트 인젝션 기반 공격을 MITRE ATT&CK 스타일 7단계(Initial Access→Privilege Escalation→Recon→Persistence→C2→Lateral Movement→Actions on Objective)로 정리. 지금까지 36건 사고 서베이, 21건이 4단계 이상 진행. [arXiv](https://arxiv.org/abs/2601.09625)
- **MITRE ATLAS** 최신 케이스스터디에 SesameOp 등 신규 등재 진행 중. [Zenity 2026 업데이트 요약](https://zenity.io/blog/current-events/mitre-atlas-ai-security)
- **HiddenLayer 2026 AI Threat Landscape Report**: [원문](https://www.hiddenlayer.com/report-and-guide/threatreport2026)

---

## 요약 — pollack-ai 연관성 매트릭스

| 공격 | 우리 쪽 유사 컴포넌트 | 지금 방어 상태 |
|---|---|---|
| EchoLeak | Investigation의 RAG 컨텍스트 처리 | S5로 부분 커버(포이즈닝 저항) |
| ZombAI/Reprompt/SesameOp | threat_landscape_agent(주기 재조회) | 미검증 — 다중사이클 지속성 테스트 없음 |
| Morris II | 6-에이전트 체인(judge 앙상블) | judge 다양성이 구조적 완충 추정, 미실증 |
| MCP Tool Poisoning | (MCP 연동 시 신규 표면) | 해당 없음(아직 MCP 미연동) |
| Memory Poisoning | ActorProfile/ExperienceRecord | 서명·write gate 있음, sleeper 패턴 미검증 |
| Dragos OT 사례 | 전체 SOC의 실물리 대응(RTB 등) | 실 SITL 폐루프로 검증됨(S1) |
