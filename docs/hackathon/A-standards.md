# A. AI 보안 표준 · 프레임워크 · 컴플라이언스

> Notion 미러 — 자동 추출. 원본: LIG D&A Hackathon

## NIST AI RMF

1. AI 시스템의 위험을 식별·평가·관리하는 **Govern · Map · Measure · Manage** 4개 함수 기반 프레임워크.
1. 신뢰성·공정성·보안·프라이버시 등 다차원 위험을 통합적으로 다룸.
1. 미국 정부·국방 채택률이 높아 평가위원에게 즉시 인용 가능.

## OWASP LLM Top 10

1. LLM 애플리케이션의 가장 흔한 10개 취약점 (Prompt Injection, Insecure Output, Data/Model Poisoning, Sensitive Info Disclosure 등).
1. 항목별 영향·완화책·테스트 시나리오 제시.
1. Red(페이로드 카탈로그) · Blue(방어 체크리스트) 양쪽 직결.

## MITRE ATLAS

1. ML/AI 시스템에 특화된 **적대 TTPs 매트릭스** — ATT&CK의 AI 버전.
1. 실제 사고·연구 기반 전술·기법 + 케이스 스터디 포함.
1. AI 위협 모델링·레드팀 시나리오 작성 표준.

## Microsoft TRiSM / PyRIT

1. MS의 generative AI 위험 식별·레드팀 자동화 도구 모음.
1. PyRIT(OSS): 자동 페이로드·다회차 공격·평가 파이프라인 내장.
1. D팀 도구로 직접 도입 가능 (Pluggable).

## MITRE ATT&CK

1. 일반 사이버 공격의 전술·기법 표준 명명체계 (14개 전술).
1. 정찰부터 영향(Impact)까지 공격 전 단계 커버.
1. 비-LLM(시스템·네트워크) 공격 영역의 백본.

## MITRE D3FEND

1. ATT&CK의 방어 쌍둥이 — **강화·탐지·격리·기만·축출** 분류.
1. 각 공격 기법에 대응되는 방어 기법 매핑 제공.
1. Blue팀 워크플로우·통제 매트릭스의 백본.

## SSDF (NIST SP 800-218)

1. 안전한 SW 개발 프레임워크 — **Prepare · Protect · Produce · Respond** 4그룹 19개 관행.
1. 미국 연방·국방 조달의 사실상 의무 표준.
1. CI/CD·공급망 통제 요구를 발표·설계 문서에 직접 인용.

## DoD DevSecOps 시리즈

1. 미국 국방부의 DevSecOps **Reference Design · Strategy · Playbook** 시리즈.
1. 컨테이너·CI/CD·SBOM·플랫폼 보안 표준 정의.
1. 국방 도메인 발표 시 인용 효과 큼.
