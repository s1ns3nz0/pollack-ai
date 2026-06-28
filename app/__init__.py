"""배포 엔트리포인트 패키지.

- `app.hotpath`  : Deployment A(SOC 핫패스) — 경보 수신 + LangGraph 파이프라인.
- `app.learning` : Deployment B(경험/학습) — OutcomeProbe→exp 적립→RuleUpdate 루프.
- `app.health`   : 공통 헬스 엔드포인트(liveness/readiness) 라우팅.
"""
