# S8 시연 녹화 런북 — 온보드 인식 AI 적대공격 (레드/블루 폐루프)

> 스토리: 정상 정찰 중 온보드 EO/IR 표적인식 → 레드가 적대 패치/디코이로 EO/IR
> 표적 불일치+신뢰도 이상분포 유발 → BLUE SOC 실시간 탐지·판정(severity m) →
> HITL 승인 → 자율교전 차단(LOITER hold) → 보수적 RTB(QGC 시각화).

## 0. 사전 준비

```bash
cd ~/pollack-ai && source .venv/bin/activate
# (a) 시뮬 기동 + 드론 이륙 + 정찰 배치 (S1 런북과 동일 인프라 재사용)
python scripts/sim_takeoff.py
# (선택) 전용 GPU Ollama(11435) 워밍업 — docs/demo-runbook.md 1절 참조
```

## 1. 녹화 — 진행

**① BLUE (SOC 방어) 먼저:**

```bash
python scripts/sim_live_bridge_onboard.py        # HITL 승인 버전
#   (무인 자동: --auto / 드론 미연동: --no-rtb / LLM 생략: --no-llm)
```

`[대기] 정상 인식 모니터링 중...` 확인.

**② RED (공격) 다른 터미널:**

```bash
python scripts/sim_inject_onboard_evade.py
```

→ BLUE 대시보드에 **🚨 SOC 탐지** + 탐지신호(EO/IR 불일치·신뢰도 이상분포)
+ RAG 근거 + LLM 분석 표시 → `[HITL] 자율교전 차단 후 RTB 승인? [y/N]` → `y`
→ QGC 에서 드론 정지(LOITER) 후 복귀(RTL).

## 2. 재촬영(테이크 반복)

```bash
python scripts/sim_inject_onboard_evade.py --clear   # 정상 인식 → 탐지기 재무장
```

BLUE 재시작 불요(자동 재무장). 그 뒤 ②를 다시 실행.

## 참고

- 스트림 경로 변경: `PERCEPTION_STREAM=/path/x.ndjson` 를 BLUE·RED 양쪽에 동일 지정.
- S1(GNSS) 폐루프는 `docs/demo-runbook.md` 참조.
