# 시연 녹화 런북 — 레드/블루 폐루프 (uav-sim-env ↔ pollack-ai SOC)

> 구성: **로컬 QGC + 두 터미널(레드=공격 / 블루=SOC) + LLM ON(로컬 A100 Ollama)**
> 스토리: 정상 비행 중 GNSS 스푸핑(레드) → SOC 실시간 탐지·판정(블루) → 자동 RTB → 드론 복귀(QGC)

---

## 0. 화면 레이아웃 (녹화)

```
┌───────────────────────────┬───────────────────────────┐
│  브라우저: QGC (noVNC)     │  터미널 BLUE — SOC 방어    │
│  http://localhost:8080     │  sim_live_bridge.py --auto │
│  /vnc.html  (드론 지도)    ├───────────────────────────┤
│                            │  터미널 RED — 공격자       │
│                            │  sim_inject_gps_spoof.py   │
└───────────────────────────┴───────────────────────────┘
```
원격 접속이면 QGC 포트 터널: `ssh -L 8080:localhost:8080 <this-host>` 후 브라우저에서 접속.

---

## 1. 사전 준비 (녹화 시작 전)

```bash
cd ~/pollack-ai && source .venv/bin/activate

# (a) 시뮬 기동 확인 (이미 떠 있으면 생략)
docker --version >/dev/null && (cd ~/uav-sim-env && docker compose ps)

# (b) LLM 워밍업 — 첫 응답 콜드로드(~16s) 방지. 모델을 GPU 메모리에 올려둠.
curl -s http://localhost:11434/api/chat -d '{"model":"qwen2.5:14b","messages":[{"role":"user","content":"준비"}],"stream":false}' >/dev/null && echo "LLM warm ✓"

# (c) 드론 이륙 — QGC 에 드론이 50m 로 떠오르는 것 확인
python scripts/sim_takeoff.py
```
QGC(브라우저)에서 드론이 발사지점(서울 좌표)에 떠 있는지 확인 → **여기서 녹화 시작**.

---

## 2. 녹화 — 시연 진행

**① 터미널 BLUE (SOC 방어) 먼저 실행** — 정상 텔레메트리 모니터링 시작:
```bash
python scripts/sim_live_bridge.py --auto
```
> `[대기] 정상 텔레메트리 모니터링 중...` + `... 텔레메트리 N건 정상` 이 흐름.

**② 터미널 RED (공격자) — GNSS 스푸핑 주입:**
```bash
python scripts/sim_inject_gps_spoof.py
```
> `[주입] GPS 스푸핑(글리치+위성감소+정확도저하) 주입 완료.`

**③ 자동으로 일어나는 일 (블루 + QGC):**
- 블루: 수 초 내 `🚨 SOC 탐지·대응 (6-에이전트, 실 RAG/LLM)` 대시보드
  - 경보 / 탐지 신호(PosHorizVariance 급증·위성 급감) / 심각도 **h** / LLM 분석 / 판정 **true_positive** → **RTB**
  - `✅ 폐루프 작동 : MAVLink RETURN_TO_LAUNCH 송신 완료`
- QGC: 드론이 **RTL 모드로 전환되어 발사지점으로 복귀** (시각적 하이라이트)

---

## 3. 재촬영(리셋)

```bash
python scripts/sim_inject_gps_spoof.py --clear   # 스푸핑 해제(정상 복원)
python scripts/sim_takeoff.py                     # 재이륙 후 2번부터 반복
```

---

## 4. 참고 / 알려진 사항

- **LLM**: 로컬 A100 Ollama `qwen2.5:14b`(`.env` 설정). 워밍업 후 요약 ~1초.
- **RAG**: 로컬 RAGFlow 는 KB/토큰 미설정(회사 PC 에 실 KB). 데모에서는 Investigation 이
  **빈 컨텍스트로 우아하게 강등**(`RAG 검색 불가 — 빈 컨텍스트로 강등(대응 계속)`) — 이는
  "RAG 장애에도 대응 지속"이라는 **복원력 시연 포인트**로 설명 가능. 풀 RAG 데모는 회사 PC 에서.
- **HITL 버전**: `--auto` 대신 옵션 없이 실행하면 RTB 송신 전 **운용자 승인(y/N)** 프롬프트 →
  방산 HITL 시연. (녹화 시 승인 누르는 장면 연출 가능)
- **폐루프 끄기**: `--no-rtb`(권고만), **LLM 끄기**: `--no-llm`(결정론 요약).
- 포트: 공격 주입·RTB 는 `tcp:127.0.0.1:5790`(mavlink-router 외부 진입점).
