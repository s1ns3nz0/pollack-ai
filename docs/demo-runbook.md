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

# (b) 전용 GPU Ollama(11435) 살아있는지 확인 — RAG 임베딩(bge-m3)+요약(qwen2.5:14b) 제공.
#     (꺼져 있으면) OLLAMA_HOST=0.0.0.0:11435 CUDA_VISIBLE_DEVICES=0 ollama serve &
curl -s http://localhost:11435/api/version >/dev/null && echo "Ollama(11435) ✓"

# (c) LLM 워밍업 — 콜드로드 방지(임베딩+챗 모델 GPU 적재)
curl -s http://localhost:11435/api/embed -d '{"model":"bge-m3","input":"준비"}' >/dev/null
curl -s http://localhost:11435/api/chat -d '{"model":"qwen2.5:14b","messages":[{"role":"user","content":"준비"}],"stream":false}' >/dev/null && echo "LLM warm ✓"

# (d) 드론 이륙 — QGC 에 드론이 50m 로 떠오르는 것 확인
python scripts/sim_takeoff.py
# (선택, 극적 연출) 정찰지점으로 멀리 보내기 — 복귀가 길게 보임:
#   python scripts/sim_patrol.py     # (있으면)
```
QGC(브라우저)에서 드론이 발사지점(서울 좌표)에 떠 있는지 확인 → **여기서 녹화 시작**.

> **풀 RAG 활성**: `.env` 가 `OLLAMA_BASE_URL=http://localhost:11435` 로 설정됨. RAGFlow 에
> KB(126문서) 적재 완료 → 대시보드에 **`RAG 근거: N건`** + LLM 이 KB 근거 기반 요약.

---

## 2. 녹화 — 시연 진행

**① 터미널 BLUE (SOC 방어) 먼저 실행** — 정상 텔레메트리 모니터링 시작:
```bash
# HITL 버전(방산 강조): RTB 전 운용자 승인(y/N) 프롬프트
python scripts/sim_live_bridge.py
#   (무인 자동 버전이면 --auto 추가)
```
> `[대기] 정상 텔레메트리 모니터링 중...` + `... 텔레메트리 N건 정상` 이 흐름.
> 탐지 시 대시보드에 **`RAG 근거: 5건`** + **LLM 분석**(KB 근거 기반) 표시 후,
> HITL 이면 `[HITL] 고위험 정탐 — RTB(자동 복귀) 실행 승인? [y/N]` 프롬프트 →
> **운용자가 `y` 입력**하면 RTB 송신(이 장면이 방산 HITL 시연 포인트).

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

- **LLM**: 로컬 A100 Ollama `qwen2.5:14b`(`.env`=11435). 워밍업 후 요약 ~1초.
- **RAG(풀세팅 완료)**: 로컬 RAGFlow + bge-m3 임베딩 + KB 126문서 적재 → 탐지 시
  **`RAG 근거: 5건`**(kb/ieee_uav_attack_gps_signatures, gps_jamming_vs_spoofing 등)
  표시, LLM 이 KB 근거 기반 요약. (재세팅: `setup_ragflow.py` → `ingest_to_ragflow.py`,
  RAGFLOW_OLLAMA_BASE=http://host.docker.internal:11435 환경변수)
  · RAG 장애 시에도 빈 컨텍스트로 우아하게 강등(복원력) — 별도 시연 포인트.
- **HITL 버전**: `--auto` 대신 옵션 없이 실행하면 RTB 송신 전 **운용자 승인(y/N)** 프롬프트 →
  방산 HITL 시연. (녹화 시 승인 누르는 장면 연출 가능)
- **폐루프 끄기**: `--no-rtb`(권고만), **LLM 끄기**: `--no-llm`(결정론 요약).
- 포트: 공격 주입·RTB 는 `tcp:127.0.0.1:5790`(mavlink-router 외부 진입점).
