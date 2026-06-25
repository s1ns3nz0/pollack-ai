# 실 시뮬(uav-sim-env) 연동·검증 결과 — 황준식 lane

> 작성: 2026-06-21 · 대상: [uav-sim-env](https://github.com/s1ns3nz0/uav-sim-env)(ArduPilot SITL)
> ↔ pollack-ai `sim_bridge` ↔ [dah-sentinel-content](https://github.com/s1ns3nz0/dah-sentinel-content)(수지 lane)
> 환경: 로컬 Docker(SITL + telemetry-tap + QGC), Ollama, RAGFlow

## 0. 한 줄 결론

실 SITL 텔레메트리로 **탐지 → 6-에이전트 SOC → 폐루프 RTB(드론 실제 복귀)** 전 고리를 검증.
그 과정에서 **수지 S1 Sentinel 룰의 사각(VelocityVariance 게이트)** 과 **실 EKF 스푸핑 시그니처**를
실측으로 확인했고, 런타임 탐지기를 그에 맞춰 보강했다.

## 1. 실 GNSS 스푸핑 시그니처 (SIM_GPS PARAM_SET 주입, 클린→스푸핑 온셋)

| 신호 | 정상 | 스푸핑 온셋 | 스푸핑 정상상태 |
|---|---|---|---|
| `PosHorizVariance` | ~0.007 | **~4.78 (급등)** | ~0.006 (흡수됨) |
| `VelocityVariance` | ~0.01 | **~0.043 (피크)** | ~0.011 |
| `EkfFlags` | 831 (0x33F) | **33599 (0x833F, GPS_GLITCHING bit15)** | 33599 유지 |
| `SatellitesVisible` | 10~14 | **5 (급감, 지속)** | 5 |
| `Eph_cm` | ~121 | (글리치 종류에 따라) | ~121 |

**핵심:** 실 ArduPilot EKF 는 일관된 GPS 글리치를 **부드럽게 흡수**한다. 잔차(PosHoriz/Vel)는
**전환(온셋/해제) 순간에만** 튀고 정상상태로 돌아간다. 반면 **GPS_GLITCHING 플래그와 위성 급감은
스푸핑 내내 지속**된다 → 가장 견고한 지속 신호.

## 2. ⚠️ 수지 S1 Sentinel 룰 사각 (`S1_GNSS_Spoofing.json`)

현재 룰: `UAVTelemetry_CL | EKF_STATUS_REPORT` 에 `series_decompose_anomalies` z-score≥3.0
**AND `PosHorizVariance>0.05` AND `VelocityVariance>0.05`** (둘 다 충족).

- 실측 온셋: PosHorizVariance ~4.78 (게이트 OK) / **VelocityVariance ~0.043 (게이트 0.05 미달)**.
- 두 조건이 **AND** 라서, VelocityVariance 게이트 때문에 **실제 스푸핑을 놓칠 수 있음**.
- 또한 룰은 가장 견고한 **EkfFlags GPS_GLITCHING 비트, SatellitesVisible 급감을 미사용**.

**제안(수지/진수 검토용):**
1. VelocityVariance 게이트 완화(예: 0.02) **또는** Pos/Vel 조건을 AND→OR.
2. 보강 조건 추가: `EkfFlags has bit 0x8000(GPS_GLITCHING)` **또는** `SatellitesVisible` 급감.
3. 게이트 0.05 는 정상 ~0.007 기준 7배로 합리적이나, **온셋이 짧아 5m make-series 평균에 희석**될 수 있음 → step/lookback 재검토.

> pollack-ai `sim_bridge/detector.py` 는 위 사각을 보완하도록 **EKF 이상(잔차 급등 OR 글리치 플래그)
> + GPS 열화(위성/Eph)** 를 **상관 윈도우**로 결합해 발화한다.

## 3. 폐루프(closed-loop) 검증 — 탐지→SOC→RTB→드론 복귀

각 고리 개별 검증 완료:
- ✅ **탐지**: 실 telemetry-tap 스트림 → `GpsSpoofDetector` 발화(PosHorizVariance 급등 + 위성 급감).
- ✅ **SOC**: 6-에이전트 그래프 → severity=h, verdict=true_positive, action=response.
- ✅ **RAG 복원력**: RAGFlow 401(아래) 시 Investigation 이 빈 컨텍스트로 강등하고 대응 계속.
- ✅ **폐루프 RTB**: `MavlinkActuator.send_rtb()` → av-mpd(5790) `MAV_CMD_NAV_RETURN_TO_LAUNCH`
  → 비행 중 드론 **GUIDED→RTL 1초 내 전환**, QGC 에서 복귀 시각화.

## 4. 환경/설정 이슈 (재현 시 주의)

- **MAVLink 진입 포트**: 외부 도구(pymavlink)는 **TCP 5790**(mavlink-router 외부 노출)로 접속.
  5760 은 SITL 1차 포트로 router 가 단독 점유 → 직접 붙으면 HEARTBEAT 안 옴.
- **Docker 기본 런타임 nvidia**: 호스트 기본 런타임이 `nvidia` 인데 `nvidia-container-runtime`
  바이너리가 없어 uav-sim-env·RAGFlow 컨테이너 기동 실패 → 각 서비스 `runtime: runc`
  override 로 우회(uav-sim-env 는 GPU 불요).
- **RAGFlow 401**: `projects/uav_soc_rag_poc/ragflow_credentials.json` 의 api_token 이
  (재기동된) RAGFlow 와 불일치 → 풀 RAG 경로는 **토큰 갱신 필요**.
- **Ollama 지연**: `.env` 기본이 `192.168.64.1:11443`(회사 PC)의 `qwen2.5:14b`. 로컬에는
  `qwen3.5:35b`(CPU·대형) 뿐이라 요약이 매우 느림 → 데모는 `sim_live_bridge.py --no-llm`
  (결정론 요약, 폐루프 결정엔 LLM 불필요)로 우회 가능.

## 5. 재현 절차 (요약)

```bash
# 시뮬 기동(GPU 불요): runc override 후
cd uav-sim-env && docker compose up -d
# 드론 이륙(GUIDED→ARM→NAV_TAKEOFF) 후
cd pollack-ai && source .venv/bin/activate
python scripts/sim_live_bridge.py --auto --no-llm   # 탐지→SOC→자동 RTB
python scripts/sim_inject_gps_spoof.py              # 다른 터미널: S1 주입
#   해제: python scripts/sim_inject_gps_spoof.py --clear
```
