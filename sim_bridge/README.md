# sim_bridge — uav-sim-env ↔ SOC 연결고리

[`uav-sim-env`](https://github.com/s1ns3nz0/uav-sim-env)(ArduPilot SITL + Gazebo +
QGroundControl) 의 telemetry-tap NDJSON 스트림을 받아 이상을 탐지하고, `Alert` 로
변환해 6-에이전트 SOC 파이프라인에 투입한다. 원래 설계의 Azure Sentinel 경로를
대체하는 직접 브리지.

## 흐름

```
av-mpd(ArduPilot) ─MAVLink→ telemetry-tap ─NDJSON→ [sim_bridge] ─Alert→ 6-에이전트 SOC
   ▲ QGC(noVNC:8080)                          탐지(GpsSpoofDetector)        ▼
   └────────────────── (선택) MAVLink RTL 폐루프 ◀───────────── 결정(RTB/HITL)
```

## 구성

| 파일 | 역할 |
|---|---|
| `models.py` | `TelemetryRecord` — telemetry-tap NDJSON 키(`PosHorizVariance/Eph_cm/...`) 그대로 매핑 |
| `detector.py` | `GpsSpoofDetector` — EKF 잔차 급증 + GPS 품질저하 결합 → S1 `Alert` (Sigma `uav_gps_spoof_residual.yml` 런타임 근사) |
| `bridge.py` | `SimBridge` — 탐지 → `build_soc_graph` 실행 → `BridgeEvent`(경보+SOC결과) |
| `synth.py` | 합성 텔레메트리(정상→스푸핑 주입) — 시뮬 빌드 없이 검증용 |

## 데모 (합성, 시뮬 불요)

```bash
python scripts/sim_demo.py     # 정상비행→GPS스푸핑→탐지→6에이전트(실 RAG/LLM) 대시보드
```

## 실 시뮬 연결 (uav-sim-env 기동 후)

`synth_records`/`synth_stream` 을 telemetry-tap 실제 스트림으로 교체:

1. **파일 sink**: telemetry-tap 을 `LOG_FILE_PATH=/tap/telemetry.ndjson` 로 띄우고,
   그 파일을 tail 하며 `TelemetryRecord.from_ndjson(json.loads(line))`.
2. **MAVLink UDP**: 호스트 노출 포트(`:14552` tap 출력, `:14550` QGC 채널)를
   `pymavlink` 로 직접 구독 → 동일 `TelemetryRecord` 로 변환.

스키마가 동일하므로 `SimBridge`/탐지기/SOC 는 그대로 재사용된다.

## 공격 주입(시뮬에서)

- **S1 GNSS 스푸핑**: av-mpd SITL `SIM_GPS_*` 파라미터를 MAVLink `PARAM_SET` 으로 변조
- (확장) S4 펌웨어: pgse-stub REST `:8000` / A4 MAVLink 인젝션: `:5790`

## 폐루프(선택, 데모 임팩트)

SOC 결정(RTB)을 MAVLink `COMMAND_LONG`(MAV_CMD_NAV_RETURN_TO_LAUNCH) 으로 av-mpd 에
송신 → QGC(noVNC)에서 드론 복귀가 시각화됨. (현재 권고만 출력, 송신은 다음 단계)
