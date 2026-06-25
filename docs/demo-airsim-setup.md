# 사실적 3D 드론 데모 — Cosys-AirSim + ArduPilot + pollack-ai SOC

> 목표: **언리얼 기반 사실적 드론 비행**(노트북 GPU) 위에서 우리 SOC 가 실시간으로
> GPS 스푸핑을 탐지·대응(RTB)하는 영상. QGC 2D 보다 임팩트 큼.
> 핵심: SOC 는 **MAVLink 로 붙으므로**(telemetry-tap 도커 불요) AirSim 과 직결된다.

## 아키텍처 (전부 노트북에서 — 렌더·녹화 일원화)
```
[Cosys-AirSim / Unreal]  ──(AirSim API)──  [ArduPilot SITL -f airsim-copter]
   사실적 3D 드론·월드                         비행 컨트롤러 (MAVLink 노출)
                                                      │ MAVLink (udp:14550)
                                                      ▼
[pollack-ai SOC]  sim_live_bridge_mav.py --conn udpin:0.0.0.0:14550
   탐지(EKF/GPS) → 6-에이전트 SOC(RAG+LLM) → 폐루프 RTB
                                                      │
[RED] sim_inject_gps_spoof.py --conn <같은 MAVLink>  → GPS 스푸핑 주입
```
→ OBS 로 **언리얼 창**(드론 비행+이탈+복귀) + SOC 터미널을 함께 녹화.

## 셋업 (노트북, Windows 권장)
1. **Cosys-AirSim** 설치 — 유지보수 포크(원조 AirSim 은 2022 아카이브):
   `https://github.com/Cosys-Lab/Cosys-AirSim` (Unreal 5 + Blocks/환경 프로젝트)
2. **ArduPilot SITL** 설치 (`git clone ardupilot`, `Tools/environment_install`).
3. **연결**: AirSim `settings.json` 에 ArduPilot 차량 설정 후
   `sim_vehicle.py -v ArduCopter -f airsim-copter --console --map`
   → ArduPilot 가 AirSim 물리에 연결되고 **MAVLink(14550/5760) 노출**.
4. **pollack-ai** 클론 + 의존성(`uv sync` 또는 venv) + `pymavlink` 설치.
   (RAG/LLM 쓰려면 RAGFlow+Ollama 도 노트북에 두거나 `--no-llm`)

## 실행 (터미널 3개 + 언리얼 창)
```bash
# (언리얼) Cosys-AirSim 환경 실행 → 드론 스폰
# (터미널 A) ArduPilot SITL — airsim 백엔드
sim_vehicle.py -v ArduCopter -f airsim-copter --console --map
#   이륙: mode guided / arm throttle / takeoff 30   (또는 scripts/sim_takeoff.py --conn ...)

# (터미널 B) SOC — MAVLink 직결
python scripts/sim_live_bridge_mav.py --conn udpin:0.0.0.0:14550 --auto

# (터미널 C) RED — GPS 스푸핑 주입
python scripts/sim_inject_gps_spoof.py --conn udpout:127.0.0.1:14550
```
→ 언리얼에서 **드론이 항로 이탈** → SOC 가 탐지·RTB → **복귀**가 사실적 3D 로 보임.

## 임팩트 연출 팁
- **글리치 강도↑**: `sim_inject_gps_spoof.py` 의 `SIM_GPS*_GLITCH_*` 값을 키워 드론이
  **눈에 띄게 이탈**하게(예: 적 경계/금지구역 방향). 이탈→SOC 구조 대비가 핵심.
- **A/B 대조**: SOC OFF(`--no-rtb`)면 이탈해 사라짐 / SOC ON 이면 복귀 — 나란히 녹화.
- **분할 화면**: 좌=언리얼 드론, 우=SOC 대시보드(탐지 근거+RAG+LLM) + 자막.

## 주의 / 검증 필요
- **GPS 스푸핑 벡터**: ArduPilot 가 FC 라 `SIM_GPS*` PARAM_SET 이 통할 가능성 높으나,
  airsim 백엔드에서 위치가 AirSim 물리로 들어오면 글리치 반영이 다를 수 있음 → **현장 확인**.
  안 되면 대안: GUIDED 위치목표 조작(가짜 항로) 또는 **S8 온보드 인식 공격**(합성 perception,
  `sim_live_bridge_onboard.py` — 시뮬 무관하게 동작).
- AirSim↔ArduPilot 포트/`settings.json` 은 Cosys-AirSim 문서 기준으로 맞출 것.
- 우리 측 준비 완료: **MAVLink 어댑터**(`sim_bridge/mavlink_source.py`) + **MAVLink 브리지**
  (`scripts/sim_live_bridge_mav.py`) — 실 SITL MAVLink 로 탐지 동작 검증됨(이 노드).
