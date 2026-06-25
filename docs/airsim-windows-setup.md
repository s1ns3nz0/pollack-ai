# AirSim + ArduPilot + pollack-ai SOC — Windows 풀세팅 가이드

> 목표: 노트북(Windows+NVIDIA GPU)에서 **사실적 3D 드론**(AirSim) 비행 위에 우리 SOC가
> GPS 스푸핑 탐지→RTB. **각 단계에 ✅체크포인트** — 통과해야 다음으로.
> 막히면 그 단계의 출력/에러를 그대로 붙여주세요(제가 진단).

전체 구성:
```
AirSim(Unreal, 9002/9003) ── ArduPilot SITL(-f airsim-copter) ──MAVLink:14550── pollack-ai SOC
```

---

## STEP 1 — AirSim 환경 실행 (사전빌드 바이너리, 빌드 불요)
1. `Cosys-Lab/Cosys-AirSim`(유지보수 포크) 또는 원조 `microsoft/AirSim` **Releases** 에서
   **패키징된 환경 ZIP**(예: Blocks/AirSimNH) 다운 → 압축해제.
2. `Documents\AirSim\settings.json` 을 이 레포의 `scripts/airsim/settings.json` 내용으로 저장.
   (UDP 9003/ControlPort 9002 = ArduPilot 연결 포트)
3. 환경 실행파일(.exe) 실행 → 드론이 보이는 3D 씬.

✅ **체크포인트 1**: 실행 콘솔에 `Waiting for connection ...`(ArduPilot 대기) 또는 드론이
   스폰된 3D 화면. (settings 의 VehicleType=ArduCopter 가 적용돼야 함)

> 메모: 사전빌드 바이너리의 ArduPilot 지원 여부는 빌드/버전에 따라 다를 수 있음.
> `Waiting for connection` 이 안 뜨면 그 포크가 ArduCopter 미지원 → 알려주세요(대안 안내).

## STEP 2 — ArduPilot SITL (WSL2 권장)
Windows 의 ArduPilot SITL 은 보통 **WSL2(Ubuntu)** 에서 돌립니다.
```bash
# WSL2 Ubuntu 안에서
git clone https://github.com/ArduPilot/ardupilot --recursive
cd ardupilot && Tools/environment_install/install-prereqs-ubuntu.sh -y
. ~/.profile
# AirSim 백엔드로 SITL 기동 (AirSim 은 Windows 호스트 → WSL에서 호스트IP 지정)
Tools/autotest/sim_vehicle.py -v ArduCopter -f airsim-copter \
  --sim-address=<Windows호스트IP> --console --map
```
- `<Windows호스트IP>`: WSL에서 `cat /etc/resolv.conf | grep nameserver` 또는 `ip route | grep default` 의 IP. (WSL↔Windows 네트워크)
- settings.json 의 `LocalHostIp`/`UdpIp` 도 그 관계에 맞게(같은 머신이면 127.0.0.1, WSL이면 호스트IP) 조정 필요할 수 있음.

✅ **체크포인트 2**: ArduPilot 콘솔에 `GPS: ... ` lock + `EKF` 정상 + AirSim 콘솔이
   `Connected`. MAVProxy 맵에 드론 표시.
   이륙 테스트: `mode guided` → `arm throttle` → `takeoff 30` → AirSim 에서 드론 상승.

## STEP 3 — SOC 붙이기 (우리 코드, 검증됨)
```bash
# (WSL 또는 Windows python) pollack-ai 받기
git clone <pollack-ai-repo> && cd pollack-ai
pip install pymavlink pydantic pydantic-settings langgraph langchain-core pyyaml httpx
# MAVLink 엔드포인트는 ArduPilot 이 노출하는 GCS 포트(기본 udp 14550)
python scripts/sim_live_bridge_mav.py --conn udpin:0.0.0.0:14550 --auto --no-llm
```
- `--no-llm`: RAGFlow/Ollama 없이 빠르게(대시보드·폐루프는 그대로). 풀 RAG 원하면 노트북에
  RAGFlow+Ollama 띄우고 `--no-llm` 빼기.

✅ **체크포인트 3**: `[대기] MAVLink 텔레메트리 모니터링 중...` + `텔레메트리 N건 정상`
   카운터 증가(= 스트림 살아있음).

## STEP 4 — 공격 + 녹화
```bash
# (다른 터미널) GPS 스푸핑 주입 — ArduPilot MAVLink 로
python scripts/sim_inject_gps_spoof.py --conn udpout:127.0.0.1:14550
```
- AirSim 에서 드론이 **항로 이탈** → SOC 가 탐지 → **RTB 복귀**.
- **OBS** 로 AirSim 창 + SOC 터미널 동시 녹화.

✅ **체크포인트 4**: SOC 에 `🚨 SOC 탐지·대응` 대시보드 + AirSim 에서 드론 RTL.

---

## 임팩트 연출
- 글리치 강도↑(`sim_inject_gps_spoof.py` 의 `SIM_GPS*_GLITCH_*`)로 이탈을 크게.
- A/B: `--no-rtb`(방어OFF, 이탈해 사라짐) vs `--auto`(방어ON, 복귀) 나란히.

## 알려진 변수 (막히면 여기부터)
- **AirSim↔ArduPilot 포트/IP**: 같은 머신이면 127.0.0.1, WSL이면 호스트IP. settings.json 과
  `--sim-address` 가 서로 가리켜야 함.
- **GPS 스푸핑 반영**: airsim 백엔드에서 `SIM_GPS` 글리치가 위치에 안 먹으면 →
  대안: GUIDED 위치목표로 가짜항로 / **S8 온보드 인식 공격**(시뮬 무관 동작).
- **방화벽**: Windows 방화벽이 UDP 9002/9003/14550 막을 수 있음 → 허용.

> 우리 측 준비 완료(검증됨): `sim_bridge/mavlink_source.py`, `scripts/sim_live_bridge_mav.py`,
> `scripts/sim_inject_gps_spoof.py`(--conn), `scripts/airsim/settings.json`.
