# Cosys-AirSim 풀 빌드 (Windows) — 플러그인 + UE5.5 + VS2022

> 목표: 소스 빌드로 AirSim(Blocks) 환경 실행 → ArduPilot/PX4 연결 → 우리 SOC.
> 각 STEP **✅체크포인트** 통과 후 다음. 막히면 그 단계 에러 그대로 붙여주세요.
> ⚠️ 정확한 스크립트명/옵션은 Cosys-AirSim **공식 docs(README/Building on Windows)** 와
> 대조하세요(버전마다 다를 수 있음). 아래는 표준 AirSim 빌드 흐름.

---

## STEP A — Visual Studio 2022 설치
- VS2022 Community + 워크로드:
  - **Desktop development with C++**
  - **Game development with C++** (Unreal 통합 포함)
  - 최신 **Windows 10/11 SDK**

✅ **A**: 시작메뉴에 **"x64 Native Tools Command Prompt for VS 2022"** 존재.

## STEP B — Unreal Engine 5.5 설치
- **Epic Games Launcher** 설치 → Unreal Engine 탭 → **5.5** 설치(~50GB+).

✅ **B**: Epic Launcher 에서 UE 5.5 "실행" 가능.

## STEP C — Cosys-AirSim 소스 빌드 (AirLib)
플러그인 ZIP 보다 **전체 repo 클론**이 빌드 스크립트·Blocks 환경까지 있어 안전합니다.
```bat
git clone https://github.com/Cosys-Lab/Cosys-AirSim
cd Cosys-AirSim
:: "x64 Native Tools Command Prompt for VS 2022" 에서 실행
build.cmd
```
(스크립트명은 docs 확인 — 보통 `build.cmd` 가 AirLib C++ 라이브러리 빌드)

✅ **C**: 빌드 에러 없이 완료(끝에 success). `Unreal\Plugins\` 에 AirSim 플러그인 생성.

## STEP D — Blocks 환경 열고 빌드
```bat
cd Unreal\Environments\Blocks
update_from_git.bat            :: 플러그인을 Blocks 로 복사(스크립트명 docs 확인)
```
- `Blocks.uproject` 우클릭 → **Generate Visual Studio project files**
- `Blocks.sln` 을 VS2022로 열고 **Build**(Development Editor, Win64) → 또는
  `Blocks.uproject` 더블클릭 시 "모듈 리빌드?" → **Yes**
- UE5.5 에디터가 열리면 상단 **▶ Play**.

✅ **D**: UE 에디터에서 Play → 3D 씬에 드론. 출력로그(Window→Developer Tools→Output Log)에
   AirSim 관련 메시지.

## STEP E — settings.json (비행체 지정)
`Documents\AirSim\settings.json` ← 레포 `scripts/airsim/settings.json` (VehicleType=ArduCopter).
- 저장 후 UE 에서 다시 **Play**.

✅ **E**: Output Log 에 **`Waiting for connection`**(ArduPilot/PX4 대기)이 뜨는지 확인.
   - 뜨면 → ArduPilot 경로(STEP F-A)
   - ArduCopter 미지원 에러 → settings 의 VehicleType 을 `"PX4Multirotor"` 로(STEP F-B)

## STEP F — 비행 컨트롤러 연결
### F-A) ArduPilot (WSL2 Ubuntu)
```bash
git clone https://github.com/ArduPilot/ardupilot --recursive
cd ardupilot && Tools/environment_install/install-prereqs-ubuntu.sh -y && . ~/.profile
Tools/autotest/sim_vehicle.py -v ArduCopter -f airsim-copter \
  --sim-address=<Windows호스트IP> --console --map
```
### F-B) PX4 (대안 — Cosys-AirSim 기본 지원)
- PX4 SITL(`make px4_sitl none_iris`)로 AirSim 연결. **우리 SOC 는 그대로**(MAVLink
  어댑터가 PX4 ESTIMATOR_STATUS 자동 처리).

✅ **F**: FC 콘솔에 GPS lock + AirSim "Connected". 이륙 테스트로 드론 상승 확인.

## STEP G — 우리 SOC 연결 + 공격
```bash
git clone <pollack-ai> && cd pollack-ai && pip install pymavlink pydantic pydantic-settings langgraph langchain-core pyyaml httpx
python scripts/sim_live_bridge_mav.py --conn udpin:0.0.0.0:14550 --auto --no-llm   # BLUE
python scripts/sim_inject_gps_spoof.py --conn udpout:127.0.0.1:14550               # RED(ArduPilot만)
#   PX4 경로면 공격은 S8 perception(sim_live_bridge_onboard.py)으로 대체
```

✅ **G**: SOC 에 `🚨 탐지·대응` + AirSim 에서 드론 이탈→RTB. OBS 녹화.

---

## 자주 막히는 곳
- `build.cmd` C++ 에러 → VS 워크로드(Game dev C++) 누락 점검.
- Blocks 모듈 리빌드 실패 → `.sln` 에서 직접 Build(Development Editor/Win64).
- WSL↔Windows IP/포트(9002/9003/14550) + Windows 방화벽 UDP 허용.
- ArduCopter 미지원 → PX4(F-B), 우리 SOC 무변경.
