# Azure 커스텀 테이블 통합 — 신규 데이터 소스 → 탐지 확장

ATT&CK 매핑표에서 **데이터가 없어 막힌 탐지**를 열기 위해 Log Analytics 커스텀
테이블(`*_CL`)을 신규 통합한다. 두 부류로 나뉜다.

> **핵심**: `*_CL` 생성 = ① 스키마 등록(ARM `workspaces/tables`) + ② 소스가 로그
> emit + ③ DCR/AMA 로 적재. 🔜 표는 ①이 끝난 상태(getschema 확인) → ②③만 하면
> ✅로 승격. SOC(pollack-ai)는 테이블을 *소비*만 하므로, 생성은 데이터/시뮬 lane
> (uav-sim-env)의 일이다. 본 문서가 그 실행 스펙이다.

배포 자산: `deploy/sentinel-tables/*.json`(테이블 ARM), DCR 패턴은 같은 폴더 README.

---

## A. 🔜 테이블 (스키마 있음 → 데이터만 채우면 ✅)

### `UAVGcsAccess_CL` — GCS 원격접속 로그
- **소스**: noVNC(:8080)/VNC(:5900)/QGC/SSH 접속 세션 로그(gcs-stub).
- **컬럼**: `TimeGenerated, SessionId, ClientIp, Transport, Operator, Action, UserAgent, BytesSent, BytesReceived, DurationSec, Result`
- **열리는 기법**: `T1133` 외부원격서비스(IA), `T1563` 세션 하이재킹(LM),
  그리고 `BytesSent/Duration` 으로 `T1113/T0852` 화면·영상 캡처(B-bucket) 간접.

### `UAVRouterStats_CL` — mavlink-router 엔드포인트 통계
- **소스**: mavlink-router 의 엔드포인트별 송수신/오류 카운터.
- **컬럼**: `TimeGenerated, EndpointName, PeerIp, PeerPort, Protocol, MsgTx, MsgRx, CrcErrors, DropCount`
- **열리는 기법**: `T1071/T0869` MAVLink C2(CrcErrors), `T1090/T0884` 프록시 중계.

### `UAVImagery_CL` — EO/IR 영상 스트림 이벤트
- **소스**: 영상 다운링크 서비스의 스트림 상태 이벤트.
- **컬럼**: `TimeGenerated, UAVId, StreamId, MsgType, EventType, FrameRate, GapMs, Resolution`
- **열리는 기법**: `T0815` Denial of View, `T0829` Loss of View(Impact).

---

## B. 신규 테이블/컬럼 (소스 계측이 새로 필요)

### `UAVFileAudit_CL` — 컨테이너 파일·exec 감사 (신규, ROI 최고)
- **소스**: 컨테이너에 **eBPF/Falco** 적용(파일 open/read/write/delete + exec).
- **컬럼**: `TimeGenerated, ContainerName, Pid, ProcessName, Operation, FilePath, BytesAccessed, User, Syscall`
- **열리는 기법(❌→탐지)**: Collection 버킷 `T1005/T1074/T1560/T0845`,
  파괴 `T0809/T1485` — **단일 센서로 다수 갭 해소**.

### 기존 테이블 컬럼 추가 (alter — 신규 테이블 아님)
| 테이블 | 추가 컬럼 | 열리는 기법 |
|---|---|---|
| `UAVSatcomLink_CL` | `TxBytes`(long) | `T1011` 별도매체 유출 |
| `UAVC4I_CL` | `RestPayloadBytes`(long), `RestEndpoint`(string) | `T1567` 웹서비스 유출 |

> 컬럼 추가는 ARM `workspaces/tables` 의 기존 테이블 `columns` 에 append 하여 갱신
> (DCR 스트림 매핑도 함께 갱신). 본 폴더 ARM 은 신규 4종만 포함.

---

## 실행 순서 (uav-sim-env / 인프라 lane)
1. **테이블 스키마 배포**: `deploy/sentinel-tables/*.json` 을 워크스페이스에 배포
   (🔜 3종은 이미 등록됐을 수 있음 — 멱등).
2. **소스 emit**: 각 stub/서비스가 위 컬럼 구조로 JSON 로그를 stdout/파일에 출력.
3. **DCR + AMA**: Data Collection Rule 로 스트림→테이블 매핑, Azure Monitor Agent
   (또는 Logs Ingestion API)로 적재(README 패턴 참조).
4. **검증**: `<Table>_CL | take 10` 으로 데이터 확인.

## SOC 후속 (pollack-ai lane)
데이터가 들어오면:
1. 해당 KQL 분석룰을 `dah-sentinel-content/AnalyticsRules/` 에 추가(또는 🔜 룰 활성).
2. `data/attack_coverage.yaml` 에서 해당 기법을 `uncovered`/`planned` → `covered` 로
   이동 → **커버리지 KPI(`/metrics`, Grafana)가 자동 갱신**.

## 열리는 커버리지 (예상)
- A(🔜 3종): `T1133, T1563, T1071, T1090, T0815, T0829` 등 planned→covered.
- B(`UAVFileAudit_CL`): Collection ❌ ~6개 + 파괴 2개 해소.
→ 현재 covered 73 / uncovered 30 에서, B 한 테이블만으로 uncovered 두 자릿수 감소.
