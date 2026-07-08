# UAVGcsAccess_CL — 시뮬 emit 시나리오 매트릭스 (D)

`deploy/sentinel-tables/UAVGcsAccess_CL.json` 스키마를 따르는 정상 베이스라인 + 공격
페어. `sim_bridge/gcs_access_synth.py` 가 이 매트릭스를 한 단일 진실로 구현하며, `scripts/sim_emit_gcs.py` 가 dry-run / Logs Ingestion POST 양쪽을 실행한다.

## 1. 스키마 (단일 진실)

| 컬럼 | 타입 | 비고 |
|---|---|---|
| `TimeGenerated` | datetime | ISO8601 Z |
| `SessionId` | string | 정상은 단조 증가, 공격은 동일 ID 재사용 |
| `ClientIp` | string | 내부 `10.10.0.0/24` / 공격은 TEST-NET-2/3 |
| `Transport` | string | `novnc` / `vnc` / `qgc` |
| `Operator` | string | 정상은 직책계정, 공격은 `unknown` |
| `Action` | string | `connect` / `auth` / `disconnect` |
| `UserAgent` | string | 정상 `QGC/4.3`, 공격 임의 |
| `BytesSent` | long | Exfil 임계 ≥ 100MB |
| `BytesReceived` | long |  |
| `DurationSec` | real | 정상 ≤ 900 |
| `Result` | string | `ok` / `fail` |

## 2. 정상 베이스라인 (`benign_session`)

- `ClientIp ∈ 10.10.0.0/24` (내부 운용망)
- `Operator ∈ {sgt.yang, lt.kim, capt.park}`
- `Transport ∈ {novnc, qgc, vnc}`
- `BytesSent ∈ [1k, 200k]`, `DurationSec ∈ [30s, 900s]`, `Result=ok`
- `UserAgent = QGC/4.3`

## 3. 공격 시나리오

| 시나리오 | 생성기 | 핵심 필드 조합 | ATT&CK |
|---|---|---|---|
| 외부 비인가 + 세션 하이재킹 + 캡처 Exfil | `hijack_session()` | `ClientIp=203.0.113.66`, `SessionId=sess-1001` 재사용, `BytesSent=500MB`, `Operator=unknown` | T1078, T1133, T1185, TA0010 |
| 자격증명 무차별 | `brute_force_session()` | `Action=auth`, `Result=fail`, 외부 IP, 짧은 `DurationSec` | T1110 |

확장 슬롯(차후):
- 비표준 `UserAgent` (자동화 도구 자기노출)
- 비정상 시간대 접속 (운용 외 시간 KQL 매칭)
- `Transport=vnc` + `Action=connect` 빈도 급증 (스캐닝)

## 4. KQL 발화 매핑

```kusto
// 외부 비인가 접근
UAVGcsAccess_CL
| where ClientIp !startswith "10."
    and ClientIp !startswith "172.16."
    and ClientIp !startswith "192.168."

// 세션 하이재킹 — 동일 SessionId / 다른 ClientIp
UAVGcsAccess_CL
| summarize ips = make_set(ClientIp) by SessionId
| where array_length(ips) > 1

// 캡처/영상 Exfil
UAVGcsAccess_CL
| where BytesSent > 100 * 1024 * 1024

// 무차별 인증
UAVGcsAccess_CL
| where Action == "auth" and Result == "fail"
| summarize fails = count() by ClientIp, bin(TimeGenerated, 5m)
| where fails >= 5
```

## 5. 운영 흐름

```text
sim_bridge.gcs_access_synth.synth_records()
        │  (records_to_rows)
        ▼
scripts/sim_emit_gcs.py  ──── dry-run ──▶  scripts/testdata/gcs/UAVGcsAccess_CL.json
        │
        └── --post ──▶  scripts.gen_table_testdata.post_rows()
                                │
                                ▼
            POST  {DCE}/dataCollectionRules/{immutableId}/streams/Custom-UAVGcsAccess_CL
                                │
                                ▼
                       Log Analytics (dah-data-law)
                                │
                                ▼
                Sentinel 분석룰 / Watch List 발화 → SOC 핫패스(Deployment A)
```

## 6. 회귀 게이트 연결 슬롯

`benchmarks/run_kpi.py` 에 GCS 시나리오 슬롯을 추가해야 한다(차후 PR):

- 입력: `synth_records(benign_n=N, include_hijack=True)` 를 SOC 그래프에 투입.
- 측정: FPR(정상 베이스라인이 TP 로 오분류되지 않음) + FNR(하이재킹이 TP 로 잡힘).
- 게이트: `FPR ≤ 임계` 와 `하이재킹 검출 = 100%` 동시 충족.
