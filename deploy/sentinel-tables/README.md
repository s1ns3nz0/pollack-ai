# Sentinel 커스텀 테이블 — 배포 + DCR 패턴

ATT&CK 갭을 여는 신규 `*_CL` 테이블의 ARM 스키마. 분석/매핑은
`docs/azure-tables-integration.md` 참조.

| 파일 | 테이블 | 컬럼 수 | 소스 |
|---|---|---|---|
| `UAVGcsAccess_CL.json` | GCS 원격접속 | 11 | noVNC/VNC/QGC 세션 |
| `UAVRouterStats_CL.json` | mavlink-router 통계 | 9 | mavlink-router |
| `UAVImagery_CL.json` | 영상 스트림 이벤트 | 8 | EO/IR 다운링크 |
| `UAVFileAudit_CL.json` | 파일·exec 감사 | 9 | eBPF/Falco |

## 1. 테이블 스키마 배포 (멱등)
```bash
WS=dah-data-law
RG=dah-data-rg
for f in deploy/sentinel-tables/*.json; do
  az deployment group create -g "$RG" \
    --template-file "$f" \
    --parameters workspaceName="$WS"
done
```

## 2. DCR 패턴 (소스 → 테이블 적재)
커스텀 테이블은 **Data Collection Rule(DCR) + Azure Monitor Agent** 또는 **Logs
Ingestion API** 로 채운다. DCR 스켈레톤(텍스트 로그 스트림 예):
```jsonc
{
  "type": "Microsoft.Insights/dataCollectionRules",
  "apiVersion": "2022-06-01",
  "name": "dcr-uav-gcsaccess",
  "properties": {
    "streamDeclarations": {
      "Custom-UAVGcsAccess_CL": {
        "columns": [ /* docs/azure-tables-integration.md 의 컬럼과 동일 */ ]
      }
    },
    "dataSources": {
      "logFiles": [{
        "name": "gcsaccess",
        "streams": ["Custom-UAVGcsAccess_CL"],
        "filePatterns": ["/var/log/gcs/access*.log"],
        "format": "json"
      }]
    },
    "destinations": {
      "logAnalytics": [{
        "workspaceResourceId": "<WS_RESOURCE_ID>",
        "name": "dah"
      }]
    },
    "dataFlows": [{
      "streams": ["Custom-UAVGcsAccess_CL"],
      "destinations": ["dah"],
      "transformKql": "source",
      "outputStream": "Custom-UAVGcsAccess_CL"
    }]
  }
}
```
- AMA 가 설치된 노드/파드에서 `filePatterns` 로그를 수집한다.
- 또는 코드에서 **Logs Ingestion API**(DCE + DCR)로 직접 POST.
- `transformKql` 로 적재 시점 변환 가능(예: 컬럼 리네임/마스킹).

## 3. 검증
```kusto
UAVGcsAccess_CL | take 10
UAVFileAudit_CL | summarize count() by Operation
```

## 4. 소유권
- **테이블 생성 + DCR + 소스 emit**: uav-sim-env / 인프라 lane.
- **KQL 분석룰 + 커버리지 갱신**: SOC(pollack-ai → dah-sentinel-content).
