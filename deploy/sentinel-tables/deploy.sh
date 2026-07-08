#!/usr/bin/env bash
# UAV SOC 커스텀 테이블 + DCR 배포 — Log Analytics(dah-data-law).
# 멱등: 여러 번 실행해도 안전(이미 있으면 갱신/스킵).
#
# 사용:
#   ./deploy.sh                # 기본 변수로
#   RG=my-rg WS=my-ws ./deploy.sh
#
# 사전: az CLI 로그인(az login) + 해당 구독 선택(az account set -s <SUB>).
set -euo pipefail

# ── 변수(환경변수로 오버라이드 가능) ──────────────
RG="${RG:-dah-data-rg}"
WS="${WS:-dah-data-law}"
LOCATION="${LOCATION:-koreacentral}"
DCE="${DCE:-dce-uav-soc}"
DCR="${DCR:-dcr-uav-soc}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── 0. 로그인 확인 + 식별자 산출 ──────────────
az account show >/dev/null 2>&1 || { echo "❌ az login 먼저 실행"; exit 1; }
SUB="$(az account show --query id -o tsv)"
WS_ID="/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.OperationalInsights/workspaces/${WS}"
echo "▶ 구독=${SUB}  RG=${RG}  WS=${WS}  LOC=${LOCATION}"

# ── 1. 커스텀 테이블 스키마 배포(멱등) ──────────────
for f in "${SCRIPT_DIR}"/UAV*_CL.json; do
  echo "▶ 테이블 배포: $(basename "$f")"
  az deployment group create -g "$RG" \
    --template-file "$f" \
    --parameters workspaceName="$WS" \
    -o none
done

# ── 2. Data Collection Endpoint(DCE) ──────────────
echo "▶ DCE 생성/확인: ${DCE}"
az monitor data-collection endpoint create \
  -g "$RG" -n "$DCE" -l "$LOCATION" \
  --public-network-access Enabled \
  -o none 2>/dev/null || echo "  (이미 존재 — 스킵)"
DCE_ID="$(az monitor data-collection endpoint show -g "$RG" -n "$DCE" --query id -o tsv)"

# ── 3. Data Collection Rule(DCR) 배포 ──────────────
echo "▶ DCR 배포: ${DCR}"
az deployment group create -g "$RG" \
  --template-file "${SCRIPT_DIR}/dcr.json" \
  --parameters dcrName="$DCR" location="$LOCATION" \
               workspaceResourceId="$WS_ID" \
               dataCollectionEndpointId="$DCE_ID" \
  -o none

DCR_ID="$(az monitor data-collection rule show -g "$RG" -n "$DCR" --query id -o tsv)"
DCR_IMMUTABLE="$(az monitor data-collection rule show -g "$RG" -n "$DCR" --query immutableId -o tsv)"
DCE_INGEST="$(az monitor data-collection endpoint show -g "$RG" -n "$DCE" --query logsIngestion.endpoint -o tsv)"

# ── 4. 적재 자격 부여(Logs Ingestion API 사용 시) ──────────────
# 로그를 POST 하는 주체(앱등록 SP 또는 매니지드 ID)에 DCR 범위로 권한 부여:
#   APP_ID=<클라이언트 또는 MI principalId>
#   az role assignment create --assignee "$APP_ID" \
#     --role "Monitoring Metrics Publisher" --scope "$DCR_ID"
echo "ℹ️ 적재 주체 권한(필요 시):"
echo "   az role assignment create --assignee <PRINCIPAL_ID> \\"
echo "     --role 'Monitoring Metrics Publisher' --scope ${DCR_ID}"

# ── 5. 결과 출력 — 소스(stub)가 이 정보로 POST ──────────────
cat <<EOF

✅ 배포 완료
  DCR immutableId : ${DCR_IMMUTABLE}
  Ingestion 엔드포인트: ${DCE_INGEST}

소스(stub) → Logs Ingestion API POST 예시(UAVGcsAccess_CL):
  curl -X POST \\
    "${DCE_INGEST}/dataCollectionRules/${DCR_IMMUTABLE}/streams/Custom-UAVGcsAccess_CL?api-version=2023-01-01" \\
    -H "Authorization: Bearer \$TOKEN" \\
    -H "Content-Type: application/json" \\
    -d '[{"TimeGenerated":"2026-06-28T00:00:00Z","SessionId":"s1","ClientIp":"10.0.0.5","Transport":"novnc","Action":"connect","Result":"ok"}]'
  # \$TOKEN = az account get-access-token --resource https://monitor.azure.com --query accessToken -o tsv

대안(AMA 파일 수집): DCR 의 dataSources.logFiles 로 전환 후 AMA 설치 노드에서 로그파일 수집.
EOF

# ── 6. 검증(데이터 적재 후) ──────────────
# WS_GUID="$(az monitor log-analytics workspace show -g "$RG" -n "$WS" --query customerId -o tsv)"
# az monitor log-analytics query -w "$WS_GUID" --analytics-query "UAVGcsAccess_CL | take 5" -o table
