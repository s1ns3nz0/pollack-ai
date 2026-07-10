#!/usr/bin/env bash
# UAV AI SOC — kagent(AKS) 배포 오케스트레이션.
# 기존 dah-soc AKS 재사용. DOMAIN 미지정 시 Azure 기본 호스트명 + 평문 HTTP 폴백.
#
# 필수 env: AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_KEY
# 선택 env: DOMAIN(미지정→Azure 호스트명), RESOURCE_GROUP, AKS_NAME,
#           AZURE_OPENAI_DEPLOYMENT(기본 gpt-4o-soc), AZURE_OPENAI_API_VERSION(기본 2024-10-21),
#           KAGENT_VERSION(기본 0.9.9), DNS_LABEL(기본 uav-soc)
set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-dah-soc-rg}"
AKS_NAME="${AKS_NAME:-dah-soc-aks}"
KAGENT_VERSION="${KAGENT_VERSION:-0.9.9}"
DNS_LABEL="${DNS_LABEL:-uav-soc}"
AZURE_OPENAI_DEPLOYMENT="${AZURE_OPENAI_DEPLOYMENT:-gpt-4o-soc}"
AZURE_OPENAI_API_VERSION="${AZURE_OPENAI_API_VERSION:-2024-10-21}"
NS_SOC="dah-soc"
NS_KAGENT="kagent"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

: "${AZURE_OPENAI_ENDPOINT:?AZURE_OPENAI_ENDPOINT 필요}"
: "${AZURE_OPENAI_KEY:?AZURE_OPENAI_KEY 필요}"
export AZURE_OPENAI_ENDPOINT AZURE_OPENAI_DEPLOYMENT AZURE_OPENAI_API_VERSION

echo "==> [1/8] AKS 자격증명 (${RESOURCE_GROUP}/${AKS_NAME})"
az aks get-credentials -g "$RESOURCE_GROUP" -n "$AKS_NAME" --overwrite-existing

echo "==> [2/8] app-routing addon 활성화 (managed nginx)"
az aks approuting enable -g "$RESOURCE_GROUP" -n "$AKS_NAME" 2>/dev/null || \
  echo "    (이미 활성 또는 enable 실패 — kubectl 로 webapprouting 확인 필요)"

echo "==> [3/8] 네임스페이스"
kubectl create namespace "$NS_SOC" --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace "$NS_KAGENT" --dry-run=client -o yaml | kubectl apply -f -

echo "==> [4/8] Azure OpenAI 시크릿 (kagent + dah-soc 양 ns)"
for ns in "$NS_KAGENT" "$NS_SOC"; do
  kubectl create secret generic kagent-azure-openai \
    --namespace "$ns" \
    --from-literal=AZUREOPENAI_API_KEY="$AZURE_OPENAI_KEY" \
    --dry-run=client -o yaml | kubectl apply -f -
done

echo "==> [5/8] kagent 플랫폼 Helm 설치 (${KAGENT_VERSION})"
helm upgrade -i kagent-crds oci://ghcr.io/kagent-dev/kagent/helm/kagent-crds \
  --version "$KAGENT_VERSION" --namespace "$NS_KAGENT"
envsubst < "$REPO_ROOT/deploy/kagent/values.yaml" > /tmp/kagent-values.rendered.yaml
helm upgrade -i kagent oci://ghcr.io/kagent-dev/kagent/helm/kagent \
  --version "$KAGENT_VERSION" --namespace "$NS_KAGENT" \
  -f /tmp/kagent-values.rendered.yaml

echo "==> [6/8] kagent CRD 스키마 확인"
kubectl get crd 2>/dev/null | grep kagent || echo "    (kagent CRD 미표시 — operator 기동 대기 후 재확인)"

echo "==> [7/8] SOC CRD 적용 (ModelConfig/RemoteMCPServer/Agent)"
for f in modelconfig remotemcpserver agent; do
  envsubst < "$REPO_ROOT/deploy/kagent/${f}.yaml" | kubectl apply -f -
done

echo "==> [8/8] 대시보드 Ingress (DOMAIN 해석)"
if [[ -n "${DOMAIN:-}" ]]; then
  echo "    실도메인: ${DOMAIN} (cert-manager TLS)"
  export DOMAIN
  export TLS_ANNOTATION="    cert-manager.io/cluster-issuer: letsencrypt-prod"
  export TLS_BLOCK="  tls:
    - hosts:
        - ${DOMAIN}
      secretName: soc-dashboard-tls"
else
  # 폴백: app-routing LB 공인 IP → Azure 기본 호스트명(평문 HTTP)
  echo "    DOMAIN 미지정 — Azure 기본 호스트명 폴백"
  LB_IP="$(kubectl get svc -n app-routing-system nginx -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)"
  if [[ -z "$LB_IP" ]]; then
    echo "    LB IP 아직 미할당 — 잠시 후 재실행하거나 DOMAIN 을 직접 지정하세요." >&2
    exit 1
  fi
  PIP_ID="$(az network public-ip list --query "[?ipAddress=='${LB_IP}'].id" -o tsv | head -1)"
  if [[ -n "$PIP_ID" ]]; then
    az network public-ip update --ids "$PIP_ID" --dns-name "$DNS_LABEL" >/dev/null
    REGION="$(az aks show -g "$RESOURCE_GROUP" -n "$AKS_NAME" --query location -o tsv)"
    export DOMAIN="${DNS_LABEL}.${REGION}.cloudapp.azure.com"
  else
    export DOMAIN="$LB_IP"  # DNS 라벨 부여 불가 시 IP 직접
  fi
  export TLS_ANNOTATION=""
  export TLS_BLOCK=""
  echo "    폴백 접속 호스트: ${DOMAIN}"
fi
envsubst < "$REPO_ROOT/deploy/ingress/dashboard-ingress.yaml.template" | kubectl apply -f -

SCHEME="http"; [[ -n "${TLS_BLOCK:-}" ]] && SCHEME="https"
echo "==> 완료. 대시보드: ${SCHEME}://${DOMAIN}/dashboard"
