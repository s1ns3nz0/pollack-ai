# 심사위원 배포 가이드

도메인 없이도 Azure 기본 호스트명으로 대시보드에 접속할 수 있습니다.

## 사전 요건
- `az` CLI 로그인(`az login`) + 대상 구독 선택(`az account set -s <sub>`)
- 기존 dah-soc AKS 접근 권한(또는 자기 AKS 좌표를 env 로 지정)
- Azure OpenAI 리소스 + 키

## 배포
1. `cp deploy/judge.env.example deploy/judge.env`
2. `deploy/judge.env` 의 `AZURE_OPENAI_*` 를 채움(도메인 없으면 `DOMAIN` 은 비워둠)
3. 실행:
   ```bash
   set -a; source deploy/judge.env; set +a
   ./deploy/scripts/deploy-soc.sh
   ```
4. 스크립트 마지막 줄의 `대시보드: http://<...>.cloudapp.azure.com/dashboard` 로 접속

## 도메인이 있는 경우
`deploy/judge.env` 에 `DOMAIN="soc.pollak.store"` 를 설정하고, 해당 도메인의 DNS A 레코드를
app-routing LB 공인 IP 로 지정하면 cert-manager 가 TLS 인증서를 자동 발급합니다
(`https://soc.pollak.store/dashboard`).

## 노출 범위(정직성)
- 외부 노출은 **대시보드만**(read-only replay). hotpath/learning/toolserver 는 ClusterIP 내부 전용.
- 도메인 없는 폴백은 **평문 HTTP**입니다(가짜 TLS 없음). 실도메인일 때만 HTTPS.
- 대시보드는 무인증(심사 공개용). write 엔드포인트/시크릿 노출 없음.
