# ⚠️ SUPERSEDED — 이 폴더는 폐기 대상

이 폴더의 CSV 들은 초기 스캐폴드(추측 기반)였고 **더 이상 유효하지 않다.**

실제 워치리스트는 `dah-sentinel-content` repo 에 **ARM 템플릿 JSON**(`Watchlists/*.json`,
CSV 는 `properties.rawContent` 내장)으로 존재한다. 형식·스키마가 다르다.

- 권위 스키마: `pollack-ai/docs/sentinel-watchlist-schemas.md`
- 실제 파일: `dah-sentinel-content/Watchlists/{name}.json`

이 폴더(`pollack-ai/sentinel/Watchlists/`)는 **통째로 삭제**해도 된다
(샌드박스 권한 문제로 자동 삭제가 안 돼 수동 삭제 필요).
