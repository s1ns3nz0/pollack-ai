# 휴면 외부 enrich(TI/샌드박스/vuln) 배선 + egress 가드 (design)

**날짜**: 2026-07-09
**작성**: 황준식 (analysis lane)
**상태**: design (Codex 교차검증 대기)

## 1. 목적 / intent

`tools/ti_tool.py`(VT·GreyNoise·AbuseIPDB·ThreatFox·Composite)·`tools/sandbox_tool.py`
(HybridAnalysis)·`tools/vuln_tool.py`(CISA KEV·NVD)는 **real HTTP 구현이 있으나
hotpath 미배선** — `build_soc_graph` 에 `_default_ti/_default_sandbox/_default_vuln`
이 없어 `app/hotpath.py` 실행 경로에서 꺼져있다(테스트에서만 실행). 코드 갭 아닌
**배선 갭**. 이 기능이 배선하되, 방산 OPSEC 를 default-deny 로 지킨다.

## 2. 결정된 설계 (grill 확정)

| 포크 | 결정 |
|---|---|
| 목표 | 휴면 TI/샌드박스/vuln 을 `_default_*` opt-in 배선(gnss/airspace 패턴) |
| egress 자세 | **master 플래그 `external_enrichment_enabled` default False**(default-deny) |
| IOC 가드 | **egress sanitizer 포함** — 사설/내부 IP·불정지표 드롭 + alert당 cap |

### 2.1 핵심 트러스트 근거
- **외부 TI 조회 = 수사의도 누설**: VT 에 IOC 조회하면 VT(및 VT 관전 적)가 "우리가
  이 지표 수사 중"임을 안다. 방산 UAV SOC 는 이 leak 를 **기본 차단**해야 → master
  플래그 default False. 키불요 CISA KEV·gpsjam 도 플래그 꺼지면 outbound 안 함.
- **untrusted wire IOC 가 egress 구동**: `alert.iocs` 는 wire(공격자 제어). enabled 시
  이 IOC 가 실제 외부로 나감 → (1) 내부 IP/호스트를 IOC 로 실으면 VT 에 **내부
  토폴로지 누설**, (2) IOC 폭주 → API 쿼터 소진. → egress sanitizer 필수.

## 3. 변경 상세

### 3.1 Settings (`core/settings.py`)
- `external_enrichment_enabled: bool = Field(default=False, ...)` — 모든 외부 enrich
  마스터 게이트(default-deny). per-source 는 여전히 키-게이트(둘 다 참이어야 outbound).
- `ioc_egress_max_per_alert: int = Field(default=32, gt=0, ...)` — egress IOC 상한.
- (타임아웃 신규 불요 — ti/sandbox/vuln_timeout_seconds 이미 존재.)

### 3.2 graph.py `_default_*` (gnss/airspace 미러)
```
def _default_ti(settings) -> ThreatIntelTool | None:
    if not settings.external_enrichment_enabled: return None
    sources = []
    if settings.virustotal_api_key.get_secret_value(): sources.append(VirusTotalTool(settings))
    if settings.greynoise_api_key.get_secret_value(): sources.append(GreyNoiseTool(settings))
    if settings.abuseipdb_api_key.get_secret_value(): sources.append(AbuseIpdbTool(settings))
    if settings.threatfox_api_key.get_secret_value(): sources.append(ThreatFoxTool(settings))
    return CompositeThreatIntel(sources) if sources else None
```
- `_default_sandbox`: `enabled` + `hybridanalysis_api_key` → `HybridAnalysisTool`, else None.
- `_default_vuln`: `enabled` → `CompositeVuln([CisaKevTool(settings), NvdTool(settings)])`
  (CISA KEV 키불요라 항상 포함, NVD 키선택). 현재 ReportAgent 에만 주입 → **투자이젠
  InvestigationAgent 에도** 주입(SBOM CVE 는 report 유지).
- InvestigationAgent 생성 시 `ti/sandbox/vuln/egress` 주입(현재 None 배선을 교체).
- HoneypotFeedTool 은 내부 decoy 피드(egress 아님)·provider 필요 → 이번 배선 제외.

### 3.3 core/egress.py (신규) — IOC egress sanitizer
```
class IocEgressFilter:
    def sanitize(self, iocs: list[str], *, cap: int) -> tuple[list[str], list[str]]:
        # 반환: (통과 IOC, 드롭 IOC[telemetry]).
```
- **드롭 규칙**(내부 누설·쿼터번 방지):
  1. IP: `ipaddress` 파싱 → `is_private/is_loopback/is_link_local/is_reserved/
     is_multicast/unspecified` 이면 드롭(RFC1918·169.254 메타데이터·127/8·::1 등).
  2. 도메인: 점 없는 단일 라벨(내부 호스트명 추정) 드롭. 유효 문자·TLD 형태만 통과.
  3. URL: http(s) + 공개 호스트만. 사설/단일라벨 호스트 URL 드롭.
  4. 해시(md5/sha1/sha256 hex): 항상 통과(토폴로지 누설 없음).
  5. 형태 불일치(위 어느 것도 아님) 드롭.
  6. 통과분 `cap` 개로 절단(초과분 드롭·기록).
- 표준 사설대역은 **코드 상수**(`ipaddress` 표준 — 튜닝 불요). cap 만 Settings.
- 드롭 목록은 telemetry(로그 + 반환) — 내부지표 유출시도 관측.

### 3.4 InvestigationAgent (`agents/investigation_agent.py`)
- 생성자에 `egress: IocEgressFilter | None = None`.
- enrich 흐름(현재 L250·263·264) 앞단에 sanitize 삽입:
```
clean, dropped = self._egress.sanitize(alert.iocs, cap=cap) if self._egress else (alert.iocs, [])
sandbox_reports = await self._detonate(clean)          # 해시만 (기존 _HASH_RE)
extracted = [...]                                       # 샌드박스 추출 IOC
ext_clean, _ = self._egress.sanitize(extracted, cap=cap) if self._egress else (extracted, [])
ti_indicators = dedup([*clean, *ext_clean])            # 추출분도 재-sanitize(오염 리포트 방어)
ti_findings = await self._lookup_ti(ti_indicators)
```
- **추출 IOC 재-sanitize 이유**: 샌드박스 리포트는 외부 산출물 → 오염 시 내부 IP 를
  extracted 에 심어 TI 조회로 exfil 유도 가능 → TI 나가기 전 재필터.
- 드롭 발생 시 `guardrail_flags`(또는 로그)에 기록.

### 3.5 .env.example
- `EXTERNAL_ENRICHMENT_ENABLED=false`(주석: 방산 OPSEC 기본 차단, 외부 TI leak).
- `IOC_EGRESS_MAX_PER_ALERT=32`.

## 4. 트러스트 / 포이즈닝 분석

| 표면 | 위험 | 완화 |
|---|---|---|
| 외부 TI 조회 자체 | 수사의도 leak(VT 관전 적) | master 플래그 default-deny(명시 opt-in) |
| wire IOC egress | 내부 토폴로지 누설 | sanitizer 사설/단일라벨 드롭 |
| IOC 폭주 | API 쿼터번·비용 | alert당 cap |
| 샌드박스 추출 IOC | 오염 리포트가 내부IP 주입 | TI 전 재-sanitize |
| TI/vuln/sandbox 응답 | 외부 JSON 신뢰 | 기존 어댑터 검증(parse/_extract) |
| enrich 결과 | severity 조작 | 기존: confidence-only(+0.2 cap), severity 미변 |

- default-deny + sanitizer 로 신규 배선의 유일 신규 표면(egress)을 최소화.
- 배선 후에도 **severity/verdict 권한 불변** — enrich 는 confidence 만 조정(기존 교리).

## 5. 테스트 (`tests/__tests__/`)
- `test_egress_drops_private_ip`: RFC1918·169.254·127/8·::1 드롭.
- `test_egress_drops_single_label_host`: 점없는 내부 호스트명 드롭.
- `test_egress_keeps_public_indicators`: 공개 해시/IP/도메인 통과.
- `test_egress_caps_count`: cap 초과분 절단.
- `test_default_ti_none_when_disabled`: 플래그 False → `_default_ti/sandbox/vuln` None.
- `test_default_ti_composite_when_enabled_with_keys`: enabled+키 → Composite.
- `test_default_vuln_cisa_kev_keyless`: enabled → CISA KEV 항상 포함.
- `test_investigation_sanitizes_before_egress`: mock TI/sandbox 에 사설IP 안 감.
- `test_hotpath_no_external_by_default`: `build_soc_graph()`(플래그 미설정) → 외부 enrich
  없음(default-deny 회귀).

## 6. 미결 / 후속
- OTX/MISP 어댑터 신규(docstring 예시만 존재) — 후속.
- HoneypotFeedTool provider 배선 — 후속(내부 decoy 피드).
- 도메인 내부/외부 판별을 단일라벨 휴리스틱 넘어 조직 도메인 denylist 로 — 후속(정책화).
- gpsjam/airspace 도 master 플래그 게이트로 통일할지 — 후속(현재 자체 URL 게이트).
- 게이트: 스펙→Codex 설계리뷰→반영→구현→black/ruff/mypy/pytest→clean-worktree→
  Codex diff 리뷰→커밋/PR/머지.
