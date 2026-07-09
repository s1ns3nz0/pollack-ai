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

### 2.1 핵심 트러스트 근거 (Codex 설계리뷰 반영)
- **외부 TI 조회 = 수사의도 누설**: VT 에 IOC 조회하면 VT(및 VT 관전 적)가 "우리가
  이 지표 수사 중"임을 안다. 방산 UAV SOC 는 이 leak 를 **기본 차단**해야 → master
  플래그 default False.
- **마스터 플래그 스코프(Codex Critical)**: `external_enrichment_enabled` 는 이번에
  새로 배선하는 **TI/샌드박스/vuln(CISA KEV·NVD 포함)에만** 적용. 기존 GNSS/Airspace
  는 각자 URL 게이트로 이미 default-on(별 배선)이라 이 플래그로 안 끈다 —
  스코프 밖(동작 변경 회피). "gpsjam 도 플래그로 꺼짐"은 **오주장이라 철회**. GNSS/
  Airspace 통합 게이트는 후속.
- **untrusted wire IOC 가 egress 구동**: `alert.iocs` 는 wire(공격자 제어). enabled 시
  이 IOC 가 실제 외부로 나감 → (1) 내부 IP/호스트를 IOC 로 실으면 VT 에 **내부
  토폴로지 누설**, (2) IOC 폭주 → API 쿼터 소진. → egress sanitizer 필수.
- **cap 은 alert당 단일 예산(Codex High)**: wire IOC 와 샌드박스 추출 IOC 에 cap 을
  **따로** 적용하면 2×cap 이 TI 로 나간다. 병합 후 **한 번만** cap(정규화·중복제거
  후) → 단일 outbound 예산.
- **wall-clock 데드라인(Codex High)**: per-request 타임아웃은 직렬 다중 IOC 조회의
  총 벽시계를 못 막는다(cap×timeout). enrich 호출을 `enrichment_deadline_seconds`
  로 감싸 fail-open 강등.

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
- **드롭 규칙**(내부 누설·쿼터번 방지, Codex Medium — 정규화로 우회 차단):
  1. IP: `ipaddress` 파싱 → `is_private/is_loopback/is_link_local/is_reserved/
     is_multicast/is_unspecified` 드롭. **IPv6-mapped IPv4**(`::ffff:10.0.0.1`)는 매핑
     v4 로 판정. octal/decimal/hex 표기(`0177.0.0.1`·`2130706433`·`0x7f.0.0.1`)는
     파싱 실패 또는 TLD-알파 규칙으로 드롭. 통과는 정규 `str(ip)`.
  2. 도메인: 단일 라벨 드롭. **IDNA/punycode 정규화**(유니코드→xn--). 내부 접미사
     (`.local .lan .internal .corp .home .intranet .svc .cluster.local`) 드롭. TLD(마지막
     라벨)에 알파벳 없으면(불정 IP 형태) 드롭. 통과는 소문자·punycode 정규형.
  3. URL: `http(s)` + **공개 호스트만**. **userinfo(`user@host`) 드롭**(내부문자열
     누설). host 에 IP/도메인 규칙 재적용. 통과 시 **query/fragment 제거**.
  4. 해시(md5/sha1/sha256 hex): 소문자 정규화 통과(토폴로지 누설 없음).
  5. 형태 불일치 드롭.
  6. **정규화 후 중복제거**(대소문자 변형 slot 낭비 방지) → `cap` 절단.
- 표준 사설대역은 **코드 상수**(`ipaddress` 표준 — 튜닝 불요). cap 만 Settings.
- 드롭 목록은 telemetry(로그 + 반환) — 내부지표 유출시도 관측.

### 3.4 InvestigationAgent (`agents/investigation_agent.py`)
- 생성자에 `egress: IocEgressFilter | None = None`.
- enrich 흐름 — **단일 cap 예산**(Codex High) + **데드라인**(Codex High):
```
cap = settings.ioc_egress_max_per_alert
clean, dropped = egress.sanitize(alert.iocs, cap=cap)     # wire → sandbox(해시)+wire
sandbox_reports = await self._bounded(self._detonate(clean), [], "sandbox")
extracted = [...]                                         # 샌드박스 추출 IOC
# 단일 예산: wire+추출 병합 후 한 번만 sanitize(추출도 재정제=오염방어), cap 1회
ti_indicators, _ = egress.sanitize([*clean, *extracted], cap=cap)
ti_findings = await self._bounded(self._lookup_ti(ti_indicators), [], "ti")
vuln_findings = await self._bounded(self._enrich_vuln(alert.cves), [], "vuln")
```
- **2×cap 방지**: 병합 후 sanitize 로 cap 을 **한 번만** 적용 → TI outbound ≤ cap.
- **추출 IOC 재-sanitize**: 샌드박스 리포트=외부 산출물 → 오염 시 내부 IP exfil 유도
  가능 → TI 나가기 전 재필터(병합 sanitize 가 겸함).
- **`_bounded`**: `asyncio.wait_for(coro, enrichment_deadline_seconds)` — 초과 시
  로깅 + 빈 결과(fail-open). enrich 는 어차피 confidence 만 조정하므로 강등 안전.
- egress 미주입(None) 시 현행 동작(정제 없음) — 하위호환.

### 3.5 .env.example
- `EXTERNAL_ENRICHMENT_ENABLED=false`(주석: 방산 OPSEC 기본 차단, 외부 TI leak).
- `IOC_EGRESS_MAX_PER_ALERT=32`, `ENRICHMENT_DEADLINE_SECONDS=20`, per-source 키.

## 4. 트러스트 / 포이즈닝 분석

| 표면 | 위험 | 완화 |
|---|---|---|
| 외부 TI 조회 자체 | 수사의도 leak(VT 관전 적) | master 플래그 default-deny(명시 opt-in) |
| wire IOC egress | 내부 토폴로지 누설 | sanitizer 사설/단일라벨 드롭 |
| IOC 폭주 | API 쿼터번·비용 | alert당 cap |
| 샌드박스 추출 IOC | 오염 리포트가 내부IP 주입 | TI 전 재-sanitize |
| TI/vuln/sandbox 응답 | 외부 JSON 신뢰 | 기존 어댑터 검증(parse/_extract) |
| enrich 결과 | verdict 간접 영향 | enrich 는 severity/verdict **직접 미기록**(confidence 만 +0.2 cap) |

- default-deny + sanitizer 로 신규 배선의 유일 신규 표면(egress)을 최소화.
- **severity/verdict 권한(Codex Medium — 과장 금지)**: enrich 는 severity/verdict 를
  **직접 안 쓴다**(confidence 만 조정). severity 는 investigation 전에 triage 에서
  산정되어 불변. 단 `signal_judge` 는 `confidence>=0.5` 를 TP 방향 보강으로 쓰므로,
  그 judge 를 쓰는 배포에선 외부 confidence 가 **간접적으로** verdict 에 영향 가능.
  기본 그래프는 `default_judge`(ground_truth oracle) 라 무영향. → "confidence-only 라
  verdict 불변"은 **배포 의존**이며, 이를 절대 안전으로 과장하지 않는다.

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
