# STIX 2.1 TI 생산 — 위협 인텔 내보내기/공유

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-09 |
| 상태 | Approved (Codex Crit+3H+2M+L 반영 → 구현) |
| 근거 | NIST 800-150(위협정보 공유), STIX 2.1(OASIS) — ingest→produce 양방향 |
| 선행 | TI ingest(atlas/kev/mitre_stix feed), DiamondEvent(침입분석 4정점) |
| base | main(CI green) |

## 1. 배경 & 동기
현재 TI 는 **ingest-only**(atlas_feed/cisa_kev_feed/mitre_stix_feed 로 소비). 800-150 은
**양방향** — 우리 분석 산물(DiamondEvent 침입분석)을 STIX 2.1 로 **생산**해 연합 방어(ISAC/
파트너 SOC)와 공유해야 한다. 이 작업은 STIX 2.1 bundle **생성**(결정론)만 — TAXII 서버 push
(외향 발송)는 비목표(운영자/별 시스템, COA 교리).

## 2. 목표 / 비목표 (Codex Crit+3H+2M+L 반영)
### 목표
- `core/stix_export.py` — 결정론 STIX 2.1 bundle 생성(외부 라이브러리 X):
  - `StixExporter(producer_name, tlp="amber").from_diamond(diamond, created_at) -> dict|None`:
    - **producer identity** SDO(created_by_ref 대상) + **표준 TLP marking-definition**(고정 id) 참조,
      전 SDO/SRO 에 `object_marking_refs`(공유 handling contract, 800-150).
    - adversary → **threat-actor**(name 필수)
    - capabilities → **attack-pattern**(name 필수·external_references ATT&CK)
    - infrastructure → **indicator**(strict pattern·pattern_type="stix"·valid_from 필수)
    - **SRO**: `threat-actor uses attack-pattern`; `indicator indicates threat-actor`(source_ref=indicator).
  - **victim 완전 생략(Crit OPSEC)**: 기본 sharing profile=external_minimal — 내부 자산 id/tier/
    임무단계 미노출(파트너에 방어자산 클래스·임무의존성 유출 방지). rich victim 은 fast-follow.
  - **결정론 id(High)**: uuid5(**platform namespace**, type+value) — OASIS ns(SCO 전용) 금지. 재현·dedup.
  - **필수필드(Med)**: 전 SDO type/spec_version/id/created/modified. created=modified=valid_from=created_at.
  - created_at 주입(Date.now 안 씀).
### 비목표
- TAXII push/구독(외향). CampaignMatch→campaign, rich victim profile(trusted_partner/internal), file/url IOC 고도화(fast-follow).

## 3. 트러스트/견고성
- 생성 전용·읽기전용·결정론(uuid5, platform ns). state 불변. 랜덤/Date.now 없음.
- **OPSEC(Crit)**: victim 기본 생략. 공유 bundle 은 위협측(actor/TTP/IOC)만 — 방어측 자산 상세 미노출.
- **TLP(High)**: 표준 TLP marking-definition(커스텀 안 만듦) + object_marking_refs. tlp 기본 amber(보수적).
- **IOC strict(High)**: ipaddress 로 IP/CIDR→ipv4-addr, 도메인→domain-name, hash 길이→file:hashes.
  판별불가 IOC 는 **skip**(무효 x-ioc pattern 안 냄). 빈 diamond → objects 없는 bundle 또는 None.

## 4. 설계
- `_PLATFORM_NS = uuid5(NAMESPACE_DNS, "pollack-ai.uav-soc")` 고정. `_sid(type, value)=f"{type}--{uuid5(NS,...)}"`.
- 표준 TLP 2.1 marking-definition 고정 id(RED/AMBER/GREEN/CLEAR) — 커스텀 SMO 생성 금지, 표준 참조만.
- indicator pattern: `ipaddress.ip_network(v, strict=False)`→ipv4/ipv6-addr, `.` 포함 도메인 정규→domain-name,
  hex 32/40/64→file:hashes.{MD5/SHA-1/SHA-256}. 그 외 skip. pattern_type="stix", valid_from=created_at.
- bundle: {type:"bundle", id:"bundle--<uuid5>", objects:[identity, marking, SDO/SRO...]}. 위협 SDO 0 → objects 생략/None.

## 5. 테스트
- threat-actor/attack-pattern/indicator/SRO 생성 + 필수필드. id 결정론(재호출 동일). external_ref ATT&CK.
- IOC 분류(IP/CIDR/도메인/hash 각 타입, unknown skip). **victim 미노출**(자산 id/tier 부재 검증).
- TLP marking + object_marking_refs 전 객체. producer identity + created_by_ref. 빈 diamond → None/objects 없음.
- SRO 방향(indicator→indicates→threat-actor).

## 6. 롤아웃
1. core/stix_export.py + 테스트.
2. Codex(설계→diff) → 게이트. 브랜치 feat/stix-ti-production.
