# JADC2 연합상호운용성 — Releasability 파트너 스코핑 (결심우위 계층 PR5)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-09 |
| 상태 | 설계(Codex 교차검증 대기) |
| 근거 | JADC2 연합상호운용성 — 파트너/연합 releasability(REL-TO/NOFORN), STIX 2.1 |
| 선행 | core/stix_export.py(TLP 마킹·OPSEC-strip·to_taxii_envelope) |

## 목표
내부 브리핑은 지휘관 전용(intent/asset/임무 = 비공개). 그 위에 **파트너 릴리서블
파생물**을 만든다 — STIX 번들을 파트너 티어별로 스코핑(비릴리서블 strip + REL-TO/
NOFORN 마킹). **외향 push 없음**(직렬화만 — TAXII 동일). 결정론·읽기전용. 인바운드
파트너 인텔=untrusted(후속).

## 데이터 모델 (Codex Critical — allowlist·default-deny)
blacklist strip 대신 **allowlist**: 명시 허용된 SDO type·field 만 파트너에 나간다
(default-deny — 미지 필드·타입 전부 차단). 잔존 객체에 내부 식별자 잔류 원천 봉쇄.

`core/policy/releasability.yaml`(신규):
```yaml
partner_tiers:
  FVEY:  { rel_to: [USA,GBR,CAN,AUS,NZL], caveat: "REL TO FVEY", release_types: [attack-pattern, indicator] }
  NATO:  { rel_to: [NATO], caveat: "REL TO NATO", release_types: [attack-pattern] }
  NOFORN:{ rel_to: [], caveat: "NOFORN", release_types: [attack-pattern] }
```
`ReleasabilityPolicy`(pydantic, validate_models 검증·fail-closed): partner_tiers 명→
{rel_to, caveat, release_types(허용 SDO type 집합)}. 미지 필드 거부.

모듈 상수 `_SAFE_FIELDS`(SDO type→허용 필드 집합) — 잔존 객체는 이 필드만 유지:
attack-pattern={type,id,spec_version,created,modified,name,external_references}(ATT&CK
공개), indicator={...,pattern,pattern_type,valid_from}, relationship={...,relationship_type,
source_ref,target_ref}, marking-definition={...,definition_type,definition,name}.

## 산정 로직 (결정론·순수)
`for_partner(bundle, tier, policy, created_at) → bundle | None`:
1. tier 미지 → None(정책 밖 파트너 유출 차단, fail-safe).
2. **type allowlist**: type ∈ release_types ∪ {marking-definition} 만 유지. identity·
   campaign·infrastructure·threat-actor 등 기본 drop(from_diamond victim 생략에 덧댐).
3. **field allowlist(deep-copy)**: 잔존 객체를 깊은 복사 후 `_SAFE_FIELDS`[type] 필드만
   유지 — created_by_ref(우리 identity)·description·labels·granular_markings·x_* 전부
   drop. object_marking_refs 는 [TLP_ref, statement_ref]로 **재설정**(댕글링·잔여 ref 제거).
4. **ref 정리**: relationship 은 source_ref/target_ref 가 잔존 객체를 가리킬 때만 유지
   (댕글링 SRO 제거). 그 외 *_ref 필드는 field allowlist 로 이미 drop.
5. **statement marking**: STIX 2.1 표준 statement marking-definition(definition_type=
   "statement", definition={statement: caveat}) 1개 생성(결정론 _sid, TLP fixed id 무충돌).
6. 남은 데이터 객체 0 → None(공유할 것 없음). 입력 bundle **무변이**(deep-copy).

## 트러스트
- 결정론·읽기전용. **외향 push 없음**(파생 번들 생산만, to_taxii_envelope 로 직렬화).
- OPSEC: 내부 자산/임무/의도는 애초에 STIX 에 없음(from_diamond victim 생략) +
  파트너 strip 추가. 브리핑(내부)은 릴리서블 파생물에 안 들어감.
- 표준 STIX 만(statement marking 은 표준 — 커스텀 SMO type 미발명). 우리가 생성한
  번들에만 작용(공격자 미영향).
- 미지 티어 → None(정책 밖 파트너에 유출 차단, fail-safe).

## 비목표
- TAXII 서버 push(외향). 인바운드 파트너 STIX 수신(untrusted 병합 — 후속). 실제 배포
  채널. 국가별 세분 릴리서빌리티(티어 수준).

## 배선
StixExporter 소비처(리포트/TI 생산 경로)가 for_partner 로 파트너 번들 파생.
정책 로드 실패 → PolicyError(graceful). metric: 선택(파트너별 릴리스 수).
