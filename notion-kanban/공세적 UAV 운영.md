# 공세적 UAV 운영

- **Status**: To Do
- **담당자**: 황준식, 양진수, 김수지, 김동언
- **마감일**: 2026-06-28
- **URL**: https://app.notion.com/p/386f5e835bb480ff9e60e02313434c21

---

# UAV 공세적 운용 개념
- 현재 한국군의 UAV 공세적 운용은 어떤 식으로 이루어지고 있는가?
- 우-러 전쟁에서 UAV의 공세적 운용은 어떻게?
- 미군에서는 어떻게?

# 사이버 공세적 운용 어떻게 할 것인가
- 아이디어 브레인 스토밍
- 예) 재밍 시도 탐지 시 > 온보드 AI 통해서 어떻게 한다~
- 예) 주변 드론 탐지 >
- 예) 네트워크 중심전을 활용한 것들??

### 광역적인 의미로 국군 > 다양한 사례 포괄
- 타격 용도(헬파이어, 대인무기, 여러 가지 타격 가능한 시나리오)
- 공세적 운용 > 언제 날릴 것이냐를 결정하는 것(방공망 고려)

---

## 조사 결과 — 공세적 운용 동향 + 타격 사례 (2026-06-25)
결론: 공세적 운용에 '타격(strike)'을 포함하는 게 맞음. 최근 30일 실데이터상 드론 위협은 정찰이 아니라 타격이 목적(에너지·물류·GCS)이라, 방어 AI가 그 타격 의도·표적을 모델링해야 위협모델 정합성이 맞음.

### 우-러 전쟁 등 최근 30일 타격 사례
- 에너지 종심타격(deep-strike): 모스크바 유일 정유소가 드론 타격으로 가동 중단 — 복구 6개월·2027년까지 생산 불가. 개전 이후 최대급 단일 야간 장거리 공격 [ABC News](https://abcnews.com/International/ukraine-strikes-moscow-oil-refinery-amid-large-scale/story?id=133990719)
- FPV 타격: 러시아 측 피격의 최대 80%를 FPV가 차지, 광케이블·재밍내성으로 진화, 물류 표적화 [drone-warfare.com](https://drone-warfare.com/research/fpv-drone-warfare/) · [전송 진화 영상](https://www.reddit.com/r/CombatFootage/comments/1udjtae/ukrainian_fpv_drones_targeting_russian_logistics/)
- 스웜 포화공격: 1월 한 야간 6개 지점에서 154기+ 동시 발사(81% 요격). 단일 counter-UAS(EW/kinetic/지향성에너지)로 방어 불가, 비용 비대칭 [AeroVironment](https://www.avinc.com/2026/05/05/were-fighting-2026-drone-swarms-with-cold-war-architecture-its-time-to-upgrade/)
- 확산: 미얀마 반군 FPV 타격 등 우크라 밖으로 공세적 운용 확산
- 장거리 loitering munition 종심타격이 $13B+ 시장으로(유럽 ELSA 공동개발 등) [Shephard/Eurosatory](https://www.shephardmedia.com/news/air-warfare/eurosatory-2026-deep-strike-uavs-working-title/)

### 방어 AI 시나리오 연결
- S9 군집 포화·SOC 과부하 ↔ swarm-vs-swarm 네트워크 방어로 직접 연결
- 타격 표적(정유소·물류·GCS) 모델링 → 탐지·대응 우선순위 설정에 반영
- 공격↔방어 루프 실증: 러 MANPADS 팀이 우크라 '타격 UAV'에 대응(6/18 영상)

### 출처
- [ABC News — 모스크바 정유소 대규모 드론 타격](https://abcnews.com/International/ukraine-strikes-moscow-oil-refinery-amid-large-scale/story?id=133990719)
- [AeroVironment — 2026 스웜 vs Cold War 방어 아키텍처](https://www.avinc.com/2026/05/05/were-fighting-2026-drone-swarms-with-cold-war-architecture-its-time-to-upgrade/)
- [drone-warfare.com — FPV Drone Warfare 연구](https://drone-warfare.com/research/fpv-drone-warfare/)
- [Shephard — Eurosatory 2026 deep-strike loitering munition 시장](https://www.shephardmedia.com/news/air-warfare/eurosatory-2026-deep-strike-uavs-working-title/)

---

## 보강 — 공세적 운용 개념(한국군·우-러·미군) + 사이버 공세 아이디어 (2026-06-25)

### 한국군 공세적 운용
- 정의: **물리적 타격이 아닌 적 방공망 무력화(통상 90% 이하) 상관없이 지휘관의 결심에 따른 작전우위달성을 위해 정보를 공세적으로 수집(ex: 적 방공망이 50%여도 기존 회랑에 따른 작전을 진행시키고 아군 UAV자산이 타격위험 노출이 있더라도 작전우선권에 따라 해당지역으로 정보수집 진행)**
- 드론작전사령부(2023 창설, 국방부 직할·합참의장 지휘): 감시정찰 외 타격·심리전·전자기전(EW)을 공식 임무로 수행
- 육군, 대대급 전투부대에 정찰드론+공격용 자폭드론 도입 추진 — 우-러 전쟁의 '저가 비대칭 전력' 교훈 반영
- '50만 드론전사 양성' 프로젝트 + 유·무인 복합(MUM-T) K-무인체계 — 단 국내 산업기반·예산 한계로 2026 중국산 상용드론 1만여대 투입(공급망 리스크)
- 심리전 공세 사례: 2024 평양 무인기 대북전단 살포(무인기를 정보·심리 공세 수단으로 사용)
- 시사점(우리 프로젝트): 한국군은 '타격+EW+심리전'을 공세 범주로 봄 → 방어 AI 시나리오도 타격뿐 아니라 EW·심리전 벡터까지 위협면에 포함하면 도메인 정합성↑

### 우-러 공세적 운용 (요약 — 상세는 위 '조사 결과' 섹션)
- 에너지·물류 종심타격(정유소 가동중단), FPV가 피격 최대 80%, 스웜 포화로 다층 방어 무력화 — 공세의 3대 축

### 미군 공세적 운용
**정의 —** 미군의 공세적 UAV 운용은 무인체계로 적에 대해 치명적·비치명적 효과를 직접 투사하는 작전을 말한다(방어·대드론(C-UAS)과 대비). ISR–타격 통합, 일방향공격(OWA)/배회폭탄(loitering munition), 화력 제압, 스웜 교전이 핵심 수단이며, 'Drone Dominance / Army Transformation' 교리 하에서 소형 UAS를 소모성 탄약으로 재분류해 분대~여단급의 유기적 정밀타격을 부여하고 Replicator로 대량 attritable 자율성을 추구한다.

- **핵심 특성 ① 대량·소모성(attritable mass):** 저가·다수 운용, 손실을 전제로 한 비대칭 화력
- **핵심 특성 ② 분산·제대 하향(organic strike):** 분대급까지 자체 정밀타격 수단 보유 — UAS를 '항공기'가 아닌 '탄약'으로 취급
- **핵심 특성 ③ 센서–슈터 압축 / MUM-T:** 탐지→타격 결심주기 단축, 유·무인 복합으로 표적 핸드오프
- **핵심 특성 ④ 자율성(Replicator):** 인간 감독 하 다수 자율 체계의 18~24개월 신속 야전화 지향

- Drone Dominance / Army Transformation: 소형 UAS를 '항공기'가 아닌 '소모성 탄약'으로 재분류, 여단→분대급까지 대량 통합(2026말 모든 분대 소형드론 휴대)
- Replicator: 수천 대 attritable·자율 체계를 18~24개월 내 야전 배치 목표 — 단 관료주의로 속도 저항
- Switchblade 600 Block 2 + 300 EFP 대전차 loitering munition $186M 승인, 월 1만 기 국내생산(SkyFoundry, 연 100만 목표)
- FPV 전쟁 교훈으로 전투교리 재작성, 공군은 일방향공격(OWA) 실험부대 창설

### 사이버/EW 공세적 운용 아이디어 (방어 AI 연계 · 브레인스토밍)
전제: 군용 C-UAS/EW 맥락의 방어적 공세. 모든 동작은 ROE·교전권한·Human-in-the-Loop 게이트 하에서만. 아래는 보고서·아키텍처 수준 개념(무기 제작 X).

- ① 재밍 시도 탐지 → 온보드 AI 자율 대응
  - 재머 방향탐지(DF)로 위협 방위 추정 → 주파수 호핑/대체 링크(SATCOM↔메시) 자동 전환
  - GNSS 재밍·스푸핑 시 INS/관성항법 페일오버 + 사전계획 임무 자율수행(통신두절 내성)
  - 'home-on-jam' 개념: 재머 위치를 표적화 후보로 SOC에 보고(타격은 HITL 승인) — 탐지→대응 루프를 우리 6-에이전트 Response에 매핑
- ② 주변 드론 탐지 → 협조 교전(cooperative engagement)
  - 온보드 센서퓨전(EO/IR+RF)으로 적·아군 드론 식별 → 회피/요격/전자적 무력화(링크 스푸핑·테이크오버) 옵션 생성
  - 스웜 분산합의로 표적 분배(swarm-vs-swarm) — AeroVironment의 '네트워크 공유 동시 무력화'와 동일 개념
- ③ 네트워크 중심전(NCW) 활용
  - 기체–GCS–AI SOC 간 표적/위협 데이터 실시간 공유 → 한 기가 탐지하면 다른 기가 교전(센서-슈터 분리)
  - 멀티도메인 표적 핸드오프 + AI SOC가 EW·사이버 상황을 통합해 대응안 권고(최종 실행은 HITL)
  - MAVLink 등 미인증 프로토콜 취약점은 '공격자가 쓰는 벡터'이자 우리가 역이용/차단할 지점 — S2/S6 시나리오와 직결
- ④ 거울상 원칙(핵심): 위 공세 아이디어 = 우리가 방어해야 할 위협의 거울상 → 그대로 S1~S11 공격자 TTP/레드팀 시나리오로 재활용 가능
