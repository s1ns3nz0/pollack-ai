# DAH 2026 참고문헌 (References) — 황준식 lane

> 예선 보고서 8장 참고문헌 초안. 공격 시나리오(S1~S11) 설계 근거를 프레임워크·표준·실전사례로 정리.
> ⚠️ **C절 검증 플래그**의 항목은 본문에서 "보도됨/주장됨/잠재"로 표기하고 단정 인용 금지.
> 시나리오 본체(YAML)는 황준식 프로토타입(`scenarios/*.yaml`)의 `references` 필드와 동기화.

마지막 갱신: 2026-06-15

---

## A. MITRE 프레임워크 / 표준

- **MITRE ATT&CK for ICS** — 산업제어 위협 매트릭스. S1~S4, S6, S7, S9~S11 매핑. https://collaborate.mitre.org/attackics
- **MITRE ATLAS** (Adversarial Threat Landscape for AI Systems) — AI 시스템 위협. S5(방어 AI), S8(온보드 표적 AI), S7/S9. https://atlas.mitre.org
- **MITRE EMB3D** (Embedded Device Threat Model, 2024) — 비행제어기·센서·모뎀 임베디드 위협. S1/S4/S7/S8/S10. https://emb3d.mitre.org
- **MITRE ATT&CK Mobile** — 모바일 앱 침해/자격증명 탈취. S11 병행 매핑. https://attack.mitre.org/matrices/mobile
- **IEC 62443** — 산업제어시스템(IACS) 보안. 방어 아키텍처 기준.
- **ISO/SAE 21434 · UNECE R155** — 차량/UGV 사이버보안 거버넌스. S7 보강.
- **NIST OSCAL** — 통제·증거 자동화 표준. 등급별 증거 아카이빙.
- **MAVLink 프로토콜 보안** — 기본 암호화·메시지 인증 부재(명령/웨이포인트 주입, 세션 하이재킹). S2/S6/S7/S11. arXiv 2512.01164; trout.software.

## B. 실전 사례 (러우전쟁 외) — 시나리오별 근거

### S1 GPS/GNSS 스푸핑 · 지역적 항법 거부
- UT Austin Radionav Lab — 이스라엘 GPS 스푸핑이 민항기에 영향(2023~). https://radionavlab.ae.utexas.edu/israel-gps-spoofing-for-defense-also-affecting-civilian-planes/
- GPS World — Finnair Tartu 운항중단(2024-04~06, 발트/Kaliningrad 재밍). https://www.gpsworld.com/finnair-cancels-flights-amid-increased-gnss-jamming/
- Maritime Executive — 흑해 AIS 스푸핑(2025-01). https://maritime-executive.com/editorials/mass-gps-spoofing-attack-in-black-sea
- Stanford GPS Lab — Russia spoofing 분석(ION ITM 2025).

### S2 C2 재밍·하이재킹 · 광케이블(재밍 내성) · 운용자 사냥
- Atlantic Council — fiber-optic drones(Rubicon·Sudny Den, 2024-08~). https://www.atlanticcouncil.org/blogs/ukrainealert/fiber-optics-drones-have-emerged-as-critical-kit-for-both-russia-and-ukraine/
- Washington Post 2025-05-23 — 광케이블 드론이 재밍 무력화. https://www.washingtonpost.com/world/2025/05/23/ukraine-russia-drones-fiberoptic-jamming/
- The Counteroffensive — RF 방향탐지 기반 드론 운용자 사냥. https://counteroffensive.pro/p/inside-ukraine-s-hunt-for-russian-drone-operators

### S4 펌웨어/공급망 변조
- HRW — Hezbollah 페이저 폭발(2024-09-17). https://www.hrw.org/news/2024/09/18/lebanon-exploding-pagers-harmed-hezbollah-civilians
- Times of Israel — 위장 제조사 B.A.C. Consulting(악성 제조 프론트).
- Utility Dive — 중국산 인버터/배터리 내 무허가 셀룰러 라디오(2025-05, **확인된 out-of-band PoC**). https://www.utilitydive.com/news/rogue-communication-devices-found-on-chinese-made-solar-power-inverters/748242/
- Tom's Hardware — DJI DoD 중국군사기업 목록 유지(**구조적/잠재**, 군용 실증 없음).

### S7 UGV 원격조종 탈취·노획
- MWI West Point — Networked for War: Ukraine's Ground Robots(전로봇 합동공격 2024-12, UGV 규모 2k→15k). https://mwi.westpoint.edu/networked-for-war-lessons-from-ukraines-ground-robots/
- USNI Proceedings — Magura USV(Black Sea, 무인체계 노획·역공학 맥락).

### S8 온보드 표적인식 AI 적대적 공격
- Breaking Defense — Auterion Skynode S(재밍·GPS 없이 lock-on). https://breakingdefense.com/2024/06/skynode-s-auterion-autonomy-kit-lets-attack-drones-fly-through-jamming/
- Kyiv Post — The Fourth Law TFL-1(종말 ~500m AI). https://www.kyivpost.com/post/60152
- Defense Express — Saker Scout / Shahed-136 'MS'(Jetson + CRPA). https://en.defence-ua.com/weapon_and_tech/whats_the_russias_new_ai_powered_shahed_136_and_what_its_capable_of-13011.html
- USNI Proceedings 2024-04 — 우크라 <$1,000 열/시각 디코이.
- arXiv 2202.08892 / 2008.13671 — 적대적 패치(객체탐지 회피) **[실험실/연구]**.
- Breaking Defense 2024-04 — Poisoned data could wreck wartime AIs. https://breakingdefense.com/2024/04/poisoned-data-could-wreck-ais-in-wartime-warns-army-software-chief/

### S9 군집 포화 · SOC 과부하
- CSIS — Drone Saturation: Russia's Shahed Campaign(단일야간 728기, 2025-07-08~09). https://www.csis.org/analysis/drone-saturation-russias-shahed-campaign
- CEPA — The Phony War: Decoy Drones(Gerbera). https://cepa.org/article/the-phony-war-ukraine-and-russias-decoy-drones/
- CSIS / Janes — Operation Spiderweb(2025-06-01). https://www.csis.org/analysis/how-ukraines-spider-web-operation-redefines-asymmetric-warfare
- BESA — Operation True Promise(Iran→Israel 2024-04). https://besacenter.org/operation-true-promise-irans-missile-attack-on-israel/
- Epirus — Leonidas HPM 49-drone swarm 무력화(2025-08, 방어 측 참고).

### S10 SATCOM 단말/관리망 무력화
- Viasat/KA-SAT 사건(2022-02-24) — AcidRain 와이퍼로 수만 모뎀 무력화(개전 당일). ESET 분석 + CISA-NSA 공동 권고. **[공식 귀속, 안전 인용]**

### S11 모바일/전술 GCS 침해
- Infamous Chisel — NCSC/CISA/Five Eyes 공동 악성코드 분석(2023, 우크라 군 Android 표적). **[공식 귀속, 안전 인용]**

### S5 RAG 포이즈닝 / 군사 AI 표적 (배경)
- +972 Magazine — Lavender/Gospel(2024-04) **[단독 보도, IDF 부인]**.
- Lieber Institute — Data Poisoning as Covert Weapon.
- Wikipedia — Project Maven / Palantir MSS.

## C. 출처 신뢰도 / 검증 플래그 (본문 단정 금지)

| 항목 | 처리 |
|---|---|
| Operation Spiderweb 폭격기 격파 수 | 영상확인 ~10대 ↔ SBU 주장 41대 → **범위로 표기** |
| Spiderweb "박물관 폭격기로 AI 학습" | 보도되나 1차 출처 미확인(CEPA: 사람 루프 유지) |
| 적대적 패치 전장 실사용 | **실험실/연구만 확인, 실전 미확인** |
| 레이저 dazzling | IR 시커에 내성 가능(파장/시커 의존) |
| DJI 백도어 | **구조적/잠재 위험만**, 군용 실증 없음 |
| 페이저 PETN 정확량/트리거 UX | 출처 상충(메커니즘만 확정) |
| Lavender 37,000/10%/20초 | +972 단독, IDF 부인 |
| KA-SAT(AcidRain) · Infamous Chisel | **공식 귀속·문서화 → 안전 인용 가능** |

> 안전 인용 가능(KA-SAT, Infamous Chisel, MITRE/표준)을 본문 핵심 근거로, 검증 플래그 항목은 보조·맥락으로 배치.
