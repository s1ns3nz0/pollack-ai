# OODA / Decision Advantage — 결심우위 템포 (결심우위 계층 PR2)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-09 |
| 상태 | 설계(Codex 교차검증 대기) |
| 근거 | Boyd OODA Loop / Decision Advantage — 적보다 빠른 결심주기 |
| 선행 | SOCState.node_timings(아군 지연), ActorProfile.kill_chain[].ts(적 진행 시각) |

## 목표 (Codex Critical 반영 — 정직한 재프레이밍)
**전(全)-OODA vs 적-OODA 를 비교하지 않는다**(적 결심주기는 미관측·미측정). 대신 정직한
측정 프록시: **SOC 브리핑 생성 지연 vs 관측된 적 진행 cadence** — "적의 다음 확정
진행 전에 지휘관 결심 브리핑을 낼 여유(margin)가 있는가". Boyd 의 본질(적 행동 주기
안에서 결심)의 관측가능 근사. 브리핑을 O/O/D/A 구조로 정렬. 결정론·읽기전용·자문.

## 데이터 모델
`DecisionAdvantage`(core/models.py, SOCReport 필드):
- `soc_latency_ms: float` — SOC 브리핑 생성 지연(detect→brief, node_timings 합).
  **report 노드 자체 시간 제외 하한**(lower bound, Codex High).
- `soc_latency_partial: bool` — 위 하한 여부(항상 True — 정직 표기).
- `adversary_cadence_ms: float | None` — 관측 적 진행 간격(kill_chain 연속 step ts
  **양(+)의 델타** 중앙값). <1 양델타 → None.
- `advance_count: int` — 관측된 kill_chain 단계 수.
- `verdict: Literal["margin","contested","unknown"]` — soc_latency < cadence =
  **margin**(다음 적 진행 전 결심 여유), ≥ = **contested**(cadence 못 따라감),
  cadence None = **unknown**. (inside/outside 대신 정직한 라벨.)
- `ooda: dict[str,list[str]]` — O/O/D/A 단계별 기여 산출물 라벨(브리핑 구조).
- `basis: list[str]` — 비교 근거·정직성 주석(무엇 vs 무엇, 하한·unknown 사유).

## 산정 로직 (결정론)
`DecisionAdvantageAssessor.assess(soc_latency_ms, kill_chain)`:
1. kill_chain step ts(ISO)를 파싱해 연속 델타(ms) 산출.
2. **양(+)의 델타만 유효**(Codex High): 0/음수/중복 ts(한 alert 다기법=동일 now)
   제외 — cadence=0 이 verdict 를 거짓 contested 로 몰지 않게.
3. 유효 양델타 <1 → adversary_cadence None, verdict "unknown"(outside 아님).
4. 유효하면 중앙값 = cadence. verdict: soc_latency < cadence → margin, ≥ → contested.
5. 순수·total(예외 불가). ts 파싱 오류는 삼켜 제외.

`ooda_alignment(present) → dict`: 리포트에 존재하는 산출물을 O/O/D/A 로 매핑(정적
교리 맵). Observe=[signals,telemetry], Orient=[diamond,actor,campaign,causal],
Decide=[coa,intent,directive,recovery], Act=[recommended_action(자문)].

## 트러스트
- 결정론·읽기전용. cadence 는 **ActorReadGate 검증 프로필(서명·포이즈닝 면역 write
  gate, 서버시각 ts)**의 kill_chain 에서만(Codex Medium) — untrusted alert 필드·
  raw store 프로필 미사용. explicit actor_id 만 회상(auto-fingerprint→cadence unknown,
  정직). soc_latency 는 측정값(관측성).
- verdict 는 자문 지표 — verdict/severity/CAT 불변. **unknown·partial·비교대상을 정직히
  노출**(과장 금지 — "적 루프 안" 단정 금지, "결심 여유" 프레이밍).
- soc_latency 는 wall-clock 측정이라 실행마다 변동 — 결정론 위반 아님. 테스트는
  soc_latency·kill_chain 주입으로 결정론 검증.

## 비목표
- BLUF 합성(PR4 — ooda 구조·verdict 를 서술로). 적 템포 예측(과거 관측만). 자동 대응.

## 배선
report_agent 가 node_timings 합(soc_latency) + ActorReadGate profile.kill_chain으로
assess → SOCReport.decision_advantage. metric: soc_decision_margin_total{verdict=
margin|contested|unknown} 카운터(판정 유형별 per-alert 이벤트).
