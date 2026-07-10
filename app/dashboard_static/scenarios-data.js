/*
 * 보고서 시나리오 A/B/C → 대시보드 snapshot(v1) 시퀀스.
 *
 * 기존 리플레이 엔진(resetSnapshots/nextSnapshot/renderSnapshot)이 그대로 소비하는
 * dashboard.snapshot.v1 형식으로 보고서 §4.4~4.6 킬체인을 매핑한다. 백엔드 무변경 —
 * scenarios-ui.js가 클라이언트에서 state.snapshots로 주입한다.
 *
 * ⚠️ 데모 재생 데이터(실 트래픽 아님). bluf.caveats에 명시된다.
 */
(function () {
  "use strict";

  var TACTICS = [
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution",
    "Persistence", "PrivilegeEscalation", "StealthEvasion", "Discovery",
    "LateralMovement", "Collection", "CommandAndControl", "Exfiltration",
    "ImpairProcessControl", "InhibitResponseFunction", "Impact",
  ];

  // dashboard.js IMPACT_LABELS 와 동일한 유효 값만 사용(미등록 값은 raw 로 표시됨).
  var IMPACT_KO = { SUSTAINED: "임무 지속 가능", MINIMAL: "제한적 임무 지속", ABORT: "임무 중지 검토" };

  // 각 시나리오: 보고서 킬체인 단계. tactic은 ATT&CK 매트릭스 열, technique은 표기.
  var DEFS = {
    A: {
      id: "SCN-A", name: "UAV 제어권 탈취", section: "§4.4",
      campaign: "시나리오 A · UAV 제어권 탈취 (C2→제어권)",
      steps: [
        { tactic: "CommandAndControl", tech: "T1071", title: "C2 앱 프로토콜 세션 하이재킹", asset: "datalink-los",
          trace: "UAVDatalinkConn_CL", cpcon: 4, impact: "SUSTAINED",
          sit: "공격자가 datalink-los(TCP 5790) MAVLink 세션을 하이재킹해 통제 채널을 장악했습니다.",
          rec: "MAVLink2 메시지 서명 강제 · 세션 소유권 고정.", next: "무허가 GUIDED 모드 강제(T0855)" },
        { tactic: "ImpairProcessControl", tech: "T0855", title: "무허가 명령으로 GUIDED 모드 강제", asset: "av-mpd",
          trace: "UAVOperator_CL", cpcon: 3, impact: "MINIMAL",
          sit: "SourceSystemId∉{1,254,255}의 무허가 명령이 av-mpd에 수용되어 비행 모드가 GUIDED로 전환됐습니다.",
          rec: "비정상 sysid 세션 차단 · 명령 발신주체 검증.", next: "제어권 전환(Loss/Manipulation of Control)" },
        { tactic: "Impact", tech: "T0827·T0831", title: "제어 권한 운용자→공격자 전환", asset: "비행 제어권",
          trace: "UAVTelemetry_CL", cpcon: 2, impact: "ABORT",
          sit: "제어 권한이 공격자로 넘어갔습니다. 기체는 비행을 유지하나 조종권을 상실했습니다.",
          rec: "링크 무결성 페일오버 · 2인 통제 강제.", next: "종착: 파괴 없이 기동 장악" },
      ],
    },
    B: {
      id: "SCN-B", name: "ISR 영상 노이즈·변조", section: "§4.5",
      campaign: "시나리오 B · ISR 영상 노이즈·변조 (시야 조작)",
      steps: [
        { tactic: "InitialAccess", tech: "T1190", title: "함대관리 API 인증우회(IDOR)", asset: "fleet/pgse API",
          trace: "pgse REST", cpcon: 4, impact: "SUSTAINED",
          sit: "함대관리 API의 객체 권한검사 부재(IDOR)로 공격자가 임무·스트림 식별자에 접근했습니다.",
          rec: "객체 단위 인가 강제 · 식별자 열거 차단.", next: "텔레메트리 위조 주입(T1565.001)" },
        { tactic: "Impact", tech: "T1565.001", title: "텔레메트리 버스 위조 데이터 주입", asset: "telemetry bus",
          trace: "UAV*_CL", cpcon: 3, impact: "MINIMAL",
          sit: "서명 없는 위조 좌표·타임스탬프가 텔레메트리 버스에 주입되어 무결성이 붕괴됐습니다.",
          rec: "producer identity·서명·replay 방지값 강제.", next: "RTSP 중간자 프레임 주입(T1557)" },
        { tactic: "Collection", tech: "T1557", title: "EO/IR RTSP 중간자 프레임 주입", asset: "EO/IR RTSP",
          trace: "RTSP", cpcon: 3, impact: "MINIMAL",
          sit: "미암호·핀닝 부재 RTSP 스트림에 중간자가 노이즈·위조 프레임을 주입했습니다.",
          rec: "RTSP 암호화·인증서 핀닝 · 프레임 시퀀스 검증.", next: "운용자 시야 조작(T0832)" },
        { tactic: "Impact", tech: "T0832", title: "운용자 화면 시야 조작(Manipulation of View)", asset: "GCS/QGC 화면",
          trace: "GCS 표시 불일치", cpcon: 2, impact: "ABORT",
          sit: "원본 텔레메트리와 GCS 표시값이 불일치합니다. 운용자가 표적을 오인합니다. 기체는 정상 비행.",
          rec: "표시-원본 교차검증 · 이상 오버레이 경보.", next: "종착: 상황인식 왜곡" },
      ],
    },
    C: {
      id: "SCN-C", name: "ISR 영상·데이터 유출", section: "§4.6",
      campaign: "시나리오 C · ISR 영상·데이터 유출 (자료 탈취)",
      steps: [
        { tactic: "InitialAccess", tech: "T1078", title: "GCS 자격 브루트포스 → 정규 계정 획득", asset: "auth-stub / GCS",
          trace: "UAVOpAudit_CL", cpcon: 4, impact: "SUSTAINED",
          sit: "MFA 미적용·약한 자격으로 공격자가 GCS 정규 계정·고권한을 획득했습니다.",
          rec: "MFA 강제 · 세션 격리 · 자격증명 재발급.", next: "링크·저장소 암호키 탈취(T1041)" },
        { tactic: "Exfiltration", tech: "T1041", title: "링크·저장소 암호키 탈취", asset: "ISR 저장소",
          trace: "동일 세션 민감객체 접근", cpcon: 3, impact: "MINIMAL",
          sit: "동일 세션에서 키·SAR·영상 등 민감 객체가 연속 접근됐습니다(향후 복호 확보).",
          rec: "객체 접근 세분화 · 키 접근 감사·격리.", next: "SAR·정찰 데이터 C2 반출(T1041·T1565)" },
        { tactic: "Exfiltration", tech: "T1041·T1565", title: "SAR 좌표·정찰 데이터 C2 반출", asset: "외부 C2",
          trace: "outbound C2", cpcon: 2, impact: "ABORT",
          sit: "SAR 표적좌표·정찰 데이터가 C2 채널로 반출됐습니다. 정찰 성과물·통신 기밀성을 상실합니다.",
          rec: "egress default-deny · outbound 이상탐지.", next: "종착: 키·SAR 유출" },
      ],
    },
  };

  function buildSnapshot(def, i) {
    var steps = def.steps;
    var cur = steps[i];
    var nxt = steps[i + 1] || null;
    var n = steps.length;
    var observedTactics = {};
    for (var k = 0; k <= i; k++) {
      if (observedTactics[steps[k].tactic] === undefined) observedTactics[steps[k].tactic] = k + 1;
    }
    var navigator = TACTICS.map(function (t, idx) {
      return {
        tactic: t, order: idx + 1,
        observed: observedTactics[t] !== undefined,
        current: t === cur.tactic,
        predicted: !!(nxt && t === nxt.tactic && observedTactics[t] === undefined),
        gap: false,
        observed_order: observedTactics[t] !== undefined ? observedTactics[t] : null,
        note: "",
      };
    });
    var alerts = steps.slice(0, i + 1).map(function (s, j) {
      return { alert_id: def.id + "-A" + (j + 1), scenario_id: s.tech, title: s.title,
               tactic: s.tactic, technique: s.tech.split("·")[0], order: j + 1 };
    });
    return {
      schema_version: "dashboard.snapshot.v1",
      step: i + 1,
      mode: "replay",
      generated_at: "2026-07-10T00:00:0" + i + "+09:00",
      summary: {
        active_story_count: 1, max_mission_impact: cur.impact,
        hitl_pending_count: 0, decision_advantage: i < n - 1 ? "margin" : "contested",
        cpcon_level: cur.cpcon,
      },
      stories: [{
        story_id: def.id, actor: "RED-" + def.id.slice(-1), campaign_id: def.id,
        campaign_name: def.campaign, matched: i + 1, total: n,
        next_expected: cur.next, target_asset: cur.asset, mission_impact: cur.impact,
        hitl_status: "NOT_REQUIRED", decision_options: [], alerts: alerts,
      }],
      selected_story_id: def.id,
      navigator: navigator,
      topology: { nodes: [], edges: [] },
      bluf: {
        situation: cur.sit, mission_impact: (IMPACT_KO[cur.impact] || cur.impact) + " · 표적 " + cur.asset,
        recommendation: cur.rec, next_move: "다음 예상 수순: " + cur.next,
        confidence: i < n - 1 ? "medium" : "high", hitl_badge: "NOT_REQUIRED",
        caveats: ["보고서 시나리오 " + def.id.slice(-1) + " 테스트 · 데모 재생(실 트래픽 아님)"],
      },
      source: { alert_id: def.id + "-A" + (i + 1), scenario_id: cur.tech, trace: [cur.trace] },
    };
  }

  var SCENARIOS = ["A", "B", "C"].map(function (key) {
    var def = DEFS[key];
    var snaps = def.steps.map(function (_, i) { return buildSnapshot(def, i); });
    return { key: key, id: def.id, name: def.name, section: def.section,
             steps: def.steps.length, snapshots: snaps };
  });

  window.REPORT_SCENARIOS = SCENARIOS;
})();
