const state = {
  snapshots: [],
  seenSnapshotKeys: new Set(),
  index: 0,
  selectedStoryId: "",
  live: false,
  connectionState: "replay",
  dataMode: "replay",
  eventSource: null,
  topology: { nodes: [], edges: [] },
  topologyDraw: null,
};

const TACTIC_LABELS = {
  Reconnaissance: "정찰",
  ResourceDevelopment: "공격 자원 준비",
  InitialAccess: "초기 침투",
  Execution: "실행",
  Persistence: "지속 거점화",
  PrivilegeEscalation: "권한 상승",
  StealthEvasion: "은닉/회피",
  Discovery: "체계 탐색",
  LateralMovement: "수평 이동",
  Collection: "정보 수집",
  CommandAndControl: "지휘통제 장악",
  Exfiltration: "자료 유출",
  ImpairProcessControl: "제어 절차 교란",
  InhibitResponseFunction: "대응 기능 무력화",
  Impact: "임무 영향/파괴",
};

const TECHNIQUE_LABELS = {
  T1595: "능동 스캔",
  T1592: "운용자/조직 정보 수집",
  T1590: "네트워크 정보 수집",
  T1596: "공개 기술정보 수집",
  T1587: "공격 도구 개발",
  T1588: "공격 도구 확보",
  T1608: "공격 인프라 준비",
  T1190: "공개 서비스 취약점 악용",
  T1195: "공급망 침해",
  T1078: "유효 계정 악용",
  T0860: "무선 링크 접근",
  T0864: "권한 있는 기능 악용",
  T1133: "외부 원격 서비스",
  T1059: "명령/스크립트 실행",
  T1106: "Native API 호출",
  T1204: "사용자 실행 유도",
  T0821: "제어 서비스 실행",
  "T1692.001": "비인가 명령 주입",
  T1556: "인증 절차 변조",
  "T1542.001": "펌웨어 부트킷",
  T1546: "이벤트 기반 실행",
  T1068: "취약점 이용 권한상승",
  T1070: "흔적 삭제",
  T1036: "정상 구성 위장",
  T1601: "시스템 이미지 변조",
  T0878: "경보 억제",
  T1014: "루트킷",
  T0842: "네트워크 스니핑",
  T0887: "무선 스니핑",
  T0840: "네트워크 연결 탐색",
  T0843: "프로그램 다운로드",
  T1210: "원격 서비스 취약점 악용",
  T1570: "측면 도구 전송",
  T1021: "원격 서비스 이동",
  T1550: "대체 인증재료 사용",
  T1694: "공유 자원 악용",
  T1080: "공유 콘텐츠 오염",
  T1563: "원격 세션 장악",
  T1185: "브라우저 세션 하이재킹",
  T1125: "영상/음성 캡처",
  T1113: "화면 캡처",
  T1005: "로컬 데이터 수집",
  T1074: "자료 임시 집결",
  T1119: "자동 수집",
  T1560: "자료 압축/보관",
  T0882: "운용정보 절취",
  T0845: "프로그램 업로드",
  T1056: "입력값 탈취",
  T0801: "공정 상태 감시",
  T0868: "운용 모드 식별",
  T0861: "표적 지정정보 식별",
  T1071: "응용계층 프로토콜 C2",
  T1571: "비표준 포트",
  T1090: "프록시/중계",
  T1008: "대체 통신채널",
  T1105: "도구/파일 전송",
  T1095: "비응용계층 프로토콜",
  T1104: "다단계 채널",
  T1219: "원격 접근 도구",
  T1659: "콘텐츠 삽입",
  T1572: "프로토콜 터널링",
  T1573: "암호화 채널",
  T1001: "데이터 난독화",
  T1132: "데이터 인코딩",
  T1041: "C2 채널 경유 유출",
  T1020: "자동 유출",
  T1029: "예약 전송",
  T1048: "대체 프로토콜 유출",
  T1030: "전송량 제한 회피",
  T1011: "대체 매체 유출",
  T1567: "웹 서비스 유출",
  T0836: "제어 논리 수정",
  T1693: "제어 명령 변조",
  T1692: "제어 명령 주입",
  T0806: "제어 파라미터 변경",
  T0838: "경보/이벤트 억제",
  T0814: "장치 재시작/정지",
  T1695: "안전 기능 우회",
  "T1691.002": "시스템 복구 방해",
  T0881: "서비스 중지",
  T0816: "장치 설정 변경",
  T0892: "프로세스 상태 은폐",
  T0835: "GNSS 스푸핑",
  T0809: "자료 파괴",
  T0800: "펌웨어 업데이트 모드 악용",
  T0851: "루트킷",
  T0832: "제어 기능 상실",
  T0827: "서비스 거부",
  T0880: "가용성 손상",
  T0879: "운용 정보 손실",
  T1498: "네트워크 서비스 거부",
  T1565: "자료 조작",
  T0831: "운용 상태 조작",
  T0813: "작동 거부",
  T0826: "제어 불능",
  T0837: "손상 상태 유도",
  T0828: "운용성 상실",
  T1499: "엔드포인트 서비스 거부",
  T1529: "시스템 종료/재부팅",
  T1495: "펌웨어 손상",
  T1485: "자료 파괴",
  T0815: "서비스 중단",
  T0829: "운용 안전 손상",
  T1531: "계정 접근 제거",
};

const ATTACK_MATRIX = [
  { tactic: "Reconnaissance", covered: ["T1595", "T1592", "T1590", "T1596"], planned: [], uncovered: [] },
  { tactic: "ResourceDevelopment", covered: [], planned: [], uncovered: ["T1587", "T1588", "T1608"] },
  { tactic: "InitialAccess", covered: ["T1190", "T1195", "T1078", "T0860", "T0864"], planned: ["T1133"], uncovered: [] },
  { tactic: "Execution", covered: ["T1059", "T1106", "T1204", "T0821", "T1692.001"], planned: [], uncovered: [] },
  { tactic: "Persistence", covered: ["T1556", "T1542.001", "T1078", "T1546"], planned: [], uncovered: [] },
  { tactic: "PrivilegeEscalation", covered: ["T1068", "T1078"], planned: [], uncovered: [] },
  { tactic: "StealthEvasion", covered: ["T1070", "T1036", "T1601", "T1692.001", "T0878", "T1014"], planned: [], uncovered: [] },
  { tactic: "Discovery", covered: ["T0842", "T0887"], planned: ["T0840"], uncovered: [] },
  { tactic: "LateralMovement", covered: ["T1078", "T0843", "T1210", "T1570", "T1021", "T1550", "T1694", "T1080"], planned: ["T1563"], uncovered: [] },
  { tactic: "Collection", covered: ["T1185", "T1125", "T1113", "T1005", "T1074", "T1119", "T1560", "T0882", "T0845", "T1056"], planned: [], uncovered: ["T0801", "T0887", "T0868", "T0861"] },
  { tactic: "CommandAndControl", covered: ["T1071", "T1571", "T1090", "T1008", "T1105", "T1095", "T1104", "T1219"], planned: ["T1659"], uncovered: ["T1572", "T1573", "T1001", "T1132"] },
  { tactic: "Exfiltration", covered: ["T1041", "T1020", "T1029", "T1048", "T1030", "T1011", "T1567"], planned: [], uncovered: [] },
  { tactic: "ImpairProcessControl", covered: ["T0836", "T1693", "T1692", "T0806"], planned: [], uncovered: [] },
  { tactic: "InhibitResponseFunction", covered: ["T0838", "T0814", "T1695", "T1691.002", "T0881", "T0816", "T0892", "T0835"], planned: [], uncovered: ["T0878", "T0809", "T0800", "T0851"] },
  { tactic: "Impact", covered: ["T0832", "T0827", "T0880", "T0879", "T1498", "T1565", "T0831", "T0813", "T0826", "T0837", "T0828", "T1499", "T1529", "T1495", "T1485"], planned: ["T0815", "T0829", "T1531"], uncovered: [] },
];

const SCENARIO_TECHNIQUES = {
  "S117-BLOS-SATCOM-MITM": "T1071",
  "S24-DATALINK-C2-TAKEOVER": "T1071",
  "S3-UNAUTHORIZED-WEAPON-CMD": "T0832",
  "S1-GNSS-SPOOFING": "T0835",
};

const ASSET_LABELS = {
  C2_LINK: "지휘통제 링크",
  SATCOM: "BLOS 위성통신 링크",
  GNSS: "항법/GNSS 수신체계",
  AUTOPILOT: "비행제어 컴퓨터",
  GCS: "지상통제소",
  AI_SOC: "AI SOC 판단 계층",
  TELEMETRY: "비행 텔레메트리",
};

const IMPACT_LABELS = {
  UNKNOWN: "평가 대기",
  STUB: "시뮬레이션/미연동",
  SUSTAINED: "임무 지속 가능",
  MINIMAL: "제한적 임무 지속",
  ABORT: "임무 중지 검토",
};

const HITL_LABELS = {
  NOT_REQUIRED: "자동 조치 가능",
  REQUIRED: "지휘관 승인 필요",
  PENDING: "결심 대기",
  APPROVED: "승인 완료",
};

const DECISION_LABELS = {
  margin: "결심 여유 있음",
  contested: "결심 여유 제한",
  unknown: "판단 대기",
};

const NODE_LABELS = {
  "av-muav": "KUS-FS 중고도 무인기",
  "datalink-los": "LOS 지상 데이터링크",
  "datalink-satcom": "BLOS 위성통신 링크",
  "gcs-qgc": "지상통제소 / MCE",
  "telemetry-tap": "SOC 텔레메트리 수집기",
  "ground-truth-tap": "시뮬레이션 기준값 수집기",
  "counter-uas": "대무인기 방어 진지",
  "service-audit": "서비스 감사 센서",
  "mps-stub": "임무계획 체계",
  "pgse-stub": "지상지원/정비장비",
  "weapon-stub": "무장통제 연동부",
  "ti-stub": "위협정보 연동부",
  "auth-stub": "운용자 인증 체계",
  "cyber-posture-stub": "사이버 태세 점검 서비스",
  "sar-stub": "SAR/임무장비 서비스",
  "web-stub": "웹 관리 접점",
  "rc-link-stub": "RC/Wi-Fi 예비 링크",
  "supply-chain-stub": "공급망 연동부",
  "file-audit-stub": "파일 감사 센서",
  "companion-stub": "동반컴퓨터/ROS 표면",
  "devops-stub": "빌드/배포 파이프라인",
  "fleet-infra-stub": "군집 운용 API",
  "c4i-stub": "C4I 인계 연동부",
  "ai-soc": "AI SOC 판단/권고 계층",
};

const PLANE_LABELS = {
  air: "항공기",
  link: "통신링크",
  ground: "지상체계",
  soc: "SOC/센서",
  c4i: "C4I",
};

const KIND_LABELS = {
  air_vehicle: "비행체",
  data_link: "데이터링크",
  ground_control_station: "지상통제소",
  sensor: "감시 센서",
  soc: "SOC 판단계층",
  weapon_control: "무장통제",
  mission_system: "임무계획",
  support_equipment: "지상지원장비",
  threat_intel: "위협정보",
  identity: "인증",
  posture: "태세점검",
  payload: "임무장비",
  application: "웹 접점",
  supply_chain: "공급망",
  companion_computer: "동반컴퓨터",
  devops: "빌드/배포",
  fleet_infra: "군집운용",
  c4i: "C4I 연동",
  defensive_system: "방어체계",
};

function text(value) {
  return value === undefined || value === null || value === ""
    ? "UNKNOWN"
    : String(value);
}

function currentSnapshot() {
  return state.snapshots[state.index] || null;
}

function snapshotDedupKey(snapshot) {
  const source = snapshot.source || {};
  const alertId = text(source.alert_id);
  const scenarioId = text(source.scenario_id);
  const generatedAt = text(snapshot.generated_at);
  return [
    text(snapshot.schema_version),
    text(snapshot.step),
    alertId,
    scenarioId,
    generatedAt,
  ].join("::");
}

function appendSnapshotIfNew(snapshot) {
  const key = snapshotDedupKey(snapshot);
  if (state.seenSnapshotKeys.has(key)) {
    return false;
  }
  state.seenSnapshotKeys.add(key);
  state.snapshots.push(snapshot);
  return true;
}

function resetSnapshots(snapshots) {
  state.snapshots = [];
  state.seenSnapshotKeys = new Set();
  snapshots.forEach((snapshot) => {
    appendSnapshotIfNew(snapshot);
  });
}

function clearNode(node) {
  node.replaceChildren();
}

function createElement(tagName, className, value) {
  const element = document.createElement(tagName);
  if (className) {
    element.className = className;
  }
  if (value !== undefined) {
    element.textContent = value;
  }
  return element;
}

function appendLabeledValue(parent, label, value, valueClass = "metric-value") {
  const labelNode = createElement("div", "metric-label", label);
  const valueNode = createElement("div", valueClass, text(value));
  parent.append(labelNode, valueNode);
}

function createFallbackCard(className, message) {
  return createElement("div", className, message);
}

function localizedTactic(tactic) {
  return TACTIC_LABELS[text(tactic)] || text(tactic);
}

function localizedTechnique(techniqueId) {
  return TECHNIQUE_LABELS[text(techniqueId)] || text(techniqueId);
}

function localizedAsset(assetId) {
  return ASSET_LABELS[text(assetId)] || text(assetId);
}

function localizedImpact(level) {
  return IMPACT_LABELS[text(level)] || text(level);
}

function localizedKind(kind) {
  return KIND_LABELS[text(kind)] || text(kind);
}

function objectParticle(value) {
  const word = text(value);
  const last = word.charCodeAt(word.length - 1);
  if (last < 0xac00 || last > 0xd7a3) {
    return "를";
  }
  return (last - 0xac00) % 28 === 0 ? "를" : "을";
}

function localizedHitl(status) {
  return HITL_LABELS[text(status)] || text(status);
}

function selectedStory(snapshot) {
  const stories = Array.isArray(snapshot.stories) ? snapshot.stories : [];
  return (
    stories.find((story) => story.story_id === state.selectedStoryId) ||
    stories[0] ||
    null
  );
}

function storyAlerts(story) {
  return story && Array.isArray(story.alerts) ? story.alerts : [];
}

function alertTechnique(alert) {
  const direct = alert.technique || alert.technique_id;
  if (direct) {
    return text(direct);
  }
  return SCENARIO_TECHNIQUES[text(alert.scenario_id)] || "";
}

function observedTechniqueSet(story) {
  const techniques = new Set();
  storyAlerts(story).forEach((alert) => {
    const technique = alertTechnique(alert);
    if (technique) {
      techniques.add(technique);
    }
  });
  return techniques;
}

function observedSequenceMaps(story) {
  const techniqueOrder = new Map();
  const tacticOrder = new Map();
  storyAlerts(story).forEach((alert) => {
    const technique = alertTechnique(alert);
    if (!technique || techniqueOrder.has(technique)) {
      return;
    }
    const order = techniqueOrder.size + 1;
    techniqueOrder.set(technique, order);
    const tactic = text(alert.tactic);
    if (!tacticOrder.has(tactic)) {
      tacticOrder.set(tactic, order);
    }
  });
  return { techniqueOrder, tacticOrder };
}

function scrollMatrixToTactic(tactic) {
  const scroll = document.querySelector(".matrix-scroll");
  const column = document.querySelector(
    `.tactic-column[data-tactic="${tactic}"]`,
  );
  if (!scroll || !column) {
    return;
  }
  scroll.scrollLeft =
    column.offsetLeft - (scroll.clientWidth - column.offsetWidth) / 2;
}

function appendKillchain(container, tacticStates, tacticOrder) {
  const track = createElement("div", "killchain");
  let lastObservedIdx = -1;
  let predictedIdx = -1;

  ATTACK_MATRIX.forEach((matrixColumn, index) => {
    const cell = tacticStates.get(matrixColumn.tactic);
    const observed =
      tacticOrder.has(matrixColumn.tactic) || Boolean(cell && cell.current);
    if (observed) {
      lastObservedIdx = index;
    }
    if (cell && cell.predicted) {
      predictedIdx = index;
    }
  });

  ATTACK_MATRIX.forEach((matrixColumn, index) => {
    const cell = tacticStates.get(matrixColumn.tactic);
    const observed =
      tacticOrder.has(matrixColumn.tactic) || Boolean(cell && cell.current);

    const stage = createElement("button", "kc-stage");
    stage.type = "button";
    stage.title = `${localizedTactic(matrixColumn.tactic)} (${matrixColumn.tactic})`;
    if (observed) {
      stage.classList.add("kc-observed");
    }
    if (cell && cell.current) {
      stage.classList.add("kc-current");
    }
    if (cell && cell.predicted) {
      stage.classList.add("kc-predicted");
    }
    if (matrixColumn.uncovered.length > 0 || (cell && cell.gap)) {
      stage.classList.add("kc-gap");
    }
    if (index > 0) {
      if (index <= lastObservedIdx) {
        stage.classList.add("link-observed");
      } else if (index <= predictedIdx) {
        stage.classList.add("link-predicted");
      }
    }

    const sequence = tacticOrder.get(matrixColumn.tactic);
    const dot = createElement(
      "span",
      "kc-dot",
      sequence === undefined ? "" : String(sequence),
    );
    const label = createElement(
      "span",
      "kc-label",
      localizedTactic(matrixColumn.tactic),
    );
    stage.append(dot, label);
    stage.addEventListener("click", () => {
      scrollMatrixToTactic(matrixColumn.tactic);
    });
    track.appendChild(stage);
  });

  container.appendChild(track);
}

function predictedTechnique(snapshot, story) {
  const nextExpected = text(story ? story.next_expected : "");
  if (SCENARIO_TECHNIQUES[nextExpected]) {
    return SCENARIO_TECHNIQUES[nextExpected];
  }
  const predictedCell = (Array.isArray(snapshot.navigator) ? snapshot.navigator : [])
    .find((cell) => cell.predicted);
  const tactic = predictedCell ? predictedCell.tactic : "";
  const matrix = ATTACK_MATRIX.find((column) => column.tactic === tactic);
  if (!matrix) {
    return "";
  }
  return matrix.planned[0] || matrix.uncovered[0] || matrix.covered[0] || "";
}

function tacticStateMap(snapshot) {
  const cells = Array.isArray(snapshot.navigator) ? snapshot.navigator : [];
  return new Map(cells.map((cell) => [cell.tactic, cell]));
}

const IMPACT_TONES = {
  SUSTAINED: "tone-sustained",
  MINIMAL: "tone-predicted",
  ABORT: "tone-gap",
};

const DECISION_TONES = {
  margin: "tone-sustained",
  contested: "tone-gap",
};

function renderTopStrip(snapshot) {
  const container = document.getElementById("top-strip");
  if (!container) {
    return;
  }

  const summary = snapshot.summary || {};
  const storyCount = Number(summary.active_story_count) || 0;
  const pendingCount = Number(summary.hitl_pending_count) || 0;
  const metrics = [
    [
      "진행 중인 적 행동",
      summary.active_story_count,
      "건",
      storyCount > 0 ? "tone-current" : "",
    ],
    [
      "최고 임무 영향",
      localizedImpact(summary.max_mission_impact),
      "",
      IMPACT_TONES[text(summary.max_mission_impact)] || "",
    ],
    [
      "지휘관 결심 대기",
      summary.hitl_pending_count,
      "건",
      pendingCount > 0 ? "tone-predicted" : "",
    ],
    [
      "결심 여유",
      DECISION_LABELS[text(summary.decision_advantage)] || text(summary.decision_advantage),
      "",
      DECISION_TONES[text(summary.decision_advantage)] || "",
    ],
  ];

  clearNode(container);
  metrics.forEach(([label, value, suffix, tone]) => {
    const card = createElement("div", "metric");
    if (tone) {
      card.classList.add(tone);
    }
    appendLabeledValue(card, label, `${text(value)}${suffix ? ` ${suffix}` : ""}`);
    container.appendChild(card);
  });
}

function normalizeSelectedStory(snapshot) {
  const stories = Array.isArray(snapshot.stories) ? snapshot.stories : [];
  const hasSelectedStory = stories.some(
    (story) => story.story_id === state.selectedStoryId,
  );

  if (!hasSelectedStory) {
    state.selectedStoryId = text(snapshot.selected_story_id);
  }

  if (state.selectedStoryId === "UNKNOWN" && stories.length > 0) {
    state.selectedStoryId = text(stories[0].story_id);
  }
}

function selectStory(storyId) {
  state.selectedStoryId = storyId;
  renderSnapshot(currentSnapshot());
}

function renderStoryRail(snapshot) {
  const container = document.getElementById("story-rail");
  if (!container) {
    return;
  }

  const stories = Array.isArray(snapshot.stories) ? snapshot.stories : [];
  normalizeSelectedStory(snapshot);
  clearNode(container);

  if (stories.length === 0) {
    container.appendChild(createFallbackCard("story-card", "진행 중인 적 행동 없음"));
    return;
  }

  stories.forEach((story) => {
    const isActive = story.story_id === state.selectedStoryId;
    const isPending = story.hitl_status === "PENDING";

    const button = createElement("button", "story-card");
    button.type = "button";
    if (isActive) {
      button.classList.add("active");
    }
    button.addEventListener("click", () => {
      selectStory(text(story.story_id));
    });

    const title = createElement("div", "story-title");
    const storyId = createElement("span", "story-id", text(story.story_id));
    const badge = createElement("span", "badge", localizedHitl(story.hitl_status));
    if (isPending) {
      badge.classList.add("pending");
    }
    title.append(storyId, badge);

    const campaign = createElement(
      "div",
      "story-meta",
      `${text(story.campaign_name || story.campaign_id)} · 진행 ${text(
        story.matched,
      )}/${text(story.total)}`,
    );
    const target = createElement(
      "div",
      "story-meta",
      `표적 ${localizedAsset(story.target_asset)} · ${localizedImpact(
        story.mission_impact,
      )}`,
    );

    const matched = Number(story.matched) || 0;
    const total = Number(story.total) || 0;
    const progress = createElement("div", "story-progress");
    const fill = createElement("div", "story-progress-fill");
    const ratio = total > 0 ? Math.min(1, matched / total) : 0;
    fill.style.width = `${Math.round(ratio * 100)}%`;
    progress.appendChild(fill);

    button.append(title, campaign, target, progress);

    storyAlerts(story).forEach((alert) => {
      const alertRef = createElement(
        "div",
        "alert-ref",
        `${text(alert.alert_id)} · ${localizedTactic(alert.tactic)} · ${localizedTechnique(alertTechnique(alert))}`,
      );
      button.appendChild(alertRef);
    });

    container.appendChild(button);
  });
}

function appendLegend(parent) {
  const legend = createElement("div", "navigator-legend");
  [
    ["legend-current", "진행 중/관측됨"],
    ["legend-predicted", "예상 다음 수순"],
    ["legend-gap", "방어 공백/미구현"],
    ["legend-planned", "보강 예정"],
  ].forEach(([className, label]) => {
    const item = createElement("div", "legend-item");
    item.append(createElement("span", `legend-dot ${className}`), createElement("span", "", label));
    legend.appendChild(item);
  });
  parent.appendChild(legend);
}

function techniqueStatus(tactic, technique, tacticCell, observedSet, predicted) {
  const classes = [];
  const labels = [];
  if (observedSet.has(technique) || (tacticCell && tacticCell.current && !predicted)) {
    classes.push("is-current");
    labels.push("진행 중");
  }
  if (predicted === technique) {
    classes.push("is-predicted");
    labels.push("예상");
  }
  if (tactic.uncovered.includes(technique)) {
    classes.push("is-gap");
    labels.push("공백");
  }
  if (tactic.planned.includes(technique)) {
    classes.push("is-planned");
    labels.push("예정");
  }
  return { classes, labels };
}

function appendTechnique(
  column,
  matrixColumn,
  technique,
  tacticCell,
  observedSet,
  predicted,
  techniqueOrder,
) {
  const row = createElement("div", "technique-row");
  const status = techniqueStatus(
    matrixColumn,
    technique,
    tacticCell,
    observedSet,
    predicted,
  );
  status.classes.forEach((className) => row.classList.add(className));

  const name = createElement("div", "technique-name");
  const sequence = techniqueOrder.get(technique);
  if (sequence !== undefined && status.classes.includes("is-current")) {
    name.appendChild(createElement("span", "seq-badge", String(sequence)));
  }
  name.appendChild(document.createTextNode(localizedTechnique(technique)));
  row.appendChild(name);
  row.appendChild(createElement("div", "technique-id", technique));
  if (status.labels.length > 0) {
    row.appendChild(createElement("div", "technique-tags", status.labels.join(" · ")));
  }
  column.appendChild(row);
}

function renderNavigator(snapshot) {
  const container = document.getElementById("navigator");
  if (!container) {
    return;
  }

  const story = selectedStory(snapshot);
  const observedSet = observedTechniqueSet(story);
  const predicted = predictedTechnique(snapshot, story);
  const tacticStates = tacticStateMap(snapshot);
  const { techniqueOrder, tacticOrder } = observedSequenceMaps(story);
  clearNode(container);

  appendKillchain(container, tacticStates, tacticOrder);

  const header = createElement("div", "navigator-header");
  header.appendChild(
    createElement(
      "div",
      "matrix-context",
      "전술 열 전체 표시 · 상태 기법 강조 · 무관 기법 압축",
    ),
  );
  appendLegend(header);
  container.appendChild(header);

  let firstActiveTactic = "";
  const matrix = createElement("div", "matrix-scroll");
  ATTACK_MATRIX.forEach((matrixColumn) => {
    const tacticCell = tacticStates.get(matrixColumn.tactic);
    const column = createElement("section", "tactic-column");
    column.dataset.tactic = matrixColumn.tactic;
    if (tacticCell && tacticCell.current) {
      column.classList.add("has-current");
      firstActiveTactic = firstActiveTactic || matrixColumn.tactic;
    }
    if (tacticCell && tacticCell.predicted) {
      column.classList.add("has-predicted");
      firstActiveTactic = firstActiveTactic || matrixColumn.tactic;
    }
    if (tacticCell && tacticCell.gap) {
      column.classList.add("has-gap");
    }

    const headerNode = createElement("div", "tactic-header");
    headerNode.appendChild(createElement("div", "tactic-ko", localizedTactic(matrixColumn.tactic)));
    headerNode.appendChild(createElement("div", "tactic-en", matrixColumn.tactic));
    headerNode.appendChild(
      createElement(
        "div",
        "tactic-count",
        `${matrixColumn.covered.length + matrixColumn.planned.length + matrixColumn.uncovered.length}개 기법`,
      ),
    );
    column.appendChild(headerNode);

    const techniques = [
      ...matrixColumn.covered,
      ...matrixColumn.planned,
      ...matrixColumn.uncovered,
    ];
    techniques.forEach((technique) => {
      appendTechnique(
        column,
        matrixColumn,
        technique,
        tacticCell,
        observedSet,
        predicted,
        techniqueOrder,
      );
    });
    matrix.appendChild(column);
  });
  container.appendChild(matrix);

  if (firstActiveTactic) {
    const targetTactic = firstActiveTactic;
    window.requestAnimationFrame(() => {
      scrollMatrixToTactic(targetTactic);
    });
  }
}

function sentenceJoin(parts) {
  return parts.filter((part) => part && part !== "UNKNOWN").join(" ");
}

function buildStaffAdvice(snapshot) {
  const story = selectedStory(snapshot) || {};
  const alerts = storyAlerts(story);
  const primaryAlert = alerts[alerts.length - 1] || {};
  const target = localizedAsset(story.target_asset);
  const impact = localizedImpact(story.mission_impact);
  const hitl = localizedHitl(story.hitl_status);
  const observed = alerts
    .map((alert) => `${localizedTactic(alert.tactic)}(${localizedTechnique(alertTechnique(alert))})`)
    .join(" → ");
  const predicted = text(story.next_expected);
  const summary = snapshot.summary || {};
  const decisionMargin = DECISION_LABELS[text(summary.decision_advantage)] || text(summary.decision_advantage);

  return {
    situation: sentenceJoin([
      `${text(story.actor || story.story_id)} 세력이 ${target}${objectParticle(target)} 표적으로 작전 중입니다.`,
      observed ? `현재 관측된 공격 흐름은 ${observed}입니다.` : "관측된 전술 흐름은 아직 부족합니다.",
      `최신 알림은 ${text(primaryAlert.alert_id)}이며, 동일 story로 묶어 추적합니다.`,
    ]),
    missionImpact: sentenceJoin([
      `임무 영향 평가는 ${impact}입니다.`,
      story.mission_impact === "MINIMAL"
        ? "지상 지휘통제 신뢰도가 떨어져 자율 페일세이프와 대체 링크 운용을 전제로 해야 합니다."
        : "주 임무는 유지 가능하지만 해당 링크/자산의 신뢰도 저하를 계속 감시해야 합니다.",
      `현재 결심 여유는 ${decisionMargin}입니다.`,
    ]),
    recommendation: sentenceJoin([
      story.hitl_status === "PENDING"
        ? "자동 차단만으로 종결하지 말고 지휘관 결심을 받아야 합니다."
        : "자동 대응을 우선 수행하고 참모는 임무 지속성 변화를 감시합니다.",
      target === "지휘통제 링크"
        ? "권고 조치는 의심 C2 세션 차단, GCS-기체 상호인증 재확인, SATCOM/LOS 대체 경로 전환, 필요 시 RTB 준비입니다."
        : "권고 조치는 링크 무결성 검증, 명령 재검증, 대체 통신경로 준비, 관련 세션 격리입니다.",
      `상태: ${hitl}.`,
    ]),
    nextMove: sentenceJoin([
      predicted && predicted !== "UNKNOWN"
        ? `다음 예상 수순은 ${predicted}입니다.`
        : "다음 수순은 아직 특정되지 않았습니다.",
      predicted.includes("WEAPON")
        ? "무장통제 연동부로 공격이 번질 경우 역공격 금지 원칙과 교전권한 확인이 필요합니다."
        : "다음 전술이 방어 공백과 겹치는지 전술/기법 매트릭스의 황색/적색 표시를 기준으로 선제 보강을 판단합니다.",
    ]),
  };
}

function renderBluf(snapshot) {
  const container = document.getElementById("bluf-card");
  if (!container) {
    return;
  }

  const advice = buildStaffAdvice(snapshot);
  const sections = [
    ["상황", advice.situation],
    ["임무 영향", advice.missionImpact],
    ["참모 권고", advice.recommendation],
    ["다음 수순", advice.nextMove],
  ];

  clearNode(container);
  sections.forEach(([label, value]) => {
    const block = createElement("div", "bluf-block");
    block.appendChild(createElement("div", "bluf-label", label));
    block.appendChild(createElement("div", "bluf-text", text(value)));
    container.appendChild(block);
  });
}

function topologyFromSnapshot(snapshot) {
  const snapshotTopology = snapshot.topology || {};
  const snapshotNodes = Array.isArray(snapshotTopology.nodes)
    ? snapshotTopology.nodes
    : [];
  const baseNodes = Array.isArray(state.topology.nodes) ? state.topology.nodes : [];
  const baseEdges = Array.isArray(state.topology.edges) ? state.topology.edges : [];
  if (baseNodes.length === 0) {
    return snapshotTopology;
  }
  const overlay = new Map(snapshotNodes.map((node) => [node.id, node]));
  return {
    nodes: baseNodes.map((node) => ({ ...node, ...(overlay.get(node.id) || {}) })),
    edges: baseEdges.map((edge) => ({ ...edge })),
  };
}

function edgeActive(edge, activeNodeIds) {
  return activeNodeIds.has(edge.source) || activeNodeIds.has(edge.target);
}

const SVG_NAMESPACE = "http://www.w3.org/2000/svg";

function relativeRect(element, containerRect) {
  const rect = element.getBoundingClientRect();
  return {
    left: rect.left - containerRect.left,
    top: rect.top - containerRect.top,
    right: rect.right - containerRect.left,
    bottom: rect.bottom - containerRect.top,
    centerX: rect.left - containerRect.left + rect.width / 2,
    centerY: rect.top - containerRect.top + rect.height / 2,
  };
}

function edgePath(sourceRect, targetRect) {
  const dx = targetRect.centerX - sourceRect.centerX;
  const dy = targetRect.centerY - sourceRect.centerY;
  if (Math.abs(dx) >= Math.abs(dy)) {
    const x1 = dx >= 0 ? sourceRect.right : sourceRect.left;
    const x2 = dx >= 0 ? targetRect.left : targetRect.right;
    const bend = (x2 - x1) / 2;
    return `M ${x1} ${sourceRect.centerY} C ${x1 + bend} ${sourceRect.centerY}, ${
      x2 - bend
    } ${targetRect.centerY}, ${x2} ${targetRect.centerY}`;
  }
  const y1 = dy >= 0 ? sourceRect.bottom : sourceRect.top;
  const y2 = dy >= 0 ? targetRect.top : targetRect.bottom;
  const bend = (y2 - y1) / 2;
  return `M ${sourceRect.centerX} ${y1} C ${sourceRect.centerX} ${y1 + bend}, ${
    targetRect.centerX
  } ${y2 - bend}, ${targetRect.centerX} ${y2}`;
}

function drawTopologyEdges() {
  const draw = state.topologyDraw;
  if (!draw || !draw.diagram.isConnected) {
    return;
  }

  const { diagram, edges, activeNodeIds, nodeElements } = draw;
  const previous = diagram.querySelector(".topo-edges");
  if (previous) {
    previous.remove();
  }

  const containerRect = diagram.getBoundingClientRect();
  if (containerRect.width === 0 || containerRect.height === 0) {
    return;
  }

  const svg = document.createElementNS(SVG_NAMESPACE, "svg");
  svg.classList.add("topo-edges");
  svg.setAttribute("width", String(containerRect.width));
  svg.setAttribute("height", String(containerRect.height));
  svg.setAttribute("aria-hidden", "true");

  edges.forEach((edge, index) => {
    const sourceNode = nodeElements.get(text(edge.source));
    const targetNode = nodeElements.get(text(edge.target));
    if (!sourceNode || !targetNode) {
      return;
    }
    const path = document.createElementNS(SVG_NAMESPACE, "path");
    path.classList.add("topo-edge");
    if (edgeActive(edge, activeNodeIds)) {
      path.classList.add("active");
    }
    path.dataset.edgeIndex = String(index);
    path.setAttribute(
      "d",
      edgePath(
        relativeRect(sourceNode, containerRect),
        relativeRect(targetNode, containerRect),
      ),
    );
    svg.appendChild(path);
  });

  diagram.prepend(svg);
}

function setEdgeHover(diagram, index, hovered) {
  const path = diagram.querySelector(
    `.topo-edge[data-edge-index="${index}"]`,
  );
  if (path) {
    path.classList.toggle("hover", hovered);
  }
}

function renderTopology(snapshot) {
  const container = document.getElementById("topology-map");
  if (!container) {
    return;
  }

  const topology = topologyFromSnapshot(snapshot);
  const nodes = Array.isArray(topology.nodes) ? topology.nodes : [];
  const edges = Array.isArray(topology.edges) ? topology.edges : [];
  clearNode(container);
  state.topologyDraw = null;

  if (nodes.length === 0) {
    container.appendChild(createFallbackCard("node", "자산 구성도 데이터 없음"));
    return;
  }

  const activeNodeIds = new Set(nodes.filter((node) => node.active).map((node) => node.id));
  const nodeElements = new Map();
  const diagram = createElement("div", "topology-diagram");
  const planes = ["ground", "link", "air", "soc", "c4i"];
  planes.forEach((plane) => {
    const lane = createElement("section", `topology-lane plane-${plane}`);
    lane.appendChild(createElement("div", "lane-title", PLANE_LABELS[plane] || plane));
    nodes
      .filter((node) => node.plane === plane)
      .forEach((node) => {
        const card = createElement("div", "node");
        card.classList.add(text(node.status));
        if (node.active) {
          card.classList.add("active");
        }
        card.appendChild(createElement("div", "node-title", NODE_LABELS[node.id] || text(node.label)));
        card.appendChild(createElement("div", "node-meta", `${PLANE_LABELS[node.plane] || text(node.plane)} · ${localizedKind(node.kind)}`));
        card.appendChild(createElement("div", "node-status", localizedImpact(node.status)));
        nodeElements.set(text(node.id), card);
        lane.appendChild(card);
      });
    diagram.appendChild(lane);
  });

  const edgePanel = createElement("aside", "edge-panel");
  edgePanel.appendChild(createElement("div", "edge-title", "주요 연결 관계"));
  edges.slice(0, 14).forEach((edge, index) => {
    const row = createElement("div", "edge-row");
    if (edgeActive(edge, activeNodeIds)) {
      row.classList.add("active");
    }
    const source = NODE_LABELS[edge.source] || text(edge.source);
    const target = NODE_LABELS[edge.target] || text(edge.target);
    row.textContent = `${source} → ${target}`;
    row.addEventListener("mouseenter", () => {
      setEdgeHover(diagram, index, true);
    });
    row.addEventListener("mouseleave", () => {
      setEdgeHover(diagram, index, false);
    });
    edgePanel.appendChild(row);
  });

  container.append(diagram, edgePanel);

  state.topologyDraw = { diagram, edges, activeNodeIds, nodeElements };
  window.requestAnimationFrame(drawTopologyEdges);
}

function renderControls() {
  const container = document.getElementById("replay-controls");
  if (!container) {
    return;
  }

  clearNode(container);

  const previousButton = createElement("button", "control", "◀");
  previousButton.type = "button";
  previousButton.title = "이전 스냅샷";
  previousButton.addEventListener("click", previousSnapshot);

  const nextButton = createElement("button", "control", "▶");
  nextButton.type = "button";
  nextButton.title = "다음 스냅샷";
  nextButton.addEventListener("click", nextSnapshot);

  const liveButton = createElement("button", "control live", "실시간");
  liveButton.type = "button";
  liveButton.addEventListener("click", connectLive);

  const step = createElement(
    "span",
    "step-counter",
    `스냅샷 ${state.index + 1} / ${state.snapshots.length || 0}`,
  );
  let statusText = "리플레이 모드";
  if (state.connectionState === "connected") {
    statusText =
      state.dataMode === "live" ? "실시간 연결됨" : "리플레이 수신 중(SSE)";
  } else if (state.connectionState === "completed") {
    statusText = "리플레이 완료";
  } else if (state.connectionState === "reconnecting") {
    statusText = "실시간 재연결 중";
  }
  const status = createElement(
    "span",
    `status-line state-${state.connectionState}`,
    statusText,
  );
  const modeBadge = createElement(
    "span",
    `mode-badge mode-${state.dataMode}`,
    state.dataMode === "live" ? "실데이터" : "리플레이 데이터",
  );

  container.append(previousButton, nextButton, liveButton, step, status, modeBadge);
}

function emptyReplaySnapshot() {
  return {
    summary: {
      active_story_count: 0,
      max_mission_impact: "UNKNOWN",
      hitl_pending_count: 0,
      decision_advantage: "unknown",
    },
    stories: [],
    selected_story_id: "",
    navigator: [],
    topology: state.topology,
    bluf: {
      situation: "리플레이 스냅샷이 없습니다.",
      mission_impact: "스냅샷 데이터를 생성하거나 실시간 연결을 시작해야 합니다.",
      recommendation: "demo.py 또는 스냅샷 생성 스크립트로 데이터를 적재하십시오.",
      next_move: "자산 구성도는 계속 확인 가능합니다.",
      confidence: "unknown",
      hitl_badge: "NOT_REQUIRED",
      caveats: ["Replay dataset is empty."],
    },
  };
}

function renderEmptyState() {
  const container = document.getElementById("top-strip");
  if (!container) {
    return;
  }

  clearNode(container);
  const metric = createElement("div", "metric");
  metric.appendChild(
    createElement("div", "metric-value", "리플레이 스냅샷 없음"),
  );
  container.appendChild(metric);
}

function renderSnapshot(snapshot) {
  if (!snapshot) {
    renderEmptyState();
    const emptySnapshot = emptyReplaySnapshot();
    renderStoryRail(emptySnapshot);
    renderNavigator(emptySnapshot);
    renderBluf(emptySnapshot);
    renderTopology(emptySnapshot);
    renderControls();
    return;
  }

  if (snapshot.mode === "live" || snapshot.mode === "replay") {
    state.dataMode = snapshot.mode;
  }
  renderTopStrip(snapshot);
  renderStoryRail(snapshot);
  renderNavigator(snapshot);
  renderBluf(snapshot);
  renderTopology(snapshot);
  renderControls();
}

function previousSnapshot() {
  if (state.snapshots.length === 0) {
    return;
  }
  state.index = Math.max(0, state.index - 1);
  renderSnapshot(currentSnapshot());
}

function nextSnapshot() {
  if (state.snapshots.length === 0) {
    return;
  }
  state.index = Math.min(state.snapshots.length - 1, state.index + 1);
  renderSnapshot(currentSnapshot());
}

async function loadTopology() {
  const response = await fetch('/api/topology');
  state.topology = await response.json();
}

async function loadReplay() {
  const response = await fetch('/api/snapshots');
  const payload = await response.json();
  resetSnapshots(Array.isArray(payload.snapshots) ? payload.snapshots : []);
  state.index = 0;
  state.connectionState = "replay";
  renderSnapshot(currentSnapshot());
}

function closeLiveConnection(nextConnectionState = "replay") {
  if (state.eventSource) {
    state.eventSource.close();
    state.eventSource = null;
  }
  state.live = false;
  state.connectionState = nextConnectionState;
}

function connectLive() {
  if (state.eventSource) {
    return;
  }

  state.eventSource = new EventSource('/events');
  state.live = true;
  state.connectionState = "reconnecting";
  renderControls();

  state.eventSource.onopen = () => {
    state.connectionState = "connected";
    renderControls();
  };

  state.eventSource.addEventListener("snapshot", (event) => {
    const snapshot = JSON.parse(event.data);
    if (!appendSnapshotIfNew(snapshot)) {
      return;
    }
    state.index = state.snapshots.length - 1;
    renderSnapshot(snapshot);
  });

  state.eventSource.addEventListener("done", () => {
    closeLiveConnection("completed");
    renderControls();
  });

  state.eventSource.onerror = () => {
    state.connectionState = "reconnecting";
    renderControls();
  };
}

let resizeRedrawTimer = 0;

window.addEventListener("resize", () => {
  window.clearTimeout(resizeRedrawTimer);
  resizeRedrawTimer = window.setTimeout(drawTopologyEdges, 150);
});

async function initializeDashboard() {
  await loadTopology();
  await loadReplay();
}

initializeDashboard();
