const state = {
  snapshots: [],
  index: 0,
  selectedStoryId: "",
  live: false,
  connectionState: "replay",
  eventSource: null,
  topology: { nodes: [], edges: [] },
};

function text(value) {
  return value === undefined || value === null || value === ""
    ? "UNKNOWN"
    : String(value);
}

function currentSnapshot() {
  return state.snapshots[state.index] || null;
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

function renderTopStrip(snapshot) {
  const container = document.getElementById("top-strip");
  if (!container) {
    return;
  }

  const summary = snapshot.summary || {};
  const metrics = [
    ["Active Stories", summary.active_story_count],
    ["Max Mission Impact", summary.max_mission_impact],
    ["HITL Pending", summary.hitl_pending_count],
    ["Decision Margin", summary.decision_advantage],
  ];

  clearNode(container);
  metrics.forEach(([label, value]) => {
    const card = createElement("div", "metric");
    appendLabeledValue(card, label, value);
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
    container.appendChild(createFallbackCard("story-card", "No active stories"));
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
    const storyId = createElement("span", "", text(story.story_id));
    const badge = createElement("span", "badge", text(story.hitl_status));
    if (isPending) {
      badge.classList.add("pending");
    }
    title.append(storyId, badge);

    const campaign = createElement(
      "div",
      "story-meta",
      `Campaign ${text(story.campaign_id)} ${text(story.matched)}/${text(
        story.total,
      )}`,
    );
    const target = createElement(
      "div",
      "story-meta",
      `Target ${text(story.target_asset)} · Impact ${text(story.mission_impact)}`,
    );

    button.append(title, campaign, target);

    const alerts = Array.isArray(story.alerts) ? story.alerts : [];
    alerts.forEach((alert) => {
      const alertRef = createElement(
        "div",
        "alert-ref",
        `${text(alert.alert_id)} · ${text(alert.scenario_id)} · ${text(
          alert.tactic,
        )}`,
      );
      button.appendChild(alertRef);
    });

    container.appendChild(button);
  });
}

function renderNavigator(snapshot) {
  const container = document.getElementById("navigator");
  if (!container) {
    return;
  }

  const cells = Array.isArray(snapshot.navigator) ? snapshot.navigator : [];
  clearNode(container);

  if (cells.length === 0) {
    container.appendChild(createFallbackCard("cell", "No navigator data"));
    return;
  }

  cells.forEach((cell) => {
    const card = createElement("div", "cell");
    if (cell.observed) {
      card.classList.add("observed");
    }
    if (cell.current) {
      card.classList.add("current");
    }
    if (cell.predicted) {
      card.classList.add("predicted");
    }
    if (cell.gap) {
      card.classList.add("gap");
    }

    const title = createElement("div", "cell-title", text(cell.tactic));
    card.appendChild(title);

    if (cell.observed_order) {
      card.appendChild(
        createElement("div", "cell-order", text(cell.observed_order)),
      );
    }

    const stateText = [cell.predicted ? "Predicted" : "", cell.gap ? "Gap" : ""]
      .filter(Boolean)
      .join(" ");
    card.appendChild(createElement("div", "story-meta", stateText || " "));
    card.appendChild(createElement("div", "story-meta", text(cell.note)));
    container.appendChild(card);
  });
}

function renderBluf(snapshot) {
  const container = document.getElementById("bluf-card");
  if (!container) {
    return;
  }

  const bluf = snapshot.bluf || {};
  const sections = [
    ["Situation", bluf.situation, [bluf.confidence]],
    ["Mission Impact", bluf.mission_impact, []],
    ["Recommendation", bluf.recommendation, [bluf.hitl_badge]],
    ["Next Move", bluf.next_move, bluf.caveats || []],
  ];

  clearNode(container);
  sections.forEach(([label, value, details]) => {
    const block = createElement("div", "bluf-block");
    block.appendChild(createElement("div", "bluf-label", label));
    block.appendChild(createElement("div", "", text(value)));

    details
      .filter((detail) => detail !== undefined && detail !== null && detail !== "")
      .forEach((detail) => {
        block.appendChild(createElement("div", "bluf-row", text(detail)));
      });

    container.appendChild(block);
  });
}

function topologyFromSnapshot(snapshot) {
  const topology = snapshot.topology || {};
  const nodes = Array.isArray(topology.nodes) ? topology.nodes : [];
  return nodes.length > 0 ? topology : state.topology;
}

function renderTopology(snapshot) {
  const container = document.getElementById("topology-map");
  if (!container) {
    return;
  }

  const topology = topologyFromSnapshot(snapshot);
  const nodes = Array.isArray(topology.nodes) ? topology.nodes : [];
  clearNode(container);

  if (nodes.length === 0) {
    container.appendChild(createFallbackCard("node", "No topology data"));
    return;
  }

  nodes.forEach((node) => {
    const card = createElement("div", "node");
    card.classList.add(text(node.status));
    if (node.active) {
      card.classList.add("active");
    }

    const label = createElement(
      "div",
      "node-title",
      text(node.label || node.id || node.name),
    );
    const plane = createElement(
      "div",
      "node-meta",
      `${text(node.plane)} · ${text(node.kind)}`,
    );
    const status = createElement("div", "node-meta", text(node.status));
    card.append(label, plane, status);
    container.appendChild(card);
  });
}

function renderControls() {
  const container = document.getElementById("replay-controls");
  if (!container) {
    return;
  }

  clearNode(container);

  const previousButton = createElement("button", "control", "◀");
  previousButton.type = "button";
  previousButton.addEventListener("click", previousSnapshot);

  const nextButton = createElement("button", "control", "▶");
  nextButton.type = "button";
  nextButton.addEventListener("click", nextSnapshot);

  const liveButton = createElement("button", "control", "LIVE");
  liveButton.type = "button";
  liveButton.addEventListener("click", connectLive);

  const step = createElement(
    "span",
    "step-counter",
    `Step ${state.index + 1} / ${state.snapshots.length || 0}`,
  );
  let statusText = "Replay mode";
  if (state.connectionState === "connected") {
    statusText = "SSE connected";
  } else if (state.connectionState === "reconnecting") {
    statusText = "SSE reconnecting";
  }
  const status = createElement("span", "status-line", statusText);

  container.append(previousButton, nextButton, liveButton, step, status);
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
      situation: "No replay snapshots loaded",
      mission_impact: "Replay snapshot data unavailable.",
      recommendation: "Load replay snapshots or connect live.",
      next_move: "Topology remains available.",
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
    createElement("div", "metric-value", "No replay snapshots loaded"),
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
  state.snapshots = Array.isArray(payload.snapshots) ? payload.snapshots : [];
  state.index = 0;
  state.connectionState = "replay";
  renderSnapshot(currentSnapshot());
}

function closeLiveConnection() {
  if (state.eventSource) {
    state.eventSource.close();
    state.eventSource = null;
  }
  state.live = false;
  state.connectionState = "replay";
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
    state.snapshots.push(snapshot);
    state.index = state.snapshots.length - 1;
    renderSnapshot(snapshot);
  });

  state.eventSource.onerror = () => {
    state.connectionState = "reconnecting";
    renderControls();
  };
}

async function initializeDashboard() {
  await loadTopology();
  await loadReplay();
}

initializeDashboard();
