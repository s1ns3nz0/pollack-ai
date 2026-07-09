const state = {
  snapshots: [],
  index: 0,
  selectedStoryId: "",
  live: false,
};

function text(value) {
  return value === undefined || value === null || value === ""
    ? "UNKNOWN"
    : String(value);
}

function currentSnapshot() {
  return state.snapshots[state.index] || null;
}

function setHtml(id, html) {
  const el = document.getElementById(id);
  if (el) {
    el.innerHTML = html;
  }
}

function renderTopStrip(snapshot) {
  const summary = snapshot.summary || {};
  setHtml(
    "top-strip",
    `
      <div class="metric"><div class="metric-label">Active Stories</div><div class="metric-value">${text(summary.active_story_count)}</div></div>
      <div class="metric"><div class="metric-label">Max Mission Impact</div><div class="metric-value">${text(summary.max_mission_impact)}</div></div>
      <div class="metric"><div class="metric-label">HITL Pending</div><div class="metric-value">${text(summary.hitl_pending_count)}</div></div>
      <div class="metric"><div class="metric-label">Decision Margin</div><div class="metric-value">${text(summary.decision_advantage)}</div></div>
    `,
  );
}

function selectStory(storyId) {
  state.selectedStoryId = storyId;
  renderSnapshot(currentSnapshot());
}

function renderStoryRail(snapshot) {
  const stories = snapshot.stories || [];
  if (!state.selectedStoryId && snapshot.selected_story_id) {
    state.selectedStoryId = snapshot.selected_story_id;
  }
  if (stories.length === 0) {
    setHtml("story-rail", '<div class="story-card">No active stories</div>');
    return;
  }
  setHtml(
    "story-rail",
    stories
      .map((story) => {
        const active = story.story_id === state.selectedStoryId ? " active" : "";
        const pending = story.hitl_status === "PENDING" ? " pending" : "";
        const alerts = (story.alerts || [])
          .map(
            (alert) =>
              `<div class="alert-ref">${text(alert.alert_id)} · ${text(alert.scenario_id)} · ${text(alert.tactic)}</div>`,
          )
          .join("");
        return `
          <button class="story-card${active}" onclick="selectStory('${story.story_id}')">
            <div class="story-title"><span>${text(story.story_id)}</span><span class="badge${pending}">${text(story.hitl_status)}</span></div>
            <div class="story-meta">Campaign ${text(story.campaign_id)} ${text(story.matched)}/${text(story.total)}</div>
            <div class="story-meta">Target ${text(story.target_asset)} · Impact ${text(story.mission_impact)}</div>
            ${alerts}
          </button>
        `;
      })
      .join(""),
  );
}

function renderNavigator(snapshot) {
  const cells = snapshot.navigator || [];
  if (cells.length === 0) {
    setHtml("navigator", '<div class="cell">No navigator data</div>');
    return;
  }
  setHtml(
    "navigator",
    cells
      .map((cell) => {
        const classes = ["cell"];
        if (cell.observed) classes.push("observed");
        if (cell.current) classes.push("current");
        if (cell.predicted) classes.push("predicted");
        if (cell.gap) classes.push("gap");
        return `
          <div class="${classes.join(" ")}">
            <div class="cell-title">${text(cell.tactic)}</div>
            ${cell.observed_order ? `<div class="cell-order">${cell.observed_order}</div>` : ""}
            <div class="story-meta">${cell.predicted ? "Predicted" : ""} ${cell.gap ? "Gap" : ""}</div>
            <div class="story-meta">${text(cell.note)}</div>
          </div>
        `;
      })
      .join(""),
  );
}

function renderBluf(snapshot) {
  const bluf = snapshot.bluf || {};
  setHtml(
    "bluf-card",
    `
      <div class="bluf-block"><div class="bluf-label">Situation</div><div>${text(bluf.situation)}</div><div class="bluf-row">${text(bluf.confidence)}</div></div>
      <div class="bluf-block"><div class="bluf-label">Mission Impact</div><div>${text(bluf.mission_impact)}</div></div>
      <div class="bluf-block"><div class="bluf-label">Recommendation</div><div>${text(bluf.recommendation)}</div><div class="bluf-row">${text(bluf.hitl_badge)}</div></div>
      <div class="bluf-block"><div class="bluf-label">Next Move</div><div>${text(bluf.next_move)}</div><div class="bluf-row">${(bluf.caveats || []).join(" / ")}</div></div>
    `,
  );
}

function renderTopology(snapshot) {
  const topology = snapshot.topology || { nodes: [] };
  const nodes = topology.nodes || [];
  if (nodes.length === 0) {
    setHtml("topology-map", '<div class="node">No topology data</div>');
    return;
  }
  setHtml(
    "topology-map",
    nodes
      .map((node) => {
        const classes = ["node", text(node.status)];
        if (node.active) classes.push("active");
        return `
          <div class="${classes.join(" ")}">
            <div class="node-title">${text(node.label)}</div>
            <div class="node-meta">${text(node.plane)} · ${text(node.kind)}</div>
            <div class="node-meta">${text(node.status)}</div>
          </div>
        `;
      })
      .join(""),
  );
}

function renderControls() {
  setHtml(
    "replay-controls",
    `
      <button class="control" onclick="previousSnapshot()">◀</button>
      <button class="control" onclick="nextSnapshot()">▶</button>
      <button class="control" onclick="connectLive()">LIVE</button>
      <span>Step ${state.index + 1} / ${state.snapshots.length || 0}</span>
      <span class="status-line">${state.live ? "SSE connected" : "Replay mode"}</span>
    `,
  );
}

function renderSnapshot(snapshot) {
  if (!snapshot) {
    setHtml(
      "top-strip",
      '<div class="metric"><div class="metric-value">No replay snapshots loaded</div></div>',
    );
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
  state.index = Math.max(0, state.index - 1);
  renderSnapshot(currentSnapshot());
}

function nextSnapshot() {
  state.index = Math.min(state.snapshots.length - 1, state.index + 1);
  renderSnapshot(currentSnapshot());
}

async function loadReplay() {
  const response = await fetch('/api/snapshots');
  const payload = await response.json();
  state.snapshots = payload.snapshots || [];
  state.index = 0;
  renderSnapshot(currentSnapshot());
}

function connectLive() {
  const events = new EventSource('/events');
  state.live = true;
  events.addEventListener("snapshot", (event) => {
    const snapshot = JSON.parse(event.data);
    state.snapshots.push(snapshot);
    state.index = state.snapshots.length - 1;
    renderSnapshot(snapshot);
  });
  events.onerror = () => {
    state.live = false;
    renderControls();
  };
}

window.selectStory = selectStory;
window.previousSnapshot = previousSnapshot;
window.nextSnapshot = nextSnapshot;
window.connectLive = connectLive;

loadReplay();
