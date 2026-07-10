/*
 * 보고서 시나리오 테스트 바 — 기존 대시보드 상단에 추가(비파괴).
 *
 * dashboard.js의 전역 리플레이 엔진(resetSnapshots/nextSnapshot/renderSnapshot/
 * currentSnapshot/loadReplay/state)을 그대로 호출한다. dashboard.js 내부는 수정하지 않음.
 * "시나리오 테스트"를 누르면 해당 킬체인 스냅샷을 주입하고 끝까지 자동 진행한다.
 */
(function () {
  "use strict";

  var scenarios = window.REPORT_SCENARIOS || [];
  var savedReplay = null;   // 원본 replay 복원용
  var activeKey = null;
  var playTimer = 0;
  var reduce = window.matchMedia("(prefers-reduced-motion:reduce)").matches;

  function stopPlay() {
    if (playTimer) { window.clearTimeout(playTimer); playTimer = 0; }
    setRunning(false);
  }

  function saveReplayOnce() {
    if (savedReplay === null && Array.isArray(state.snapshots)) {
      savedReplay = state.snapshots.slice();
    }
  }

  function status(txt) {
    var el = document.getElementById("scn-status");
    if (el) el.textContent = txt;
  }

  function setRunning(on) {
    var btn = document.getElementById("scn-play");
    if (!btn) return;
    btn.textContent = on ? "⏹ 정지" : "▶ 시나리오 테스트";
    btn.classList.toggle("running", on);
  }

  function markActive() {
    scenarios.forEach(function (s) {
      var b = document.getElementById("scn-tab-" + s.key);
      if (b) b.setAttribute("aria-pressed", String(s.key === activeKey));
    });
  }

  function loadScenario(key) {
    var scn = scenarios.find(function (s) { return s.key === key; });
    if (!scn) return;
    stopPlay();
    saveReplayOnce();
    activeKey = key;
    markActive();
    resetSnapshots(scn.snapshots);
    state.index = 0;
    state.connectionState = "replay";
    renderSnapshot(currentSnapshot());
    status("시나리오 " + key + " · " + scn.name + " — step 1/" + scn.steps + " (재생 대기)");
  }

  function playActive() {
    var scn = scenarios.find(function (s) { return s.key === activeKey; });
    if (!scn) { loadScenario("A"); scn = scenarios[0]; }
    // 이미 진행 중이면 정지 토글
    if (playTimer) { stopPlay(); status("시나리오 " + scn.key + " · 정지 (step " + (state.index + 1) + "/" + scn.steps + ")"); return; }
    // 끝까지 갔으면 처음부터
    if (state.index >= scn.steps - 1) { state.index = 0; renderSnapshot(currentSnapshot()); }
    setRunning(true);
    var gap = reduce ? 350 : 1600;
    var tick = function () {
      if (state.index >= scn.steps - 1) {
        stopPlay();
        status("시나리오 " + scn.key + " · " + scn.name + " — 완료 (종착: " + scn.steps + "/" + scn.steps + ")");
        return;
      }
      nextSnapshot();
      status("시나리오 " + scn.key + " · " + scn.name + " — step " + (state.index + 1) + "/" + scn.steps + " 진행 중");
      playTimer = window.setTimeout(tick, gap);
    };
    status("시나리오 " + scn.key + " · " + scn.name + " — step 1/" + scn.steps + " 진행 중");
    playTimer = window.setTimeout(tick, reduce ? 150 : 700);
  }

  function restoreReplay() {
    stopPlay();
    activeKey = null;
    markActive();
    savedReplay = null;
    if (typeof loadReplay === "function") { loadReplay(); }
    status("실 replay 복귀 (OP-077)");
  }

  function build() {
    if (!scenarios.length || document.getElementById("scenario-bar")) return;
    var host = document.getElementById("top-strip");
    if (!host || !host.parentNode) return;

    var bar = document.createElement("section");
    bar.id = "scenario-bar";
    bar.className = "scenario-bar";
    bar.setAttribute("aria-label", "보고서 시나리오 테스트");

    var tabs = scenarios.map(function (s) {
      return '<button id="scn-tab-' + s.key + '" class="scn-tab" aria-pressed="false" type="button">'
        + '<span class="scn-id">시나리오 ' + s.key + '</span>'
        + '<span class="scn-name">' + s.name + '</span>'
        + '<span class="scn-sec">보고서 ' + s.section + '</span></button>';
    }).join("");

    bar.innerHTML =
      '<div class="scn-head"><span class="scn-kicker">보고서 시나리오 테스트</span>'
      + '<span class="scn-sub">§4.4~4.6 킬체인을 ATT&amp;CK 매트릭스로 라이브 재생</span></div>'
      + '<div class="scn-tabs">' + tabs + '</div>'
      + '<div class="scn-actions" id="scn-actions">'
      + '<button id="scn-play" class="scn-btn scn-btn-run" type="button">▶ 시나리오 테스트</button>'
      + '<button id="scn-restore" class="scn-btn" type="button">↺ 실 replay 복귀</button>'
      + '<span id="scn-status" class="scn-status">시나리오 A·B·C 선택 후 ▶ 시나리오 테스트</span>'
      + '</div>';

    host.parentNode.insertBefore(bar, host);

    // 하단의 리플레이 컨트롤(스냅샷 N/N · ◀▶ · 실시간)을 시나리오 테스트와 같은 행으로 이동.
    // dashboard.js 는 계속 #replay-controls 를 id 로 렌더하므로 이동해도 정상 동작.
    var replay = document.getElementById("replay-controls");
    if (replay) { document.getElementById("scn-actions").appendChild(replay); }

    scenarios.forEach(function (s) {
      document.getElementById("scn-tab-" + s.key).addEventListener("click", function () { loadScenario(s.key); });
    });
    document.getElementById("scn-play").addEventListener("click", playActive);
    document.getElementById("scn-restore").addEventListener("click", restoreReplay);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", build);
  } else {
    build();
  }
})();
