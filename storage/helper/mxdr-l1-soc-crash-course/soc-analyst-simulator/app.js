/* ============================================================
   SOC Analyst Simulator - application logic
   ============================================================ */
"use strict";

const $ = id => document.getElementById(id);
const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const isHardMode = () => !!PROG.hardMode;

function copyText(txt, msg) {
  if (navigator.clipboard && navigator.clipboard.writeText)
    navigator.clipboard.writeText(txt).then(() => toast(msg || "Copied to clipboard"), () => {});
  else toast("Couldn't access the clipboard.");
}

/* ---------------- persistence ---------------- */
let PROG = { best: {}, quizBest: 0, shifts: 0, alerts: 0, recent: [], shiftState: null, onboarded: false, lastRef: "events", hardMode: false };
try {
  const p = JSON.parse(localStorage.getItem("socSimProg"));
  if (p) PROG = Object.assign(PROG, p);
} catch (e) { /* first run */ }
function saveProg() { try { localStorage.setItem("socSimProg", JSON.stringify(PROG)); } catch (e) {} }

/* ============================================================
   COURSE CROSS-LINKS
   Maps each scenario / quiz tag back to the crash-course module
   that teaches it, so the simulator can point back into
   ../index.html?m=<n> for further reading.
   ============================================================ */
const SCEN_MODULE = {
  "brute-tor": { n: 2, t: "Alert Triage Methodology" },
  "backup-benign": { n: 2, t: "Alert Triage Methodology" },
  "pw-spray-vpn": { n: 2, t: "Alert Triage Methodology" },
  "ransomware": { n: 3, t: "Incident Severity and Escalation" },
  "admin-rdp-impossible": { n: 3, t: "Incident Severity and Escalation" },
  "log-clear": { n: 4, t: "Windows Security & Event Logs" },
  "lsass-dump": { n: 5, t: "Sysmon Telemetry" },
  "runkey-persistence": { n: 5, t: "Sysmon Telemetry" },
  "phish-ps-c2": { n: 6, t: "PowerShell Security" },
  "powershell-dc": { n: 6, t: "PowerShell Security" },
  "lolbin-download": { n: 6, t: "PowerShell Security" },
  "kerberoast": { n: 7, t: "Active Directory" },
  "pth-lateral": { n: 7, t: "Active Directory" },
  "ntds-dump": { n: 7, t: "Active Directory" },
  "vuln-scan": { n: 9, t: "Networking for SOC" },
  "rdp-brute": { n: 9, t: "Networking for SOC" },
  "dns-dga": { n: 10, t: "DNS Security" },
  "dns-tunnel": { n: 10, t: "DNS Security" },
  "sqli": { n: 20, t: "Web Security" },
  "iis-webshell": { n: 20, t: "Web Security" },
  "cloud-exfil": { n: 12, t: "Network Traffic Analysis" },
  "usb-malware": { n: 13, t: "Endpoint Security" },
  "linux-crypto": { n: 21, t: "Linux Security for SOC Analysts" },
  "bec-invoice": { n: 16, t: "Phishing and Email Security" },
  "cloud-iam": { n: 27, t: "Cloud Security Basics for L1" },
  "mfa-fatigue": { n: 27, t: "Cloud Security Basics for L1" },
  "legacy-auth": { n: 27, t: "Cloud Security Basics for L1" }
};
const TAG_MODULE = {
  Events: { n: 4, t: "Windows Security & Event Logs" },
  Sysmon: { n: 5, t: "Sysmon Telemetry" },
  Triage: { n: 2, t: "Alert Triage Methodology" },
  Concepts: { n: 0, t: "SOC and MXDR Fundamentals" },
  MITRE: { n: 18, t: "MITRE ATT&CK" },
  Severity: { n: 3, t: "Incident Severity and Escalation" },
  Network: { n: 9, t: "Networking for SOC" },
  Web: { n: 20, t: "Web Security" },
  Linux: { n: 21, t: "Linux Security for SOC Analysts" },
  Cloud: { n: 27, t: "Cloud Security Basics for L1" }
};
const courseModuleHref = n => "../index.html?m=" + n;
function courseLinkHtml(mod, label) {
  if (!mod) return "";
  return `<a class="btn" href="${courseModuleHref(mod.n)}" target="_blank" rel="noopener">${esc(label || ("Read: " + mod.t))} ↗</a>`;
}

/* ---------------- state ---------------- */
const S = {
  mode: null,            // 'single' | 'shift'
  shift: null,           // { ids, idx, results }
  cur: null,             // current scenario object
  viewResult: null,      // result being displayed in debrief
  tab: "overview",
  timerStart: 0,
  timerInt: null,
  evidence: new Set(),
  tiViewed: new Set(),
  ctxViewed: new Set(),
  quiz: null,            // { list, idx, score, done }
  quizTopics: new Set(),
  quizCount: 10,
  timelineFilter: "all",
  decision: null,        // live decision selections
  ref: "events",
  lastTab: "overview",
  mdFocus: true,       // one-section-at-a-time reader for markdown cheat sheets
  mdSec: {}            // per-sheet current section index { sheetId: n }
};

const TIME_BUDGET = { Easy: 240, Medium: 360, Hard: 480 };

/* ---------------- helpers ---------------- */
function grade(score) {
  if (score >= 90) return { t: "Elite Analyst", c: "#a371f7" };
  if (score >= 75) return { t: "Sharp Analyst", c: "#3fb950" };
  if (score >= 60) return { t: "Solid L1", c: "#58a6ff" };
  if (score >= 40) return { t: "Trainee", c: "#d29922" };
  return { t: "Rookie", c: "#f85149" };
}
function f1(hits, gold, pred) {
  if (gold.length === 0 && pred.length === 0) return 1;
  if (gold.length === 0) return 0;
  if (pred.length === 0) return 0;
  const p = hits / pred.length, r = hits / gold.length;
  return p + r === 0 ? 0 : 2 * p * r / (p + r);
}
function clsScore(ex, ch) {
  const m = {
    TP: { TP: 30, IC: 12, BP: 4,  FP: 0 },
    FP: { FP: 30, BP: 18, IC: 8,  TP: 0 },
    BP: { BP: 30, FP: 20, IC: 8,  TP: 0 },
    IC: { IC: 30, TP: 10, BP: 6,  FP: 6 }
  };
  return (m[ex] || {})[ch] || 0;
}
function sevScore(ex, ch) {
  if (ex === ch) return 15;
  const o = ["P1", "P2", "P3", "P4"];
  return Math.abs(o.indexOf(ex) - o.indexOf(ch)) === 1 ? 7 : 0;
}

/* ---------------- screen router ---------------- */
function show(id) {
  document.querySelectorAll(".screen").forEach(s => s.classList.remove("active"));
  $(id).classList.add("active");
  S.screen = id;
  window.scrollTo(0, 0);
  const navMap = { home: "nav-home", quiz: "nav-quiz", ref: "nav-ref" };
  document.querySelectorAll(".nav button").forEach(b => b.classList.toggle("active", b.id === navMap[id]));
  document.querySelectorAll(".bottom-nav button").forEach(b => b.classList.toggle("active", b.dataset.screen === id));
}

/* ---------------- toast ---------------- */
function toast(msg) {
  let t = $("toast");
  if (!t) {
    t = document.createElement("div");
    t.id = "toast";
    t.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#11151d;border:1px solid #58a6ff;color:#d7e0ef;padding:10px 16px;border-radius:10px;font-size:13px;z-index:999;box-shadow:0 6px 24px rgba(0,0,0,.5);max-width:90%;text-align:center;";
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.style.opacity = "1";
  clearTimeout(t._h);
  t._h = setTimeout(() => { t.style.opacity = "0"; t.style.transition = "opacity .4s"; }, 2600);
}

function awardEvidence(id) {
  if (S.evidence.has(id)) return;
  S.evidence.add(id);
  const total = S.cur ? S.cur.keyEvidence.length : 0;
  const found = S.cur ? S.cur.keyEvidence.filter(k => S.evidence.has(k.id)).length : 0;
  if (!PROG.hardMode) toast("Evidence step completed (" + found + "/" + total + ")");
  const el = $("evidenceCount");
  if (el) el.textContent = found + "/" + total;
}

/* ============================================================
   HOME
   ============================================================ */
function go(id) {
  if (id === "queue" && !S.shift) { toast("No active shift — start one from Home."); return; }
  if (id === "scen-grid") renderScenarios();
  show(id);
  if (id === "inv") renderInv();
  if (id === "debrief" && S.viewResult) showDebrief(S.viewResult);
  if (id === "ref") renderRef();
  if (id === "quiz" && !S.quiz) renderQuizSetup();
}

/* Lets course pages deep-link straight into a scenario or a pre-filtered
   quiz round, e.g. index.html?...simulator/?scenario=kerberoast or
   soc-analyst-simulator/?quiz=MITRE */
function applyDeepLink() {
  const params = new URLSearchParams(location.search);
  const scenId = params.get("scenario");
  const shiftReq = params.get("shift");
  const quizTag = params.get("quiz");
  if (!scenId && !shiftReq && !quizTag) return;
  if ($("onboardModal")) dismissOnboarding(); // arriving with intent from the course — skip the tour
  if (scenId && SCENARIOS.some(s => s.id === scenId)) { startSingle(scenId); return; }
  if (shiftReq) { startShift(); return; }
  if (quizTag && quizTags().includes(quizTag)) {
    S.quizTopics = new Set([quizTag]);
    renderQuizSetup();
    go("quiz");
  }
}

function renderHome() {
  $("recent-strip").innerHTML = "";
  renderStats();
  renderResume();
  renderRecent();
  const qBest = PROG.quizBest;
  $("quiz-stat").textContent = qBest ? qBest + "% best" : "Not tried yet";
  $("quiz-stat-detail").textContent = QUIZ.length + " questions on event IDs, Sysmon, MITRE & severity";
}

function renderStats() {
  const scenCount = SCENARIOS.length;
  const done = Object.keys(PROG.best).length;
  const bestList = Object.values(PROG.best);
  const best = bestList.length ? Math.max(...bestList) : 0;
  const ring = best ? Math.round(2 * Math.PI * 21 * (1 - best / 100)) : 0;
  $("stat-row").innerHTML = `
    <div class="stat-card"><div class="ic">&#9889;</div><div><div class="n" id="stat-alerts">${PROG.alerts}</div><div class="l">Alerts triaged</div></div></div>
    <div class="stat-card"><div class="ic">&#128226;</div><div><div class="n" id="stat-shifts">${PROG.shifts}</div><div class="l">Shifts worked</div></div></div>
    <div class="stat-card"><div class="ic">&#127919;</div><div><div class="n" id="stat-scen">${done}/${scenCount}</div><div class="l">Scenarios bested</div></div></div>
    <div class="stat-card"><div class="ic">&#127942;</div><div><div class="n" id="stat-best">${best ? best + "%" : "&mdash;"}</div><div class="l">Best score</div></div></div>
    <div class="stat-card"><div class="ring-wrap"><svg width="52" height="52"><circle class="ring-bg" cx="26" cy="26" r="21"/><circle class="ring-fg" cx="26" cy="26" r="21" stroke-dasharray="131.9" stroke-dashoffset="${ring}"/></svg><div class="ring-val">${best}%</div></div><div class="l">Overall best</div></div>`;
}

function renderResume() {
  const strip = $("recent-strip");
  if (PROG.shiftState && PROG.shiftState.ids.length > PROG.shiftState.results.length) {
    const st = PROG.shiftState;
    strip.insertAdjacentHTML("afterbegin", `
      <div class="continue-card" onclick="resumeShift()">
        <div class="c-icon">&#128218;</div>
        <div class="c-main">
          <b>Resume your shift</b>
          <span>${st.results.length}/${st.ids.length} alerts triaged &middot; queue was saved mid-triage</span>
          <div class="c-bar"><i style="width:${Math.round(100 * st.results.length / st.ids.length)}%"></i></div>
        </div>
      </div>`);
  }
}

function renderRecent() {
  const strip = $("recent-strip");
  if (!PROG.recent.length) return;
  const items = PROG.recent.slice(-8).reverse().map(r => {
    const sc = SCENARIOS.find(s => s.id === r.id);
    if (!sc) return "";
    return `<div class="recent-item" onclick="startSingle('${r.id}')">
      <div class="r-top"><div class="r-title">${esc(sc.title)}</div><div class="r-score">${r.score}%</div></div>
      <div class="r-meta">${esc(sc.category)} &middot; ${esc(sc.difficulty)} &middot; ${new Date(r.t).toLocaleString()}</div>
    </div>`;
  }).join("");
  strip.insertAdjacentHTML("beforeend", `<div class="recent-list">${items}</div>`);
}

/* ---- first-run onboarding overlay ---- */
function maybeOnboarding() {
  if (PROG.onboarded) return;
  const steps = [
    ["1", "Open the alert", "Read the Alert Overview, then build the timeline in the SIEM Search tab."],
    ["2", "Enrich & decide", "Look up indicators, check assets/users, then classify, rate severity and pick actions."],
    ["3", "Get debriefed", "Every decision is scored against the expected analysis — wrong picks show exactly what to study."]
  ];
  const m = document.createElement("div");
  m.id = "onboardModal";
  m.className = "modal-backdrop show";
  m.innerHTML = `<div class="modal">
    <h3>Welcome to your SOC console</h3>
    <div class="modal-body">
      <div class="modal-row">You are the L1 triage analyst. Alerts land in your queue and you must resolve them like a real shift.</div>
      ${steps.map(s => `<div class="modal-row" style="display:flex;gap:10px;align-items:flex-start">
        <span class="kbd" style="min-width:26px;text-align:center">${s[0]}</span>
        <div><b style="display:block">${s[1]}</b><span style="color:var(--muted);font-size:12.5px">${s[2]}</span></div>
      </div>`).join("")}
      <div class="modal-row small" style="color:#8a97ad">Start a Shift for the full 3-alert loop, or browse individual scenarios first.</div>
    </div>
    <div class="modal-foot"><button class="btn primary" onclick="dismissOnboarding()">Start training</button></div>
  </div>`;
  document.body.appendChild(m);
}
function dismissOnboarding() {
  const m = $("onboardModal");
  if (m) m.remove();
  PROG.onboarded = true;
  saveProg();
}

/* ============================================================
   SCENARIO GRID
   ============================================================ */
let SCEN_FILTER = { cat: "", diff: "", q: "", sort: "title" };

function scenCategories() {
  return [...new Set(SCENARIOS.map(s => s.category))].sort();
}

function renderScenCats() {
  const cats = scenCategories();
  $("scenCats").innerHTML = `<button class="chip-btn ${SCEN_FILTER.cat === "" ? "active" : ""}" onclick="setScenCat('')">All</button>` +
    cats.map(c => `<button class="chip-btn ${SCEN_FILTER.cat === c ? "active" : ""}" onclick="setScenCat('${esc(c)}')">${esc(c)}</button>`).join("");
}

function setScenCat(c) {
  SCEN_FILTER.cat = c === "All" ? "" : c;
  renderScenCats();
  renderScenarios();
}

function clearScenSearch() {
  $("scenSearch").value = "";
  SCEN_FILTER.q = "";
  renderScenarios();
}

function filteredScenarios() {
  let list = SCENARIOS.filter(sc => {
    if (SCEN_FILTER.cat && sc.category !== SCEN_FILTER.cat) return false;
    if (SCEN_FILTER.diff && sc.difficulty !== SCEN_FILTER.diff) return false;
    if (SCEN_FILTER.q) {
      const hay = (sc.title + " " + sc.summary + " " + sc.alert.rule + " " + (sc.alert.mitreHint || "")).toLowerCase();
      if (!hay.includes(SCEN_FILTER.q)) return false;
    }
    return true;
  });
  if (SCEN_FILTER.sort === "best") list = list.slice().sort((a, b) => (PROG.best[b.id] || 0) - (PROG.best[a.id] || 0));
  else if (SCEN_FILTER.sort === "new") {
    const order = { Easy: 1, Medium: 2, Hard: 3 };
    list = list.slice().sort((a, b) => order[a.difficulty] - order[b.difficulty]);
  } else list = list.slice().sort((a, b) => a.title.localeCompare(b.title));
  return list;
}

function renderScenarios() {
  renderScenCats();
  SCEN_FILTER.diff = $("scenDiff").value;
  SCEN_FILTER.sort = $("scenSort").value;
  const list = filteredScenarios();
  const el = $("scenario-grid");
  $("scenCount").textContent = list.length === SCENARIOS.length
    ? SCENARIOS.length + " scenarios"
    : list.length + " of " + SCENARIOS.length + " scenarios";
  $("scenEmpty").style.display = list.length ? "none" : "block";
  el.innerHTML = list.map(sc => {
    const best = PROG.best[sc.id];
    return `
      <div class="scenario-card" data-sid="${sc.id}" onclick="startSingle('${sc.id}')">
        <div class="head">
          <h4>${esc(sc.title)}</h4>
          <span>
            ${sc.new ? `<span class="badge new">NEW</span>` : ""}
            <span class="badge ${sc.difficulty.toLowerCase()}">${sc.difficulty}</span>
          </span>
        </div>
        <div class="summary">${esc(sc.summary)}</div>
        <div class="meta">
          <span class="badge cat">${esc(sc.category)}</span>
          ${best ? `<span class="badge best">Best: ${best}%</span>` : ""}
          ${SCEN_MODULE[sc.id] ? `<a class="badge course" href="${courseModuleHref(SCEN_MODULE[sc.id].n)}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="Read the course module first">📘 Module ${SCEN_MODULE[sc.id].n}</a>` : ""}
        </div>
        <div class="card-tasks">
          <span>&#128295; ${sc.keyEvidence.length} evidence steps</span>
          <span>&#128197; ${sc.events.length} events</span>
          <span>&#128373; ${(sc.alert.ips || []).length + (sc.alert.domains || []).length + (sc.alert.hashes || []).length} indicators</span>
        </div>
      </div>`;
  }).join("");
}

/* ============================================================
   SHIFT (queue) MODE
   ============================================================ */
function startShift() {
  const ids = SCENARIOS.map(s => s.id).sort(() => Math.random() - 0.5).slice(0, 3);
  S.mode = "shift";
  S.shift = { ids: ids, idx: 0, results: [], startTs: Date.now() };
  PROG.shifts++;
  saveShiftSnapshot();
  saveProg();
  renderQueue();
  show("queue");
}

function saveShiftSnapshot() {
  if (S.mode === "shift" && S.shift) {
    PROG.shiftState = {
      ids: S.shift.ids,
      results: S.shift.results,
      startTs: S.shift.startTs
    };
    saveProg();
  }
}

function clearShiftSnapshot() {
  PROG.shiftState = null;
  saveProg();
}

function restoreShift() {
  if (!PROG.shiftState) return;
  const st = PROG.shiftState;
  if (!st.ids || !st.ids.length) return;
  S.mode = "shift";
  S.shift = { ids: st.ids, idx: 0, results: st.results || [], startTs: st.startTs || Date.now() };
}

function resumeShift() {
  restoreShift();
  if (!S.shift) return;
  renderQueue();
  show("queue");
  const m = $("onboardModal");
  if (m) m.remove();
}

function renderQueue() {
  const el = $("queue-list");
  el.innerHTML = S.shift.ids.map(id => {
    const sc = SCENARIOS.find(s => s.id === id);
    const res = S.shift.results.find(r => r.scenId === id);
    const status = res
      ? `<span class="status-pill done">Scored ${res.total}%</span>`
      : `<span class="status-pill open">Pending</span>`;
    return `
      <div class="queue-alert" onclick="${res ? `viewDebrief('${id}')` : `startAlert('${id}')`}">
        <div class="alert-id">INC-2024-${String(S.shift.ids.indexOf(id) + 1).padStart(4, "0")}</div>
        <div style="flex:1;min-width:0">
          <div class="rule">${esc(sc.alert.rule)}</div>
          <div class="ent">Host: ${esc(sc.alert.host)} · User: ${esc(sc.alert.user)} · ${esc(sc.alert.ts)}</div>
        </div>
        <div class="time">${esc(sc.title)}</div>
        ${status}
      </div>`;
  }).join("");
  $("shift-progress").textContent = S.shift.results.length + "/" + S.shift.ids.length + " triaged";
}

function startSingle(id) {
  S.mode = "single";
  S.shift = null;
  startAlert(id);
}

function startAlert(id) {
  const sc = SCENARIOS.find(s => s.id === id);
  S.cur = sc;
  S.evidence = new Set();
  S.tiViewed = new Set();
  S.ctxViewed = new Set();
  S.tab = "overview";
  S.timelineFilter = "all";
  S.decision = null;
  document.querySelectorAll("#tabs button").forEach(b => b.classList.remove("active"));
  const dp = $("decision-panel");
  if (dp) dp.classList.remove("open");
  S.timerStart = Date.now();
  clearInterval(S.timerInt);
  S.timerInt = setInterval(() => {
    const el = $("timer");
    if (!el) return;
    const secs = (Date.now() - S.timerStart) / 1000;
    el.textContent = fmtTime(secs);
    const budget = TIME_BUDGET[sc.difficulty] || 360;
    el.classList.toggle("over", secs > budget);
    el.title = "Time budget: " + fmtTime(budget);
  }, 500);
  renderInv();
  show("inv");
}

/* ============================================================
   INVESTIGATION SCREEN
   ============================================================ */
function fmtTime(s) {
  s = Math.floor(s);
  const m = Math.floor(s / 60), r = s % 60;
  return String(m).padStart(2, "0") + ":" + String(r).padStart(2, "0");
}

function renderInv() {
  const sc = S.cur;
  $("inv-title").textContent = sc.alert.rule;
  $("inv-sub").innerHTML = `<span class="badge ${sc.difficulty.toLowerCase()}">${sc.difficulty}</span> <span class="badge cat">${esc(sc.category)}</span> <span>${esc(sc.alert.ts)}</span>`;
  $("timer").textContent = "00:00";
  $("evidenceCount").textContent = "0/" + sc.keyEvidence.length;
  const evPill = document.querySelector(".evidence-pill");
  if (evPill) evPill.style.display = PROG.hardMode ? "none" : "";
  const endBtn = document.querySelector("#inv-meta .btn");
  if (endBtn) endBtn.style.display = S.mode === "shift" ? "" : "none";

  const tabs = [
    ["overview", "Alert", "&#128203;", null],
    ["timeline", "Timeline", "&#128197;", null],
    ["search", "SIEM Search", "&#128269;", e => !!e.keyword],
    ["tree", "Process Tree", "&#129516;", e => e.id === "process-tree"],
    ["intel", "Threat Intel", "&#128373;", e => e.id.indexOf("intel-") === 0],
    ["ctx", "Assets & Users", "&#128101;", e => e.id.indexOf("asset-") === 0 || e.id.indexOf("user-") === 0],
    ["decoder", "Decoder", "&#128295;", e => e.id === "decode-base64"]
  ];
  S.lastTab = S.tab;
  $("tabs").innerHTML = tabs.map(t => {
    const ke = t[3] ? sc.keyEvidence.find(t[3]) : null;
    const has = ke && S.evidence.has(ke.id);
    return `<button class="${S.tab === t[0] ? "active" : ""}" onclick="switchTab('${t[0]}')">
      <span class="tab-ic">${t[2]}</span>${t[1]}<span class="tab-dot ${has ? "has" : ""}"></span></button>`;
  }).join("");

  renderDecision();
  updateDecisionStatus();
  switchTab(S.tab, true);
}

function switchTab(t, force) {
  S.tab = t;
  document.querySelectorAll("#tabs button").forEach(b => b.classList.toggle("active", b.onclick.toString().includes(t)));
  if (t === "tree") awardEvidence("process-tree");
  if (t === "overview") renderOverview();
  else if (t === "timeline") renderTimeline(S.cur.events);
  else if (t === "search") renderSearch();
  else if (t === "tree") renderTree();
  else if (t === "intel") renderIntel();
  else if (t === "ctx") renderCtx();
  else if (t === "decoder") renderDecoder();
}

/* ---- Alert overview ---- */
function renderOverview() {
  const sc = S.cur;
  const chips = (items, kind) => (items && items.length
    ? items.map(i => `<span class="chip" onclick="lookup('${esc(i)}','${kind}')">${esc(i)}</span>`).join(" ")
    : `<span class="chip dim">none</span>`);
  $("tab-body").innerHTML = `
    <div class="alert-card">
      <div class="kv">
        <span class="k">Rule</span><span class="v">${esc(sc.alert.rule)}</span>
        <span class="k">Alert severity</span><span class="v">${esc(sc.alert.severity)}</span>
        <span class="k">Timestamp</span><span class="v">${esc(sc.alert.ts)}</span>
        <span class="k">Host</span><span class="v" onclick="openCtxHost('${esc(sc.alert.host)}')" style="cursor:pointer;color:#58a6ff;text-decoration:underline">${esc(sc.alert.host)}</span>
        <span class="k">User</span><span class="v" onclick="openCtxUser('${esc(sc.alert.user)}')" style="cursor:pointer;color:#58a6ff;text-decoration:underline">${esc(sc.alert.user)}</span>
        <span class="k">Source / Dest IP</span><span class="v">${chips(sc.alert.ips, "ip")}</span>
        <span class="k">Domains</span><span class="v">${chips(sc.alert.domains, "domain")}</span>
        <span class="k">File hashes</span><span class="v">${chips(sc.alert.hashes, "hash")}</span>
        ${PROG.hardMode ? "" : `<span class="k">MITRE hint</span><span class="v">${esc(sc.alert.mitreHint)}</span>`}
      </div>
      <button class="btn" style="margin-top:10px;display:inline-block" onclick="copyAlert()">Copy alert details</button>
    </div>
    <div class="hint mt-14">${esc(sc.summary)}</div>
    ${PROG.hardMode ? "" : `<div class="playbook mt-14">
      <details>
        <summary>Triage playbook (Module 2 — 20-question framework)</summary>
        <ol>
          <li>What triggered it? Which rule / detection logic?</li>
          <li>Which asset? (role, tier, EDR health) → Assets & Users tab</li>
          <li>Which user? (privilege, MFA, risk) → Assets & Users tab</li>
          <li>What happened? Build the timeline (before AND after the alert).</li>
          <li>Which process? Parent? Full command line? → Process Tree</li>
          <li>Any network connections? Beaconing? → Timeline + Threat Intel</li>
          <li>Any files/registry/persistence? → Timeline</li>
          <li>Any auth events? Logon types, source IP, MFA?</li>
          <li>Enrich: IP/domain/hash reputation → Threat Intel tab</li>
          <li>Classify: TP / FP / Benign / Inconclusive → justify with evidence</li>
          <li>Severity: P1-P4 (apply asset-tier multiplier)</li>
          <li>Act: contain first (P1/P2), then escalate with a package</li>
        </ol>
      </details>
    </div>`}
    <div class="small mt-14">Indicator chips are clickable — they jump to Threat Intel or context tabs.</div>`;
}

/* ---- Timeline ---- */
const SUSP_WORDS = ["powershell", "lsass", "mimikatz", "sekurlsa", "0xc000006a", "0xc000006d",
  "nxdomain", "beacon", "outbound", "rundll32", "mshta", "certutil", "bitsadmin", "wmic",
  "4698", "download", "registry", "persistence", "\\temp\\", "encoded", "invoke-",
  "downloadstring", "whoami", "net user", "net localgroup", "taskkill", "vssadmin",
  "wscript", "cscript", "logon was cleared", "account locked", "brute force", "unusual",
  "new executable", "suspicious", "meterpreter", "cobalt", "c2", "eicar"];

function isSuspEvent(e) {
  if (PROG.hardMode) return false;
  if (e.susp) return true;
  const hay = (e.id + " " + e.title + " " + e.detail + " " + e.source).toLowerCase();
  return SUSP_WORDS.some(w => hay.includes(w));
}

function setTimelineFilter(v) {
  S.timelineFilter = v;
  renderTimeline(S.cur.events);
}

function copyEvent(i) {
  const e = S.cur.events[i];
  const txt = "[" + e.time + "] " + e.id + " " + e.title + " (" + e.source + ") " + e.host + "\n" + e.detail;
  copyText(txt, "Event copied to clipboard");
}

function copyAlert() {
  const sc = S.cur;
  const txt = [
    "Rule: " + sc.alert.rule,
    "Severity: " + sc.alert.severity,
    "Time: " + sc.alert.ts,
    "Host: " + sc.alert.host,
    "User: " + sc.alert.user,
    "IPs: " + (sc.alert.ips && sc.alert.ips.length ? sc.alert.ips.join(", ") : "—"),
    "Domains: " + (sc.alert.domains && sc.alert.domains.length ? sc.alert.domains.join(", ") : "—"),
    "Hashes: " + (sc.alert.hashes && sc.alert.hashes.length ? sc.alert.hashes.join(", ") : "—"),
    "MITRE hint: " + sc.alert.mitreHint,
    "Summary: " + sc.summary
  ].join("\n");
  copyText(txt, "Alert details copied to clipboard");
}

function renderTimeline(events) {
  const list = S.timelineFilter === "susp" ? events.filter(isSuspEvent) : events;
  const rows = list.map(e => {
    const idx = events.indexOf(e);
    const typeCls = "type-" + e.type;
    const chips = (e.detail.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[a-f0-9]{32,64})\b|[\w.-]+\.(?:com|net|org|tk|ru|xyz|io|ps1)\b/gi) || [])
      .filter((v, i, a) => a.indexOf(v) === i).slice(0, 6)
      .map(v => `<span class="chip" onclick="lookup('${esc(v)}','auto')">${esc(v)}</span>`).join(" ");
    return `
      <div class="ev-row ${isSuspEvent(e) ? "susp" : ""}">
        <div class="t">${e.time}</div>
        <div class="body">
          <div class="hd">
            <span class="eid">${esc(e.id)}</span>
            <span class="title">${esc(e.title)}</span>
            <span class="type-tag ${typeCls}">${e.type}</span>
            <span class="src">${esc(e.source)}</span>
            <span class="host">${esc(e.host)}</span>
          </div>
          <div class="det">${esc(e.detail)}</div>
          ${chips ? `<div class="mt-8">${chips}</div>` : ""}
        </div>
        <button class="copy-evt" title="Copy this event" onclick="copyEvent(${idx})">&#128203;</button>
      </div>`;
  }).join("");
  $("tab-body").innerHTML = `
    <div class="timeline-tools">
      <div class="chips">
        <button class="chip-btn ${S.timelineFilter === "all" ? "active" : ""}" onclick="setTimelineFilter('all')">All</button>
        ${PROG.hardMode ? "" : `<button class="chip-btn ${S.timelineFilter === "susp" ? "active" : ""}" onclick="setTimelineFilter('susp')">Suspicious only</button>`}
      </div>
      <span class="count">${list.length}/${events.length} events${S.timelineFilter === "susp" ? " flagged by detection logic" : ""}</span>
    </div>
    <div>${rows || '<div class="empty">No events.</div>'}</div>`;
}

/* ---- SIEM search ---- */
function renderSearch() {
  $("tab-body").innerHTML = `
    <div class="searchbar">
      <input id="searchInput" placeholder="KQL-ish search: try 4625, powershell, lsass, IP, UNION, MFA, NXDOMAIN..." onkeydown="if(event.key==='Enter')doSearch()"/>
      <button onclick="doSearch()">Query</button>
    </div>
    <div class="preset">
      ${PRESET_QUERIES.map((p, i) => `<button onclick="presetQuery(${i})">${p.label}</button>`).join("")}
    </div>
    <div id="searchResults" class="small">Run a query to see events (you have the full telemetry corpus of this alert).</div>`;
  $("searchInput").focus();
}

function runSearch(filter, queryText) {
  let results = filter ? S.cur.events.filter(filter) : S.cur.events;
  const q = (queryText || "").toLowerCase().trim();
  if (q) results = results.filter(e => e.q.includes(q));
  return results;
}

function showSearchResults(results, queryText) {
  const el = $("searchResults");
  const q = (queryText || "").toLowerCase().trim();
  S.cur.keyEvidence.forEach(k => {
    if (!k.keyword) return;
    const kw = k.keyword.toLowerCase();
    const hit = (q && q.includes(kw)) ||
      (results.length && results.some(e => e.q.includes(kw)));
    if (hit) awardEvidence(k.id);
  });
  const hl = text => {
    if (!q) return esc(text);
    const out = esc(text);
    const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").split(/\s+/).filter(Boolean);
    return escaped.length ? out.replace(new RegExp("(" + escaped.join("|") + ")", "gi"), "<mark>$1</mark>") : out;
  };
  if (!results.length) {
    el.innerHTML = `<div class="empty">0 results for "${esc(queryText || "query")}". Try another keyword (e.g. an event ID, IP, process name).</div>`;
    return;
  }
  el.innerHTML = `<div class="results-count">${results.length} event(s) &middot; query: <span class="mono">${esc(queryText || "all")}</span></div>` +
    results.map(e => `
      <div class="ev-row ${isSuspEvent(e) ? "susp" : ""}">
        <div class="t">${e.time}</div>
        <div class="body">
          <div class="hd">
            <span class="eid">${esc(e.id)}</span>
            <span class="title">${hl(e.title)}</span>
            <span class="type-tag type-${e.type}">${e.type}</span>
            <span class="host">${esc(e.host)}</span>
          </div>
          <div class="det">${hl(e.detail)}</div>
        </div>
      </div>`).join("");
}

function doSearch() {
  const q = $("searchInput").value;
  showSearchResults(runSearch(null, q), q);
}
function presetQuery(i) {
  const p = PRESET_QUERIES[i];
  showSearchResults(runSearch(p.filter, p.label), p.label);
}

/* ---- Process tree ---- */
function renderTree() {
  const sc = S.cur;
  if (!sc.processes || !sc.processes.length) {
    $("tab-body").innerHTML = `<div class="empty">No process telemetry for this detection source (auth / network / cloud log only). In a real environment, pull this from EDR / Sysmon EID 1.</div>`;
    return;
  }
  const byParent = {};
  sc.processes.forEach(p => {
    (byParent[p.parent == null ? "root" : p.parent] = byParent[p.parent == null ? "root" : p.parent] || []).push(p);
  });
  function node(p) {
    const kids = (byParent[p.id] || []).map(node).join("");
    return `<li>
      <span class="pnode ${p.susp ? "susp" : ""}" onclick="treeDetail(${p.id})" id="pnode-${p.id}">
        <span class="img">${esc(p.image)}</span>${p.susp ? ` <span class="flag">▲ suspicious</span>` : ""}<br>
        <span class="cmd">${esc(p.cmd)}</span> · <span class="uid">${esc(p.user)} · ${esc(p.il)}</span>
      </span>
      ${kids ? `<ul>${kids}</ul>` : ""}
    </li>`;
  }
  $("tab-body").innerHTML = `
    <div class="small mb-8">Click a node for detail. Red-bordered nodes = behavior flagged by detection logic.</div>
    <div class="tree"><ul>${(byParent.root || []).map(node).join("")}</ul></div>
    <div id="treeDetail" class="mt-14"></div>`;
}

function treeDetail(id) {
  const p = S.cur.processes.find(x => x.id === id);
  document.querySelectorAll(".pnode").forEach(n => n.classList.remove("selected"));
  const el = $("pnode-" + id);
  if (el) el.classList.add("selected");
  $("treeDetail").innerHTML = `
    <div class="intel-card">
      <div class="ind ${p.susp ? "bad" : ""}">${esc(p.image)}</div>
      <div class="row"><b>Command line:</b> ${esc(p.cmd)}</div>
      <div class="row"><b>User:</b> ${esc(p.user)}</div>
      <div class="row"><b>Integrity:</b> ${esc(p.il)}</div>
      ${p.susp ? '<div class="row" style="color:#f85149"><b>Why flagged:</b> part of a suspicious process chain (see detection rule / parent-child context)</div>' : ""}
    </div>`;
}

/* ---- Threat intel ---- */
function renderIntel() {
  const sc = S.cur;
  const inds = [];
  (sc.alert.ips || []).forEach(i => inds.push([i, "ip"]));
  (sc.alert.domains || []).forEach(i => inds.push([i, "domain"]));
  (sc.alert.hashes || []).forEach(i => inds.push([i, "hash"]));
  Object.keys(sc.intel || {}).forEach(i => { if (!inds.some(x => x[0] === i)) inds.push([i, "auto"]); });

  $("tab-body").innerHTML = `
    <div class="small mb-8">Look up indicators to enrich the alert. Chip color = reputation verdict.</div>
    <div class="intel-grid">
      ${inds.map(([i, kind]) => {
        const d = sc.intel[i];
        const cls = !d ? "" : (/malicious|tor|rus|credential|ransom|scan/i.test(d.notes + " " + d.geo) ? "bad" : "ok");
        return `<span class="chip ${cls}" onclick="lookup('${esc(i)}','${kind}')">${esc(i)}</span>`;
      }).join("")}
    </div>
    <div id="intelCards">
      <div class="empty">Click an indicator above (or one in the timeline) to pull its reputation.</div>
    </div>`;
}

function lookup(ind, kind) {
  const sc = S.cur;
  if (!sc) return;
  const d = sc.intel[ind];
  if (d) {
    S.tiViewed.add(ind);
    if (S.tiViewed.has(ind)) awardEvidence("intel-" + ind);
  }
  if (kind === "user") { openCtxUser(ind); return; }
  if (kind === "host") { openCtxHost(ind); return; }
  const cards = $("intelCards");
  if (!cards) { switchTab("intel"); }
  setTimeout(() => {
    const c = $("intelCards");
    if (!c) return;
    if (!d) {
      c.innerHTML = `<div class="intel-card"><div class="ind">${esc(ind)}</div><div class="row">No reputation data in this dataset. <b>Unknown</b> — enrich via external TI in a real SOC.</div></div>`;
      return;
    }
    const verdict = /malicious|tor|rus|credential|ransom|scan|strike|dga/i.test(d.notes + " " + d.geo) ? "bad" : "ok";
    c.innerHTML = `<div class="intel-card">
      <div class="ind ${verdict}">${esc(ind)} <span class="small">(${kind})</span></div>
      <div class="row"><b>VirusTotal:</b> ${esc(d.vt)}</div>
      <div class="row"><b>AbuseIPDB:</b> ${esc(d.abuse)}</div>
      <div class="row"><b>Geo / host:</b> ${esc(d.geo)}</div>
      <div class="row"><b>Notes:</b> ${esc(d.notes)}</div>
    </div>`;
  }, 30);
}

/* ---- Assets & users ---- */
function renderCtx() {
  const sc = S.cur;
  const hosts = Object.keys(sc.assets || {});
  const users = Object.keys(sc.users || {});
  $("tab-body").innerHTML = `
    <div class="small mb-8">Click a host or user to open its context card. Context drives asset-tier severity.</div>
    <h4 style="margin:8px 0 6px">Assets</h4>
    ${hosts.length ? hosts.map(h => `<span class="chip" onclick="openCtxHost('${esc(h)}')">${esc(h)}</span>`).join(" ") : '<span class="chip dim">none</span>'}
    <h4 style="margin:14px 0 6px">Users</h4>
    ${users.length ? users.map(u => `<span class="chip" onclick="openCtxUser('${esc(u)}')">${esc(u)}</span>`).join(" ") : '<span class="chip dim">none</span>'}
    <div id="ctxCards" class="mt-14"></div>`;
}

function ctxCard(title, rows) {
  return `<div class="ctx-card"><div class="name">${esc(title)}</div>${rows.map(r =>
    `<div class="row"><b>${esc(r[0])}:</b> ${esc(r[1])}</div>`).join("")}</div>`;
}

function openCtxHost(h) {
  const sc = S.cur;
  const d = sc.assets[h];
  S.ctxViewed.add("asset-" + h);
  if (S.ctxViewed.has("asset-" + h)) awardEvidence("asset-" + h);
  const el = $("ctxCards");
  if (el) {
    el.innerHTML = d
      ? ctxCard(h, [["Role", d.role], ["Tier", d.tier], ["OS", d.os], ["EDR", d.edr], ["Owner", d.owner], ["Notes", d.note || "—"]])
      : `<div class="ctx-card"><div class="name">${esc(h)}</div><div class="row">No CMDB record for this host in the dataset.</div></div>`;
  }
}
function openCtxUser(u) {
  const sc = S.cur;
  const d = sc.users[u];
  S.ctxViewed.add("user-" + u);
  if (S.ctxViewed.has("user-" + u)) awardEvidence("user-" + u);
  const el = $("ctxCards");
  if (el) {
    el.innerHTML = d
      ? ctxCard(u, [["Department", d.dept], ["Title", d.title], ["Groups", (d.groups || []).join(", ")], ["MFA", d.mfa], ["Last password change", d.lastPw], ["Notes", d.note || "—"]])
      : `<div class="ctx-card"><div class="name">${esc(u)}</div><div class="row">No directory record for this user in the dataset.</div></div>`;
  }
}

/* ---- Decoder ---- */
function renderDecoder() {
  $("tab-body").innerHTML = `
    <div class="small mb-8">Encoded (base64) commands are common in PowerShell attacks (T1027.010). Paste one to decode.</div>
    <div class="decoder">
      <textarea id="decInput" placeholder="Paste base64 string here, e.g. SQBFAFgAIAAoAE4A..."></textarea>
      <button onclick="doDecode()">Decode base64</button>
      <div id="decOut"></div>
    </div>`;
}

function decodeFormat(input) {
  const t = input.replace(/\s+/g, "");
  if (/^[0-9a-f]+$/i.test(t) && t.length % 2 === 0) return "hex";
  if (/%[0-9a-f]{2}/i.test(t)) return "url";
  if (/^[A-Za-z0-9+/=]+$/.test(t) && t.length >= 8) return "base64";
  return "plain";
}

function doDecode() {
  const raw = ($("decInput") || {}).value || "";
  const input = raw.trim();
  const out = $("decOut");
  if (!input) { out.innerHTML = ""; return; }
  const fmt = decodeFormat(input);
  let decoded = "";
  try {
    if (fmt === "base64") {
      const bin = atob(input.replace(/\s+/g, ""));
      let text = "";
      for (let i = 0; i < bin.length; i++) text += String.fromCharCode(bin.charCodeAt(i) & 0xff);
      decoded = decodeURIComponent(escape(text));
    } else if (fmt === "hex") {
      decoded = input.replace(/\s+/g, "").replace(/([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
    } else if (fmt === "url") {
      decoded = decodeURIComponent(input);
    } else {
      decoded = "(plain text — nothing to decode)";
    }
  } catch (e) {
    decoded = "(couldn't decode — if it's base64, paste a PowerShell -enc string like SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA)";
  }
  if (S.cur.encodedCommands && S.cur.encodedCommands.some(c => c === input)) {
    awardEvidence("decode-base64");
  }
  const fmtLbl = { base64: "base64 → UTF-16", hex: "hex → ASCII", url: "URL-encoded", plain: "plain text" }[fmt];
  out.innerHTML = `<div class="dec-head"><span class="dec-format ${fmt}">${fmtLbl}</span></div><div class="dec-out">${esc(decoded)}</div>`;
}

/* ---------------- decision panel ---------------- */
function actionGroups() {
  const g = {};
  ACTIONS.forEach(a => (g[a.group] = g[a.group] || []).push(a));
  return g;
}

function renderDecision() {
  const sc = S.cur;
  const clsRadios = ["TP", "FP", "BP", "IC"].map(c => `
    <label class="${c === "TP" ? "sel-tp" : c === "FP" ? "sel-fp" : c === "BP" ? "sel-bp" : "sel-ic"}">
      <input type="radio" name="cls" value="${c}" onchange="updateDecisionStatus()"> ${CLASS_LABELS[c]}
    </label>`).join("");

  const sevOpts = Object.entries(SEV_LABELS).map(([k, v]) => `<option value="${k}">${v}</option>`).join("");

  const actGroups = Object.entries(actionGroups()).map(([name, list]) => `
    <div class="decision-group">
      <label>${esc(name)}</label>
      <div class="check-list">${list.map(a =>
        `<label><input type="checkbox" name="act" value="${a.id}" onchange="updateDecisionStatus()"> ${esc(a.label)}</label>`).join("")}</div>
    </div>`).join("");

  const mitChecks = MITRE_OPTIONS.map(m => `
    <label title="${esc(m[1])}"><input type="checkbox" name="mitre" value="${m[0]}" onchange="updateDecisionStatus()"> <span class="mono">${m[0]}</span></label>`).join("");

  $("decision-body").innerHTML = `
    <div class="hint" style="margin-bottom:14px">Analyze the alert with the tabs, then classify and decide. Contain first (P1/P2), then escalate with a package.</div>
    <div class="field">
      <label>Classification</label>
      <div class="radio-grid">${clsRadios}</div>
    </div>
    <div class="field">
      <label>Severity / Priority</label>
      <select id="sevSel" onchange="updateDecisionStatus()">${sevOpts}</select>
      <div class="small mt-8">Apply the asset-tier multiplier (Tier 0/1 raises priority).</div>
    </div>
    <div class="field">
      <label>Actions taken (check all that apply)</label>
      ${actGroups}
    </div>
    <div class="field">
      <label>MITRE techniques observed</label>
      <div class="check-list" style="max-height:260px">${mitChecks}</div>
    </div>
    <div class="field">
      <label>Notes (optional)</label>
      <textarea class="notes" id="notesTa" placeholder="Evidence → conclusion → action. No speculation." oninput="updateDecisionStatus()"></textarea>
    </div>
    <button class="submit-btn" onclick="submitDecision()">Submit Decision</button>`;
  updateDecisionStatus();
}

function updateDecisionStatus() {
  const sc = S.cur;
  if (!sc) return;
  const clsEl = document.querySelector('input[name="cls"]:checked');
  const sev = $("sevSel");
  const actSel = document.querySelectorAll('input[name="act"]:checked').length;
  const mitSel = document.querySelectorAll('input[name="mitre"]:checked').length;
  const sevVal = sev && sev.value;
  const meter = $("decision-meter");
  if (meter) {
    meter.innerHTML = ["P1", "P2", "P3", "P4"].map(p =>
      `<i class="${sevVal === p ? "on" : ""}"></i>`).join("") +
      (sevVal ? `<span>${sevVal}</span>` : "<span>set severity</span>");
  }
  const bar = $("decision-bar-status");
  if (bar) {
    const parts = [];
    if (clsEl) parts.push(CLASS_LABELS[clsEl.value]);
    if (sevVal) parts.push(sevVal);
    if (actSel) parts.push(actSel + " action" + (actSel > 1 ? "s" : ""));
    if (mitSel) parts.push(mitSel + " MITRE");
    bar.textContent = parts.length ? parts.join(" · ") : "Classify to submit";
  }
}

function toggleDrawer() {
  const dp = $("decision-panel");
  if (!dp) return;
  const open = dp.classList.toggle("open");
  const bar = $("decision-bar");
  if (bar) bar.style.display = open ? "none" : "";
  if (open) dp.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function collectDecision() {
  const clsEl = document.querySelector('input[name="cls"]:checked');
  if (!clsEl) { toast("Choose a classification first (TP / FP / Benign / Inconclusive)."); return null; }
  const sevEl = $("sevSel");
  if (!sevEl || !sevEl.value) { toast("Pick a severity / priority."); return null; }
  return {
    classification: clsEl.value,
    severity: sevEl.value,
    actions: Array.from(document.querySelectorAll('input[name="act"]:checked')).map(i => i.value),
    mitre: Array.from(document.querySelectorAll('input[name="mitre"]:checked')).map(i => i.value),
    notes: $("notesTa").value.trim()
  };
}

function submitDecision() {
  const d = collectDecision();
  if (!d) return;
  const sc = S.cur;
  clearInterval(S.timerInt);
  const elapsed = (Date.now() - S.timerStart) / 1000;

  const ex = sc.expected;
  const actHits = d.actions.filter(a => ex.actions.includes(a));
  const mitHits = d.mitre.filter(m => ex.mitre.includes(m));
  const evFound = sc.keyEvidence.filter(k => S.evidence.has(k.id)).length;
  const evMissed = sc.keyEvidence.filter(k => !S.evidence.has(k.id));

  const partCls = clsScore(ex.classification, d.classification);
  const partSev = sevScore(ex.severity, d.severity);
  const partAct = Math.round(20 * f1(actHits.length, ex.actions, d.actions));
  const partMit = Math.round(10 * f1(mitHits.length, ex.mitre, d.mitre));
  const partEv = Math.round(15 * evFound / Math.max(1, sc.keyEvidence.length));
  const budget = TIME_BUDGET[sc.difficulty] || 360;
  const partTime = Math.max(0, Math.round(10 * Math.max(0, 1 - elapsed / budget)));

  const total = Math.min(100, partCls + partSev + partAct + partMit + partEv + partTime);

  const result = {
    scenId: sc.id,
    classification: d.classification,
    severity: d.severity,
    actions: d.actions,
    mitre: d.mitre,
    notes: d.notes,
    elapsed,
    parts: { cls: partCls, sev: partSev, act: partAct, mit: partMit, ev: partEv, time: partTime },
    total,
    actHits, actMiss: d.actions.filter(a => !ex.actions.includes(a)),
    actMissing: ex.actions.filter(a => !d.actions.includes(a)),
    mitHits, mitMiss: d.mitre.filter(m => !ex.mitre.includes(m)),
    mitMissing: ex.mitre.filter(m => !d.mitre.includes(m)),
    evFound, evMissed
  };

  if (S.mode === "shift" && S.shift) {
    S.shift.results = S.shift.results.filter(r => r.scenId !== sc.id);
    S.shift.results.push(result);
  }
  PROG.alerts++;
  if (!PROG.best[sc.id] || total > PROG.best[sc.id]) PROG.best[sc.id] = total;
  PROG.recent = PROG.recent.filter(r => r.id !== sc.id);
  PROG.recent.push({ id: sc.id, score: total, t: Date.now() });
  PROG.recent = PROG.recent.slice(-24);
  saveShiftSnapshot();
  saveProg();

  showDebrief(result);
}

/* ============================================================
   DEBRIEF
   ============================================================ */
function showDebrief(result) {
  S.viewResult = result;
  const sc = SCENARIOS.find(s => s.id === result.scenId);
  const g = grade(result.total);
  const ex = sc.expected;
  const secs = Math.floor(result.elapsed);

  const verdictCls = result.classification === ex.classification ? "good" :
    (result.classification === "IC" && ex.classification !== "IC" ? "part" : "bad");
  const verdictSev = result.severity === ex.severity ? "good" :
    (Math.abs(["P1", "P2", "P3", "P4"].indexOf(result.severity) - ["P1", "P2", "P3", "P4"].indexOf(ex.severity)) === 1 ? "part" : "bad");

  const bars = [
    ["Classification", result.parts.cls, 30],
    ["Severity", result.parts.sev, 15],
    ["Actions", result.parts.act, 20],
    ["MITRE mapping", result.parts.mit, 10],
    ["Evidence", result.parts.ev, 15],
    ["Speed", result.parts.time, 10]
  ].map(([l, v, m]) => `
    <div class="bar-row">
      <div class="lbl">${l}</div>
      <div class="track"><div class="fill" style="width:${Math.round(100 * v / m)}%;background:${v >= m ? "#3fb950" : v >= m / 2 ? "#d29922" : "#f85149"}"></div></div>
      <div class="v">${v}/${m}</div>
    </div>`).join("");

  const evItems = sc.keyEvidence.map(k => {
    const done = S.evidence.has(k.id) || result.evFound >= 0 && sc.keyEvidence.indexOf(k) < result.evFound;
    const isDone = done;
    const labels = { "decode-base64": "Decode the encoded PowerShell command", "process-tree": "Review the process tree" };
    const hint = labels[k.id] || (k.keyword ? `Run a query that surfaces "${k.keyword}"` : "Use the relevant investigation tool");
    return `<div class="ev-item ${isDone ? "done" : "miss"}">
      <span class="st">${isDone ? "✓ " : "✗ "}</span> ${esc(hint)}
      <div class="ex">${isDone ? "Completed" : "Missed — try it next time"}</div>
    </div>`;
  }).join("");

  const chips = (items, hitFn) => items.length ? items.map(i =>
    `<span class="chip ${hitFn(i) ? "ok" : ""}" ${hitFn(i) ? 'style="border-color:#3fb950;color:#3fb950"' : ""}>${esc(i)}</span>`).join(" ") : '<span class="chip dim">none</span>';

  const focus = [];
  if (result.classification !== ex.classification)
    focus.push(["Classification", "TP vs FP vs Benign — read the IOC / IOA / TTP cheat sheet and the FP-vs-BP distinction in the quiz."]);
  if (result.severity !== ex.severity)
    focus.push(["Severity / Priority", "Review the incident severity matrix and asset-tier multiplier in the Incident Severity cheat sheet."]);
  if (result.actMissing.length || result.actMiss.length)
    focus.push(["Actions", "Contain first, then escalate with a package — see the SOC Escalation cheat sheet."]);
  if (result.mitMissing.length || result.mitMiss.length)
    focus.push(["MITRE mapping", "Re-check which ATT&CK techniques the alert really matches in the MITRE cheat sheet."]);
  if ((result.evMissed || []).length)
    focus.push(["Evidence", result.evMissed.map(k => "Try \u201c" + (k.keyword || k.id) + "\u201d").join(" · ") + " — build the timeline before deciding."]);
  const courseMod = SCEN_MODULE[sc.id];
  const focusHtml = focus.length ? `<div class="reason mt-14"><div class="lbl">Learning focus</div>
    ${focus.map(([t, d]) => `<div class="row" style="margin:4px 0"><b>${t}:</b> ${esc(d)}</div>`).join("")}
    <div class="small mt-8">Open <button class="btn" style="display:inline-block;padding:2px 10px;font-size:11px" onclick="go('ref')">Cheat Sheets</button>
    ${courseMod ? `or ${courseLinkHtml(courseMod).replace('class="btn"', 'class="btn" style="display:inline-block;padding:2px 10px;font-size:11px"')}` : ""} to review the gap.</div>
  </div>` : (courseMod ? `<div class="reason mt-14"><div class="lbl">Go deeper</div>${courseLinkHtml(courseMod)}</div>` : "");

  $("debrief-content").innerHTML = `
    <div class="debrief-grid">
      <div>
        <div class="panel">
          <div class="panel-head">Triage report — ${esc(sc.title)}</div>
          <div class="panel-body">
            <div class="reason">
              <div class="lbl">Expected analysis</div>
              ${esc(ex.reasoning)}
            </div>

            <div class="verdict ${verdictCls}" style="margin-top:14px">
              <h4>Classification</h4>
              Yours: <span class="yours">${CLASS_LABELS[result.classification]}</span> — Expected:
              <span class="yours"><span class="hit">${CLASS_LABELS[ex.classification]}</span></span>
            </div>
            <div class="verdict ${verdictSev}">
              <h4>Severity / Priority</h4>
              Yours: <span class="yours">${SEV_LABELS[result.severity]}</span> — Expected:
              <span class="yours"><span class="hit">${SEV_LABELS[ex.severity]}</span></span>
            </div>

            <div class="verdict ${result.actHits.length === ex.actions.length && !result.actMiss.length ? "good" : result.actMiss.length > ex.actions.length ? "bad" : "part"}">
              <h4>Actions (hits ✓ / extras ✗ / missing)</h4>
              <span class="yours">
                ${result.actHits.map(a => `<span class="hit">${esc(a)}</span>`).join(" ") || '<span class="dim">none</span>'}
                ${result.actMiss.map(a => `<span class="extra">${esc(a)} ✗</span>`).join(" ")}
              </span>
              <div class="mt-8 small">Expected actions: ${ex.actions.map(a => esc(a)).join(", ") || "none"}</div>
            </div>

            <div class="verdict ${result.mitHits.length === ex.mitre.length && !result.mitMiss.length ? "good" : "part"}">
              <h4>MITRE ATT&CK mapping</h4>
              <span class="yours">
                ${result.mitHits.map(m => `<span class="hit">${esc(m)}</span>`).join(" ") || '<span class="dim">none</span>'}
                ${result.mitMiss.map(m => `<span class="extra">${esc(m)} ✗</span>`).join(" ")}
              </span>
              <div class="mt-8 small">Expected techniques: ${ex.mitre.map(m => esc(m)).join(", ") || "none"}</div>
            </div>

            <div class="mt-14">
              <div class="small mb-8" style="font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#8a97ad">Evidence collected (${result.evFound}/${sc.keyEvidence.length})</div>
              <div class="evidence-grid">${evItems}</div>
            </div>
            ${focusHtml}
          </div>
        </div>
      </div>

      <div>
        <div class="panel" style="position:sticky;top:70px">
          <div class="panel-head">Score</div>
          <div class="panel-body">
            <div class="score-ring" style="--p:${result.total}">
              <div class="inner"><div class="val">${result.total}</div><div class="lbl">/ 100</div></div>
            </div>
            <div class="grade" style="color:${g.c}">${g.t}</div>
            <div class="small" style="text-align:center;margin-top:4px">Triage time: ${String(Math.floor(secs / 60)).padStart(2, "0")}:${String(secs % 60).padStart(2, "0")}</div>
            <div class="bars">${bars}</div>
            <div class="small mt-8" style="color:#8a97ad">Speed bonus vs budget: ${TIME_BUDGET[sc.difficulty]}s target for ${sc.difficulty} alerts.</div>
            ${result.notes ? `<div class="reason mt-14"><div class="lbl">Your notes</div>${esc(result.notes)}</div>` : ""}
            <div class="debrief-actions">
              ${S.mode === "shift" && S.shift ? `<button class="btn primary" onclick="nextShiftAlert()">Next Alert</button>
               <button class="btn" onclick="endShift()">End Shift</button>` : `
               <button class="btn primary" onclick="retryAlert()">Try Again</button>
               <button class="btn" onclick="show('home')">Home</button>`}
               <button class="btn" onclick="copyReport()">Copy report</button>
            </div>
          </div>
        </div>
      </div>
    </div>`;
  show("debrief");
}

function viewDebrief(id) {
  const res = S.shift.results.find(r => r.scenId === id);
  if (res) showDebrief(res);
}

function buildReportMd(result) {
  const sc = SCENARIOS.find(s => s.id === result.scenId);
  const ex = sc.expected;
  const L = [];
  L.push("# Triage report — " + sc.title, "");
  L.push("- **Alert:** " + sc.alert.rule);
  L.push("- **Host:** " + sc.alert.host + " · **User:** " + sc.alert.user + " · **Time:** " + sc.alert.ts);
  L.push("- **Classification (yours):** " + CLASS_LABELS[result.classification] + " / **Expected:** " + CLASS_LABELS[ex.classification]);
  L.push("- **Severity:** " + result.severity + " / **Expected:** " + ex.severity);
  L.push("- **Score:** " + result.total + "/100", "");
  L.push("## Actions taken", result.actions.length ? result.actions.map(a => "- " + a) : ["- (none)"], "");
  L.push("## Expected actions", ex.actions.length ? ex.actions.map(a => "- " + a) : ["- (none)"], "");
  L.push("## MITRE techniques (yours)", result.mitre.length ? result.mitre.join(", ") : "none", "");
  L.push("## Expected MITRE", ex.mitre.length ? ex.mitre.join(", ") : "none", "");
  if (result.notes) L.push("## Analyst notes", result.notes, "");
  L.push("## Expected analysis", ex.reasoning);
  return L.join("\n");
}

function copyReport() {
  copyText(buildReportMd(S.viewResult), "Report copied to clipboard");
}

function retryAlert() {
  startAlert(S.viewResult.scenId);
}
function nextShiftAlert() {
  const done = new Set(S.shift.results.map(r => r.scenId));
  const next = S.shift.ids.find(id => !done.has(id));
  if (next) startAlert(next);
  else endShift();
}
function endShift() {
  renderReport();
  clearShiftSnapshot();
  show("report");
}

/* ============================================================
   REPORT
   ============================================================ */
function buildShiftReportMd() {
  const L = [];
  L.push("# Shift report — " + (S.shift ? new Date(S.shift.startTs).toLocaleString() : ""), "");
  S.shift.results.forEach((r, i) => {
    const sc = SCENARIOS.find(s => s.id === r.scenId);
    L.push("## " + (i + 1) + ". " + sc.title + " — " + r.total + "/100", "");
    L.push("- Classification: **" + CLASS_LABELS[r.classification] + "** (expected " + CLASS_LABELS[sc.expected.classification] + ")");
    L.push("- Severity: **" + r.severity + "** (expected " + sc.expected.severity + ")");
    if (r.actions.length) L.push("- Actions: " + r.actions.join(", "));
    if (r.mitre.length) L.push("- MITRE: " + r.mitre.join(", "));
    if (r.notes) L.push("- Notes: " + r.notes);
    L.push("");
  });
  return L.join("\n");
}

function copyShiftReport() {
  copyText(buildShiftReportMd(), "Shift report copied to clipboard");
}

function renderReport() {
  const results = (S.shift && S.shift.results) || [];
  const total = results.reduce((s, r) => s + r.total, 0);
  const avg = results.length ? Math.round(total / results.length) : 0;
  const g = grade(avg);
  const rows = results.map(r => {
    const sc = SCENARIOS.find(s => s.id === r.scenId);
    return `<tr>
      <td>${esc(sc.title)}</td>
      <td><span class="badge ${r.classification === sc.expected.classification ? "tp" : "ic"}">${CLASS_LABELS[r.classification]}</span>
          <span class="small"> / ${CLASS_LABELS[sc.expected.classification]}</span></td>
      <td>${r.severity} <span class="small">/ ${sc.expected.severity}</span></td>
      <td class="num">${r.total}%</td>
    </tr>`;
  }).join("");
  const details = results.map((r, i) => {
    const sc = SCENARIOS.find(s => s.id === r.scenId);
    const ex = sc.expected;
    return `<div class="report-detail">
      <div class="rd-head">${i + 1}. ${esc(sc.title)} <span class="badge ${sc.difficulty.toLowerCase()}">${sc.difficulty}</span></div>
      <div class="rd-row"><b>Your actions:</b> ${r.actions.length ? r.actions.map(a => `<span class="chip">${esc(a)}</span>`).join(" ") : '<span class="chip dim">none</span>'}</div>
      <div class="rd-row"><b>Expected actions:</b> ${ex.actions.length ? ex.actions.map(a => `<span class="chip ok">${esc(a)}</span>`).join(" ") : '<span class="chip dim">none</span>'}</div>
      <div class="rd-row"><b>Your MITRE:</b> ${r.mitre.length ? r.mitre.map(m => `<span class="chip">${esc(m)}</span>`).join(" ") : "none"}</div>
      <div class="rd-row"><b>Expected MITRE:</b> ${ex.mitre.length ? ex.mitre.map(m => `<span class="chip ok">${esc(m)}</span>`).join(" ") : "none"}</div>
      ${r.notes ? `<div class="rd-row"><b>Your notes:</b> ${esc(r.notes)}</div>` : ""}
      <div class="rd-row small" style="color:#8a97ad"><b>Analysis:</b> ${esc(ex.reasoning)}</div>
    </div>`;
  }).join("");
  $("report-body").innerHTML = `
    <div class="grade-big" style="color:${g.c}">${g.t}</div>
    <div class="small mb-8">Average score: ${avg}% across ${results.length} alert(s).</div>
    <table class="report-table">
      <thead><tr><th>Alert</th><th>Classification (yours / expected)</th><th>Severity</th><th>Score</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="4" class="empty">No alerts triaged.</td></tr>'}</tbody>
    </table>
    <div class="mt-14">${details}</div>
    <div class="debrief-actions">
      <button class="btn primary" onclick="startShift()">New Shift</button>
      <button class="btn" onclick="copyShiftReport()">Copy shift report</button>
      <button class="btn" onclick="show('home')">Home</button>
      <button class="btn" onclick="show('scen-grid')">Browse Scenarios</button>
    </div>`;
}

/* ============================================================
   QUIZ
   ============================================================ */
function quizTags() {
  return [...new Set(QUIZ.map(q => q.tag))].sort();
}

function renderQuizSetup() {
  const tags = quizTags();
  if (!S.quizTopics.size) tags.forEach(t => S.quizTopics.add(t));
  $("quiz-topics").innerHTML = tags.map(t =>
    `<button class="chip-btn ${S.quizTopics.has(t) ? "active" : ""}" onclick="toggleQuizTopic('${esc(t)}')">${esc(t)}</button>`).join("");
  const counts = [10, 20, 50, -1];
  $("quiz-counts").innerHTML = counts.map(c =>
    `<button class="chip-btn ${S.quizCount === c ? "active" : ""}" onclick="S.quizCount=${c}; renderQuizSetup()">${c === -1 ? "All " + QUIZ.length : c}</button>`).join("");
}

function toggleQuizTopic(t) {
  if (S.quizTopics.has(t)) S.quizTopics.delete(t);
  else S.quizTopics.add(t);
  renderQuizSetup();
}

function startQuiz() {
  const topics = S.quizTopics.size ? S.quizTopics : new Set(quizTags());
  const pool = QUIZ.map((q, i) => Object.assign({ oi: i }, q))
    .filter(q => topics.has(q.tag))
    .sort(() => Math.random() - 0.5);
  const n = S.quizCount === -1 ? pool.length : Math.min(S.quizCount, pool.length);
  if (!n) { toast("No questions match the selected topics."); return; }
  const list = pool.slice(0, n);
  S.quiz = { list, idx: 0, correct: 0, answered: false, answers: {} };
  $("quiz-setup").style.display = "none";
  $("quiz-progress-wrap").style.display = "";
  $("quiz-review").innerHTML = "";
  renderQuiz();
  show("quiz");
}

function renderQuiz() {
  const z = S.quiz;
  const q = z.list[z.idx];
  $("quiz-progress-fill").style.width = Math.round(100 * z.idx / z.list.length) + "%";
  $("quiz-body").innerHTML = `
    <div class="quiz-q">
      <div class="qmeta">Question ${z.idx + 1} / ${z.list.length} · Score ${z.correct}/${z.idx} <span class="rq-tag">${esc(q.tag)}</span></div>
      <div class="qtext">${esc(q.q)}</div>
      ${q.o.map((opt, i) =>
        `<button class="quiz-opt" data-i="${i}" onclick="answerQuiz(${i})" ${z.answered ? "disabled" : ""}><span class="opt-key">${i + 1}</span>${esc(opt)}</button>`).join("")}
      <div class="small mt-8" style="color:#8a97ad">Tip: press <span class="kbd">1</span>&ndash;<span class="kbd">4</span> to answer, <span class="kbd">Enter</span> to continue.</div>
      <div id="quizExplain"></div>
    </div>`;
}

function answerQuiz(i) {
  const z = S.quiz;
  if (z.answered) return;
  z.answered = true;
  z.answers[z.idx] = i;
  const q = z.list[z.idx];
  const opts = document.querySelectorAll(".quiz-opt");
  opts.forEach((b, j) => {
    if (j === q.a) b.classList.add("correct");
    else if (j === i) b.classList.add("wrong");
  });
  if (i === q.a) z.correct++;
  const tagMod = TAG_MODULE[q.tag];
  $("quizExplain").innerHTML = `
    <div class="quiz-explain">
      <b>${i === q.a ? "Correct ✓" : "Incorrect ✗ (answer: " + esc(q.o[q.a]) + ")"}</b><br>${esc(q.e)}
      ${tagMod ? `<div class="mt-8">${courseLinkHtml(tagMod, "Study: " + tagMod.t)}</div>` : ""}
    </div>
    <button class="btn primary mt-8" onclick="${z.idx + 1 < z.list.length ? "nextQuiz()" : "finishQuiz()"}">${z.idx + 1 < z.list.length ? "Next" : "Finish"}</button>`;
}

function nextQuiz() {
  const z = S.quiz;
  if (z.idx + 1 >= z.list.length) { finishQuiz(); return; }
  z.idx++; z.answered = false;
  renderQuiz();
}

function showQuizReview() {
  const z = S.quiz;
  const items = z.list.map((q, i) => {
    const your = z.answers[i];
    const ok = your === q.a;
    return `<div class="review-q">
      <div class="rq-q">${i + 1}. ${esc(q.q)} <span class="rq-tag">${esc(q.tag)}</span></div>
      <div class="rq-answer">${ok ? "Correct ✓" : "You answered: " + esc(your == null ? "(skipped)" : q.o[your]) + " · Correct: " + esc(q.o[q.a])}</div>
      <div class="rq-explain">${esc(q.e)}</div>
    </div>`;
  }).join("");
  $("quiz-review").innerHTML = `<h3>Review — ${z.correct}/${z.list.length} correct (${Math.round(100 * z.correct / z.list.length)}%)</h3>${items}`;
}

function finishQuiz() {
  const z = S.quiz;
  const pct = Math.round(100 * z.correct / z.list.length);
  if (pct > PROG.quizBest) { PROG.quizBest = pct; saveProg(); }
  $("quiz-progress-fill").style.width = "100%";
  $("quiz-progress-wrap").style.display = "none";
  $("quiz-body").innerHTML = `
    <div class="quiz-q">
      <div class="qtext">Quiz complete — ${z.correct}/${z.list.length} correct (${pct}%)</div>
      <div class="grade-big" style="color:${grade(pct).c}">${grade(pct).t}</div>
      <div class="small">Best quiz score: ${PROG.quizBest}%</div>
      <div class="debrief-actions">
        <button class="btn primary" onclick="startQuiz()">New Quiz</button>
        <button class="btn" onclick="S.quiz=null; $('quiz-setup').style.display=''; $('quiz-review').innerHTML=''; go('quiz')">Back to topics</button>
        <button class="btn" onclick="show('home')">Home</button>
      </div>
    </div>`;
  showQuizReview();
}

/* ============================================================
   REFERENCE
   ============================================================ */
const MD_SHEETS = [
  { id: "md-common-ports",     file: "../cheatsheets/common-ports-cheatsheet.md",           title: "Common Ports" },
  { id: "md-incident-severity", file: "../cheatsheets/incident-severity-cheatsheet.md",     title: "Incident Severity" },
  { id: "md-ioc-ioa-ttp",      file: "../cheatsheets/ioc-ioa-ttp-cheatsheet.md",           title: "IOC / IOA / TTP" },
  { id: "md-readiness",        file: "../cheatsheets/l1-soc-readiness-checklist.md",       title: "L1 Readiness Checklist" },
  { id: "md-mitre",            file: "../cheatsheets/mitre-attck-cheatsheet.md",           title: "MITRE ATT&CK" },
  { id: "md-siem-edr",         file: "../cheatsheets/siem-edr-xdr-mxdr-comparison.md",     title: "SIEM / EDR / XDR / MXDR" },
  { id: "md-escalation",       file: "../cheatsheets/soc-escalation-cheatsheet.md",       title: "SOC Escalation" },
  { id: "md-windows-events",   file: "../cheatsheets/windows-event-id-cheatsheet.md",     title: "Windows Event IDs" },
  { id: "md-linux-logs",       file: "../cheatsheets/linux-log-directories-cheatsheet.md", title: "Linux Log Directories" },
  { id: "md-linux-commands",   file: "../cheatsheets/linux-commands-cheatsheet.md",       title: "Linux Commands (Intermediate)" },
  { id: "md-windows-commands", file: "../cheatsheets/windows-commands-cheatsheet.md",     title: "Windows Endpoint Commands" },
  { id: "md-kql-spl",          file: "../cheatsheets/kql-spl-regex-cheatsheet.md",        title: "KQL / SPL & Regex" },
  { id: "md-phishing-email",   file: "../cheatsheets/phishing-email-header-cheatsheet.md", title: "Phishing & Email Headers" },
  { id: "md-malware-triage",   file: "../cheatsheets/malware-triage-cheatsheet.md",       title: "Malware Triage" },
  { id: "md-ad-attacks",       file: "../cheatsheets/ad-attack-indicators-cheatsheet.md", title: "AD Attack Indicators" },
  { id: "md-net-traffic",      file: "../cheatsheets/network-traffic-pcap-cheatsheet.md", title: "Network Traffic & PCAP" },
  { id: "md-cloud-sec",        file: "../cheatsheets/cloud-security-cheatsheet.md",       title: "Cloud Security (Azure/AWS)" },
  { id: "md-ticketing",        file: "../cheatsheets/soc-ticketing-cheatsheet.md",        title: "SOC Ticketing & SLA" }
];

const mdCache = {};

function renderRef() {
  PROG.lastRef = S.ref;
  saveProg();
  const md = MD_SHEETS.find(r => r.id === S.ref);
  document.querySelectorAll(".ref-nav button").forEach(b =>
    b.classList.toggle("active", b.dataset.id === S.ref));
  if (md) { renderRefMd(md); return; }
  const sec = REFERENCE.find(r => r.id === S.ref);
  if (!sec) { $("ref-panel").innerHTML = `<div class="empty">Nothing here yet.</div>`; return; }
  $("ref-panel").innerHTML = `
    <div class="ref-search">
      <input id="refSearch" type="text" placeholder="Filter rows in this sheet&hellip;" oninput="refTableSearch()" aria-label="Search this reference table">
    </div>
    <div id="refTables"><h3>${esc(sec.title)}</h3>` + sec.sections.map(s => `
      <h4>${esc(s.h)}</h4>
      <table class="ref-table">
        <thead><tr>${s.headers.map(h => `<th>${esc(h)}</th>`).join("")}</tr></thead>
        <tbody>${s.rows.map(r => `<tr>${r.map(c => `<td class="${/^0x|\d/.test(c) && c.length < 12 ? "mono" : ""}">${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody>
      </table>`).join("") + `</div>`;
}

function refTableSearch() {
  const q = ($("refSearch") || {}).value || "";
  document.querySelectorAll("#refTables .ref-table").forEach(t => {
    const showRows = !q || t.querySelectorAll("tbody tr").length === 0;
    t.style.display = "";
    t.querySelectorAll("tbody tr").forEach(row => {
      row.style.display = row.textContent.toLowerCase().includes(q.toLowerCase()) ? "" : "none";
    });
    const visible = t.querySelectorAll("tbody tr").length && Array.from(t.querySelectorAll("tbody tr")).some(r => r.style.display !== "none");
    t.style.display = q && !visible ? "none" : "";
  });
}

function renderRefMd(md) {
  const panel = $("ref-panel");
  if (mdCache[md.id]) { renderMdDoc(md, mdCache[md.id]); return; }
  panel.innerHTML = `<div class="md-msg">Loading <code>${esc(md.file)}</code>&hellip;</div>`;
  fetch(md.file).then(r => {
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.text();
  }).then(text => {
    if (typeof marked === "undefined" || typeof DOMPurify === "undefined") throw new Error("renderer missing");
    mdCache[md.id] = DOMPurify.sanitize(marked.parse(text));
    if (S.ref === md.id) renderMdDoc(md, mdCache[md.id]);
  }).catch(err => {
    delete mdCache[md.id];
    if (S.ref === md.id) panel.innerHTML = mdNotice(md);
  });
}

/* ---- ADHD-friendly markdown reader (one section at a time) ---- */
let MD_CUR = null;   // { id, total }

function splitMdSections(html) {
  const doc = new DOMParser().parseFromString(html, "text/html");
  const model = { title: "", intro: "", sections: [] };
  let sec = null, sub = null;
  for (const el of Array.from(doc.body.childNodes)) {
    const tag = (el.tagName || "").toLowerCase();
    if (tag === "h1") { model.title = el.textContent.trim(); continue; }
    if (tag === "h2") { sec = { title: el.textContent.trim(), html: "", subs: [] }; model.sections.push(sec); sub = null; continue; }
    if (tag === "h3" && sec) { sub = { title: el.textContent.trim(), html: "" }; sec.subs.push(sub); continue; }
    const chunk = el.outerHTML || "";
    if (sec) { if (sub) sub.html += chunk; else sec.html += chunk; }
    else model.intro += chunk;
  }
  return model;
}

function wrapTables(html) {
  return html.replace(/<table>/g, '<div class="md-twrap"><table>').replace(/<\/table>/g, "</table></div>");
}

function injectChk(html, ctr, saved) {
  return wrapTables(html.replace(/<input[^>]*type="checkbox"[^>]*>/g, m => {
    const i = ctr.n++;
    const on = saved ? saved.has(i) : /checked/.test(m);
    return `<span class="chk${on ? " on" : ""}" data-i="${i}" role="checkbox" aria-checked="${on}" tabindex="0"></span>`;
  }));
}

function renderMdDoc(md, html) {
  const model = splitMdSections(html);
  const total = model.sections.length;
  if (!(md.id in S.mdSec)) S.mdSec[md.id] = 0;
  if (S.mdSec[md.id] >= total) S.mdSec[md.id] = total ? 0 : -1;
  const ctr = { n: 0 };
  const saved = getChkSet(md.id);
  model.sections.forEach(s => {
    s.html = injectChk(s.html, ctr, saved);
    s.subs.forEach(su => su.html = injectChk(su.html, ctr, saved));
  });
  MD_CUR = { id: md.id, total: total };

  const chips = model.sections.map((s, i) =>
    `<button class="md-chip" data-s="${i}" onclick="mdJump(${i})">${esc(s.title)}<span class="md-chip-done" data-cd="${i}"></span></button>`).join("");
  const body = model.sections.map((s, i) => {
    const subHtml = s.subs.length
      ? s.subs.map(su => `<div class="md-sub open"><h3 class="md-sub-h">${esc(su.title)} <span class="chev">&#9660;</span></h3><div class="md-sub-b">${su.html}</div></div>`).join("")
      : s.html;
    return `<section class="md-sec" data-s="${i}">
      <h2 class="md-sec-h">${esc(s.title)}<span class="md-sec-done" data-done="${i}"></span></h2>
      ${subHtml}
    </section>`;
  }).join("");

  $("ref-panel").innerHTML = `<div class="md-adhd">
    <div class="md-ctrl">
      <div class="md-ctrl-top">
        <button class="btn ghost small" id="mdFocusBtn" onclick="toggleMdFocus()">Focus mode</button>
        <div class="md-progress" title="Section progress"><div class="md-progress-fill" id="mdProgressFill"></div></div>
        <span class="md-progress-txt" id="mdProgressTxt"></span>
      </div>
      <div class="md-chips">${chips}</div>
    </div>
    ${model.title ? `<div class="md-title">${esc(model.title)}</div>` : ""}
    ${model.intro ? `<div class="md-intro md-content">${model.intro}</div>` : ""}
    <div class="md-sections md-content">${body}</div>
    <div class="md-navbtns">
      <button class="btn" onclick="mdMove(-1)">&#8592; Prev</button>
      <span class="md-nav-prog" id="mdNavProg"></span>
      <button class="btn primary" onclick="mdMove(1)">Next &rarr;</button>
    </div>
  </div>`;
  updateMdFocusUI();
  mdShow(total ? S.mdSec[md.id] : -1);
}

function mdShow(i) {
  if (!MD_CUR || !MD_CUR.total) return;
  i = Math.max(0, Math.min(MD_CUR.total - 1, i));
  S.mdSec[MD_CUR.id] = i;
  document.querySelectorAll("#ref-panel .md-sec").forEach((sec, n) => sec.classList.toggle("on", n === i));
  document.querySelectorAll("#ref-panel .md-chip").forEach((c, n) => c.classList.toggle("active", n === i));
  const pct = Math.round(((i + 1) / MD_CUR.total) * 100);
  const fill = $("mdProgressFill"), txt = $("mdProgressTxt"), nav = $("mdNavProg");
  if (fill) fill.style.width = pct + "%";
  if (txt) txt.textContent = "Section " + (i + 1) + " of " + MD_CUR.total;
  if (nav) nav.textContent = (i + 1) + " / " + MD_CUR.total;
  refreshMdProgress();
  const cur = document.querySelector("#ref-panel .md-sec.on");
  if (cur) cur.scrollIntoView({ block: "start", behavior: "smooth" });
}

function mdMove(step) {
  if (!MD_CUR || !MD_CUR.total) return;
  mdShow((S.mdSec[MD_CUR.id] || 0) + step);
}

function mdJump(i) {
  if (!MD_CUR || !MD_CUR.total) return;
  mdShow(i);
}

function toggleMdFocus() {
  S.mdFocus = !S.mdFocus;
  try { localStorage.setItem("adhdFocus", S.mdFocus ? "1" : "0"); } catch (e) {}
  updateMdFocusUI();
}

function updateMdFocusUI() {
  const panel = $("ref-panel");
  if (panel) panel.classList.toggle("md-focus", S.mdFocus);
  const b = $("mdFocusBtn");
  if (b) b.textContent = S.mdFocus ? "Focus mode: on (one at a time)" : "Focus mode: off (full page)";
}

function refreshMdProgress() {
  const panel = $("ref-panel");
  if (!panel) return;
  document.querySelectorAll("#ref-panel .md-sec").forEach(sec => {
    const done = sec.querySelectorAll(".chk.on").length;
    const total = sec.querySelectorAll(".chk").length;
    const d = sec.querySelector("[data-done]");
    if (d) d.textContent = total ? " " + done + "/" + total + " \u2713" : "";
    const chip = panel.querySelector('.md-chip[data-s="' + sec.dataset.s + '"] .md-chip-done');
    if (chip) chip.textContent = total ? " " + done + "/" + total : "";
  });
}

function getChkSet(id) {
  try {
    const raw = localStorage.getItem("adhdChk." + id);
    return raw === null ? null : new Set(JSON.parse(raw));
  } catch (e) { return null; }
}

function toggleChkMd(el) {
  const id = MD_CUR ? MD_CUR.id : S.ref;
  const i = +el.dataset.i;
  let set = getChkSet(id);
  if (set === null) set = new Set();
  if (set.has(i)) set.delete(i); else set.add(i);
  try { localStorage.setItem("adhdChk." + id, JSON.stringify([...set])); } catch (e) {}
  el.classList.toggle("on", set.has(i));
  el.setAttribute("aria-checked", set.has(i));
  refreshMdProgress();
}

function mdNotice(md) {
  return `<div class="md-msg"><b>Couldn't load <code>${esc(md.file)}</code>.</b><br>` +
    `Browsers block fetching local files when the page is opened by double-click (file:// protocol). ` +
    `Serve the <code>mxdr-l1-soc-crash-course</code> folder, then open over http:<br>` +
    `<code>python3 -m http.server 8000</code> &nbsp;&rarr;&nbsp; ` +
    `<a href="http://localhost:8000/soc-analyst-simulator/" target="_blank">http://localhost:8000/soc-analyst-simulator/</a><br>` +
    `Or view the raw file directly: <a href="${esc(md.file)}" target="_blank">${esc(md.file)}</a>` +
    `<button class="btn" style="display:inline-block;margin-left:8px;padding:2px 10px;font-size:11px" onclick="copyPath('${esc(md.file)}')">Copy path</button></div>`;
}

function copyPath(p) {
  copyText(p, "Path copied");
}

/* ============================================================
   SETTINGS
   ============================================================ */
function toggleSettings() {
  const c = $("hardModeChk");
  if (c) c.checked = !!PROG.hardMode;
  const m = $("settingsModal");
  if (m) m.classList.toggle("show");
}

function setHardMode(v) {
  PROG.hardMode = !!v;
  saveProg();
  toast(v ? "Hard mode ON — no hints, no suspicious highlighting" : "Hard mode OFF");
  const m = $("settingsModal");
  if (m) m.classList.remove("show");
}

function exportProg() {
  const blob = new Blob([JSON.stringify(PROG, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "soc-sim-progress.json";
  a.click();
  URL.revokeObjectURL(a.href);
  toast("Progress exported");
}

function importProg(ev) {
  const f = ev.target.files && ev.target.files[0];
  if (!f) return;
  const rd = new FileReader();
  rd.onload = () => {
    try {
      const data = JSON.parse(rd.result);
      PROG = Object.assign(PROG, data);
      saveProg();
      toast("Progress imported");
      renderHome();
      renderScenarios();
      renderQuizSetup();
    } catch (e) { toast("Invalid progress file"); }
  };
  rd.readAsText(f);
  ev.target.value = "";
}

function resetProg() {
  if (!confirm("Reset all progress (best scores, shift history, settings)?")) return;
  localStorage.removeItem("socSimProg");
  location.reload();
}

/* ============================================================
   KEYBOARD SHORTCUTS
   ============================================================ */
const TAB_KEYS = ["overview", "timeline", "search", "tree", "intel", "ctx", "decoder"];

function bindShortcuts() {
  document.addEventListener("keydown", e => {
    const inv = $("inv") && $("inv").classList.contains("active");
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement || {}).tagName);
    if (e.key === "/" && inv) {
      const si = $("searchInput");
      if (si && document.activeElement !== si) { e.preventDefault(); si.focus(); return; }
    }
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      if (inv) { e.preventDefault(); submitDecision(); return; }
    }
    const quizActive = $("quiz") && $("quiz").classList.contains("active");
    if (quizActive && S.quiz && !typing) {
      if (!S.quiz.answered && /^[1-4]$/.test(e.key) && !e.ctrlKey && !e.metaKey && !e.altKey) { e.preventDefault(); answerQuiz(+e.key - 1); return; }
      if (S.quiz.answered && e.key === "Enter") { e.preventDefault(); nextQuiz(); return; }
    }
    const refActive = $("ref") && $("ref").classList.contains("active");
    if (refActive && MD_CUR && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
      if (e.key === "f" || e.key === "F") { e.preventDefault(); toggleMdFocus(); return; }
      if (e.key === "ArrowRight" || e.key === "n" || e.key === "N") { e.preventDefault(); mdMove(1); return; }
      if (e.key === "ArrowLeft" || e.key === "p" || e.key === "P") { e.preventDefault(); mdMove(-1); return; }
    }
    if (inv && !typing && /^[1-7]$/.test(e.key) && !e.ctrlKey && !e.metaKey && !e.altKey) {
      const t = TAB_KEYS[+e.key - 1];
      if (t) switchTab(t);
    }
  });
}

/* ============================================================
   INIT (runs at script load, after the DOM is parsed)
   ============================================================ */
(function initUI() {
  if (PROG.lastRef) S.ref = PROG.lastRef;
  S.mdFocus = (function () { try { return localStorage.getItem("adhdFocus") !== "0"; } catch (e) { return true; } })();
  const rp = $("ref-panel");
  if (rp) {
    rp.addEventListener("click", e => {
      const chk = e.target.closest(".chk");
      if (chk) { toggleChkMd(chk); return; }
      const sh = e.target.closest(".md-sub-h");
      if (sh) { sh.parentElement.classList.toggle("open"); return; }
    });
  }
  const se = $("scenSearch");
  if (se) {
    se.addEventListener("input", () => {
      SCEN_FILTER.q = se.value.trim().toLowerCase();
      renderScenarios();
    });
    se.addEventListener("keydown", e => {
      if (e.key === "Escape") { se.value = ""; SCEN_FILTER.q = ""; renderScenarios(); }
    });
  }
  maybeOnboarding();
})();
