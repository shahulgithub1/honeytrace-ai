// ── State ─────────────────────────────────────────────────────────────────────
const S = {
  summary:null, attackers:[], events:[], alerts:[], iocs:{},
  tactics:[], blocked:[], geo:[], livefeed:[], killchain:[],
  filter:"", drawerIp:null, drawerTab:"profile", drawerData:null
};
const $  = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const fmt     = new Intl.DateTimeFormat(undefined,{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"});
const fmtTime = new Intl.DateTimeFormat(undefined,{hour:"2-digit",minute:"2-digit",second:"2-digit"});

// ── Tab titles ────────────────────────────────────────────────────────────────
const TITLES = {
  overview:"Overview", livefeed:"Live Feed", worldmap:"World Map",
  alerts:"Alerts", attackers:"Attackers", killchain:"Kill Chain",
  mitre:"MITRE ATT&CK", iocs:"IOCs", blocked:"Blocked IPs",
  events:"Events", import:"Import Logs"
};

let currentTab = "overview";

function switchTab(id) {
  if (!document.getElementById(`tab-${id}`)) return;
  currentTab = id;
  $$(".page").forEach(p => p.classList.remove("active"));
  $$(".nav-link").forEach(a => a.classList.remove("active"));
  $(`#tab-${id}`).classList.add("active");
  const nav = document.querySelector(`[data-tab="${id}"]`);
  if (nav) nav.classList.add("active");
  $("#tabTitle").textContent = TITLES[id] || id;
  history.replaceState(null, "", `#${id}`);
  if (id === "worldmap" && S.geo.length) renderWorldMap();
  if (id === "livefeed") loadFeed();
  if (id === "killchain") renderKillChain();
}

// ── API ───────────────────────────────────────────────────────────────────────
async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(await r.text() || `HTTP ${r.status}`);
  const ct = r.headers.get("content-type") || "";
  return ct.includes("json") ? r.json() : r.text();
}

// ── Load ──────────────────────────────────────────────────────────────────────
async function load() {
  const [summary, attackers, events, alerts, iocs, tactics, blocked, geo, killchain] = await Promise.all([
    api("/api/summary"), api("/api/attackers"), api("/api/events?limit=100"),
    api("/api/alerts"),  api("/api/iocs"),      api("/api/tactics"),
    api("/api/blocked"), api("/api/geo"),        api("/api/killchain")
  ]);
  Object.assign(S, {summary, attackers, events, alerts, iocs, tactics, blocked, geo, killchain});
  $("#lastRefresh").textContent = `Updated ${fmtTime.format(new Date())}`;
  render();
}

async function loadFeed() {
  S.livefeed = await api("/api/livefeed?limit=50");
  renderFeed();
}

// ── Master render ─────────────────────────────────────────────────────────────
function render() {
  const activeAlerts = S.alerts.filter(a => !a.acknowledged).length;
  $("#totalEvents").textContent       = S.summary.totalEvents;
  $("#uniqueAttackers").textContent   = S.summary.uniqueAttackers;
  $("#criticalAttackers").textContent = S.summary.criticalAttackers;
  $("#avgRisk").textContent           = `${S.summary.avgRisk}/100`;
  $("#totalAlerts").textContent       = activeAlerts;
  $("#totalBlocked").textContent      = S.blocked.length;
  $("#topTechnique").textContent      = S.summary.topTechnique;

  // Alert badge
  const badge = $("#alertBadge");
  badge.textContent = activeAlerts;
  badge.style.display = activeAlerts > 0 ? "inline-flex" : "none";

  // Pulse cards
  const critCard  = $("#criticalAttackers").closest(".stat-card");
  const alertCard = $("#totalAlerts").closest(".stat-card");
  critCard.classList.toggle("pulsing",      S.summary.criticalAttackers > 0);
  alertCard.classList.toggle("pulsing-warn", activeAlerts > 0);

  renderTimeline();
  renderSignals();
  renderOverviewAttackers();
  renderOverviewMitre();
  renderAlerts();
  renderAttackers();
  renderMitreBar();
  renderMitreHeat();
  renderTacticMatrix();
  renderIOCs();
  renderBlocked();
  renderEvents();
  if (currentTab === "worldmap")  renderWorldMap();
  if (currentTab === "killchain") renderKillChain();
}

// ── Timeline ──────────────────────────────────────────────────────────────────
function renderTimeline() {
  const cv = $("#timelineChart"), ctx = cv.getContext("2d");
  const W = cv.width, H = cv.height;
  ctx.clearRect(0, 0, W, H);
  const data = S.summary.timeline.length ? S.summary.timeline : [{date:"–",value:0}];
  const max  = Math.max(...data.map(d => d.value), 1), pad = 30;
  const step = data.length > 1 ? (W - pad*2) / (data.length - 1) : 0;

  // Grid
  ctx.strokeStyle = "rgba(255,255,255,.05)"; ctx.lineWidth = 0.5;
  for (let i = 0; i < 4; i++) {
    const y = pad + ((H - pad*2) / 3) * i;
    ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(W - pad, y); ctx.stroke();
  }
  const pts = data.map((d, i) => ({ x: pad + step*i, y: H - pad - (d.value/max)*(H - pad*2), d }));

  // Fill
  const g = ctx.createLinearGradient(0, pad, 0, H);
  g.addColorStop(0, "rgba(57,208,192,.22)"); g.addColorStop(1, "rgba(57,208,192,0)");
  ctx.beginPath(); pts.forEach((p, i) => i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y));
  ctx.lineTo(pts[pts.length-1].x, H); ctx.lineTo(pts[0].x, H);
  ctx.closePath(); ctx.fillStyle = g; ctx.fill();

  // Line
  ctx.beginPath(); pts.forEach((p, i) => i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y));
  ctx.strokeStyle = "#39d0c0"; ctx.lineWidth = 2; ctx.stroke();

  // Dots
  ctx.fillStyle = "#39d0c0";
  pts.forEach(p => { ctx.beginPath(); ctx.arc(p.x, p.y, 3, 0, Math.PI*2); ctx.fill(); });

  // Labels
  ctx.fillStyle = "rgba(125,133,144,.7)"; ctx.font = "11px system-ui";
  pts.forEach(p => ctx.fillText(p.d.date.slice(5), p.x - 14, H - 8));
}

// ── Signals ───────────────────────────────────────────────────────────────────
function renderSignals() {
  const rows = [
    ...S.summary.topCountries.map(d => ({...d})),
    ...S.summary.topUsernames.map(d => ({...d}))
  ].slice(0, 8);
  const max = Math.max(...rows.map(d => d.value), 1);
  $("#signalBars").innerHTML = rows.map(d => `
    <div class="bar-row">
      <span>${esc(d.name)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${(d.value/max)*100}%"></div></div>
      <span>${d.value}</span>
    </div>`).join("");
}

// ── Overview quick lists ──────────────────────────────────────────────────────
function renderOverviewAttackers() {
  $("#overviewAttackers").innerHTML = S.attackers.slice(0, 5).map(a => `
    <div class="ov-row" data-ip="${a.sourceIp}">
      <div class="ov-score ${a.aiProfile.risk.toLowerCase()}">${a.aiProfile.score}</div>
      <div class="ov-info"><b>${esc(a.sourceIp)}</b><small>${esc(a.country)} · ${esc(a.aiProfile.persona)}</small></div>
      <span class="risk ${a.aiProfile.risk.toLowerCase()}">${a.aiProfile.risk}</span>
    </div>`).join("");
  $$(".ov-row[data-ip]").forEach(r => r.addEventListener("click", () => { switchTab("attackers"); openDrawer(r.dataset.ip); }));
}

function renderOverviewMitre() {
  const data = S.summary.mitre.slice(0, 6);
  const max  = Math.max(...data.map(m => m.hits), 1);
  const C = MITRE_COLORS;
  $("#overviewMitre").innerHTML = data.map(m => {
    const c = C[m.tactic] || C.default;
    return `<div class="bar-row">
      <span style="color:${c};font-weight:700">${m.id}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${(m.hits/max)*100}%;background:${c}"></div></div>
      <span>${m.hits}</span>
    </div>`;
  }).join("");
}

// ── MITRE color map ───────────────────────────────────────────────────────────
const MITRE_COLORS = {
  "Credential Access":"#f85149","Defense Evasion":"#d29922",
  "Execution":"#58a6ff","Persistence":"#db6d28",
  "Command and Control":"#bc8cff","Impact":"#f85149",
  "Discovery":"#3fb950","default":"#39d0c0"
};

// ── Live feed ─────────────────────────────────────────────────────────────────
function renderFeed() {
  const TYPE_CLASS = {critical:"c", high:"h", medium:"m", warn:"m", info:"i"};
  if (!S.livefeed.length) {
    $("#feedList").innerHTML = `<div class="empty">No events yet. Click "+ Simulate" to generate activity.</div>`;
    return;
  }
  $("#feedList").innerHTML = `
    <div class="feed-head"><span>Time</span><span>Source</span><span>Event</span><span>Detail</span></div>` +
    S.livefeed.map(f => `
    <div class="feed-row ${TYPE_CLASS[f.type]||"i"}">
      <span class="feed-time">${fmtTime.format(new Date(f.timestamp))}</span>
      <span class="feed-ip">${esc(f.sourceIp)}<small>${esc(f.country)}</small></span>
      <span class="feed-label">${esc(f.label)}</span>
      <span class="feed-cmd"><code>${esc(f.detail)}</code></span>
    </div>`).join("");
}

// ── World map ─────────────────────────────────────────────────────────────────
function renderWorldMap() {
  const geo = S.geo;
  const max = Math.max(...geo.map(g => g.attacks), 1);
  $("#mapCount").textContent = `${geo.length} source${geo.length !== 1 ? "s" : ""}`;

  WorldMap.render($("#worldMapCanvas"), geo, g => showCountryPopup(g));

  $("#geoList").innerHTML = geo.slice(0, 14).map((g, i) => {
    const pct = Math.round((g.attacks / max) * 100);
    const c = i === 0 ? "#f85149" : i < 3 ? "#db6d28" : i < 6 ? "#d29922" : "#39d0c0";
    return `<div class="geo-item" data-country="${esc(g.country)}">
      <span class="geo-rank">${i+1}</span>
      <div><div class="geo-name">${esc(g.country)}</div><div class="geo-bar"><div class="geo-fill" style="width:${pct}%;background:${c}"></div></div></div>
      <span class="geo-count" style="color:${c}">${g.attacks}</span>
    </div>`;
  }).join("");

  $$(".geo-item").forEach(el => el.addEventListener("click", () => {
    const g = S.geo.find(x => x.country === el.dataset.country);
    if (g) showCountryPopup(g);
  }));
}

function showCountryPopup(g) {
  const attackers = S.attackers.filter(a => a.country === g.country);
  const techniques = [...new Set(attackers.flatMap(a => a.mitre.map(m => m.technique)))];
  const personas   = [...new Set(attackers.map(a => a.aiProfile.persona))];
  const topRisk    = attackers.reduce((m, a) => a.aiProfile.score > m ? a.aiProfile.score : m, 0);

  const PLAIN = {
    "Brute Force":"repeatedly guessing passwords",
    "Command and Scripting Interpreter":"running commands on the server",
    "Ingress Tool Transfer":"downloading malware from the internet",
    "Obfuscated Files or Information":"hiding commands to avoid detection",
    "Scheduled Task/Job":"installing malware to auto-start after reboot",
    "Resource Hijacking":"stealing CPU power to mine cryptocurrency",
    "Network Service Discovery":"scanning for other computers to attack",
    "Indicator Removal":"deleting logs to hide evidence",
    "Account Discovery":"checking what user accounts exist",
    "Masquerading":"disguising malware as normal system processes"
  };

  const techPlain = techniques.slice(0, 3).map(t => PLAIN[t] || t).join(", ");
  const danger = topRisk >= 70
    ? `<strong style="color:var(--red)">Very dangerous</strong> — full server takeover attempted.`
    : topRisk >= 40
    ? `<strong style="color:var(--amber)">Moderately dangerous</strong> — active probing with malicious intent.`
    : `<strong style="color:var(--green)">Low-level scanning</strong> — automated bots looking for easy targets.`;

  $("#countryDetail").innerHTML = `
    <div class="country-popup">
      <div class="country-popup-head">
        <div><div class="eyebrow">Attack origin</div><b style="font-size:1.1rem">${esc(g.country)}</b></div>
        <button class="close-btn" id="closeCountry">✕</button>
      </div>
      <div class="country-stats">
        <div class="cs-box"><b>${g.attacks}</b><span>Total attacks</span></div>
        <div class="cs-box"><b>${attackers.length}</b><span>Unique IPs</span></div>
        <div class="cs-box"><b style="color:var(--red)">${topRisk}</b><span>Highest risk</span></div>
      </div>
      <div class="eyebrow" style="margin-bottom:6px">What were they doing?</div>
      <p class="country-plain">${techPlain ? `Attackers from ${esc(g.country)} were caught <strong>${techPlain}</strong>. ` : `Attackers were scanning for weak SSH passwords. `}${danger}</p>
      <div class="eyebrow" style="margin:10px 0 6px">Attacker types</div>
      <div style="margin-bottom:10px">${personas.map(p => `<span class="tag">${esc(p)}</span>`).join("")}</div>
      <div class="eyebrow" style="margin-bottom:6px">Click an IP to view full profile</div>
      ${attackers.map(a => `
        <div class="country-ip-row" data-ip="${a.sourceIp}">
          <span class="risk ${a.aiProfile.risk.toLowerCase()}">${a.aiProfile.risk}</span>
          <b>${esc(a.sourceIp)}</b>
          <span class="ml-auto text-muted">${a.aiProfile.score}/100 · ${a.eventCount} events</span>
        </div>`).join("") || "<p class='text-muted'>No detailed profiles.</p>"}
    </div>`;

  $("#closeCountry").addEventListener("click", () => { $("#countryDetail").innerHTML = ""; });
  $$(".country-ip-row[data-ip]").forEach(r => r.addEventListener("click", () => {
    $("#countryDetail").innerHTML = "";
    openDrawer(r.dataset.ip);
  }));
}

// ── Alerts ────────────────────────────────────────────────────────────────────
function renderAlerts() {
  const active = S.alerts.filter(a => !a.acknowledged);
  const acked  = S.alerts.filter(a => a.acknowledged);

  if (!active.length) {
    $("#alertList").innerHTML = `<div class="empty">✓ No active alerts</div>`;
  } else {
    $("#alertList").innerHTML = active.map(a => `
      <div class="alert-item ${a.severity}">
        <span class="alert-sev ${a.severity}">${a.severity.toUpperCase()}</span>
        <div class="alert-body">
          <b>${esc(a.name)}</b>
          <div class="text-muted">${esc(a.sourceIp)} · ${esc(a.country)} · Risk ${a.riskScore}/100</div>
          <div class="alert-action-text">→ ${esc(a.action)}</div>
        </div>
        <button class="ack-btn" data-id="${a.id}">✓ Acknowledge</button>
      </div>`).join("");
    $$(".ack-btn").forEach(b => b.addEventListener("click", async () => {
      await api(`/api/alerts/${b.dataset.id}/ack`, {method:"PATCH"});
      await load();
    }));
  }

  if (!acked.length) {
    $("#ackedList").innerHTML = `<div class="empty">No acknowledged alerts yet.</div>`;
  } else {
    $("#ackedList").innerHTML = acked.map(a => `
      <div class="acked-item">
        <span class="check">✓</span>
        <span class="risk ${a.severity}">${a.severity}</span>
        <b>${esc(a.name)}</b>
        <span class="text-muted" style="margin-left:8px">${esc(a.sourceIp)} · ${esc(a.country)}</span>
      </div>`).join("");
  }
}

// ── Attackers ─────────────────────────────────────────────────────────────────
function renderAttackers() {
  const q = S.filter.trim().toLowerCase();
  const blockedSet = new Set(S.blocked.map(b => b.ip));
  const list = S.attackers.filter(a =>
    [a.sourceIp, a.country, a.aiProfile.persona, a.aiProfile.objective].join(" ").toLowerCase().includes(q)
  );

  if (!list.length) {
    $("#attackerGrid").innerHTML = `<div class="empty" style="grid-column:1/-1">No attackers match your search.</div>`;
    return;
  }

  $("#attackerGrid").innerHTML = list.map(a => {
    const rc = a.aiProfile.risk.toLowerCase();
    const isBlocked = blockedSet.has(a.sourceIp);
    const mitre = a.mitre.slice(0, 3).map(m => `<span class="mc">${m.id}</span>`).join("");
    return `<div class="acard${isBlocked ? " blocked" : ""}" data-ip="${a.sourceIp}">
      <div class="acard-top">
        <div>
          <div class="acard-ip">${esc(a.sourceIp)}${isBlocked ? `<span class="blocked-chip">BLOCKED</span>` : ""}</div>
          <div class="acard-meta">${esc(a.country)} · ${a.eventCount} events</div>
        </div>
        <span class="risk ${rc}">${a.aiProfile.risk}</span>
      </div>
      <div class="acard-profile">
        <div class="score-ring" style="--s:${a.aiProfile.score}">${a.aiProfile.score}</div>
        <div>
          <div class="acard-persona">${esc(a.aiProfile.persona)}</div>
          <div class="acard-obj">${esc(a.aiProfile.objective)}</div>
          <div class="conf-bar">
            <span class="conf-fill" style="width:${a.aiProfile.confidence}%"></span>
            <span class="conf-label">${a.aiProfile.confidence}% confidence</span>
          </div>
        </div>
      </div>
      <div class="mitre-chips">${mitre || '<span class="tag">No mapping</span>'}</div>
    </div>`;
  }).join("");

  $$(".acard").forEach(c => c.addEventListener("click", () => openDrawer(c.dataset.ip)));
}

// ── Kill Chain ────────────────────────────────────────────────────────────────
function renderKillChain() {
  if (!S.killchain.length) { $("#killChain").innerHTML = `<div class="empty">No data yet.</div>`; return; }
  $("#killChain").innerHTML = S.killchain.map(p => `
    <div class="kc-card${p.active ? " active" : ""}">
      <div class="kc-icon">${p.icon}</div>
      <div class="kc-phase">${esc(p.phase)}</div>
      <div class="kc-desc">${esc(p.desc)}</div>
      <span class="kc-hits${p.active ? " active" : " inactive"}">${p.active ? `${p.hits} hit${p.hits===1?"":"s"} detected` : "Not observed"}</span>
    </div>`).join("");
}

// ── MITRE bar ─────────────────────────────────────────────────────────────────
function renderMitreBar() {
  const data = S.summary.mitre.slice(0, 10);
  if (!data.length) { $("#mitreBar").innerHTML = `<div class="empty">No data yet.</div>`; return; }
  const max = Math.max(...data.map(m => m.hits), 1);
  $("#mitreBar").innerHTML = data.map(m => {
    const c = MITRE_COLORS[m.tactic] || MITRE_COLORS.default;
    return `<div class="mitre-bar-row">
      <span class="mitre-id" style="color:${c}">${m.id}</span>
      <span class="mitre-name">${esc(m.technique)}</span>
      <div class="mitre-track"><div class="mitre-fill" style="width:${Math.round((m.hits/max)*100)}%;background:${c}"></div></div>
      <span class="mitre-hits">${m.hits} hit${m.hits===1?"":"s"}</span>
      <span class="mitre-tactic" style="color:${c}">${esc(m.tactic)}</span>
    </div>`;
  }).join("");
}

// ── MITRE heatmap ─────────────────────────────────────────────────────────────
function renderMitreHeat() {
  const rules = [
    {id:"T1110",tactic:"Credential Access",  technique:"Brute Force"},
    {id:"T1087",tactic:"Discovery",          technique:"Account Discovery"},
    {id:"T1059",tactic:"Execution",          technique:"Cmd Interpreter"},
    {id:"T1105",tactic:"Command and Control",technique:"Tool Transfer"},
    {id:"T1027",tactic:"Defense Evasion",    technique:"Obfuscation"},
    {id:"T1036",tactic:"Defense Evasion",    technique:"Masquerading"},
    {id:"T1053",tactic:"Persistence",        technique:"Scheduled Task"},
    {id:"T1496",tactic:"Impact",             technique:"Resource Hijack"},
    {id:"T1046",tactic:"Discovery",          technique:"Net Discovery"},
    {id:"T1070",tactic:"Defense Evasion",    technique:"Log Removal"}
  ];
  const hitMap = new Map(S.summary.mitre.map(m => [m.id, m]));
  $("#mitreHeat").innerHTML = rules.map(r => {
    const h = hitMap.get(r.id);
    const c = MITRE_COLORS[r.tactic] || MITRE_COLORS.default;
    const bg = h ? `${c}22` : "rgba(255,255,255,.02)";
    const border = h ? `${c}44` : "rgba(255,255,255,.07)";
    return `<div class="heat-tile" style="background:${bg};border-color:${border}" title="${r.tactic}${h?" · "+h.hits+" hits":""}">
      <b style="${h?`color:${c}`:"color:var(--muted)"}">${r.id}</b>
      <small>${esc(r.technique)}</small>
      <span class="hits" style="${h?`color:${c}`:"color:var(--muted)"}">${h ? h.hits : "–"}</span>
    </div>`;
  }).join("");
}

// ── Tactic matrix ─────────────────────────────────────────────────────────────
function renderTacticMatrix() {
  if (!S.tactics.length) { $("#tacticMatrix").innerHTML = `<div class="empty">No data yet.</div>`; return; }
  $("#tacticMatrix").innerHTML = S.tactics.map(t => `
    <div class="tactic-row">
      <span class="tactic-name">${esc(t.tactic)}</span>
      <div class="tactic-chips-wrap">${t.techniques.map(x => `<span class="tc" title="${esc(x.technique)}">${x.id}</span>`).join("")}</div>
      <span class="tactic-score">${t.totalScore}</span>
    </div>`).join("");
}

// ── IOCs ──────────────────────────────────────────────────────────────────────
function renderIOCs() {
  const {urls=[],ips=[],files=[],domains=[],hashes=[]} = S.iocs;
  const sec = (label, items, cls) => !items.length ? "" : `
    <div class="ioc-section">
      <div class="ioc-label">${label} <span class="ioc-count">${items.length}</span></div>
      <div class="ioc-chips">${items.map(v => `<span class="ioc-chip ${cls}">${esc(v)}</span>`).join("")}</div>
    </div>`;
  const html = [sec("URLs",urls,"ioc-url"), sec("External IPs",ips,"ioc-ip"), sec("Domains",domains,"ioc-domain"), sec("File paths",files,"ioc-file"), sec("Hashes",hashes,"ioc-hash")].filter(Boolean).join("");
  $("#iocPanel").innerHTML = html || `<div class="empty">No IOCs yet. Simulate events to populate.</div>`;
}

// ── Blocked ───────────────────────────────────────────────────────────────────
function renderBlocked() {
  if (!S.blocked.length) {
    $("#blockedList").innerHTML = `<div class="empty">No IPs blocked yet. Open an attacker card → "Block this IP".</div>`;
    return;
  }
  $("#blockedList").innerHTML = `<div class="table-wrap"><table>
    <thead><tr><th>IP</th><th>Country</th><th>Persona</th><th>Risk</th><th>Blocked at</th><th></th></tr></thead>
    <tbody>${S.blocked.map(b => `<tr>
      <td><b>${esc(b.ip)}</b></td>
      <td>${esc(b.country)}</td>
      <td>${esc(b.persona)}</td>
      <td>${b.riskScore}</td>
      <td>${fmt.format(new Date(b.blockedAt))}</td>
      <td><button class="unblock-btn-sm" data-ip="${b.ip}">Unblock</button></td>
    </tr>`).join("")}</tbody>
  </table></div>`;
  $$(".unblock-btn-sm").forEach(b => b.addEventListener("click", async () => {
    await api(`/api/block/${encodeURIComponent(b.dataset.ip)}`, {method:"DELETE"});
    await load();
  }));
}

// ── Events ────────────────────────────────────────────────────────────────────
function renderEvents() {
  $("#eventsBody").innerHTML = S.events.map(ev => `<tr>
    <td>${fmt.format(new Date(ev.timestamp))}</td>
    <td><b>${esc(ev.sourceIp)}</b><br><small class="text-muted">${esc(ev.country)}</small></td>
    <td>${esc(ev.eventType)}</td>
    <td><code>${esc(ev.username||"–")}:${esc(ev.password||"–")}</code></td>
    <td><code>${esc(ev.command||ev.message||"–")}</code></td>
  </tr>`).join("");
}

// ── Drawer ────────────────────────────────────────────────────────────────────
async function openDrawer(ip) {
  S.drawerIp = ip;
  S.drawerTab = "profile";
  $$(".dtab").forEach(t => t.classList.toggle("active", t.dataset.dtab === "profile"));

  const [d, analysis, session] = await Promise.all([
    api(`/api/attackers/${encodeURIComponent(ip)}`),
    api(`/api/attackers/${encodeURIComponent(ip)}/analysis`),
    api(`/api/attackers/${encodeURIComponent(ip)}/session`)
  ]);
  S.drawerData = {d, analysis, session};
  $("#drawerIp").textContent = ip;

  $("#drawer").classList.remove("hidden");
  $("#overlay").classList.remove("hidden");
  renderDrawerTab();
}

function closeDrawer() {
  $("#drawer").classList.add("hidden");
  $("#overlay").classList.add("hidden");
}

function renderDrawerTab() {
  const {d, analysis, session} = S.drawerData;
  const isBlocked = S.blocked.some(b => b.ip === d.sourceIp);
  const rc = d.aiProfile.risk.toLowerCase();
  const riskColor = {critical:"var(--red)",high:"var(--orange)",medium:"var(--amber)",low:"var(--green)"}[rc] || "var(--muted)";

  if (S.drawerTab === "profile") {
    const breakdown = (d.aiProfile.breakdown || []).map(b =>
      `<div class="sbrow"><span>${esc(b.label)}</span><span class="sbpts">+${b.points}</span><small>${esc(b.detail)}</small></div>`
    ).join("");

    $("#drawerBody").innerHTML = `
      <div class="ai-card">
        <div class="ai-head">
          <span class="ai-tag">🤖 AI Analyst</span>
          <span class="ai-risk" style="color:${riskColor}">${d.aiProfile.risk} · ${d.aiProfile.score}/100</span>
        </div>
        <p class="ai-text">${esc(analysis.narrative)}</p>
        <div class="ai-findings">${(analysis.keyFindings||[]).map(f => `<span class="ai-finding">${esc(f)}</span>`).join("")}</div>
        <div class="eyebrow" style="margin-bottom:6px">Recommended actions</div>
        ${(analysis.recommendedActions||[]).map(a => `<p class="ai-action">→ ${esc(a)}</p>`).join("")}
      </div>

      <div class="dblock">
        <h4>Why risk = ${d.aiProfile.score}/100</h4>
        <div class="score-breakdown">${breakdown || "<p class='text-muted'>No scoring factors detected.</p>"}</div>
        ${breakdown ? `<div class="score-total">Total: ${d.aiProfile.score} / 100</div>` : ""}
      </div>

      <div class="dblock">
        <h4>Profile</h4>
        <div class="profile-grid">
          <div class="pi"><span>IP Address</span><strong>${esc(d.sourceIp)}</strong></div>
          <div class="pi"><span>Country</span><strong>${esc(d.country)}</strong></div>
          <div class="pi"><span>Risk score</span><strong style="color:${riskColor}">${d.aiProfile.score}/100</strong></div>
          <div class="pi"><span>Confidence</span><strong>${d.aiProfile.confidence}%</strong></div>
          <div class="pi"><span>Total events</span><strong>${d.eventCount}</strong></div>
          <div class="pi"><span>Sessions</span><strong>${d.sessions}</strong></div>
          <div class="pi"><span>Commands run</span><strong>${d.commandCount}</strong></div>
          <div class="pi"><span>Persona</span><strong>${esc(d.aiProfile.persona)}</strong></div>
        </div>
      </div>

      <div class="dblock">
        <h4>MITRE ATT&amp;CK</h4>
        <div>${d.mitre.map(m => `<span class="mtag"><b>${m.id}</b>${esc(m.technique)}<em>${m.hits}×</em></span>`).join("") || "<p class='text-muted'>None mapped.</p>"}</div>
      </div>

      <div class="dblock">
        <button class="${isBlocked ? "unblock-btn-sm" : "block-btn"}" id="blockToggleBtn" data-ip="${d.sourceIp}">
          ${isBlocked ? "✓ Unblock this IP" : "🚫 Block this IP"}
        </button>
      </div>`;

    const btn = $("#blockToggleBtn");
    btn.addEventListener("click", async () => {
      const ip = btn.dataset.ip;
      if (isBlocked) {
        await api(`/api/block/${encodeURIComponent(ip)}`, {method:"DELETE"});
      } else {
        await api(`/api/block/${encodeURIComponent(ip)}`, {method:"POST"});
      }
      closeDrawer();
      await load();
    });
  }

  else if (S.drawerTab === "session") {
    const DANGER_COLOR = {critical:"var(--red)",high:"var(--orange)",medium:"var(--amber)",low:"var(--muted)"};
    const steps = session.timeline || [];
    if (!steps.length) { $("#drawerBody").innerHTML = `<div class="empty">No session data for this IP.</div>`; return; }
    $("#drawerBody").innerHTML = `
      <div class="dblock" style="margin-bottom:0">
        <h4>Session replay — ${steps.length} steps</h4>
        ${steps.map((s, i) => `
          <div class="session-line-wrap">
            <div class="session-dot-col">
              <div class="sdot" style="background:${DANGER_COLOR[s.danger]||"var(--muted)"}"></div>
              ${i < steps.length-1 ? '<div class="sline"></div>' : ""}
            </div>
            <div class="session-content">
              <div class="stime">${fmtTime.format(new Date(s.timestamp))} · <span style="color:${DANGER_COLOR[s.danger]||"var(--muted)"}font-weight:700">${esc(s.label)}</span></div>
              <b>${esc(s.action)}</b>
            </div>
          </div>`).join("")}
      </div>`;
  }

  else if (S.drawerTab === "commands") {
    const CMD_MAP = {wget:"Payload Download",curl:"Payload Download",chmod:"File Prep",crontab:"Persistence",xmrig:"Cryptomining",stratum:"Cryptomining",nmap:"Recon Scan",whoami:"Privilege Check",uname:"System Info","history -c":"Cover Tracks","unset HISTFILE":"Cover Tracks",base64:"Obfuscated Cmd",bash:"Shell Spawned"};
    const DANGER_LABELS = ["Payload Download","Persistence","Cryptomining","Cover Tracks"];
    const HIGH_LABELS   = ["Obfuscated Cmd","File Prep"];

    const cmds = d.topCommands;
    if (!cmds.length) { $("#drawerBody").innerHTML = `<div class="empty">No commands captured for this IP.</div>`; return; }

    const rows = cmds.map(cmd => {
      const lower = cmd.toLowerCase();
      const label = Object.entries(CMD_MAP).find(([k]) => lower.includes(k))?.[1] || "Command Execution";
      const c = DANGER_LABELS.includes(label) ? "var(--red)" : HIGH_LABELS.includes(label) ? "var(--orange)" : "var(--amber)";
      return `<div class="cmd-table-row">
        <div><code>${esc(cmd)}</code></div>
        <div style="color:${c};font-weight:700">● ${label}</div>
      </div>`;
    }).join("");

    const creds = d.credentialsTried.map(c => {
      const [u,p] = c.split(":");
      return `<div class="cred-row"><span class="cu">${esc(u)}</span><span class="cs">:</span><span class="cp">${esc(p)}</span></div>`;
    }).join("") || "<p class='text-muted'>None recorded.</p>";

    $("#drawerBody").innerHTML = `
      <div class="dblock">
        <h4>Command analysis — what the attacker ran</h4>
        <div class="cmd-table">
          <div class="cmd-table-head"><span>Command</span><span>Classification</span></div>
          ${rows}
        </div>
      </div>
      <div class="dblock">
        <h4>Credentials tried (${d.credentialsTried.length})</h4>
        <div class="cred-list">${creds}</div>
      </div>`;
  }
}

// ── PDF export ────────────────────────────────────────────────────────────────
function exportPDF() {
  const summary  = S.summary;
  const profiles = S.attackers.slice(0, 5);
  const alerts   = S.alerts.filter(a => !a.acknowledged);
  const iocs     = S.iocs;

  const html = `<!DOCTYPE html><html><head><meta charset="utf-8">
  <style>
    body{font-family:Arial,sans-serif;font-size:12px;color:#1a1a1a;margin:0;padding:24px;}
    h1{font-size:22px;margin-bottom:4px;} h2{font-size:15px;border-bottom:2px solid #39d0c0;padding-bottom:4px;margin:18px 0 8px;}
    h3{font-size:13px;margin:12px 0 4px;} .row{display:flex;gap:16px;margin-bottom:16px;}
    .stat{flex:1;padding:10px;border:1px solid #ddd;border-radius:6px;text-align:center;}
    .stat b{display:block;font-size:20px;} .stat small{color:#666;font-size:10px;}
    .alert{padding:8px 10px;margin-bottom:5px;border-left:3px solid #e74c3c;background:#fff5f5;font-size:11px;}
    .alert.high{border-color:#e67e22;background:#fff9f0;} .alert.medium{border-color:#f39c12;background:#fffdf0;}
    table{width:100%;border-collapse:collapse;margin-bottom:12px;font-size:11px;}
    th{background:#f5f5f5;padding:6px 8px;text-align:left;border-bottom:1px solid #ddd;}
    td{padding:6px 8px;border-bottom:1px solid #eee;} .chip{padding:2px 6px;border-radius:3px;font-size:10px;background:#e8f5f4;color:#1a7a72;}
    .ioc{padding:2px 6px;border-radius:3px;font-size:10px;background:#f5f5f5;margin:2px;display:inline-block;font-family:monospace;}
    footer{margin-top:30px;padding-top:10px;border-top:1px solid #ddd;font-size:10px;color:#999;text-align:center;}
  </style></head><body>
  <h1>🍯 HoneyTrace AI — Threat Report</h1>
  <p style="color:#666">Generated: ${new Date().toLocaleString()}</p>
  <h2>Executive Summary</h2>
  <div class="row">
    <div class="stat"><b>${summary.totalEvents}</b><small>Total Events</small></div>
    <div class="stat"><b>${summary.uniqueAttackers}</b><small>Unique Attackers</small></div>
    <div class="stat"><b style="color:#e74c3c">${summary.criticalAttackers}</b><small>Critical Actors</small></div>
    <div class="stat"><b>${summary.avgRisk}/100</b><small>Avg Risk Score</small></div>
    <div class="stat"><b style="color:#e67e22">${alerts.length}</b><small>Active Alerts</small></div>
  </div>
  <h2>Active Alerts</h2>
  ${alerts.length ? alerts.map(a => `<div class="alert ${a.severity}"><b>[${a.severity.toUpperCase()}] ${a.name}</b> · ${a.sourceIp} (${a.country}) · Score: ${a.riskScore}<br><small>Action: ${a.action}</small></div>`).join("") : "<p>No active alerts.</p>"}
  <h2>Top Attackers</h2>
  <table><thead><tr><th>IP</th><th>Country</th><th>Persona</th><th>Risk</th><th>Score</th><th>Top MITRE</th></tr></thead><tbody>
  ${profiles.map(p => `<tr><td><b>${p.sourceIp}</b></td><td>${p.country}</td><td>${p.aiProfile.persona}</td><td>${p.aiProfile.risk}</td><td>${p.aiProfile.score}/100</td><td>${p.mitre.slice(0,2).map(m=>`<span class="chip">${m.id}</span>`).join(" ")}</td></tr>`).join("")}
  </tbody></table>
  <h2>Indicators of Compromise</h2>
  ${(iocs.urls||[]).length ? `<b>URLs:</b><br>${(iocs.urls||[]).map(v=>`<span class="ioc">${v}</span>`).join("")}<br><br>` : ""}
  ${(iocs.ips||[]).length  ? `<b>IPs:</b><br>${(iocs.ips||[]).map(v=>`<span class="ioc">${v}</span>`).join("")}<br><br>` : ""}
  ${(iocs.files||[]).length? `<b>Files:</b><br>${(iocs.files||[]).map(v=>`<span class="ioc">${v}</span>`).join("")}` : ""}
  <h2>MITRE ATT&CK Coverage</h2>
  <table><thead><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Hits</th></tr></thead><tbody>
  ${summary.mitre.map(m=>`<tr><td><b>${m.id}</b></td><td>${m.technique}</td><td>${m.tactic}</td><td>${m.hits}</td></tr>`).join("")}
  </tbody></table>
  <footer>HoneyTrace AI · SSH Threat Monitor · ${new Date().toLocaleDateString()}</footer>
  </body></html>`;

  const blob = new Blob([html], {type:"text/html"});
  const url  = URL.createObjectURL(blob);
  const win  = window.open(url, "_blank");
  setTimeout(() => { if (win) win.print(); }, 800);
}

// ── SSE ───────────────────────────────────────────────────────────────────────
function connectSSE() {
  const es = new EventSource("/api/stream");
  es.addEventListener("events", () => $("#liveBar").classList.remove("hidden"));
  es.addEventListener("reset",  () => { load(); });
  es.addEventListener("blocked",() => { load(); });
  es.onerror = () => setTimeout(connectSSE, 5000);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function esc(v) {
  return String(v ?? "")
    .replaceAll("&","&amp;").replaceAll("<","&lt;")
    .replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;");
}

// ── Button handlers ───────────────────────────────────────────────────────────
$$(".nav-link").forEach(a => a.addEventListener("click", e => { e.preventDefault(); switchTab(a.dataset.tab); }));

$("#simulateBtn").addEventListener("click", async () => {
  $("#simulateBtn").disabled = true;
  await api("/api/simulate?count=10", {method:"POST"});
  await load();
  if (currentTab === "livefeed") await loadFeed();
  $("#simulateBtn").disabled = false;
});

$("#resetBtn").addEventListener("click", async () => {
  if (!confirm("Reset all events to clean seed data?")) return;
  await api("/api/reset", {method:"POST"});
  await load();
  $("#liveBar").classList.add("hidden");
});

$("#reportBtn").addEventListener("click", () => window.open("/api/report", "_blank", "noopener"));
$("#csvBtn").addEventListener("click",    () => window.open("/api/export/csv", "_blank", "noopener"));
$("#pdfBtn").addEventListener("click",    () => exportPDF());
$("#refreshBtn").addEventListener("click", async () => { await load(); $("#liveBar").classList.add("hidden"); });
$("#refreshFeedBtn")?.addEventListener("click", loadFeed);

$("#importBtn").addEventListener("click", async () => {
  const input = $("#cowrieInput").value.trim();
  const msg = $("#importMsg");
  if (!input) { msg.textContent = "Paste JSONL first."; msg.className = "import-msg err"; return; }
  try {
    const r = await api("/api/import/cowrie", {method:"POST", headers:{"Content-Type":"application/json"}, body:input});
    $("#cowrieInput").value = "";
    msg.textContent = `✓ Imported ${r.imported} event${r.imported===1?"":"s"} successfully.`;
    msg.className = "import-msg ok";
    await load();
  } catch { msg.textContent = "✗ Import failed — check JSON format."; msg.className = "import-msg err"; }
});

$("#clearImport").addEventListener("click", () => { $("#cowrieInput").value = ""; $("#importMsg").textContent = ""; });

$("#copyIOCsBtn").addEventListener("click", () => {
  const {urls=[],ips=[],domains=[],files=[],hashes=[]} = S.iocs;
  navigator.clipboard.writeText([...urls,...ips,...domains,...files,...hashes].join("\n"))
    .then(() => { $("#copyIOCsBtn").textContent = "Copied!"; setTimeout(() => $("#copyIOCsBtn").textContent = "Copy all", 2000); });
});

$("#searchInput").addEventListener("input", e => { S.filter = e.target.value; renderAttackers(); });

document.addEventListener("click", e => {
  if (e.target.id === "goAttackers") switchTab("attackers");
  if (e.target.id === "goMitre")     switchTab("mitre");
});

$$(".dtab").forEach(t => t.addEventListener("click", () => {
  S.drawerTab = t.dataset.dtab;
  $$(".dtab").forEach(x => x.classList.toggle("active", x === t));
  renderDrawerTab();
}));

$("#closeDrawer").addEventListener("click", closeDrawer);
$("#overlay").addEventListener("click", closeDrawer);
document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });

// ── Boot ──────────────────────────────────────────────────────────────────────
connectSSE();
const initTab = location.hash.replace("#","") || "overview";
if (TITLES[initTab]) switchTab(initTab);

load().catch(err => {
  document.body.innerHTML = `<div style="padding:40px;font-family:sans-serif">
    <h2>Failed to load</h2><p style="color:#888">${esc(err.message)}</p>
    <p>Make sure <code>node server.js</code> is running on port 3000.</p></div>`;
});
