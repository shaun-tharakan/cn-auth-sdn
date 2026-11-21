(() => {
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const fmt = (t) => t ? new Date(t * 1000).toLocaleTimeString([], {hour12: false}) : "-";
  const badge = (cls, text) => `<span class="badge b-${cls}">${esc(text)}</span>`;
  const seen = {};           // section -> {rowKey: signature}; used to flash new/changed rows
  let category = "";
  let overviewState = [], accessState = [];

  async function get(url) {
    try {
      const r = await fetch(url, {cache: "no-store"});
      if (!r.ok) throw new Error("HTTP " + r.status);
      return await r.json();
    } catch (e) { return {available: false, error: "dashboard backend unreachable: " + e.message}; }
  }

  function table(section, cols, rows, keyFn) {
    const prev = seen[section] || {}, now = {};
    const body = rows.map((r) => {
      const key = keyFn(r), sig = JSON.stringify(r);
      now[key] = sig;
      const cls = prev[key] !== sig && Object.keys(prev).length ? ' class="fresh"' : "";
      return `<tr${cls}>` + cols.map((c) => `<td class="${c.mono ? "mono" : ""}">${c.cell(r)}</td>`).join("") + "</tr>";
    }).join("");
    seen[section] = now;
    return `<table><thead><tr>${cols.map((c) => `<th>${c.h}</th>`).join("")}</tr></thead><tbody>${body}</tbody></table>`;
  }
  const stateBadge = (s) => ({running: "allow", stopped: "deny", disconnected: "warn"}[s] || "off");

  function renderOverview(d) {
    if (!d.components) return;
    overviewState = d.components;
    $("cards").innerHTML = d.components.map((c) =>
      `<div class="card ${esc(c.state)}"><h3>${esc(c.name)}</h3><div class="st">${esc(c.state)}</div><p>${esc(c.detail)}</p></div>`).join("");
    renderTopo();
  }

  function renderTopo() {
    const hosts = [{name: "h1", y: 36, swY: 63}, {name: "h2", y: 90, swY: 63}, {name: "h3", y: 162, swY: 162}];
    const st = (h) => { const a = accessState.find((x) => x.host === h); return a ? a.state : "unknown"; };
    const color = (s) => s === "granted" ? "var(--allow)" : (s === "denied" || s === "blocked") ? "var(--deny)" : "var(--off)";
    const comp = (k) => (overviewState.find((c) => c.key === k) || {}).state || "unknown";
    const swc = comp("switch") === "running" ? "var(--accent)" : "var(--off)";
    const svc = comp("service") === "running" ? "var(--allow)" : "var(--off)";
    const s2Grant = st("h1") === "granted" || st("h2") === "granted";
    const s3Grant = st("h3") === "granted";
    let g = "";
    hosts.forEach((h) => {
      const s = st(h.name);
      g += `<line x1="92" y1="${h.y}" x2="180" y2="${h.swY}" stroke="${color(s)}" stroke-width="2.5" ${s === "granted" ? "" : 'stroke-dasharray="5 5"'}/>`;
      g += `<rect x="14" y="${h.y - 17}" width="78" height="34" rx="8" fill="var(--raised)" stroke="${color(s)}"/><text x="53" y="${h.y + 5}" text-anchor="middle" fill="var(--text)" font-size="13" font-family="monospace">${h.name}</text>`;
    });
    g += `<line x1="244" y1="63" x2="332" y2="108" stroke="${s2Grant ? "var(--allow)" : swc}" stroke-width="2.5"/>`;
    g += `<line x1="244" y1="162" x2="332" y2="108" stroke="${s3Grant ? "var(--allow)" : swc}" stroke-width="2.5"/>`;
    g += `<rect x="180" y="39" width="64" height="48" rx="10" fill="var(--raised)" stroke="${swc}"/><text x="212" y="68" text-anchor="middle" fill="var(--text)" font-size="13" font-family="monospace">s2</text>`;
    g += `<rect x="180" y="138" width="64" height="48" rx="10" fill="var(--raised)" stroke="${swc}"/><text x="212" y="167" text-anchor="middle" fill="var(--text)" font-size="13" font-family="monospace">s3</text>`;
    g += `<line x1="396" y1="108" x2="464" y2="108" stroke="${svc}" stroke-width="2.5"/>`;
    g += `<rect x="332" y="84" width="64" height="48" rx="10" fill="var(--raised)" stroke="${swc}"/><text x="364" y="113" text-anchor="middle" fill="var(--text)" font-size="13" font-family="monospace">s1</text>`;
    g += `<rect x="464" y="80" width="90" height="56" rx="10" fill="var(--raised)" stroke="${svc}"/><text x="509" y="104" text-anchor="middle" fill="var(--text)" font-size="13">srv</text><text x="509" y="122" text-anchor="middle" fill="var(--muted)" font-size="11">:9000</text>`;
    $("topo").innerHTML = `<svg viewBox="0 0 570 216" role="img">${g}</svg>`;
  }

  function renderAuth(d) {
    const el = $("auth-body");
    if (!d.events || !d.events.length) { el.innerHTML = '<div class="empty">No sign-in attempts recorded yet.</div>'; return; }
    el.innerHTML = table("auth", [
      {h: "Time", cell: (r) => fmt(r.ts), mono: 1},
      {h: "User", cell: (r) => esc(r.username)},
      {h: "Result", cell: (r) => r.event === "login_success" ? badge("allow", "success") : badge("deny", "failure")},
      {h: "Host", cell: (r) => esc(r.host || "unregistered") + ` <span class="muted mono">${esc(r.client_ip)}</span>`},
      {h: "Detail", cell: (r) => esc(r.reason || "")},
    ], d.events, (r) => r.ts + r.username + r.event);
  }

  function renderSessions(d) {
    const el = $("sessions-body");
    if (!d.available) { el.innerHTML = `<div class="err">Session data unavailable: ${esc(d.error)}</div>`; return; }
    if (!d.sessions.length) { el.innerHTML = '<div class="empty">No sessions yet. Log in from a Mininet host to create one.</div>'; return; }
    const sb = {active: "allow", expired: "warn", logged_out: "off", revoked: "deny"};
    el.innerHTML = table("sessions", [
      {h: "User", cell: (r) => esc(r.username) + ` <span class="muted">(${esc(r.role)})</span>`},
      {h: "Host", cell: (r) => esc(r.host || "unregistered")},
      {h: "Status", cell: (r) => badge(sb[r.status] || "off", r.status.replace("_", " "))},
      {h: "Created", cell: (r) => fmt(r.created_at), mono: 1},
      {h: "Expires", cell: (r) => fmt(r.expires_at) + (r.status === "active" ? ` <span class="muted">(${r.seconds_remaining}s)</span>` : ""), mono: 1},
      {h: "Authorized service", cell: (r) => r.services.length ? esc(r.services.join(", ")) : '<span class="muted">none</span>'},
      {h: "Why it ended", cell: (r) => esc(r.end_reason || "") + (r.revocation === "pending" ? " " + badge("warn", "revocation pending") : "")},
    ], d.sessions, (r) => r.ref);
  }

  function renderAccess(d) {
    const el = $("access-body");
    if (!d.available) { accessState = []; el.innerHTML = `<div class="err">Access data unavailable: ${esc(d.error)}</div>`; renderTopo(); return; }
    accessState = d.access;
    el.innerHTML = table("access", [
      {h: "Host", cell: (r) => esc(r.host)},
      {h: "Protected service", cell: (r) => esc(r.service)},
      {h: "State", cell: (r) => r.state === "granted" ? badge("allow", "granted") : badge("deny", "denied")},
      {h: "Reason", cell: (r) => esc(r.reason)},
      {h: "Last policy change", cell: (r) => fmt(r.changed_at), mono: 1},
    ], d.access, (r) => r.host + r.service);
    renderTopo();
  }

  function renderFlows(d) {
    const el = $("flows-body"), meta = $("flows-meta");
    if (!d.available) { meta.textContent = ""; el.innerHTML = `<div class="err">Flow table unavailable: ${esc(d.error)}</div>`; return; }
    meta.innerHTML = d.stale ? `<span class="stale">stale: read ${d.age_seconds}s ago</span>` : `read from the switch ${d.age_seconds}s ago`;
    const kb = {grant: "allow", "default-deny": "deny", "l2-forward": "info", "table-miss": "off"};
    el.innerHTML = table("flows", [
      {h: "Priority", cell: (r) => r.priority, mono: 1},
      {h: "Kind", cell: (r) => badge(kb[r.kind] || "off", r.kind)},
      {h: "Match", cell: (r) => esc(r.match_text), mono: 1},
      {h: "Actions", cell: (r) => esc(r.actions.join(", ")), mono: 1},
      {h: "Packets", cell: (r) => r.packets, mono: 1},
      {h: "Age", cell: (r) => r.age_seconds + "s" + (r.hard_timeout ? ` / ${r.hard_timeout}s` : ""), mono: 1},
    ], d.flows, (r) => r.priority + r.match_text);
  }

  function renderEvents(d) {
    const el = $("events-body");
    if (!d.events || !d.events.length) { el.innerHTML = '<div class="empty">No events recorded yet.</div>'; return; }
    el.innerHTML = d.events.map((e) =>
      `<div class="ev ${esc(e.level)}"><time>${fmt(e.ts)}</time><span>${badge("info", e.category)}</span><span class="t">${esc(e.summary)}</span></div>`).join("");
  }

  async function refresh() {
    const [ov, au, se, ac, fl, ev] = await Promise.all([
      get("/api/overview"), get("/api/auth"), get("/api/sessions"), get("/api/access"), get("/api/flows"),
      get("/api/events?category=" + encodeURIComponent(category))]);
    renderOverview(ov); renderAccess(ac); renderAuth(au); renderSessions(se); renderFlows(fl); renderEvents(ev);
    $("updated").textContent = "updated " + new Date().toLocaleTimeString([], {hour12: false});
  }

  let timer = null;
  function schedule() {
    clearInterval(timer);
    if ($("auto").checked) timer = setInterval(refresh, Number(document.body.dataset.refresh) || 2000);
  }
  $("refresh").addEventListener("click", refresh);
  $("auto").addEventListener("change", schedule);
  $("chips").addEventListener("click", (e) => {
    if (e.target.tagName !== "BUTTON") return;
    category = e.target.dataset.cat;
    document.querySelectorAll("#chips button").forEach((b) => b.classList.toggle("on", b === e.target));
    refresh();
  });
  refresh(); schedule();
})();
