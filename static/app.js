"use strict";
// TikManager single-page app. Every request carries the session's CSRF token; the server enforces who can see what.
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const ago = (ts) => {
  if (!ts) return "never";
  const s = Math.max(0, Date.now() / 1000 - ts);
  return s < 90 ? "just now" : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 86400 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} d ago`;
};
const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "");
const bytes = (n) => { if (!n) return "0"; const u = ["B", "KB", "MB", "GB", "TB"]; const i = Math.min(4, Math.floor(Math.log(n) / Math.log(1024))); return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`; };
// RouterOS uptime ("1w2d3h4m5s", "55d7h20m") -> "9 weeks, 3 days" style, two largest units
function uptime(s, short = false) {
  if (!s) return "—";
  const unit = { w: 604800, d: 86400, h: 3600, m: 60, s: 1 };
  let secs = 0;
  for (const [, n, u] of String(s).matchAll(/(\d+)([wdhms])/g)) secs += Number(n) * unit[u];
  if (!secs) return String(s);
  const parts = [[Math.floor(secs / 86400), "day"], [Math.floor((secs % 86400) / 3600), "hour"], [Math.floor((secs % 3600) / 60), "minute"]];
  const first = parts.findIndex(([n]) => n > 0);
  if (first < 0) return short ? "<1m" : "less than a minute";
  const top = parts.slice(first, first + 2).filter(([n]) => n > 0);
  return short ? top.map(([n, w]) => `${n}${w[0]}`).join(" ") : top.map(([n, w]) => `${n} ${w}${n === 1 ? "" : "s"}`).join(", ");
}
const bps = (n) => (n == null ? "—" : n < 1e6 ? `${(n / 1e3).toFixed(0)} kbps` : `${(n / 1e6).toFixed(1)} Mbps`);

let me = null, view = "dashboard", timer = null;

// a page opened before TikManager was upgraded keeps running the old code: reload once the server reports a new
// version - but not while a dialog is open or someone is typing (the next request after that does it)
function newVersionLoaded(v) {
  if (!me?.version || v === me.version || $("dlg")?.open || document.activeElement?.closest?.("#main input, #main select, #main textarea")) return;
  try { if (sessionStorage.getItem("reloadedFor") === v) return; sessionStorage.setItem("reloadedFor", v); } catch {}
  location.reload();
}

async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { "Content-Type": "application/json", "X-CSRF-Token": me?.csrf || "", ...(opts.headers || {}) } });
  const sv = r.headers.get("X-TikManager-Version");
  if (sv) setTimeout(() => newVersionLoaded(sv), 0);
  const body = await r.json().catch(() => ({}));
  if (r.status === 401) { location.href = "/login"; throw new Error("Signed out"); }
  if (!r.ok) throw new Error(body.error || r.statusText);
  return body;
}
const post = (path, data = {}) => api(path, { method: "POST", body: JSON.stringify(data) });
const isTech = () => me.kind === "tech";
const canWrite = () => isTech() && me.role !== "readonly";
// "Acme staff" once Admin > Branding has a company name, otherwise "Staff"
const staffName = () => (window.BRAND && window.BRAND.company ? `${window.BRAND.company} staff` : "Staff");

// MikroTik product picture (cached by TikManager), or a generic router icon
function thumbImg(d, cls) {
  return `<img class="${cls}" src="${d.thumb_slug ? `/thumb/${encodeURIComponent(d.thumb_slug)}` : "/router.svg"}" alt="${esc(d.model || "router")}" loading="lazy">`;
}

function stateDot(d) {
  if (d.state !== "adopted") return `<span class="dot pending"></span>Waiting for approval`;
  return d.online ? `<span class="dot on"></span>Online` : `<span class="dot off"></span>Offline`;
}

function setBars(root) {   // widths are set from JS: the security policy doesn't allow inline style attributes
  root.querySelectorAll(".bar > i[data-pct]").forEach((i) => { i.style.width = `${Math.min(100, Number(i.dataset.pct) || 0)}%`; });
}

// --- views ------------------------------------------------------------------------------------------------
async function dashboard() {
  const [devices, events] = await Promise.all([api("/api/devices"), api("/api/events")]);
  const adopted = devices.filter((d) => d.state === "adopted");
  const offline = adopted.filter((d) => !d.online);
  $("main").innerHTML = `<h1>Dashboard</h1><p class="muted">${me.org ? esc(me.org) : "All clients"}</p>
    <div class="tiles">
      <div class="tile"><div class="v">${adopted.length}</div><div class="l">Routers</div></div>
      <div class="tile good"><div class="v">${adopted.length - offline.length}</div><div class="l">Online</div></div>
      <div class="tile ${offline.length ? "bad" : ""}"><div class="v">${offline.length}</div><div class="l">Offline</div></div>
      <div class="tile warn"><div class="v">${devices.length - adopted.length}</div><div class="l">Waiting for approval</div></div>
    </div>
    ${isTech() && devices.length > adopted.length ? `<div class="card"><h2>Waiting for approval</h2>${pendingTable(devices.filter((d) => d.state !== "adopted"))}</div>` : ""}
    <div class="card"><h2>Offline routers</h2>${offline.length ? table(offline, ["state", "org", "name", "last_seen", "last_error"]) : `<p class="muted">Everything is online.</p>`}</div>
    <div class="card"><h2>Recent events</h2>${events.length ? `<div class="table-wrap"><table><thead><tr><th>When</th><th>Router</th><th>Client</th><th>Event</th><th>Detail</th></tr></thead><tbody>
      ${events.slice(0, 25).map((e) => `<tr class="click" data-dev="${e.device_id}"><td>${when(e.ts)}</td><td>${esc(e.device)}</td><td>${esc(e.org)}</td>
        <td><span class="pill">${esc(e.kind)}</span></td><td class="muted">${esc(e.detail)}</td></tr>`).join("")}</tbody></table></div>` : `<p class="muted">No events yet.</p>`}</div>`;
  bindRows();
  bindPending();
}

// Routers that ran the adoption command and wait for a tech to pick their client
function pendingTable(rows) {
  return `<div class="table-wrap"><table><thead><tr><th>Router identity</th><th>Model</th><th>Serial</th><th>RouterOS</th><th>From</th><th>Registered</th><th></th></tr></thead><tbody>
    ${rows.map((d) => `<tr><td><strong>${esc(d.identity || d.name)}</strong></td><td>${esc(d.model || "")}</td><td class="mono">${esc(d.serial || "")}</td>
      <td>${esc((d.version || "").replace(" (stable)", ""))}</td><td class="mono">${esc(d.public_ip || "")}</td><td>${ago(d.first_seen)}</td>
      <td class="row">${canWrite() ? `<button class="btn primary" type="button" data-approve="${d.id}">Approve</button>
        <button class="btn danger" type="button" data-reject="${d.id}">Reject</button>` : ""}</td></tr>`).join("")}</tbody></table></div>`;
}

function bindPending() {
  document.querySelectorAll("[data-approve]").forEach((b) => b.addEventListener("click", () => approve(b.dataset.approve)));
  document.querySelectorAll("[data-reject]").forEach((b) => b.addEventListener("click", async () => {
    if (b.dataset.confirm !== "1") { b.dataset.confirm = "1"; b.textContent = "Click again"; return; }
    await post(`/api/devices/${b.dataset.reject}/delete`);
    go(view);
  }));
}

async function approve(id) {
  const [d, orgs] = await Promise.all([api(`/api/devices/${id}`), api("/api/orgs")]);
  if (!orgs.length) { alert("Add the client first (Clients page)."); return; }
  dialog(`<h2>Approve ${esc(d.identity || d.name)}</h2>
    <p class="muted small">${esc(d.model || "")} · serial <span class="mono">${esc(d.serial || "—")}</span> · RouterOS ${esc(d.version || "")} · registered from <span class="mono">${esc(d.public_ip || "")}</span></p>
    <div class="grid2">
      <label class="field">Client <select id="pOrg">${orgs.map((o) => `<option value="${o.id}">${esc(o.name)}</option>`).join("")}</select></label>
      <label class="field">Name in TikManager <input id="pName" value="${esc(d.identity || d.name)}" maxlength="80"></label>
      <label class="field">Site / address <input id="pSite" value="${esc(d.site || "")}" maxlength="120"></label>
    </div>
    <p class="small muted">Leave the name as the router's identity to keep them in sync; a different name sticks.</p>
    <div class="actions"><button class="btn primary" type="button" id="pOk">Approve</button><button class="btn" type="button" data-close>Cancel</button>
      <span class="status" id="pStatus"></span></div>`);
  $("pOk").addEventListener("click", async () => {
    try {
      await post(`/api/devices/${id}/approve`, { org_id: $("pOrg").value, name: $("pName").value, site: $("pSite").value });
      $("dlg").close();
      go("router", id);
    } catch (e) { $("pStatus").textContent = e.message; $("pStatus").className = "status err"; }
  });
}

// Sort routers by a table column. Status: offline before online (ascending). Empty values always go last.
const upSecs = (s) => { let n = 0; for (const [, v, u] of String(s || "").matchAll(/(\d+)([wdhms])/g)) n += Number(v) * { w: 604800, d: 86400, h: 3600, m: 60, s: 1 }[u]; return n || null; };
function sortRouters(rows, sort) {
  if (!sort || !sort.key) return rows;
  const val = (d) => ({ state: d.state !== "adopted" ? -1 : d.online ? 1 : 0, uptime: upSecs(d.uptime), cpu: d.cpu, last_seen: d.last_seen })[sort.key]
    ?? (sort.key in { state: 1, uptime: 1, cpu: 1, last_seen: 1 } ? null : String(d[sort.key] ?? "").trim() || null);
  const dir = sort.dir === "desc" ? -1 : 1;
  return [...rows].sort((a, b) => {
    const x = val(a), y = val(b);
    if (x == null || y == null) return x == null && y == null ? 0 : x == null ? 1 : -1;
    const c = typeof x === "number" ? x - y : x.localeCompare(y, undefined, { numeric: true, sensitivity: "base" });
    return c * dir || String(a.name || "").localeCompare(String(b.name || ""), undefined, { numeric: true });
  });
}

// sort = { key, dir } makes the headers clickable buttons (data-sort); the caller re-sorts and redraws
function table(rows, cols, sort) {
  const head = { state: "Status", org: "Client", name: "Router", site: "Site", model: "Model", version: "RouterOS", uptime: "Uptime",
                 cpu: "CPU", last_seen: "Last seen", last_error: "Problem", tunnel_ip: "Tunnel IP" };
  head.thumb = "";
  const th = (c) => {
    if (!sort || c === "thumb") return `<th>${head[c]}</th>`;
    const on = sort.key === c, aria = on ? (sort.dir === "desc" ? "descending" : "ascending") : "none";
    return `<th aria-sort="${aria}"><button type="button" class="th-sort${on ? " on" : ""}" data-sort="${c}">${head[c]}<span class="th-arrow">${on ? (sort.dir === "desc" ? "▼" : "▲") : ""}</span></button></th>`;
  };
  const cell = (d, c) => c === "thumb" ? thumbImg(d, "thumb-sm") : c === "state" ? stateDot(d) : c === "last_seen" ? ago(d.last_seen)
    : c === "cpu" ? (d.cpu == null ? "" : `<div class="row"><div class="bar"><i data-pct="${d.cpu}"></i></div>${d.cpu}%</div>`)
    : c === "uptime" ? `<span class="nowrap" title="${esc(uptime(d.uptime))}">${esc(d.uptime ? uptime(d.uptime, true) : "")}</span>`
    : c === "version" ? esc((d.version || "").replace(" (stable)", ""))
    : c === "org" ? (d.org ? esc(d.org) : `<span class="muted">Unassigned</span>`) : esc(d[c] ?? "");
  return `<div class="table-wrap"><table><thead><tr>${cols.map(th).join("")}</tr></thead><tbody>
    ${rows.map((d) => `<tr class="click" data-dev="${d.id}">${cols.map((c) => `<td>${cell(d, c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}

function bindRows() {
  document.querySelectorAll("tr[data-dev]").forEach((tr) => tr.addEventListener("click", () => go("router", tr.dataset.dev)));
  setBars($("main"));
}

let routerSort = { key: "", dir: "asc" };   // kept while you move around the app
async function routers() {
  const [devices, orgs] = await Promise.all([api("/api/devices"), api("/api/orgs")]);
  const pending = devices.filter((d) => d.state !== "adopted");
  $("main").innerHTML = `<div class="row"><div><h1>Routers</h1><p class="muted">${devices.length - pending.length} router(s)</p></div><span class="spacer"></span>
      ${isTech() ? `<button class="btn primary" type="button" id="adoptBtn">Adopt routers</button>` : ""}</div>
    ${isTech() && pending.length ? `<div class="card"><h2>Waiting for approval (${pending.length})</h2>${pendingTable(pending)}</div>` : ""}
    <div class="card"><div class="row">
      ${isTech() ? `<select id="fOrg" aria-label="Client"><option value="">All clients</option>${orgs.map((o) => `<option value="${o.id}">${esc(o.name)}</option>`).join("")}</select>` : ""}
      <select id="fState" aria-label="Status"><option value="">Any status</option><option value="online">Online</option><option value="offline">Offline</option></select>
      <input id="fText" placeholder="Search name, model, version…" aria-label="Search">
    </div><div id="list"></div></div>`;
  const draw = () => {
    const o = $("fOrg")?.value, st = $("fState").value, t = $("fText").value.toLowerCase();
    const rows = devices.filter((d) => d.state === "adopted" && (!o || String(d.org_id) === o) && (!st || !!d.online === (st === "online"))
      && (!t || `${d.name} ${d.identity} ${d.model} ${d.version} ${d.site} ${d.org}`.toLowerCase().includes(t)));
    $("list").innerHTML = rows.length ? table(sortRouters(rows, routerSort), isTech() ? ["thumb", "state", "org", "name", "site", "model", "version", "uptime", "cpu", "last_seen"] : ["thumb", "state", "name", "site", "model", "version", "uptime", "cpu", "last_seen"], routerSort)
      : `<p class="muted">No routers match.</p>`;
    bindRows();
    // click a header to sort by it; click it again to reverse
    $("list").querySelectorAll("[data-sort]").forEach((b) => b.addEventListener("click", () => {
      const k = b.dataset.sort;
      routerSort = { key: k, dir: routerSort.key === k && routerSort.dir === "asc" ? "desc" : "asc" };
      draw();
    }));
  };
  ["fOrg", "fState", "fText"].forEach((id) => $(id)?.addEventListener("input", draw));
  draw();
  bindPending();
  $("adoptBtn")?.addEventListener("click", showAdoption);
}

async function showAdoption() {
  const r = await api("/api/adoption");
  dialog(`<h2>Adopt routers</h2>
    <p>Paste this command into any router's terminal (Winbox → New Terminal, or SSH). The router registers itself with its own
      name and shows up under <strong>Waiting for approval</strong>, where you pick its client.</p>
    <div class="code" id="cmd">${esc(r.command)}</div>
    <p class="small muted">Same command for every router. Needs RouterOS 7 and internet access from the router. Routers can't do anything until a
      technician approves them; if this command ever leaks, an admin can replace it.</p>
    <div class="actions"><button class="btn primary" type="button" id="copy">Copy command</button>
      ${me.dev ? `<button class="btn" type="button" id="sim">Simulate a router registering (dev)</button>` : ""}
      ${me.role === "admin" ? `<button class="btn danger" type="button" id="rotate">Replace command</button>` : ""}
      <button class="btn" type="button" data-close>Done</button><span class="status" id="cStatus"></span></div>`);
  const say = (t, k) => { $("cStatus").textContent = t; $("cStatus").className = `status ${k || ""}`; };
  $("copy").addEventListener("click", async () => { await navigator.clipboard.writeText($("cmd").textContent); say("Copied.", "ok"); });
  $("sim")?.addEventListener("click", async () => { await post("/api/dev/register"); say("A simulated router registered.", "ok"); });
  $("rotate")?.addEventListener("click", async (e) => {
    if (e.target.dataset.confirm !== "1") { e.target.dataset.confirm = "1"; e.target.textContent = "Click again - old copies stop working"; return; }
    const n = await post("/api/adoption/rotate");
    $("cmd").textContent = n.command;
    say("Replaced. Routers already adopted keep working.", "ok");
  });
  $("dlg").addEventListener("close", () => { if (view === "routers" || view === "dashboard") go(view); }, { once: true });
}

// --- router page (UniFi-style: summary panel on the left, activity chart and details on the right) ----------------
const rView = { range: "1d", iface: "", latency: true, loss: true };   // kept across the page's 30-second refresh

async function router(id) {
  const d = await api(`/api/devices/${id}`);
  const memPct = d.mem_total ? Math.round(100 * d.mem_used / d.mem_total) : null;
  const diskPct = d.hdd_total ? Math.round(100 * (d.hdd_total - d.hdd_free) / d.hdd_total) : null;
  const wan = (d.interfaces || []).find((i) => /wan/i.test(i.comment || "")) || (d.interfaces || []).find((i) => i.name === "ether1");
  const fwState = d.fw_current ? (d.fw_upgrade && d.fw_upgrade !== d.fw_current ? `<span class="status warn">Upgrade to ${esc(d.fw_upgrade)}</span>` : `<span class="muted">Up to date</span>`) : "";
  const kv = (k, v, raw) => `<div class="kv"><span>${k}</span><span class="${raw ? "" : "mono"}">${raw ? v : esc(v || "—")}</span></div>`;
  const meter = (label, pct, text) => `<div class="meter"><div class="row small"><span>${label}</span><span class="spacer"></span><span class="muted">${text}</span></div>
    <div class="bar"><i data-pct="${pct ?? 0}" class="${pct >= 90 ? "hot" : pct >= 75 ? "warm" : ""}"></i></div></div>`;
  $("main").innerHTML = `<p><a href="#" id="back">← Routers</a></p>
  <div class="dev-layout">
    <aside class="card dev-side">
      <div class="dev-head">${thumbImg(d, "thumb-lg")}</div>
      <div class="dev-name">${esc(d.name)}</div>
      <div class="dev-sub">${stateDot(d)}${d.state === "adopted" ? ` <span class="muted small">· seen ${ago(d.last_seen)}</span>` : ""}</div>
      ${d.state !== "adopted" ? `<p class="small">Registered ${ago(d.first_seen)} from <span class="mono">${esc(d.public_ip || "")}</span>. Approve it to pick its client and start monitoring.</p>
        ${canWrite() ? `<button class="btn primary wide" type="button" data-approve="${d.id}">Approve</button>` : ""}` : ""}
      <div class="kvs">
        ${kv("Client", d.org || "Unassigned")}${d.site ? kv("Site", d.site) : ""}
        ${kv("WAN IP", d.wan_ip)}${kv("Tunnel IP", d.tunnel_ip)}${kv("Uptime", uptime(d.uptime))}
        ${kv("RouterOS", esc((d.version || "—").replace(" (stable)", "")), true)}${d.fw_current ? kv("Firmware", `${esc(d.fw_current)} ${fwState}`, true) : ""}
        ${kv("Model", d.model)}${kv("Serial", d.serial)}
      </div>
      ${d.state === "adopted" && isTech() ? upgradeBox(d) : ""}
      ${d.vpn ? `<div class="up-box"><div class="row small"><b>Site-to-site VPN</b><span class="spacer"></span><a href="#vpn/${d.vpn.id}">${esc(d.vpn.name)}</a></div>
        <div class="small">${d.vpn.role === "hub" ? "Hub" : "Spoke"} · <span class="mono">${esc(d.vpn.tunnel_ip)}</span></div>${tunnelState(d.vpn)}</div>` : ""}
      ${d.state === "adopted" ? `
      ${meter("CPU", d.cpu, d.cpu != null ? `${d.cpu}%` : "—")}
      ${meter("Memory", memPct, d.mem_total ? `${bytes(d.mem_used)} / ${bytes(d.mem_total)}` : "—")}
      ${d.hdd_total ? meter("Disk", diskPct, `${bytes(d.hdd_total - d.hdd_free)} / ${bytes(d.hdd_total)}`) : ""}
      <div class="thru"><span class="small muted">Throughput${wan ? ` (${esc(wan.name)})` : ""}</span>
        <div><span class="in">↓ ${bps(wan?.rx_bps)}</span> <span class="out">↑ ${bps(wan?.tx_bps)}</span></div></div>
      <svg class="spark" id="spark" role="img" aria-label="Last hour of WAN traffic"></svg>
      ${canWrite() ? `<button class="btn wide" type="button" id="sideBackup">Back up now</button>
      <button class="btn wide" type="button" id="sideScript" ${d.online ? "" : "disabled"}>Run script...</button>` : ""}` : ""}
    </aside>
    <section class="dev-main">
      ${d.state === "adopted" ? `
      ${d.last_error && !d.online ? `<div class="card"><span class="status err">${esc(d.last_error)}</span></div>` : ""}
      <div class="card">
        <div class="chart-toolbar">
          <select id="cIface" aria-label="Interface"><option value="">WAN (internet)</option></select>
          <label class="chk"><input type="checkbox" id="cLat" ${rView.latency ? "checked" : ""}><i class="sw lat"></i> Latency</label>
          <label class="chk"><input type="checkbox" id="cLoss" ${rView.loss ? "checked" : ""}><i class="sw loss"></i> Packet loss</label>
          <span class="spacer"></span>
          <div class="seg" role="group" aria-label="Time range">${["1h", "1d", "1w", "1m"].map((r) => `<button type="button" data-range="${r}" class="${rView.range === r ? "on" : ""}">${r.toUpperCase()}</button>`).join("")}</div>
        </div>
        <div class="act-wrap"><svg class="act" id="act" role="img" aria-label="Internet activity"></svg><div class="tip hidden" id="tip"></div></div>
        <div class="legend small"><span><i class="sw in"></i> Download</span><span><i class="sw out"></i> Upload</span>
          <span class="muted" id="cNote"></span></div>
      </div>
      <div class="health" id="health"></div>
      ${lteCard(d.interfaces || [])}
      <div class="card"><h2>Interfaces</h2><div class="table-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Status</th><th>Details</th><th>In now</th><th>Out now</th><th>Total in / out</th><th>Comment</th></tr></thead><tbody>
        ${(d.interfaces || []).map((i) => `<tr><td class="mono">${esc(i.name)}</td><td>${esc(i.type)}</td>
          <td>${i.disabled ? `<span class="pill">disabled</span>` : i.running ? `<span class="dot on"></span>up` : `<span class="dot off"></span>down`}</td>
          <td class="small">${esc(ifaceDetail(i))}</td><td class="mono">${i.running ? bps(i.rx_bps) : ""}</td><td class="mono">${i.running ? bps(i.tx_bps) : ""}</td>
          <td class="small nowrap">${bytes(i.rx)} / ${bytes(i.tx)}</td><td class="muted">${esc(i.comment)}</td></tr>`).join("")}</tbody></table></div></div>
      ${d.online ? `<div class="card" id="dhcpCard"><div class="row"><h2>DHCP clients</h2><span class="spacer"></span>
        <input id="dhcpQ" type="search" placeholder="Search name, IP, MAC" aria-label="Search DHCP clients">
        <button class="btn" type="button" id="dhcpRefresh">Refresh</button></div><div id="dhcpBody"><p class="muted small">Reading leases...</p></div></div>` : ""}
      ${d.vpn_found && d.vpn_found.length ? `<div class="card"><div class="row"><h2>VPNs on this router</h2><span class="spacer"></span><span class="small muted">read ${ago(d.vpn_inv_at)}</span></div>
        <div class="table-wrap"><table><thead><tr><th>Type</th><th>Name</th><th>Remote end</th><th>Status</th><th>Networks / users</th><th>Traffic</th><th>Notes</th></tr></thead>
        <tbody>${tunnelRows(d.vpn_found.map((t) => ({ r: d, t })), false)}</tbody></table></div></div>` : ""}
      ${d.online ? `<div class="card" id="topoCard"><h2>Network map</h2><p class="muted small">Reading the router's routes, neighbours and devices...</p></div>` : ""}
      ${d.online && isTech() ? `<div class="card" id="fwCard"><h2>Firewall &amp; NAT</h2><p class="muted small">Reading the rules...</p></div>` : ""}
      <div class="card" id="bkCard"><h2>Configuration backups</h2><p class="muted">Loading…</p></div>
      <div class="card" id="locCard"><h2>Location</h2></div>` : ""}
      <div class="card"><h2>Events</h2>${d.events.length ? `<table><tbody>${d.events.map((e) => `<tr><td class="nowrap">${when(e.ts)}</td><td><span class="pill">${esc(e.kind)}</span></td><td class="muted">${esc(e.detail)}</td></tr>`).join("")}</tbody></table>` : `<p class="muted">None yet.</p>`}</div>
      ${canWrite() ? `<div class="card"><h2>Manage</h2>
        ${d.state === "adopted" ? `<div class="row"><label class="field">Router identity (on the MikroTik) <input id="rIdent" value="${esc(d.identity || "")}" maxlength="64" spellcheck="false"></label>
          <button class="btn" type="button" id="rIdentSet" ${d.online ? "" : "disabled title=\"The router is offline\""}>Set on router</button></div>
          <p class="small muted">Changes <span class="mono">/system identity</span> on the router; the name in TikManager follows it.${d.online ? "" : " The router must be online."}</p>
          <div class="row"><label class="field">Name in TikManager <input id="rName" value="${d.name_custom ? esc(d.name) : ""}" placeholder="${esc(d.identity || d.name)} (router identity)" maxlength="80"></label>
          <label class="field">Site / address <input id="rSite" value="${esc(d.site || "")}" maxlength="120"></label>
          <button class="btn" type="button" id="rSave">Save</button></div>
          <p class="small muted">Leave the name blank to follow the router's identity.</p>
          <div class="row"><label class="field">Client <select id="rOrg" aria-label="Client"><option value="${d.org_id}">${esc(d.org || "")}</option></select></label>
            <button class="btn" type="button" id="rMove" disabled>Move to this client</button></div>
          <p class="small muted">Moves the router with its backups, events and upgrade history. Users of the old client lose access to it.</p>` : ""}
        <div class="actions"><button class="btn danger" type="button" id="remove">${d.state === "adopted" ? "Remove router" : "Reject"}</button><span class="status" id="mStatus"></span></div>
        <p class="small muted">Removing it disconnects the tunnel. On the router you can then delete the <span class="mono">tikmanager</span> interface, user, logging action and firewall rule.</p></div>` : ""}
    </section>
  </div>`;
  setBars($("main"));
  $("back").addEventListener("click", (e) => { e.preventDefault(); go("routers"); });
  bindPending();
  $("rIdentSet")?.addEventListener("click", async () => {
    const v = $("rIdent").value.trim();
    if (!v || v === d.identity) { $("mStatus").textContent = "Type the new identity first."; $("mStatus").className = "status err"; return; }
    $("rIdentSet").disabled = true;
    try { await post(`/api/devices/${d.id}/identity`, { identity: v }); router(d.id); }
    catch (err) { $("rIdentSet").disabled = false; $("mStatus").textContent = err.message; $("mStatus").className = "status err"; }
  });
  $("rSave")?.addEventListener("click", async () => {
    try { await post(`/api/devices/${d.id}/rename`, { name: $("rName").value, site: $("rSite").value }); router(d.id); }
    catch (err) { $("mStatus").textContent = err.message; $("mStatus").className = "status err"; }
  });
  if ($("rOrg")) {
    api("/api/orgs").then((orgs) => {
      $("rOrg").innerHTML = orgs.map((o) => `<option value="${o.id}" ${o.id === d.org_id ? "selected" : ""}>${esc(o.name)}</option>`).join("");
    }).catch(() => {});
    $("rOrg").addEventListener("change", () => { $("rMove").disabled = +$("rOrg").value === d.org_id; });
    $("rMove").addEventListener("click", async () => {
      const name = $("rOrg").selectedOptions[0].textContent;
      if ($("rMove").dataset.confirm !== "1") { $("rMove").dataset.confirm = "1"; $("rMove").textContent = `Click again to move to ${name}`; return; }
      try { await post(`/api/devices/${d.id}/move`, { org_id: $("rOrg").value }); router(d.id); }
      catch (err) { $("mStatus").textContent = err.message; $("mStatus").className = "status err"; $("rMove").dataset.confirm = ""; $("rMove").textContent = "Move to this client"; }
    });
  }
  $("remove")?.addEventListener("click", async (e) => {
    if (e.target.dataset.confirm !== "1") { e.target.dataset.confirm = "1"; e.target.textContent = "Click again to remove"; return; }
    try { await post(`/api/devices/${d.id}/delete`); go("routers"); } catch (err) { $("mStatus").textContent = err.message; $("mStatus").className = "status err"; }
  });
  if (d.state !== "adopted") return;
  $("sideBackup")?.addEventListener("click", () => $("bkNow") ? $("bkNow").click() : null);
  $("sideScript")?.addEventListener("click", () => runScriptOn(d));
  $("rUpgrade")?.addEventListener("click", () => upgradeDialog([d], () => router(d.id)));
  $("rUpCancel")?.addEventListener("click", async () => { await post(`/api/upgrades/${d.upgrade.id}/cancel`); router(d.id); });
  loadBackups(d);
  if ($("dhcpCard")) loadDhcp(d);
  if ($("topoCard")) loadTopology(d);
  if ($("fwCard")) loadFirewall(d);
  loadLocation(d);
  const load = async () => {
    const s = await api(`/api/devices/${d.id}/series?range=${rView.range}&iface=${encodeURIComponent(rView.iface)}`);
    const sel = $("cIface");
    if (sel && sel.options.length === 1) {
      sel.insertAdjacentHTML("beforeend", s.interfaces.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join(""));
      sel.value = rView.iface;
    }
    activityChart($("act"), s, rView);
    healthStrip(s, d, memPct, diskPct);
  };
  $("cIface").addEventListener("change", (e) => { rView.iface = e.target.value; load(); });
  $("cLat").addEventListener("change", (e) => { rView.latency = e.target.checked; load(); });
  $("cLoss").addEventListener("change", (e) => { rView.loss = e.target.checked; load(); });
  document.querySelectorAll("[data-range]").forEach((b) => b.addEventListener("click", () => {
    rView.range = b.dataset.range;
    document.querySelectorAll("[data-range]").forEach((x) => x.classList.toggle("on", x === b));
    load();
  }));
  await load();
  api(`/api/devices/${d.id}/series?range=1h`).then((s) => sparkline($("spark"), s.traffic)).catch(() => {});
}

// DHCP leases (read live from the router when the page opens or on Refresh)
const dhcpView = { q: "" };
async function loadDhcp(d) {
  let x;
  try { x = await api(`/api/devices/${d.id}/dhcp`); }
  catch (e) { if ($("dhcpBody")) $("dhcpBody").innerHTML = `<p class="status err small">${esc(e.message)}</p>`; return; }
  if (!$("dhcpBody")) return;
  const since = (s) => (s == null ? "" : s < 90 ? "just now" : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 86400 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} d ago`);
  const ipKey = (a) => a.split(".").map((n) => n.padStart(3, "0")).join(".");
  const all = x.leases.slice().sort((a, b) => ipKey(a.address).localeCompare(ipKey(b.address)));
  const draw = () => {
    const q = dhcpView.q.toLowerCase();
    const rows = all.filter((l) => !q || `${l.host} ${l.address} ${l.mac} ${l.comment}`.toLowerCase().includes(q));
    const bound = all.filter((l) => l.status === "bound").length;
    $("dhcpBody").innerHTML = `<p class="small muted">${bound} connected (bound) · ${all.length} leases · read ${since(Date.now() / 1000 - x.read_at) || "just now"}</p>
      ${rows.length ? `<div class="table-wrap"><table><thead><tr><th>Host name</th><th>IP address</th><th>MAC address</th><th>Network</th><th>Status</th><th>Type</th><th>Last seen</th><th>Comment</th></tr></thead><tbody>
      ${rows.map((l) => `<tr class="${l.disabled || l.blocked ? "muted" : ""}"><td>${esc(l.host || "—")}</td><td class="mono">${esc(l.address)}</td><td class="mono small">${esc(l.mac)}</td>
        <td class="small">${esc(l.server)}${l.interface ? ` <span class="muted">(${esc(l.interface)})</span>` : ""}</td>
        <td>${l.status === "bound" ? `<span class="dot on"></span>bound` : `<span class="dot off"></span>${esc(l.status || "—")}`}${l.blocked ? ` <span class="pill">blocked</span>` : ""}${l.disabled ? ` <span class="pill">disabled</span>` : ""}</td>
        <td class="small">${l.dynamic ? "dynamic" : "static"}</td><td class="small nowrap">${since(l.last_seen)}</td><td class="small muted">${esc(l.comment)}</td></tr>`).join("")}
      </tbody></table></div>` : `<p class="muted small">${all.length ? "Nothing matches." : "This router has no DHCP leases (no DHCP server, or nothing connected)."}</p>`}`;
  };
  $("dhcpQ").value = dhcpView.q;
  $("dhcpQ").oninput = (e) => { dhcpView.q = e.target.value; draw(); };
  $("dhcpRefresh").onclick = () => { $("dhcpBody").innerHTML = `<p class="muted small">Reading leases...</p>`; loadDhcp(d); };
  draw();
}

// Upgrade status / button in the router page's side panel (technicians)
function upgradeBox(d) {
  const j = d.upgrade, last = d.last_upgrade;
  const avail = hasUpdate(d), fw = fwUpdate(d);
  let html = "";
  if (j) html = `<div class="up-box">${upStatus(j)}${j.status === "scheduled" && canWrite() ? `<button class="btn wide" type="button" id="rUpCancel">Cancel scheduled upgrade</button>` : ""}</div>`;
  else {
    html = `<div class="up-box ${avail || fw ? "avail" : ""}">${avail ? `<b>RouterOS ${esc(d.ros_latest)} is available</b><div class="small muted">${esc(d.ros_channel || "")} channel</div>`
      : fw ? `<b>RouterBOARD firmware ${esc(d.fw_upgrade)} is available</b>` : d.ros_latest ? `<span class="small status ok">RouterOS is up to date</span>` : `<span class="small muted">Not checked for updates yet</span>`}
      ${canWrite() ? `<button class="btn wide ${avail || fw ? "primary" : ""}" type="button" id="rUpgrade">${avail || fw ? "Upgrade..." : "Upgrade / change channel..."}</button>` : ""}</div>`;
  }
  if (last && !j) html += `<p class="small ${last.status === "failed" ? "status err" : "muted"}">Last upgrade ${ago(last.finished_at)}: ${esc(last.detail || last.status)}</p>`;
  return html;
}

// Health strip under the chart: averages over the selected range
function healthStrip(s, d, memPct, diskPct) {
  const h = s.health.filter((x) => x.latency != null);
  const avg = (a) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : null);
  const lat = avg(h.map((x) => x.latency));
  const loss = avg(s.health.filter((x) => x.loss != null).map((x) => x.loss));
  const cpu = avg(s.health.filter((x) => x.cpu != null).map((x) => x.cpu));
  const tone = (v, good, ok) => (v == null ? "" : v <= good ? "good" : v <= ok ? "warn" : "bad");
  const label = { "1h": "last hour", "1d": "last 24 hours", "1w": "last 7 days", "1m": "last 30 days" }[rView.range];
  $("health").innerHTML = [["Latency", lat != null ? `${lat.toFixed(0)} ms` : "—", tone(lat, 40, 100)],
    ["Packet loss", loss != null ? `${loss.toFixed(loss < 1 ? 2 : 1)}%` : "—", tone(loss, 0.5, 2)],
    ["Average CPU", cpu != null ? `${cpu.toFixed(0)}%` : "—", tone(cpu, 60, 85)],
    ["Memory", memPct != null ? `${memPct}%` : "—", tone(memPct, 75, 90)],
    ["Disk", diskPct != null ? `${diskPct}%` : "—", tone(diskPct, 80, 90)]]
    .map(([k, v, c]) => `<div class="hcell ${c}"><div class="hv">${v}</div><div class="hl">${k}${k === "Latency" || k === "Packet loss" || k === "Average CPU" ? ` · ${label}` : ""}</div></div>`).join("");
}

function sparkline(svg, pts) {
  if (!svg || pts.length < 2) return;
  const W = svg.clientWidth || 260, H = 40;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  const max = Math.max(1, ...pts.map((p) => Math.max(p.rx || 0, p.tx || 0)));
  const t0 = pts[0].t, t1 = pts[pts.length - 1].t;
  const x = (t) => (W * (t - t0)) / Math.max(1, t1 - t0), y = (v) => H - 2 - ((H - 4) * (v || 0)) / max;
  const line = (k) => pts.map((p) => `${x(p.t).toFixed(1)},${y(p[k]).toFixed(1)}`).join(" ");
  svg.innerHTML = `<polygon class="area-in" points="0,${H} ${line("rx")} ${W},${H}"/><polyline class="l-in" fill="none" points="${line("rx")}"/>
    <polyline class="l-out" fill="none" points="${line("tx")}"/>`;
}

// The big chart: download area, upload line, latency (right axis) and packet loss marks, with a hover readout
function activityChart(svg, s, opt) {
  if (!svg) return;
  const W = Math.max(320, svg.clientWidth || 800), H = 280, L = 56, R = opt.latency ? 48 : 12, T = 12, B = 26;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  const tr = s.traffic, hl = s.health;
  if (tr.length < 2 && hl.length < 2) { svg.innerHTML = `<text x="${W / 2}" y="${H / 2}" text-anchor="middle" class="axis">Collecting data…</text>`; $("cNote").textContent = ""; return; }
  const now = Date.now() / 1000, t0 = now - s.range, t1 = now;
  const x = (t) => L + ((W - L - R) * (t - t0)) / (t1 - t0);
  const maxBps = niceMax(Math.max(1, ...tr.map((p) => Math.max(p.rx || 0, p.tx || 0))));
  const maxLat = niceMax(Math.max(10, ...hl.map((p) => p.latency || 0)));
  const yB = (v) => H - B - ((H - B - T) * (v || 0)) / maxBps, yL = (v) => H - B - ((H - B - T) * (v || 0)) / maxLat;
  const fmtT = (t) => { const dt = new Date(t * 1000); return s.range <= 86400 ? dt.toLocaleTimeString([], { hour: "numeric", minute: s.range <= 3600 ? "2-digit" : undefined }) : dt.toLocaleDateString([], { month: "short", day: "numeric" }); };
  let g = "";
  for (let i = 0; i <= 4; i++) {
    const yy = T + ((H - B - T) * i) / 4;
    g += `<line class="grid" x1="${L}" y1="${yy}" x2="${W - R}" y2="${yy}"/><text class="axis" x="${L - 6}" y="${yy + 3}" text-anchor="end">${esc(bpsShort(maxBps * (1 - i / 4)))}</text>`;
    if (opt.latency) g += `<text class="axis" x="${W - R + 6}" y="${yy + 3}">${Math.round(maxLat * (1 - i / 4))}${i === 0 ? " ms" : ""}</text>`;
  }
  for (let i = 0; i <= 5; i++) { const tt = t0 + ((t1 - t0) * i) / 5; g += `<text class="axis" x="${x(tt)}" y="${H - 8}" text-anchor="${i === 0 ? "start" : i === 5 ? "end" : "middle"}">${esc(i === 5 ? "Now" : fmtT(tt))}</text>`; }
  const pts = (k, yf, src) => src.filter((p) => p[k] != null).map((p) => `${x(p.t).toFixed(1)},${yf(p[k]).toFixed(1)}`).join(" ");
  const inPts = pts("rx", yB, tr);
  let body = tr.length > 1 ? `<polygon class="area-in" points="${x(tr[0].t).toFixed(1)},${H - B} ${inPts} ${x(tr[tr.length - 1].t).toFixed(1)},${H - B}"/>
    <polyline class="l-in" fill="none" points="${inPts}"/><polyline class="l-out" fill="none" points="${pts("tx", yB, tr)}"/>` : "";
  if (opt.latency) body += `<polyline class="l-lat" fill="none" points="${pts("latency", yL, hl)}"/>`;
  if (opt.loss) body += hl.filter((p) => p.loss > 0).map((p) => `<rect class="r-loss" x="${(x(p.t) - 1.5).toFixed(1)}" y="${T}" width="3" height="${H - B - T}" opacity="${Math.min(0.5, 0.15 + p.loss / 100)}"/>`).join("");
  svg.innerHTML = g + body + `<line class="cursor hidden" id="cur" x1="0" y1="${T}" x2="0" y2="${H - B}"/>`;
  const peak = tr.reduce((m, p) => Math.max(m, p.rx || 0), 0);
  $("cNote").textContent = tr.length ? `Peak download ${bps(peak)}` : "";
  const byT = (arr, t) => arr.reduce((best, p) => (!best || Math.abs(p.t - t) < Math.abs(best.t - t) ? p : best), null);
  svg.onmousemove = (ev) => {
    const r = svg.getBoundingClientRect(), px = ((ev.clientX - r.left) * W) / r.width;
    if (px < L || px > W - R) { svg.onmouseleave(); return; }
    const t = t0 + ((px - L) * (t1 - t0)) / (W - L - R), a = byT(tr, t), h = byT(hl, t);
    const cur = $("cur"); cur.setAttribute("x1", px); cur.setAttribute("x2", px); cur.classList.remove("hidden");
    const tip = $("tip");
    tip.innerHTML = `<b>${esc(new Date((a || h).t * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }))}</b>
      ${a ? `<div><i class="sw in"></i> ${bps(a.rx)} <i class="sw out"></i> ${bps(a.tx)}</div>` : ""}
      ${h && h.latency != null ? `<div><i class="sw lat"></i> ${h.latency.toFixed(0)} ms${h.loss ? ` · <span class="status err">${h.loss.toFixed(0)}% loss</span>` : ""}</div>` : ""}`;
    tip.classList.remove("hidden");
    const left = (px / W) * r.width;
    tip.style.left = `${Math.min(r.width - 180, Math.max(0, left + 12))}px`;
  };
  svg.onmouseleave = () => { $("cur")?.classList.add("hidden"); $("tip")?.classList.add("hidden"); };
}
function niceMax(v) { const p = 10 ** Math.floor(Math.log10(v)); return [1, 2, 2.5, 5, 10].map((m) => m * p).find((m) => m >= v); }
function bpsShort(n) { return n >= 1e9 ? `${(n / 1e9).toFixed(1)}G` : n >= 1e6 ? `${(n / 1e6).toFixed(n >= 1e7 ? 0 : 1)}M` : n >= 1e3 ? `${(n / 1e3).toFixed(0)}k` : `${Math.round(n)}`; }
// --- configuration backups (export scripts, restorable on a different model) ------------------------------------
async function loadBackups(d) {
  const card = $("bkCard");
  if (!card) return;
  const b = await api(`/api/devices/${d.id}/backups`);
  const v = b.versions;
  card.innerHTML = `<div class="row"><h2>Configuration backups</h2><span class="spacer"></span>
      ${canWrite() ? `<button class="btn" type="button" id="bkNow">Back up now</button>` : ""}</div>
    <p class="muted small">Nightly export script (<span class="mono">.rsc</span>) with passwords and keys, stored encrypted - import it on any
      RouterOS 7 router, including a different model. A new version is kept only when the configuration changes.
      Last checked: ${b.last_backup_at ? ago(b.last_backup_at) : "never"}.</p>
    ${b.last_backup_error ? `<p class="status err">Last attempt failed: ${esc(b.last_backup_error)}</p>` : ""}
    <span class="status" id="bkStatus"></span>
    ${v.length ? `<div class="table-wrap"><table><thead><tr><th>Saved</th><th>Changes</th><th>Size</th><th>By</th><th></th></tr></thead><tbody>
      ${v.map((x, i) => `<tr><td>${when(x.ts)}${i === 0 ? ` <span class="pill">latest</span>` : ""}</td>
        <td>${i === v.length - 1 ? `first backup (${x.lines} lines)` : `<span class="add">+${x.added}</span> / <span class="del">-${x.removed}</span>`}</td>
        <td>${bytes(x.size)}</td><td class="small muted">${esc(x.trigger === "manual" ? x.by_user : "nightly")}</td>
        <td class="row">${b.can_view ? `<button class="btn" type="button" data-bk-view="${x.id}">View</button>
          ${i < v.length - 1 ? `<button class="btn" type="button" data-bk-diff="${x.id}">What changed</button>` : ""}
          <a class="btn" href="/api/backups/${x.id}/download">Download .rsc</a>` : ""}</td></tr>`).join("")}</tbody></table></div>`
      : `<p class="muted">No backups yet - the first one runs tonight${canWrite() ? ", or click Back up now" : ""}.</p>`}`;
  $("bkNow")?.addEventListener("click", async (e) => {
    e.target.disabled = true; e.target.textContent = "Backing up…";
    try { const r = await post(`/api/devices/${d.id}/backup`); $("bkStatus").textContent = r.detail; $("bkStatus").className = "status ok"; loadBackups(d); }
    catch (err) { $("bkStatus").textContent = err.message; $("bkStatus").className = "status err"; e.target.disabled = false; e.target.textContent = "Back up now"; }
  });
  card.querySelectorAll("[data-bk-view]").forEach((btn) => btn.addEventListener("click", async () => {
    const r = await api(`/api/backups/${btn.dataset.bkView}`);
    dialog(`<h2>${esc(r.device)} - ${when(r.ts)}</h2><pre class="code cfg">${esc(r.text)}</pre>
      <div class="actions"><a class="btn primary" href="/api/backups/${btn.dataset.bkView}/download">Download .rsc</a><button class="btn" type="button" data-close>Close</button></div>`);
    $("dlg").classList.add("wide");
  }));
  card.querySelectorAll("[data-bk-diff]").forEach((btn) => btn.addEventListener("click", async () => {
    const r = await api(`/api/backups/${btn.dataset.bkDiff}/diff`);
    dialog(`<h2>What changed</h2><p class="muted small">Compared with the version from ${when(r.previous_ts)}. Green lines were added, red removed.</p>
      <pre class="code cfg">${r.diff.map((l) => `<span class="${l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : l.startsWith("@@") ? "hunk" : ""}">${esc(l)}</span>`).join("\n") || "No differences."}</pre>
      <div class="actions"><button class="btn" type="button" data-close>Close</button></div>`);
    $("dlg").classList.add("wide");
  }));
}

async function backupsView() {
  const rows = await api("/api/backups");
  const stale = rows.filter((r) => !r.last_backup_at || Date.now() / 1000 - r.last_backup_at > 36 * 3600);
  $("main").innerHTML = `<h1>Backups</h1><p class="muted">Every approved router is exported nightly; a new version is saved when its configuration changes.</p>
    <div class="tiles"><div class="tile"><div class="v">${rows.length}</div><div class="l">Routers</div></div>
      <div class="tile good"><div class="v">${rows.length - stale.length}</div><div class="l">Backed up in the last 36 hours</div></div>
      <div class="tile ${stale.length ? "bad" : ""}"><div class="v">${stale.length}</div><div class="l">Missing or failing</div></div></div>
    <div class="card"><div class="table-wrap"><table><thead><tr><th>Router</th><th>Client</th><th>Last checked</th><th>Last change</th><th>Versions</th><th>Problem</th></tr></thead><tbody>
      ${rows.map((r) => `<tr class="click" data-dev="${r.id}"><td>${esc(r.name)}</td><td>${esc(r.org || "")}</td>
        <td>${r.last_backup_at ? ago(r.last_backup_at) : `<span class="status err">never</span>`}</td><td>${r.last_change ? when(r.last_change) : "—"}</td>
        <td>${r.versions}</td><td class="small">${r.last_backup_error ? `<span class="status err">${esc(r.last_backup_error)}</span>` : !r.online ? "offline" : ""}</td></tr>`).join("")
        || `<tr><td colspan="6" class="muted">No approved routers yet.</td></tr>`}</tbody></table></div></div>`;
  bindRows();
}

// one line of type-specific detail per interface (what Cloutik's interface report carries)
function ifaceDetail(i) {
  if (i.vlan_id) return `VLAN ${i.vlan_id} on ${i.parent || "?"}`;
  if (i.ssid !== undefined) return [i.ssid && `SSID ${i.ssid}`, i.band, i.freq && `${i.freq} MHz`, i.mode].filter(Boolean).join(" · ");
  if (i.operator !== undefined) return [i.operator, i.access, i.band_lte, i.rsrp && `RSRP ${i.rsrp}`].filter(Boolean).join(" · ");
  return [i.speed, i.mac].filter(Boolean).join(" · ");
}

// LTE signal at a glance: RSRP/RSRQ/SINR with plain-English quality
function lteCard(ifaces) {
  const lte = ifaces.filter((i) => i.operator !== undefined);
  if (!lte.length) return "";
  const q = (v, good, ok) => (v == null || v === "" ? "" : Number(v) >= good ? "good" : Number(v) >= ok ? "warn" : "bad");
  const label = { good: "good", warn: "fair", bad: "poor", "": "" };
  return `<div class="card"><h2>LTE signal</h2>${lte.map((i) => `<p class="muted">${esc(i.name)} · ${esc(i.operator || "no operator")} · ${esc(i.access || "")} ${esc(i.band_lte || "")}${i.cell ? ` · cell ${esc(i.cell)}` : ""}</p>
    <div class="tiles">${[["RSRP", i.rsrp, "dBm", q(i.rsrp, -90, -105)], ["RSRQ", i.rsrq, "dB", q(i.rsrq, -10, -15)], ["SINR", i.sinr, "dB", q(i.sinr, 13, 0)],
      ["RSSI", i.rssi, "dBm", q(i.rssi, -65, -85)]].map(([k, v, u, c]) => `<div class="tile ${c}"><div class="v">${v ?? "—"}<span class="small"> ${u}</span></div>
      <div class="l">${k}${label[c] ? ` · ${label[c]}` : ""}</div></div>`).join("")}</div>`).join("")}</div>`;
}



async function clients() {
  const orgs = await api("/api/orgs");
  $("main").innerHTML = `<div class="row"><div><h1>Clients</h1><p class="muted">Each client sees only its own routers.</p></div><span class="spacer"></span></div>
    ${canWrite() ? `<div class="card"><form id="oForm" class="row"><input id="oName" placeholder="New client name" maxlength="120" required aria-label="Client name">
      <button class="btn primary" type="submit">Add client</button><span class="status" id="oStatus"></span></form></div>` : ""}
    <div class="card"><div class="table-wrap"><table><thead><tr><th>Client</th><th>Routers</th><th>Online</th><th>Offline</th></tr></thead><tbody>
      ${orgs.map((o) => `<tr><td>${esc(o.name)}</td><td>${o.devices}</td><td>${o.online || 0}</td><td>${o.offline ? `<span class="status err">${o.offline}</span>` : 0}</td></tr>`).join("") || `<tr><td colspan="4" class="muted">No clients yet.</td></tr>`}
    </tbody></table></div></div>`;
  $("oForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    try { await post("/api/orgs", { name: $("oName").value }); clients(); } catch (err) { $("oStatus").textContent = err.message; $("oStatus").className = "status err"; }
  });
}

async function users() {
  const [rows, orgs] = await Promise.all([api("/api/users"), isTech() ? api("/api/orgs") : Promise.resolve([])]);
  $("main").innerHTML = `<h1>Users</h1><p class="muted">${isTech() ? `${staffName()} sign in with Microsoft. Client users are invited and must set up an authenticator app.` : "People in your organization."}</p>
    ${(canWrite() || (me.kind === "client" && me.role === "admin")) ? `<div class="card"><h2>Invite a client user</h2><form id="iForm" class="row">
      ${isTech() ? `<select id="iOrg" aria-label="Client">${orgs.map((o) => `<option value="${o.id}">${esc(o.name)}</option>`).join("")}</select>` : ""}
      <input id="iEmail" type="email" placeholder="Email" required aria-label="Email"><input id="iName" placeholder="Name" aria-label="Name">
      <select id="iRole" aria-label="Role"><option value="viewer">Viewer</option><option value="admin">Client admin</option></select>
      <button class="btn primary" type="submit">Create invitation</button></form><div id="iResult"></div></div>` : ""}
    <div class="card"><div class="table-wrap"><table><thead><tr><th>Email</th><th>Name</th><th>Type</th>${isTech() ? "<th>Client</th>" : ""}<th>Role</th><th>MFA</th><th>Last sign-in</th><th></th></tr></thead><tbody>
      ${rows.map((u) => `<tr><td>${esc(u.email)}${u.disabled ? ` <span class="pill">disabled</span>` : ""}${u.invited ? ` <span class="pill">invited</span>` : ""}</td>
        <td>${esc(u.name)}</td><td>${u.kind === "tech" ? esc((window.BRAND && window.BRAND.company) || "Staff") : "Client"}</td>${isTech() ? `<td>${esc(u.org || "")}</td>` : ""}<td>${esc(u.role)}</td>
        <td>${u.kind === "tech" ? "Microsoft" : u.totp_enabled ? "✓" : "—"}</td><td>${ago(u.last_login)}</td>
        <td class="row">${u.email === me.email ? "" : `
          ${u.invited ? `<button class="btn" type="button" data-act="resend" data-id="${u.id}">New link</button>` : ""}
          ${u.kind === "client" && u.totp_enabled ? `<button class="btn" type="button" data-act="reset-mfa" data-id="${u.id}">Reset MFA</button>` : ""}
          <button class="btn" type="button" data-act="${u.disabled ? "enable" : "disable"}" data-id="${u.id}">${u.disabled ? "Enable" : "Disable"}</button>`}</td></tr>`).join("")}
    </tbody></table></div></div>`;
  $("iForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const r = await post("/api/users/invite", { org_id: $("iOrg")?.value, email: $("iEmail").value, name: $("iName").value, role: $("iRole").value });
      $("iResult").innerHTML = `<p>Send this link to the person (valid ${r.expires_days} days). They'll choose a password and set up their authenticator app.</p><div class="code">${esc(r.link)}</div>`;
      setTimeout(users, 15000);
    } catch (err) { $("iResult").innerHTML = `<p class="status err">${esc(err.message)}</p>`; }
  });
  document.querySelectorAll("[data-act]").forEach((b) => b.addEventListener("click", async () => {
    try {
      const r = await post(`/api/users/${b.dataset.id}/${b.dataset.act}`);
      if (r.link) { dialog(`<h2>New invitation link</h2><div class="code">${esc(r.link)}</div><div class="actions"><button class="btn" type="button" data-close>Done</button></div>`); }
      else users();
    } catch (err) { alert(err.message); }
  }));
}

// --- Admin: branding, technicians, system ---------------------------------------------------------------------
async function admin(tab = "branding") {
  $("main").innerHTML = `<h1>Admin</h1><div class="tabs" role="tablist">
      ${[["branding", "Branding"], ["techs", "Technicians"], ["integrations", "Integrations"], ["system", "Settings"]].map(([k, l]) => `<button type="button" role="tab" data-tab="${k}" class="${k === tab ? "active" : ""}">${l}</button>`).join("")}
    </div><div id="adminBody"></div>`;
  document.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => admin(b.dataset.tab)));
  const tabs = { branding: adminBranding, techs: adminTechs, integrations: adminIntegrations, system: adminSystem };
  await (tabs[tab] || adminBranding)();
}

async function adminBranding() {
  const b = await api("/api/branding");
  $("adminBody").innerHTML = `<div class="card"><h2>Branding</h2><p class="muted">Shown to everyone, including clients on the sign-in page.</p>
    <div class="grid2">
      <label class="field">Product name <input id="bProduct" value="${esc(b.product)}" maxlength="60"></label>
      <label class="field">Company name <input id="bCompany" value="${esc(b.company)}" maxlength="60"></label>
      <label class="field">Accent colour <span class="row"><input id="bAccent" type="color" value="${esc(b.accent)}"><span class="mono" id="bAccentHex">${esc(b.accent)}</span></span></label>
      <label class="field">Support email (shown to clients) <input id="bEmail" type="email" value="${esc(b.support_email)}" maxlength="120"></label>
      <label class="field">Support phone <input id="bPhone" value="${esc(b.support_phone)}" maxlength="40"></label>
    </div>
    <label class="field">Message on the sign-in page <textarea id="bMsg" rows="2" maxlength="500">${esc(b.login_message)}</textarea></label>
    <div class="actions"><button class="btn primary" type="button" id="bSave">Save branding</button><span class="status" id="bStatus"></span></div></div>
    <div class="card"><h2>Logo</h2><p class="muted">PNG, JPEG or WebP, up to 512 KB; wide logos look best (about 4:1). Shown next to the product name.</p>
      <div class="row">${b.logo_url ? `<img class="logo-preview" src="${esc(b.logo_url)}" alt="Current logo">` : `<span class="muted">No logo yet.</span>`}
        <input type="file" id="bLogo" accept="image/png,image/jpeg,image/webp">
        ${b.logo_url ? `<button class="btn danger" type="button" id="bLogoRemove">Remove logo</button>` : ""}<span class="status" id="lStatus"></span></div></div>`;
  $("bAccent").addEventListener("input", () => { $("bAccentHex").textContent = $("bAccent").value; applyBrand({ ...b, accent: $("bAccent").value }); });
  const say = (id, t, k) => { $(id).textContent = t; $(id).className = `status ${k || ""}`; };
  $("bSave").addEventListener("click", async () => {
    try {
      const r = await post("/api/admin/branding", { product: $("bProduct").value, company: $("bCompany").value, accent: $("bAccent").value,
        support_email: $("bEmail").value, support_phone: $("bPhone").value, login_message: $("bMsg").value });
      applyBrand(r); say("bStatus", "Saved.", "ok");
    } catch (e) { say("bStatus", e.message, "err"); }
  });
  $("bLogo").addEventListener("change", () => {
    const f = $("bLogo").files[0];
    if (!f) return;
    if (f.size > 512 * 1024) { say("lStatus", "That file is over 512 KB.", "err"); return; }
    const rd = new FileReader();
    rd.onload = async () => {
      try { const r = await post("/api/admin/branding/logo", { data: rd.result }); applyBrand(r); adminBranding(); }
      catch (e) { say("lStatus", e.message, "err"); }
    };
    rd.readAsDataURL(f);
  });
  $("bLogoRemove")?.addEventListener("click", async () => { const r = await post("/api/admin/branding/logo", { data: "" }); applyBrand(r); adminBranding(); });
}

async function adminTechs() {
  const techs = (await api("/api/users")).filter((u) => u.kind === "tech");
  $("adminBody").innerHTML = `<div class="card"><h2>Technicians</h2><p class="muted">${staffName()} sign in with Microsoft and appear here after their first sign-in.
      <strong>Admin</strong>: everything, including this page. <strong>Tech</strong>: adopt, manage and back up routers, invite client users.
      <strong>Read-only</strong>: view only.</p>
    <div class="table-wrap"><table><thead><tr><th>Email</th><th>Name</th><th>Role</th><th>Last sign-in</th><th></th></tr></thead><tbody>
    ${techs.map((u) => `<tr><td>${esc(u.email)}${u.disabled ? ` <span class="pill">disabled</span>` : ""}</td><td>${esc(u.name)}</td>
      <td><select data-role="${u.id}" ${u.email === me.email ? "disabled" : ""}>${["admin", "tech", "readonly"].map((r) => `<option value="${r}" ${u.role === r ? "selected" : ""}>${r === "readonly" ? "Read-only" : r[0].toUpperCase() + r.slice(1)}</option>`).join("")}</select></td>
      <td>${ago(u.last_login)}</td><td class="nowrap">${u.email === me.email ? "" : `<button class="btn" type="button" data-act="${u.disabled ? "enable" : "disable"}" data-id="${u.id}">${u.disabled ? "Enable" : "Disable"}</button>
        <button class="btn" type="button" data-act="reset-mfa" data-id="${u.id}" title="Unlinks the Microsoft account (for a renamed or replaced account) and resets the authenticator app">Reset sign-in</button>`}</td></tr>`).join("")}
    </tbody></table></div><span class="status" id="tStatus"></span></div>`;
  document.querySelectorAll("[data-role]").forEach((s) => s.addEventListener("change", async () => {
    try { await post(`/api/users/${s.dataset.role}/role`, { role: s.value }); $("tStatus").textContent = "Saved."; $("tStatus").className = "status ok"; }
    catch (e) { $("tStatus").textContent = e.message; $("tStatus").className = "status err"; adminTechs(); }
  }));
  document.querySelectorAll("#adminBody [data-act]").forEach((b) => b.addEventListener("click", async () => { await post(`/api/users/${b.dataset.id}/${b.dataset.act}`); adminTechs(); }));
}

// --- Admin > Integrations: ConnectWise PSA and IT Glue ---------------------------------------------------------------
// Keys are typed here and stored encrypted on the server; saved secrets are never sent back (the field shows "saved").
const intView = { q: "" };
async function adminIntegrations() {
  const r = await api("/api/integrations");
  const field = (kind, k, label, o = {}) => `<label class="field">${label}
    <input id="i_${kind}_${k}" ${o.secret ? `type="password" autocomplete="new-password" placeholder="${r[kind][`${k}_set`] ? "saved - leave blank to keep" : ""}"` : `value="${esc(r[kind][k] || "")}" placeholder="${esc(o.ph || "")}"`} spellcheck="false"></label>`;
  const pill = (c) => c ? `<span class="pill up-done">Set up</span>` : `<span class="pill">Not set up</span>`;
  $("adminBody").innerHTML = `
    <div class="card"><div class="row"><h2>ConnectWise PSA</h2>${pill(r.cw.configured)}</div>
      <p class="small muted">Import companies as TikManager clients, or link the clients you already have. Create an API member
        (System > Members > API Members) with a read-only security role, then generate its keys. The client ID comes from developer.connectwise.com.</p>
      <div class="grid2">${field("cw", "site", "Site", { ph: "api-na.myconnectwise.net" })}${field("cw", "company", "Company ID")}
        ${field("cw", "public_key", "Public key")}${field("cw", "private_key", "Private key", { secret: true })}
        ${field("cw", "client_id", "Client ID")}${field("cw", "codebase", "Codebase", { ph: "v4_6_release" })}</div>
      <div class="actions"><button class="btn primary" type="button" data-isave="cw">Save</button><button class="btn" type="button" data-itest="cw">Test connection</button>
        <span class="status" id="iStatus_cw"></span></div>
      ${r.cw.configured ? `<h3>Companies</h3><div class="row"><input id="cwQ" type="search" placeholder="Search companies" value="${esc(intView.q)}">
        <label class="chk"><input type="checkbox" id="cwActive" ${r.cw.active_only !== "0" ? "checked" : ""}> Active only</label><span class="spacer"></span>
        <button class="btn" type="button" id="cwLoad">Refresh from PSA</button></div>
        <div class="cw-types" id="cwTypes"></div><div id="cwBody"><p class="muted small">Loading companies...</p></div>` : ""}
    </div>
    <div class="card"><div class="row"><h2>IT Glue</h2>${pill(r.itg.configured)}</div>
      <p class="small muted">Document every router in IT Glue as a configuration (name, model, serial, WAN IP, RouterOS version and a link back here).
        Create the key under Account > Settings > API Keys - leave "Password access" off.</p>
      <div class="grid2"><label class="field">Region <select id="i_itg_region">${[["us", "United States"], ["eu", "Europe"], ["au", "Australia"]].map(([v, l]) => `<option value="${v}" ${r.itg.region === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>
        ${field("itg", "api_key", "API key", { secret: true })}</div>
      <div class="actions"><button class="btn primary" type="button" data-isave="itg">Save</button><button class="btn" type="button" data-itest="itg">Test connection</button>
        <span class="status" id="iStatus_itg"></span></div>
      ${r.itg.configured ? `<div id="itgBody"><p class="muted small">Loading IT Glue organizations...</p></div>` : ""}
    </div>`;
  const say = (kind, msg, ok) => { $(`iStatus_${kind}`).textContent = msg; $(`iStatus_${kind}`).className = `status ${ok ? "ok" : "err"}`; };
  document.querySelectorAll("[data-isave]").forEach((b) => b.addEventListener("click", async () => {
    const kind = b.dataset.isave, body = {};
    document.querySelectorAll(`[id^="i_${kind}_"]`).forEach((el) => { body[el.id.slice(kind.length + 3)] = el.value; });
    try { await post(`/api/integrations/${kind}`, body); await adminIntegrations(); say(kind, "Saved.", true); } catch (e) { say(kind, e.message); }
  }));
  document.querySelectorAll("[data-itest]").forEach((b) => b.addEventListener("click", async () => {
    const kind = b.dataset.itest;
    say(kind, "Testing...", true);
    try { const x = await post(`/api/integrations/${kind}/test`); say(kind, x.detail, x.ok); } catch (e) { say(kind, e.message); }
  }));
  if (r.cw.configured) loadCw(false);
  if (r.itg.configured) loadItg(r, false);
}

// Which ConnectWise company types count as customers: saved on the server; first time, everything except the usual
// non-customer types (vendors, prospects, partners, former clients...) is ticked.
const NOT_CUSTOMER = /\b(vendors?|suppliers?|prospects?|leads?|partners?|competitors?|former|inactive|distributors?|manufacturers?|carriers?|isps?|internal|not[- ]?a[- ]?fit)\b/i;
const INACTIVE = /inactive|no longer|not[- ]?approved|deleted|former|closed|cancel/i;
const NO_TYPE = "(no type)";
async function loadCw(refresh) {
  let x, cfg;
  try { [x, cfg] = await Promise.all([api(`/api/integrations/cw/companies${refresh ? "?refresh=1" : ""}`), api("/api/integrations")]); }
  catch (e) { $("cwBody").innerHTML = `<p class="status err">${esc(e.message)}</p>`; return; }
  const typesOf = (c) => (c.types ? c.types.split(", ").filter(Boolean) : []).concat(c.types ? [] : [NO_TYPE]);
  const counts = {};
  x.companies.forEach((c) => typesOf(c).forEach((t) => { counts[t] = (counts[t] || 0) + 1; }));
  const types = Object.keys(counts).sort((a, b) => a.localeCompare(b));
  // saved as {show, known}: types first seen later start ticked unless they look like vendors, prospects, etc.
  let saved = null;
  try { saved = cfg.cw.show_types ? JSON.parse(cfg.cw.show_types) : null; } catch { saved = null; }
  if (Array.isArray(saved)) saved = { show: saved, known: types };   // older format: everything present was a deliberate choice
  const known = new Set(saved ? saved.known : []);
  const byDefault = (t) => t !== NO_TYPE && !NOT_CUSTOMER.test(t);
  const shown = new Set(types.filter((t) => (saved && known.has(t) ? saved.show.includes(t) : byDefault(t))));
  let active = cfg.cw.active_only !== "0";
  const persist = () => post("/api/integrations/cw", { show_types: JSON.stringify({ show: [...shown], known: [...new Set([...known, ...types])] }),
                                                      active_only: active ? "1" : "0" }).catch(() => {});
  $("cwTypes").innerHTML = `<span class="small muted">Show types:</span> ${types.map((t) => `<label class="chk"><input type="checkbox" data-cwtype="${esc(t)}" ${shown.has(t) ? "checked" : ""}>
    ${esc(t)} <span class="muted small">(${counts[t]})</span></label>`).join("")}`;
  const isActive = (c) => !INACTIVE.test(c.status || "");
  const free = x.orgs.filter((o) => !o.cw_id);
  const draw = () => {
    const q = intView.q.toLowerCase();
    const hit = (c) => !q || `${c.name} ${c.identifier}`.toLowerCase().includes(q);
    const typeOk = (c) => typesOf(c).some((t) => shown.has(t));
    const rows = x.companies.filter((c) => hit(c) && (c.org || (typeOk(c) && (!active || isActive(c)))));   // linked ones always show
    // a search that matches companies the filters hide says which and why (e.g. a customer with no type set)
    const hidden = q ? x.companies.filter((c) => hit(c) && !rows.includes(c)) : [];
    $("cwBody").innerHTML = `<p class="small muted">${rows.length} companies shown of ${x.companies.length} in ConnectWise · ${x.companies.filter((c) => c.org).length} linked</p>
      ${q && !rows.length && !hidden.length ? `<p class="small status warn" id="cwFind">No company in the list matches "${esc(intView.q)}" - asking ConnectWise directly...</p>` : ""}
      ${hidden.length ? `<p class="small status warn">Hidden by the filters: ${hidden.slice(0, 10).map((c) => `${esc(c.name)} (type: ${esc(c.types || "none")}, status: ${esc(c.status || "none")})`).join("; ")}${hidden.length > 10 ? ` and ${hidden.length - 10} more` : ""}</p>` : ""}
      <div class="table-wrap"><table><thead><tr><th>Company</th><th>Type</th><th>Status</th><th>TikManager client</th></tr></thead><tbody>
      ${rows.slice(0, 2000).map((c) => `<tr><td><b>${esc(c.name)}</b> <span class="small muted mono">${esc(c.identifier)}</span></td><td class="small">${esc(c.types || "—")}</td>
        <td class="small">${esc(c.status)}</td><td>${c.org ? `<span class="status ok">${esc(c.org.name)}</span> <button class="btn" type="button" data-unlink="${c.org.id}">Unlink</button>`
          : `<div class="row">${c.suggest ? `<button class="btn" type="button" data-link="${c.id}" data-org="${c.suggest.id}">Link to ${esc(c.suggest.name)}</button>` : ""}
            ${free.length ? `<select data-pick="${c.id}" aria-label="Link to client"><option value="">Link to...</option>${free.map((o) => `<option value="${o.id}">${esc(o.name)}</option>`).join("")}</select>` : ""}
            <button class="btn" type="button" data-import="${c.id}">Import as new client</button></div>`}</td></tr>`).join("")}</tbody></table></div>`;
    if ($("cwFind")) {   // not in the list at all: deleted in ConnectWise, or the API member can't see it
      const asked = intView.q;
      clearTimeout(loadCw.findTimer);
      loadCw.findTimer = setTimeout(async () => {
        if (intView.q !== asked || !$("cwFind")) return;
        try {
          const f = (await api(`/api/integrations/cw/find?q=${encodeURIComponent(asked)}`)).results;
          const inList = (id) => x.companies.some((c) => c.id === id);
          $("cwFind").innerHTML = f.length ? f.map((c) => `${esc(c.name)}: ${c.deleted ? "marked <b>deleted</b> in ConnectWise" : inList(c.id) ? "in the list" :
              `exists (type: ${esc(c.types || "none")}, status: ${esc(c.status || "none")}) but wasn't in the list - click Refresh from PSA`}`).join("<br>")
            : `ConnectWise returned no company matching "${esc(asked)}" to TikManager's API member - check the spelling, or the member's security role
               (Companies: Inquire level "All", no location / business unit restriction).`;
        } catch (e) { $("cwFind").textContent = e.message; }
      }, 500);
    }
    const act = async (body) => { try { await post("/api/integrations/cw/link", body); loadCw(false); } catch (e) { alert(e.message); } };
    $("cwBody").querySelectorAll("[data-link]").forEach((b) => b.addEventListener("click", () => act({ cw_id: b.dataset.link, org_id: b.dataset.org })));
    $("cwBody").querySelectorAll("[data-pick]").forEach((s) => s.addEventListener("change", () => s.value && act({ cw_id: s.dataset.pick, org_id: s.value })));
    $("cwBody").querySelectorAll("[data-import]").forEach((b) => b.addEventListener("click", () => act({ cw_id: b.dataset.import })));
    $("cwBody").querySelectorAll("[data-unlink]").forEach((b) => b.addEventListener("click", async () => { await post("/api/integrations/cw/unlink", { org_id: b.dataset.unlink }); loadCw(false); }));
  };
  $("cwTypes").querySelectorAll("[data-cwtype]").forEach((c) => c.addEventListener("change", () => { c.checked ? shown.add(c.dataset.cwtype) : shown.delete(c.dataset.cwtype); persist(); draw(); }));
  $("cwQ").oninput = (e) => { intView.q = e.target.value; draw(); };
  $("cwActive").onchange = (e) => { active = e.target.checked; persist(); draw(); };
  $("cwLoad").onclick = () => loadCw(true);
  draw();
}
async function loadItg(r, refresh) {
  let x;
  try { x = await api(`/api/integrations/itg/orgs${refresh ? "?refresh=1" : ""}`); }
  catch (e) { $("itgBody").innerHTML = `<p class="status err">${esc(e.message)}</p>`; return; }
  const ls = r.itg_last_sync, opt = (rows, cur) => rows.map((o) => `<option value="${esc(o.id)}" ${String(cur) === String(o.id) ? "selected" : ""}>${esc(o.name)}</option>`).join("");
  $("itgBody").innerHTML = `<h3>Router documentation</h3><div class="grid2">
      <label class="field">Configuration type for routers <select id="itgType"><option value="">Pick one...</option>${opt(x.types, r.itg.config_type_id)}</select></label>
      <label class="field">Configuration status <select id="itgStatus"><option value="">(IT Glue default)</option>${opt(x.statuses, r.itg.config_status_id)}</select></label></div>
    <label class="chk"><input type="checkbox" id="itgNightly" ${r.itg.sync === "1" ? "checked" : ""}> Update IT Glue every night</label>
    <div class="actions"><button class="btn primary" type="button" id="itgSave">Save</button><button class="btn" type="button" id="itgSync" ${r.itg.config_type_id ? "" : "disabled"}>Sync now</button>
      <button class="btn" type="button" id="itgRefresh">Refresh from IT Glue</button><span class="status" id="itgMsg"></span></div>
    <p class="small muted">${r.itg_sync && r.itg_sync.running ? "A sync is running now..." : ls ? `Last sync ${ago(ls.finished)}: ${ls.ok} updated, ${ls.failed} failed, ${ls.skipped} skipped (client not linked).` : "Not synced yet."}</p>
    ${x.errors.length ? `<ul class="small status err">${x.errors.map((e) => `<li>${esc(e.name)}: ${esc(e.itg_error)}</li>`).join("")}</ul>` : ""}
    <h3>Clients</h3><div class="table-wrap"><table><thead><tr><th>TikManager client</th><th>Routers</th><th>IT Glue organization</th></tr></thead><tbody>
    ${x.clients.map((c) => `<tr><td><b>${esc(c.name)}</b></td><td class="small">${c.routers}${c.routers ? ` · ${c.synced || 0} in IT Glue${c.errors ? ` · <span class="status err">${c.errors} failed</span>` : ""}` : ""}</td>
      <td><div class="row"><select data-itg="${c.id}" aria-label="IT Glue organization for ${esc(c.name)}"><option value="">Not linked</option>${opt(x.orgs, c.itg_id)}</select>
        ${!c.itg_id && c.suggest ? `<button class="btn" type="button" data-itgsug="${c.id}" data-val="${esc(c.suggest)}">Link to ${esc((x.orgs.find((o) => o.id === c.suggest) || {}).name || "")}</button>` : ""}</div></td></tr>`).join("")}
    </tbody></table></div>`;
  const msg = (m, ok) => { $("itgMsg").textContent = m; $("itgMsg").className = `status ${ok ? "ok" : "err"}`; };
  const link = async (org, val) => { try { await post("/api/integrations/itg/link", { org_id: org, itg_id: val }); loadItg(r, false); } catch (e) { msg(e.message); } };
  $("itgBody").querySelectorAll("[data-itg]").forEach((s) => s.addEventListener("change", () => link(s.dataset.itg, s.value)));
  $("itgBody").querySelectorAll("[data-itgsug]").forEach((b) => b.addEventListener("click", () => link(b.dataset.itgsug, b.dataset.val)));
  $("itgSave").onclick = async () => {
    try {
      await post("/api/integrations/itg", { config_type_id: $("itgType").value, config_status_id: $("itgStatus").value, sync: $("itgNightly").checked ? "1" : "0" });
      r = await api("/api/integrations"); loadItg(r, false);
    } catch (e) { msg(e.message); }
  };
  $("itgSync").onclick = async () => {
    try { await post("/api/integrations/itg/sync"); msg("Syncing in the background - refresh in a minute to see the results.", true); } catch (e) { msg(e.message); }
  };
  $("itgRefresh").onclick = () => loadItg(r, true);
}
async function adminSystem() {
  const s = await api("/api/admin/system");
  const f = (id, label, val, o = {}) => `<label class="field">${label} <input id="${id}" value="${esc(val || "")}" placeholder="${esc(o.ph || "")}" ${o.type ? `type="${o.type}"` : ""} spellcheck="false" ${o.auto ? `autocomplete="${o.auto}"` : ""}></label>`;
  $("adminBody").innerHTML = `
    <div class="card" id="verCard"><h2>Version &amp; updates</h2><p class="muted">Loading…</p></div>
    <div class="card"><h2>Staff sign-in</h2>
      <p class="muted">Your technicians sign in with Microsoft. Anyone from these email domains becomes a technician at first sign-in;
        the listed emails become administrators. Roles can be changed on the Technicians tab.</p>
      <div class="grid2">${f("cfDomains", "Staff email domains (comma-separated)", s.tech_domains, { ph: "example.com" })}
        ${f("cfAdmins", "Administrator emails (comma-separated)", s.tech_admins, { ph: "you@example.com" })}</div>
      <h3>Microsoft sign-in (Entra ID)</h3>
      <p class="small muted">In Entra admin center: App registrations > New registration (single tenant). Redirect URI (Web):
        <span class="mono">${esc(s.redirect_uri)}</span>. Then Certificates &amp; secrets > New client secret.</p>
      <div class="grid2">${f("cfTenant", "Directory (tenant) ID", s.entra_tenant_id, { ph: "00000000-0000-0000-0000-000000000000" })}
        ${f("cfClient", "Application (client) ID", s.entra_client_id, { ph: "00000000-0000-0000-0000-000000000000" })}
        <label class="field">Client secret <input id="cfSecret" type="password" autocomplete="new-password" placeholder="${s.entra_client_secret_set ? "saved - leave blank to keep" : ""}"></label></div>
      <h3>Routers</h3>
      <div class="grid2">${f("cfEndpoint", "WireGuard address routers connect to", s.wg_endpoint, { ph: "tikmanager.example.com:51820" })}
        ${f("cfPing", "Latency test target", s.ping_target, { ph: "1.1.1.1" })}</div>
      <p class="small muted">Change the WireGuard address only if routers must reach this server by a different name or port than the web address
        (the adoption command uses it; routers already adopted keep the address they were given).</p>
      <div class="actions"><button class="btn primary" type="button" id="cfSave">Save settings</button><span class="status" id="cfStatus"></span></div>
    </div>
    <div class="card"><h2>Backups</h2><div class="row">
      <label class="field">Nightly backup time (server clock) <select id="sHour">${Array.from({ length: 24 }, (_, h) => `<option value="${h}" ${h === s.backup_hour ? "selected" : ""}>${String(h).padStart(2, "0")}:00</option>`).join("")}</select></label>
      <label class="field">Versions to keep per router <input id="sKeep" type="number" min="1" max="100" value="${s.backup_keep_versions}"></label>
      <button class="btn primary" type="button" id="sSave">Save</button><span class="status" id="sStatus"></span></div>
      <p class="small muted">A new version is saved only when the configuration changes; when a router has more than this, the oldest is removed. Stored configurations are encrypted with ${esc(s.encryption)}.</p></div>
    <div class="card"><h2>About this installation</h2><div class="grid2">
      ${[["Public address", s.public_url], ["WireGuard address", s.wg_endpoint], ["Controller WireGuard key", s.wg_server_pubkey], ["Tunnel network", s.wg_network],
         ["Data folder", s.data_dir], ["Approved routers", s.routers], ["Stored backup versions", s.backups]]
        .map(([k, v]) => `<div class="kv"><span>${k}</span><span class="mono">${esc(v)}</span></div>`).join("")}</div>
      <p class="small muted">The public address is set when TikManager is installed (the HTTPS certificate depends on it).</p></div>`;
  versionCard();
  const say = (id, m, ok) => { $(id).textContent = m; $(id).className = `status ${ok ? "ok" : "err"}`; };
  $("cfSave").addEventListener("click", async () => {
    try {
      await post("/api/admin/settings", { tech_domains: $("cfDomains").value, tech_admins: $("cfAdmins").value, entra_tenant_id: $("cfTenant").value,
        entra_client_id: $("cfClient").value, entra_client_secret: $("cfSecret").value, wg_endpoint: $("cfEndpoint").value, ping_target: $("cfPing").value });
      await adminSystem(); say("cfStatus", "Saved.", true);
    } catch (e) { say("cfStatus", e.message); }
  });
  $("sSave").addEventListener("click", async () => {
    try { await post("/api/admin/system", { backup_hour: $("sHour").value, backup_keep_versions: $("sKeep").value }); say("sStatus", "Saved.", true); }
    catch (e) { say("sStatus", e.message); }
  });
}

async function audit() {
  const rows = await api("/api/audit");
  $("main").innerHTML = `<h1>Audit log</h1><p class="muted">Every sign-in and change, newest first (last 500).</p>
    <div class="card"><div class="table-wrap"><table><thead><tr><th>When</th><th>Who</th><th>Action</th><th>What</th><th>From</th><th>Detail</th></tr></thead><tbody>
    ${rows.map((a) => `<tr><td>${when(a.ts)}</td><td>${esc(a.user)}</td><td>${esc(a.action)}</td><td>${esc(a.target)}</td><td class="mono">${esc(a.ip)}</td><td class="muted">${esc(a.detail)}</td></tr>`).join("")}
    </tbody></table></div></div>`;
}

// --- firmware upgrades: now, scheduled, or many routers at once -----------------------------------------------------
function vkey(v) {   // "7.20.2 (stable)" -> comparable array; betas/rcs sort before the release
  const s = String(v || "").split(" ")[0], base = s.split(/beta|rc/)[0];
  return base.split(".").map(Number).concat(/beta|rc/.test(s) ? [0] : [1]);
}
const newer = (a, b) => { const x = vkey(a), y = vkey(b); for (let i = 0; i < Math.max(x.length, y.length); i++) { if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0); } return false; };
const hasUpdate = (d) => !!d.ros_latest && newer(d.ros_latest, d.version);
const fwUpdate = (d) => !!d.fw_upgrade && !!d.fw_current && newer(d.fw_upgrade, d.fw_current);
const shortVer = (v) => String(v || "").split(" ")[0];
function upStatus(j) {
  if (!j) return "";
  if (j.status === "running") return `<span class="pill up-run">Upgrading</span> <span class="small muted">${esc(j.step || "")}</span>`;
  if (j.status === "scheduled") return `<span class="pill up-sched">Scheduled</span> <span class="small muted">${when(j.scheduled_at)}</span>`;
  return `<span class="pill up-${j.status}">${esc({ done: "Done", failed: "Failed", cancelled: "Cancelled" }[j.status] || j.status)}</span>`;
}

function upgradeDialog(list, onDone) {
  const bulk = list.length > 1, avail = list.filter(hasUpdate).length;
  const t = new Date(); t.setDate(t.getDate() + (t.getHours() >= 2 ? 1 : 0)); t.setHours(2, 0, 0, 0);   // default: 02:00 tonight
  const local = (d) => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  dialog(`<h2>Upgrade ${bulk ? `${list.length} routers` : esc(list[0].name)}</h2>
    <p class="small muted">${bulk ? `${avail} of ${list.length} have a newer RouterOS available: ${esc(list.slice(0, 6).map((d) => d.name).join(", "))}${list.length > 6 ? ` and ${list.length - 6} more` : ""}.`
      : `RouterOS ${esc(shortVer(list[0].version))}${hasUpdate(list[0]) ? ` → <b>${esc(list[0].ros_latest)}</b> available` : list[0].ros_latest ? " (newest on its channel)" : ""}${list[0].fw_current ? ` · RouterBOARD ${esc(list[0].fw_current)}` : ""}`}</p>
    <fieldset class="up-when"><legend class="small muted">When</legend>
      <label class="chk"><input type="radio" name="upWhen" value="now" checked> Now</label>
      <label class="chk"><input type="radio" name="upWhen" value="later"> Later: <input type="datetime-local" id="upAt" value="${local(t)}" min="${local(new Date())}"></label>
    </fieldset>
    <div class="grid2">
      <label class="field">Update channel <select id="upChan"><option value="">Router's current channel</option><option value="stable">stable</option><option value="long-term">long-term</option></select></label>
      ${bulk ? `<label class="field">Stagger (minutes between routers) <input id="upStag" type="number" min="0" max="240" value="0"></label>` : ""}
    </div>
    <label class="chk"><input type="checkbox" id="upFw" checked> Also update the RouterBOARD firmware (one more reboot)</label>
    <p class="small muted">Each router is backed up first (the upgrade stops if the backup fails), then reboots - expect 2-5 minutes offline per reboot.
      ${bulk ? "At most 4 routers upgrade at the same time; with a stagger they start one after another." : ""}</p>
    <div class="actions"><button class="btn primary" type="button" id="upOk">Upgrade now</button><button class="btn" type="button" data-close>Cancel</button>
      <span class="status" id="upStatus"></span></div>`);
  const sync = () => { $("upOk").textContent = document.querySelector("[name=upWhen]:checked").value === "now" ? "Upgrade now" : "Schedule"; };
  document.querySelectorAll("[name=upWhen]").forEach((r) => r.addEventListener("change", sync));
  $("upAt").addEventListener("focus", () => { document.querySelector("[name=upWhen][value=later]").checked = true; sync(); });
  $("upOk").addEventListener("click", async () => {
    const later = document.querySelector("[name=upWhen]:checked").value === "later";
    const at = later ? new Date($("upAt").value).getTime() / 1000 : null;
    if (later && !(at > Date.now() / 1000 - 60)) { $("upStatus").textContent = "Pick a time in the future."; $("upStatus").className = "status err"; return; }
    $("upOk").disabled = true;
    try {
      const r = await post("/api/upgrades", { device_ids: list.map((d) => d.id), when: at, channel: $("upChan").value, firmware: $("upFw").checked,
                                              stagger: $("upStag") ? $("upStag").value : 0 });
      if (r.skipped.length) {
        dialog(`<h2>${r.created ? `${r.created} upgrade${r.created === 1 ? "" : "s"} ${later ? "scheduled" : "started"}` : "Nothing scheduled"}</h2>
          <p class="small">Skipped:</p><ul class="small">${r.skipped.map((x) => `<li>${esc(x.name)} - ${esc(x.reason)}</li>`).join("")}</ul>
          <div class="actions"><button class="btn" type="button" data-close>OK</button></div>`);
      } else $("dlg").close();
      onDone && onDone();
    } catch (e) { $("upOk").disabled = false; $("upStatus").textContent = e.message; $("upStatus").className = "status err"; }
  });
}

const upView = { q: "", org: "", only: false, sel: new Set() };
async function upgradesView() {
  const r = await api("/api/upgrades");
  const active = new Map(r.jobs.filter((j) => j.status === "scheduled" || j.status === "running").map((j) => [j.device_id, j]));
  const ids = new Set(r.routers.map((d) => d.id));
  upView.sel.forEach((id) => { if (!ids.has(id)) upView.sel.delete(id); });
  const orgs = [...new Map(r.routers.map((d) => [d.org_id, d.org || "Unassigned"])).entries()];
  const count = (st) => r.jobs.filter((j) => j.status === st).length;
  $("main").innerHTML = `<h1>Upgrades</h1><p class="muted">RouterOS and RouterBOARD firmware - upgrade now, schedule it, or pick many routers at once.</p>
    <div class="tiles">
      <div class="tile ${r.routers.some(hasUpdate) ? "warn" : "good"}"><div class="v">${r.routers.filter(hasUpdate).length}</div><div class="l">Routers with a RouterOS update</div></div>
      <div class="tile"><div class="v">${count("scheduled")}</div><div class="l">Scheduled</div></div>
      <div class="tile"><div class="v">${count("running")}</div><div class="l">Upgrading now</div></div>
      <div class="tile ${count("failed") ? "bad" : ""}"><div class="v">${count("failed")}</div><div class="l">Failed (30 days)</div></div>
    </div>
    <div class="card">
      <div class="row"><input id="upQ" type="search" placeholder="Search routers" value="${esc(upView.q)}">
        ${orgs.length > 1 ? `<select id="upOrg"><option value="">All clients</option>${orgs.map(([id, n]) => `<option value="${id}">${esc(n)}</option>`).join("")}</select>` : ""}
        <label class="chk"><input type="checkbox" id="upOnly" ${upView.only ? "checked" : ""}> Only routers with an update</label>
        <span class="spacer"></span>
        ${canWrite() ? `<button class="btn" type="button" id="upCheck">Check for updates</button>
        <button class="btn primary" type="button" id="upGo" disabled>Upgrade selected</button>` : ""}</div>
      <p class="small muted" id="upMsg"></p>
      <div class="table-wrap"><table><thead><tr>${canWrite() ? `<th><input type="checkbox" id="upAll" aria-label="Select all shown"></th>` : ""}<th></th><th>Router</th><th>Model</th>
        <th>RouterOS</th><th>Newest</th><th>RouterBOARD</th><th>Upgrade</th></tr></thead><tbody id="upRows"></tbody></table></div>
    </div>
    <div class="card"><h2>Upgrade jobs</h2>${r.jobs.length ? `<div class="table-wrap"><table><thead><tr><th>When</th><th>Router</th><th>Client</th><th>Change</th><th>Status</th><th>By</th><th></th></tr></thead><tbody>
      ${r.jobs.map((j) => `<tr><td class="nowrap">${when(j.finished_at || j.started_at || j.scheduled_at)}</td><td><a href="#router/${j.device_id}">${esc(j.device)}</a></td><td>${esc(j.org || "")}</td>
        <td class="nowrap">${esc(j.from_version || "")}${j.to_version && j.to_version !== j.from_version ? ` → ${esc(j.to_version)}` : ""}${j.channel ? ` <span class="small muted">(${esc(j.channel)})</span>` : ""}</td>
        <td>${upStatus(j)}${j.detail ? `<div class="small muted">${esc(j.detail)}</div>` : ""}</td><td class="small">${esc(j.created_by || "")}</td>
        <td>${j.status === "scheduled" && canWrite() ? `<button class="btn" type="button" data-cancel="${j.id}">Cancel</button>` : ""}</td></tr>`).join("")}
      </tbody></table></div>` : `<p class="muted">No upgrades yet.</p>`}</div>`;
  if ($("upOrg")) $("upOrg").value = upView.org;
  let shown = [];
  const draw = () => {
    const q = upView.q.toLowerCase();
    shown = r.routers.filter((d) => (!upView.org || String(d.org_id) === upView.org) && (!upView.only || hasUpdate(d) || fwUpdate(d)) &&
      (!q || [d.name, d.org, d.model, d.version].some((v) => (v || "").toLowerCase().includes(q))));
    $("upRows").innerHTML = shown.map((d) => `<tr>${canWrite() ? `<td><input type="checkbox" data-sel="${d.id}" ${upView.sel.has(d.id) ? "checked" : ""} aria-label="Select ${esc(d.name)}"></td>` : ""}
      <td>${thumbImg(d, "thumb-sm")}</td>
      <td><a href="#router/${d.id}"><b>${esc(d.name)}</b></a><div class="small muted"><span class="dot ${d.online ? "on" : "off"}"></span>${esc(d.org || "Unassigned")}</div></td>
      <td class="small">${esc(d.model || "")}</td><td class="mono">${esc(shortVer(d.version))}</td>
      <td>${d.ros_latest ? `${hasUpdate(d) ? `<b class="status warn">${esc(d.ros_latest)}</b>` : `<span class="muted">${esc(d.ros_latest)}</span>`} <span class="small muted">${esc(d.ros_channel || "")}</span>`
        : `<span class="small muted">${d.ros_checked ? "unknown" : "not checked yet"}</span>`}</td>
      <td class="small">${d.fw_current ? `${esc(d.fw_current)}${fwUpdate(d) ? ` → <b class="status warn">${esc(d.fw_upgrade)}</b>` : ""}` : `<span class="muted">—</span>`}</td>
      <td>${active.has(d.id) ? upStatus(active.get(d.id)) : hasUpdate(d) || fwUpdate(d) ? `<span class="small status warn">Update available</span>` : d.ros_latest ? `<span class="small status ok">Up to date</span>` : ""}</td></tr>`).join("")
      || `<tr><td colspan="8" class="muted">No routers match.</td></tr>`;
    document.querySelectorAll("[data-sel]").forEach((c) => c.addEventListener("change", () => { c.checked ? upView.sel.add(+c.dataset.sel) : upView.sel.delete(+c.dataset.sel); sel(); }));
    sel();
  };
  const sel = () => {
    if (!$("upGo")) return;
    $("upGo").disabled = !upView.sel.size;
    $("upGo").textContent = upView.sel.size ? `Upgrade ${upView.sel.size} selected` : "Upgrade selected";
    $("upAll").checked = shown.length > 0 && shown.every((d) => upView.sel.has(d.id));
  };
  $("upQ").addEventListener("input", (e) => { upView.q = e.target.value; draw(); });
  $("upOrg")?.addEventListener("change", (e) => { upView.org = e.target.value; draw(); });
  $("upOnly").addEventListener("change", (e) => { upView.only = e.target.checked; draw(); });
  $("upAll")?.addEventListener("change", (e) => { shown.forEach((d) => (e.target.checked ? upView.sel.add(d.id) : upView.sel.delete(d.id))); draw(); });
  $("upGo")?.addEventListener("click", () => upgradeDialog(r.routers.filter((d) => upView.sel.has(d.id)), () => { upView.sel.clear(); upgradesView(); }));
  $("upCheck")?.addEventListener("click", async () => {
    $("upCheck").disabled = true; $("upMsg").textContent = "Asking the routers for their newest version...";
    try {
      const x = await post("/api/upgrades/check", { device_ids: [...upView.sel] });
      if (x.background) { $("upMsg").textContent = `Checking ${x.count} routers in the background - this page refreshes as results come in.`; }
      else upgradesView();
    } catch (e) { $("upMsg").textContent = e.message; $("upCheck").disabled = false; }
  });
  document.querySelectorAll("[data-cancel]").forEach((b) => b.addEventListener("click", async () => { await post(`/api/upgrades/${b.dataset.cancel}/cancel`); upgradesView(); }));
  draw();
}
// --- tasks: scripts, groups, scheduled script runs and firmware upgrades ---------------------------------------------
let taskTab = "tasks";
const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const runPill = (st) => `<span class="pill ${{ ok: "up-done", done: "up-done", failed: "up-failed", running: "up-run", pending: "up-run", waiting: "up-sched", skipped: "up-cancelled" }[st] || ""}">${esc(st)}</span>`;
function scheduleText(t) {
  if (t.kind === "once") return `Once, ${when(t.run_at)}`;
  if (t.kind === "hourly") return `Every ${t.every_hours} hour${t.every_hours === 1 ? "" : "s"}`;
  if (t.kind === "daily") return `Daily at ${t.at_time}`;
  return `${JSON.parse(t.days || "[]").map((d) => DAYS[d]).join(", ")} at ${t.at_time}`;
}
function targetText(tg, ref) {
  if (tg.all) return "All routers";
  const parts = [];
  if (tg.orgs?.length) parts.push(tg.orgs.map((id) => ref.orgs.find((o) => o.id === id)?.name || "?").join(", "));
  if (tg.groups?.length) parts.push(tg.groups.map((id) => `group ${ref.groups.find((g) => g.id === id)?.name || "?"}`).join(", "));
  if (tg.devices?.length) parts.push(tg.devices.length <= 3 ? tg.devices.map((id) => ref.routers.find((r) => r.id === id)?.name || "?").join(", ") : `${tg.devices.length} routers`);
  return parts.join(" · ");
}

async function tasksView() {
  $("main").innerHTML = `<div class="row"><h1>Tasks</h1><span class="spacer"></span>
      ${canWrite() ? `<button class="btn primary" type="button" id="tkNew">${{ tasks: "New task", scripts: "New script", groups: "New group", history: "New task" }[taskTab]}</button>` : ""}</div>
    <div class="tabs" role="tablist">${[["tasks", "Scheduled tasks"], ["scripts", "Scripts"], ["groups", "Groups"], ["history", "History"]].map(([k, l]) =>
      `<button type="button" role="tab" data-ttab="${k}" class="${k === taskTab ? "active" : ""}">${l}</button>`).join("")}</div><div id="tkBody" class="tk-body"></div>`;
  document.querySelectorAll("[data-ttab]").forEach((b) => b.addEventListener("click", () => { taskTab = b.dataset.ttab; tasksView(); }));
  const ref = await api("/api/groups");
  const scripts = await api("/api/scripts");
  $("tkNew")?.addEventListener("click", () => (taskTab === "scripts" ? scriptEditor(null, scripts) : taskTab === "groups" ? groupEditor(null, ref) : taskEditor(null, ref, scripts)));
  if (taskTab === "scripts") return scriptsTab(scripts, ref);
  if (taskTab === "groups") return groupsTab(ref);
  if (taskTab === "history") return historyTab();
  const rows = await api("/api/tasks");
  $("tkBody").innerHTML = `<div class="card">${rows.length ? `<div class="table-wrap"><table><thead><tr><th>Task</th><th>Does</th><th>Runs on</th><th>Schedule</th><th>Next run</th><th>Last run</th><th></th></tr></thead><tbody>
    ${rows.map((t) => { const tg = JSON.parse(t.targets || "{}"), o = JSON.parse(t.options || "{}");
      return `<tr class="${t.enabled ? "" : "muted"}"><td><b>${esc(t.name)}</b>${t.enabled ? "" : ` <span class="pill">paused</span>`}</td>
      <td class="small">${t.action === "upgrade" ? `Firmware upgrade${o.channel ? ` (${esc(o.channel)})` : ""}${o.firmware ? " + RouterBOARD" : ""}` : `Script: ${esc(t.script_name || "?")}`}</td>
      <td class="small">${esc(targetText(tg, ref))} <span class="muted">(${t.count})</span></td><td class="small">${esc(scheduleText(t))}</td>
      <td class="small nowrap">${t.enabled && t.next_run ? when(t.next_run) : "—"}</td><td class="small">${t.last_run ? `${ago(t.last_run)}<div class="muted">${esc(t.last_status || "")}</div>` : "never"}</td>
      <td class="nowrap">${canWrite() ? `<button class="btn" type="button" data-trun="${t.id}">Run now</button> <button class="btn" type="button" data-tedit="${t.id}">Edit</button>
        <button class="btn" type="button" data-ttog="${t.id}">${t.enabled ? "Pause" : "Resume"}</button> <button class="btn danger" type="button" data-tdel="${t.id}">Delete</button>` : ""}
        <button class="btn" type="button" data-thist="${t.id}">History</button></td></tr>`; }).join("")}
    </tbody></table></div>` : `<p class="muted">No tasks yet. A task runs a script, or upgrades firmware, on chosen routers - now, once later, or on a schedule.</p>`}</div>`;
  const act = async (url) => { try { const r = await post(url); if (r.run_id) return runDialog(r.run_id); tasksView(); } catch (e) { alert(e.message); } };
  document.querySelectorAll("[data-trun]").forEach((b) => b.addEventListener("click", () => act(`/api/tasks/${b.dataset.trun}/run`)));
  document.querySelectorAll("[data-ttog]").forEach((b) => b.addEventListener("click", () => act(`/api/tasks/${b.dataset.ttog}/toggle`)));
  document.querySelectorAll("[data-tdel]").forEach((b) => b.addEventListener("click", () => {
    if (b.dataset.confirm !== "1") { b.dataset.confirm = "1"; b.textContent = "Click again"; return; }
    act(`/api/tasks/${b.dataset.tdel}/delete`);
  }));
  document.querySelectorAll("[data-tedit]").forEach((b) => b.addEventListener("click", () => taskEditor(rows.find((t) => t.id === +b.dataset.tedit), ref, scripts)));
  document.querySelectorAll("[data-thist]").forEach((b) => b.addEventListener("click", () => historyTab(+b.dataset.thist)));
}

// router picker used by tasks and groups: search + client filter + checkboxes
function routerPicker(el, ref, selected) {
  const sel = new Set(selected);
  let q = "", org = "";
  const draw = () => {
    const rows = ref.routers.filter((r) => (!org || String(r.org_id) === org) && (!q || `${r.name} ${r.org || ""} ${r.model || ""}`.toLowerCase().includes(q)));
    el.querySelector(".rp-list").innerHTML = rows.map((r) => `<label class="chk"><input type="checkbox" value="${r.id}" ${sel.has(r.id) ? "checked" : ""}>
      <span class="dot ${r.online ? "on" : "off"}"></span>${esc(r.name)} <span class="muted small">${esc(r.org || "")}</span></label>`).join("") || `<span class="muted small">No routers match.</span>`;
    el.querySelectorAll(".rp-list input").forEach((c) => c.addEventListener("change", () => { c.checked ? sel.add(+c.value) : sel.delete(+c.value); el.querySelector(".rp-count").textContent = `${sel.size} selected`; }));
    el.querySelector(".rp-count").textContent = `${sel.size} selected`;
  };
  el.innerHTML = `<div class="row"><input type="search" class="rp-q" placeholder="Search routers"><select class="rp-org"><option value="">All clients</option>${ref.orgs.map((o) => `<option value="${o.id}">${esc(o.name)}</option>`).join("")}</select>
    <button class="btn" type="button">Select shown</button><span class="small muted rp-count"></span></div><div class="rp-list"></div>`;
  el.querySelector(".rp-q").addEventListener("input", (e) => { q = e.target.value.toLowerCase(); draw(); });
  el.querySelector(".rp-org").addEventListener("change", (e) => { org = e.target.value; draw(); });
  el.querySelector(".row .btn").addEventListener("click", () => { el.querySelectorAll(".rp-list input").forEach((c) => sel.add(+c.value)); draw(); });
  draw();
  return () => [...sel];
}

function taskEditor(t, ref, scripts, preset = {}) {
  const tg = t ? JSON.parse(t.targets || "{}") : preset.targets || {};
  const o = t ? JSON.parse(t.options || "{}") : { firmware: true };
  const local = (ts) => { const d = new Date((ts || Date.now() / 1000 + 3600) * 1000); return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16); };
  const days = t ? JSON.parse(t.days || "[]") : [6];
  dialog(`<h2>${t ? "Edit task" : "New task"}</h2>
    <div class="grid2"><label class="field">Name <input id="tName" maxlength="100" value="${esc(t?.name || preset.name || "")}" placeholder="e.g. Nightly firmware updates"></label>
      <label class="field">Does <select id="tAction"><option value="script">Run a script</option><option value="upgrade">Upgrade firmware (when an update is available)</option></select></label></div>
    <div id="tScriptBox" class="grid2"><label class="field">Script <select id="tScript">${scripts.scripts.map((s) => `<option value="${s.id}">${esc(s.name)}</option>`).join("")}</select></label></div>
    <div id="tUpBox" class="grid2"><label class="field">Update channel <select id="tChan"><option value="">Router's current channel</option><option value="stable">stable</option><option value="long-term">long-term</option></select></label>
      <label class="chk"><input type="checkbox" id="tFw" ${o.firmware !== false ? "checked" : ""}> Also RouterBOARD firmware</label></div>
    <h3>Runs on</h3>
    <label class="chk"><input type="checkbox" id="tAll" ${tg.all ? "checked" : ""}> All routers</label>
    <div id="tPick"><div class="grid2"><label class="field">Clients <select id="tOrgs" multiple size="4">${ref.orgs.map((x) => `<option value="${x.id}" ${(tg.orgs || []).includes(x.id) ? "selected" : ""}>${esc(x.name)}</option>`).join("")}</select></label>
      <label class="field">Groups <select id="tGroups" multiple size="4">${ref.groups.map((g) => `<option value="${g.id}" ${(tg.groups || []).includes(g.id) ? "selected" : ""}>${esc(g.name)}</option>`).join("")}</select></label></div>
      <p class="small muted">Ctrl-click to pick several. Plus individual routers:</p><div id="tRouters" class="rp"></div></div>
    <h3>When</h3>
    <div class="row"><select id="tKind"><option value="once">Once</option><option value="daily">Every day</option><option value="weekly">Every week</option><option value="hourly">Every N hours</option></select>
      <span id="tOnce"><label class="chk"><input type="radio" name="tOnceWhen" value="now" ${t?.run_at ? "" : "checked"}> now</label> <label class="chk"><input type="radio" name="tOnceWhen" value="at" ${t?.run_at ? "checked" : ""}> at</label>
        <input type="datetime-local" id="tAt" value="${local(t?.run_at)}"></span>
      <span id="tTime">at <input type="time" id="tHHMM" value="${esc(t?.at_time || "02:00")}"></span>
      <span id="tDays">${DAYS.map((d, i) => `<label class="chk"><input type="checkbox" value="${i}" ${days.includes(i) ? "checked" : ""}>${d}</label>`).join("")}</span>
      <span id="tHours">every <input type="number" id="tEvery" min="1" max="720" value="${t?.every_hours || 24}"> hours</span></div>
    <h3>Options</h3>
    <label class="chk" id="tBackupBox"><input type="checkbox" id="tBackup" ${t ? (t.backup_first ? "checked" : "") : "checked"}> Back up each router first (skip it if the backup fails)</label>
    <div class="row"><span class="small">If a router is offline:</span><select id="tOffline"><option value="skip">skip it</option><option value="wait">run when it comes back (within 24 h)</option></select></div>
    <p class="small muted" id="tHelp"></p>
    <div class="actions"><button class="btn primary" type="button" id="tSave">Save task</button><button class="btn" type="button" data-close>Cancel</button><span class="status" id="tStatus"></span></div>`);
  $("dlg").classList.add("wide");
  $("tAction").value = t?.action || preset.action || (scripts.scripts.length ? "script" : "upgrade");
  if (t?.script_id || preset.script_id) $("tScript").value = t?.script_id || preset.script_id;
  $("tChan").value = o.channel || "";
  $("tKind").value = t?.kind || preset.kind || "once";
  $("tOffline").value = t?.offline || "skip";
  const pick = routerPicker($("tRouters"), ref, tg.devices || []);
  const sync = () => {
    const up = $("tAction").value === "upgrade", k = $("tKind").value;
    $("tScriptBox").classList.toggle("hidden", up); $("tUpBox").classList.toggle("hidden", !up); $("tBackupBox").classList.toggle("hidden", up);
    $("tPick").classList.toggle("hidden", $("tAll").checked);
    $("tOnce").classList.toggle("hidden", k !== "once"); $("tTime").classList.toggle("hidden", k !== "daily" && k !== "weekly");
    $("tDays").classList.toggle("hidden", k !== "weekly"); $("tHours").classList.toggle("hidden", k !== "hourly");
    $("tHelp").textContent = up ? "Each router with a newer RouterOS (or RouterBOARD firmware) gets the Upgrades page's safe upgrade: backup, download, reboot, wait for it to come back. Routers already up to date are skipped."
      : `Placeholders filled per router: ${scripts.placeholders.map((p) => `{{${p}}}`).join(" ")}`;
  };
  ["tAction", "tKind", "tAll"].forEach((id) => $(id).addEventListener("change", sync));
  $("tAt").addEventListener("focus", () => { document.querySelector("[name=tOnceWhen][value=at]").checked = true; });
  sync();
  $("tSave").addEventListener("click", async () => {
    const k = $("tKind").value, onceAt = document.querySelector("[name=tOnceWhen]:checked").value === "at";
    const body = { id: t?.id, name: $("tName").value, action: $("tAction").value, script_id: $("tScript").value, channel: $("tChan").value, firmware: $("tFw").checked,
      targets: { all: $("tAll").checked, orgs: [...$("tOrgs").selectedOptions].map((x) => +x.value), groups: [...$("tGroups").selectedOptions].map((x) => +x.value), devices: pick() },
      kind: k, run_at: k === "once" && onceAt ? new Date($("tAt").value).getTime() / 1000 : null, at_time: $("tHHMM").value,
      days: [...document.querySelectorAll("#tDays input:checked")].map((x) => +x.value), every_hours: $("tEvery").value,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone, backup_first: $("tBackup").checked, offline: $("tOffline").value, enabled: t ? !!t.enabled : true };
    try { await post("/api/tasks", body); $("dlg").close(); taskTab = "tasks"; if (view === "tasks") tasksView(); else go("tasks"); }
    catch (e) { $("tStatus").textContent = e.message; $("tStatus").className = "status err"; }
  });
}

function scriptsTab(scripts, ref) {
  $("tkBody").innerHTML = `<div class="card">${scripts.scripts.length ? `<div class="table-wrap"><table><thead><tr><th>Script</th><th>Description</th><th>Used by</th><th>Updated</th><th></th></tr></thead><tbody>
    ${scripts.scripts.map((s) => `<tr><td><b>${esc(s.name)}</b></td><td class="small muted">${esc(s.description)}</td><td class="small">${s.tasks} task${s.tasks === 1 ? "" : "s"}</td>
      <td class="small">${ago(s.updated_at)} · ${esc(s.updated_by || "")}</td><td class="nowrap">${canWrite() ? `<button class="btn" type="button" data-sedit="${s.id}">Edit</button>
      <button class="btn" type="button" data-srun="${s.id}">Run / schedule...</button> <button class="btn danger" type="button" data-sdel="${s.id}">Delete</button>` : `<button class="btn" type="button" data-sedit="${s.id}">View</button>`}</td></tr>`).join("")}
    </tbody></table></div>` : `<p class="muted">No scripts yet. Add RouterOS commands you want to push to routers, e.g. a firewall rule or an NTP setting.</p>`}</div>`;
  document.querySelectorAll("[data-sedit]").forEach((b) => b.addEventListener("click", () => scriptEditor(scripts.scripts.find((s) => s.id === +b.dataset.sedit), scripts)));
  document.querySelectorAll("[data-srun]").forEach((b) => b.addEventListener("click", () => { const s = scripts.scripts.find((x) => x.id === +b.dataset.srun); taskEditor(null, ref, scripts, { action: "script", script_id: s.id, name: s.name }); }));
  document.querySelectorAll("[data-sdel]").forEach((b) => b.addEventListener("click", async () => {
    if (b.dataset.confirm !== "1") { b.dataset.confirm = "1"; b.textContent = "Click again"; return; }
    try { await post(`/api/scripts/${b.dataset.sdel}/delete`); tasksView(); } catch (e) { alert(e.message); }
  }));
}

function scriptEditor(s, scripts) {
  dialog(`<h2>${s ? esc(s.name) : "New script"}</h2>
    <div class="grid2"><label class="field">Name <input id="sName" maxlength="100" value="${esc(s?.name || "")}"></label>
      <label class="field">Description <input id="sDesc" maxlength="300" value="${esc(s?.description || "")}"></label></div>
    <label class="field">RouterOS script <textarea id="sBody" class="code script-box" spellcheck="false" placeholder="/system ntp client set enabled=yes servers=time.cloudflare.com">${esc(s?.body || "")}</textarea></label>
    <p class="small muted">Runs as TikManager's account on each router (REST "execute"); whatever it prints with :put is saved as the output.
      Placeholders: ${scripts.placeholders.map((p) => `<span class="mono">{{${p}}}</span>`).join(" ")}</p>
    ${canWrite() ? `<div class="actions"><button class="btn primary" type="button" id="sSave">Save</button><button class="btn" type="button" data-close>Cancel</button><span class="status" id="sStatus"></span></div>` : ""}`);
  $("dlg").classList.add("wide");
  $("sSave")?.addEventListener("click", async () => {
    try { await post("/api/scripts", { id: s?.id, name: $("sName").value, description: $("sDesc").value, body: $("sBody").value }); $("dlg").close(); taskTab = "scripts"; tasksView(); }
    catch (e) { $("sStatus").textContent = e.message; $("sStatus").className = "status err"; }
  });
}

function groupsTab(ref) {
  $("tkBody").innerHTML = `<div class="card">${ref.groups.length ? `<div class="table-wrap"><table><thead><tr><th>Group</th><th>Description</th><th>Routers</th><th></th></tr></thead><tbody>
    ${ref.groups.map((g) => `<tr><td><b>${esc(g.name)}</b></td><td class="small muted">${esc(g.description)}</td>
      <td class="small">${g.device_ids.length}: ${esc(g.device_ids.slice(0, 6).map((id) => ref.routers.find((r) => r.id === id)?.name || "?").join(", "))}${g.device_ids.length > 6 ? "..." : ""}</td>
      <td class="nowrap">${canWrite() ? `<button class="btn" type="button" data-gedit="${g.id}">Edit</button> <button class="btn danger" type="button" data-gdel="${g.id}">Delete</button>` : ""}</td></tr>`).join("")}
    </tbody></table></div>` : `<p class="muted">No groups yet. Groups are named sets of routers (e.g. "Gas stations") that tasks can target.</p>`}</div>`;
  document.querySelectorAll("[data-gedit]").forEach((b) => b.addEventListener("click", () => groupEditor(ref.groups.find((g) => g.id === +b.dataset.gedit), ref)));
  document.querySelectorAll("[data-gdel]").forEach((b) => b.addEventListener("click", async () => {
    if (b.dataset.confirm !== "1") { b.dataset.confirm = "1"; b.textContent = "Click again"; return; }
    await post(`/api/groups/${b.dataset.gdel}/delete`); tasksView();
  }));
}

function groupEditor(g, ref) {
  dialog(`<h2>${g ? "Edit group" : "New group"}</h2>
    <div class="grid2"><label class="field">Name <input id="gName" maxlength="80" value="${esc(g?.name || "")}"></label>
      <label class="field">Description <input id="gDesc" maxlength="300" value="${esc(g?.description || "")}"></label></div>
    <h3>Routers</h3><div id="gPick" class="rp"></div>
    <div class="actions"><button class="btn primary" type="button" id="gSave">Save group</button><button class="btn" type="button" data-close>Cancel</button><span class="status" id="gStatus"></span></div>`);
  $("dlg").classList.add("wide");
  const pick = routerPicker($("gPick"), ref, g?.device_ids || []);
  $("gSave").addEventListener("click", async () => {
    try { await post("/api/groups", { id: g?.id, name: $("gName").value, description: $("gDesc").value, device_ids: pick() }); $("dlg").close(); taskTab = "groups"; tasksView(); }
    catch (e) { $("gStatus").textContent = e.message; $("gStatus").className = "status err"; }
  });
}

async function historyTab(taskId) {
  taskTab = "history";
  document.querySelectorAll("[data-ttab]").forEach((b) => b.classList.toggle("active", b.dataset.ttab === "history"));
  const runs = await api(`/api/runs${taskId ? `?task_id=${taskId}` : ""}`);
  $("tkBody").innerHTML = `<div class="card">${taskId ? `<p class="small">Runs of one task · <a href="#" id="hAll">show all</a></p>` : ""}
    ${runs.length ? `<div class="table-wrap"><table><thead><tr><th>Started</th><th>Task</th><th>Does</th><th>Status</th><th>Results</th><th>By</th></tr></thead><tbody>
    ${runs.map((u) => `<tr class="click" data-run="${u.id}"><td class="nowrap">${when(u.started_at)}</td><td>${esc(u.task_name || "Run now")}</td>
      <td class="small">${u.action === "upgrade" ? "Firmware upgrade" : `Script: ${esc(u.script_name || "")}`}</td><td>${runPill(u.status)}</td>
      <td class="small">${u.ok || 0} ok · ${u.failed || 0} failed · ${u.skipped || 0} skipped${u.open ? ` · ${u.open} to go` : ""}</td><td class="small">${esc(u.by_user || "")} <span class="muted">(${esc(u.trigger || "")})</span></td></tr>`).join("")}
    </tbody></table></div>` : `<p class="muted">Nothing has run yet.</p>`}</div>`;
  $("hAll")?.addEventListener("click", (e) => { e.preventDefault(); historyTab(); });
  document.querySelectorAll("[data-run]").forEach((r) => r.addEventListener("click", () => runDialog(+r.dataset.run)));
}

async function runDialog(id) {
  const u = await api(`/api/runs/${id}`);
  const open = u.results.some((r) => ["pending", "running"].includes(r.status));
  dialog(`<h2>${esc(u.task_name || "Run now")} - ${when(u.started_at)}</h2>
    <p class="small muted">${u.action === "upgrade" ? "Firmware upgrade" : `Script: ${esc(u.script_name || "")}`} · ${runPill(u.status)} · by ${esc(u.by_user || "")}${open ? " · refreshing..." : ""}</p>
    <div class="table-wrap"><table><thead><tr><th>Router</th><th>Status</th><th>Output</th></tr></thead><tbody>
    ${u.results.map((r) => `<tr><td class="nowrap">${r.device_id ? `<a href="#router/${r.device_id}">${esc(r.device_name)}</a>` : esc(r.device_name)}</td><td>${runPill(r.status)}</td>
      <td>${r.output ? `<pre class="code run-out">${esc(r.output)}</pre>` : `<span class="muted small">${r.status === "waiting" ? "waiting for the router to come online" : ""}</span>`}</td></tr>`).join("") || `<tr><td colspan="3" class="muted">No routers matched the targets.</td></tr>`}
    </tbody></table></div>
    ${u.script_body ? `<details><summary class="small">Script that ran</summary><pre class="code">${esc(u.script_body)}</pre></details>` : ""}
    <div class="actions"><button class="btn" type="button" data-close>Close</button></div>`);
  $("dlg").classList.add("wide");
  if (open) setTimeout(() => { if ($("dlg").open && $("dlgBody").textContent.includes("refreshing")) runDialog(id); }, 3000);
}

// "Run script" on the router page
async function runScriptOn(d) {
  const scripts = await api("/api/scripts");
  if (!scripts.scripts.length) { alert("Add a script first (Tasks > Scripts)."); return; }
  dialog(`<h2>Run a script on ${esc(d.name)}</h2>
    <label class="field">Script <select id="rsScript">${scripts.scripts.map((s) => `<option value="${s.id}">${esc(s.name)}</option>`).join("")}</select></label>
    <pre class="code" id="rsBody"></pre>
    <label class="chk"><input type="checkbox" id="rsBackup" checked> Back up the router first</label>
    <div class="actions"><button class="btn primary" type="button" id="rsGo">Run now</button><button class="btn" type="button" data-close>Cancel</button><span class="status" id="rsStatus"></span></div>`);
  $("dlg").classList.add("wide");
  const show = () => { $("rsBody").textContent = scripts.scripts.find((s) => s.id === +$("rsScript").value)?.body || ""; };
  $("rsScript").addEventListener("change", show); show();
  $("rsGo").addEventListener("click", async () => {
    try { const r = await post("/api/run-script", { script_id: $("rsScript").value, device_ids: [d.id], backup_first: $("rsBackup").checked }); runDialog(r.run_id); }
    catch (e) { $("rsStatus").textContent = e.message; $("rsStatus").className = "status err"; }
  });
}
// --- version and updates ------------------------------------------------------------------------------------------
// The "new version" banner under the top bar, on every page (administrators: only they can upgrade). Hidden for a day
// with × (for that version only), replaced by a progress line while an upgrade runs.
function showUpdate(u) {
  const banner = $("updateBanner");
  if (!banner || !u) return banner?.classList.add("hidden");
  const st = u.status || {};
  const busy = ["requested", "running"].includes(st.state);
  let snooze = {};
  try { snooze = JSON.parse(localStorage.getItem("updateSnooze") || "{}"); } catch {}
  const snoozed = snooze.v === u.latest && snooze.until > Date.now();
  banner.classList.toggle("hidden", !(busy || (u.available && !snoozed)));
  banner.classList.toggle("busy", busy);
  $("ubText").innerHTML = busy
    ? `<b>Upgrading TikManager to ${esc(st.version || u.latest || "")}…</b> ${esc(st.detail || "")} - it restarts by itself in about a minute.`
    : `<b>TikManager ${esc(u.latest || "")} is available.</b> You're on ${esc(u.version || "")}.`;
  $("ubNotes").classList.toggle("hidden", busy || !u.url);
  if (u.url) $("ubNotes").href = u.url;
  $("ubGo").classList.toggle("hidden", busy);
  $("ubClose").classList.toggle("hidden", busy);
  $("ubGo").onclick = () => go("admin", "system");
  $("ubClose").onclick = () => {
    try { localStorage.setItem("updateSnooze", JSON.stringify({ v: u.latest, until: Date.now() + 86400000 })); } catch {}
    banner.classList.add("hidden");
  };
}

// administrators: the server checks GitHub every hour; the page re-reads its answer every 5 minutes (no GitHub call),
// and "Check for updates" next to the version asks GitHub right away
function watchUpdates() {
  if (!me.update) return;
  setInterval(() => api("/api/version").then(showUpdate).catch(() => {}), 5 * 60 * 1000);
  const b = $("verCheck");
  b.classList.remove("hidden");
  b.addEventListener("click", async () => {
    b.disabled = true;
    b.textContent = "Checking…";
    try {
      const u = await post("/api/admin/update-check");
      if (u.available) { try { localStorage.removeItem("updateSnooze"); } catch {} }   // asked on purpose: show it even if hidden earlier
      showUpdate(u);
      b.textContent = u.error ? "Couldn't check" : u.available ? `${u.latest} available` : "Up to date";
      b.title = u.error || `Checked just now - newest release ${u.latest || "unknown"}`;
    } catch (e) { b.textContent = "Couldn't check"; b.title = e.message; }
    setTimeout(() => { b.disabled = false; b.textContent = "Check for updates"; }, 5000);
  });
}

async function versionCard() {
  const el = $("verCard");
  if (!el) return;
  let u;
  try { u = await api("/api/version"); }
  catch { el.innerHTML = `<h2>Version &amp; updates</h2><p class="muted">Restarting… this page reloads when the new version is up.</p>`; setTimeout(versionCard, 4000); return; }
  if (u.version !== me.version) { location.reload(); return; }   // the upgrade finished
  showUpdate(u);
  const st = u.status || {};
  const busy = ["requested", "running"].includes(st.state);
  const result = st.state === "done" ? `<p class="status ok">${esc(st.detail || "")}</p>`
    : st.state === "failed" ? `<p class="status err">Last upgrade failed: ${esc(st.detail || "")}</p>` : "";
  el.innerHTML = `<h2>Version &amp; updates</h2>
    <div class="grid2"><div class="kv"><span>This installation</span><span class="mono">${esc(u.version)}</span></div>
      <div class="kv"><span>Newest release</span><span class="mono">${esc(u.latest || "—")}</span></div>
      <div class="kv"><span>Checked</span><span>${u.checked_at ? ago(u.checked_at) : "not yet"}</span></div>
      <div class="kv"><span>Updates from</span><span class="mono">${esc(u.repo ? `github.com/${u.repo}` : "—")}</span></div></div>
    ${u.error ? `<p class="small status err">${esc(u.error)}</p>` : ""}
    ${busy ? `<p class="status">Upgrading to ${esc(st.version)}: ${esc(st.detail || "")}…</p>` : result}
    ${u.available && !busy ? `<div class="up-box avail"><b>TikManager ${esc(u.latest)} is available.</b>
        ${u.url ? `<a href="${esc(u.url)}" target="_blank" rel="noopener noreferrer">What's new</a>` : ""}
        <p class="small muted">The server backs up the current version and the database, installs ${esc(u.latest)} and restarts (about a minute).
          If the new version doesn't start, it goes back to ${esc(u.version)} automatically.</p>
        ${u.supported ? `<button class="btn primary" type="button" id="verUpgrade">Upgrade now</button>`
          : `<p class="small">One-click upgrade needs a Linux server set up with the installer. Upgrade from a terminal instead:
             <span class="mono">sudo bash /opt/tikmanager/deploy/self-update.sh</span></p>`}</div>`
      : !busy && u.latest && !u.available ? `<p class="small status ok">You're on the newest version.</p>`
      : !busy && u.checked_at && !u.error ? `<p class="small muted">No releases have been published yet.</p>` : ""}
    <div class="actions"><button class="btn" type="button" id="verCheck" ${busy ? "disabled" : ""}>Check for updates</button><span class="status" id="verStatus"></span></div>`;
  $("verCheck")?.addEventListener("click", async () => {
    $("verStatus").textContent = "Checking…";
    try { await post("/api/admin/update-check"); versionCard(); } catch (e) { $("verStatus").textContent = e.message; $("verStatus").className = "status err"; }
  });
  $("verUpgrade")?.addEventListener("click", async (e) => {
    if (e.target.dataset.confirm !== "1") { e.target.dataset.confirm = "1"; e.target.textContent = `Click again to upgrade to ${u.latest}`; return; }
    e.target.disabled = true;
    try { await post("/api/admin/upgrade", { version: u.latest }); versionCard(); }
    catch (err) { e.target.disabled = false; $("verStatus").textContent = err.message; $("verStatus").className = "status err"; }
  });
  if (busy) setTimeout(versionCard, 3000);
}

// --- shell ------------------------------------------------------------------------------------------------
function dialog(html) {
  $("dlg").classList.remove("wide");
  $("dlgBody").innerHTML = html;
  $("dlgBody").querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", () => $("dlg").close()));
  if (!$("dlg").open) $("dlg").showModal();
}

// --- appearance: each person's colour theme and light / dark mode (theme.js applies it; saved on the server) -----------
const THEME_INFO = {   // name and swatch colours (sidebar, accent) shown in the chooser
  company: ["Company colours", "#0c2d5a", ""], navy: ["Navy", "#0c2d5a", "#2f7cf6"], slate: ["Slate", "#1f2937", "#4f6bed"],
  ocean: ["Ocean", "#0b4f5c", "#0e9f9a"], forest: ["Forest", "#173d2c", "#2e9d5b"], plum: ["Plum", "#3b1f5e", "#8b5cf6"],
  tiki: ["Tiki", "#4a2a14", "#e8611a"],
};

function showAppearance() {
  const cur = { theme: document.documentElement.dataset.theme, mode: document.documentElement.dataset.mode };
  const company = (window.BRAND && window.BRAND.accent) || "#e2462f";
  const draw = () => {
    $("apBody").innerHTML = `
      <div class="field-label small muted">Mode</div>
      <div class="ap-modes" role="radiogroup" aria-label="Mode">${[["system", "System"], ["light", "Light"], ["dark", "Dark"]].map(([v, l]) =>
        `<button type="button" role="radio" aria-checked="${cur.mode === v}" class="${cur.mode === v ? "on" : ""}" data-ap-mode="${v}">${l}</button>`).join("")}</div>
      <p class="small muted">System follows your computer's or phone's light / dark setting.</p>
      <div class="field-label small muted">Theme</div>
      <div class="ap-themes" role="radiogroup" aria-label="Theme">${(window.TM_THEMES || Object.keys(THEME_INFO)).map((k) => {
        const [name, side, accent] = THEME_INFO[k] || [k, "#333", "#888"];
        const on = cur.theme === k;
        return `<button type="button" role="radio" aria-checked="${on}" class="ap-theme ${on ? "on" : ""}" data-theme-pick="${k}" data-side="${side}" data-acc="${accent || company}">
          <span class="ap-swatch"><span class="sb"><i></i><i></i><i></i></span><span class="pg"><i></i><i></i></span></span>
          <span class="ap-name">${esc(name)}${on ? `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m5 12 5 5 9-10"/></svg>` : ""}</span></button>`;
      }).join("")}</div>
      <p class="small muted">Company colours uses the accent set on Admin &gt; Branding. Your choice is saved to your account, so it follows you to other devices.</p>
      <div class="actions"><span class="spacer"></span><span class="status" id="apStatus"></span><button class="btn" type="button" data-close>Done</button></div>`;
    $("apBody").querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", () => $("dlg").close()));
    // swatch colours come from data attributes (no inline styles: the security policy forbids them)
    $("apBody").querySelectorAll(".ap-theme").forEach((b) => {
      b.querySelector(".sb").style.background = b.dataset.side;
      b.style.setProperty("--sw-accent", b.dataset.acc);
    });
    $("apBody").querySelectorAll("[data-ap-mode]").forEach((b) => b.addEventListener("click", () => { cur.mode = b.dataset.apMode; save(); }));
    $("apBody").querySelectorAll("[data-theme-pick]").forEach((b) => b.addEventListener("click", () => { cur.theme = b.dataset.themePick; save(); }));
  };
  const save = () => {
    window.setAppearance(cur);
    draw();
    post("/api/me/prefs", cur).then(() => { if ($("apStatus")) { $("apStatus").textContent = "Saved"; $("apStatus").className = "status ok"; } })
      .catch((e) => { if ($("apStatus")) { $("apStatus").textContent = e.message; $("apStatus").className = "status err"; } });
  };
  dialog(`<h2>Appearance</h2><div id="apBody"></div>`);
  draw();
}

// --- network map behind one router (Internet -> router -> networks -> switches / APs -> device groups) -------------------
const TI = (d) => `<svg viewBox="0 0 24 24" aria-hidden="true">${d}</svg>`;
const TOPO_ICONS = {
  cloud: TI('<path d="M7 18a4.5 4.5 0 0 1-.5-9A6 6 0 0 1 18 9.5a4 4 0 0 1-.5 8.5z"/>'),
  router: TI('<rect x="2.5" y="13" width="19" height="7" rx="2"/><path d="M6.5 16.5h.01M10 16.5h.01M8 13l-2-6M16 13l2-6"/>'),
  net: TI('<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/>'),
  network: TI('<rect x="2" y="8" width="20" height="8" rx="2"/><path d="M6 12h.01M9 12h.01M12 12h.01M15 12h.01M18 12h.01"/>'),
  ap: TI('<path d="M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0"/><circle cx="12" cy="19.5" r="1"/>'),
  phone: TI('<path d="M5 4h4l2 5-2.5 1.5a11 11 0 0 0 5 5L15 13l5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 3 6a2 2 0 0 1 2-2"/>'),
  printer: TI('<path d="M6 9V3h12v6M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="7"/>'),
  camera: TI('<path d="M23 7l-7 5 7 5V7z"/><rect x="1" y="5" width="15" height="14" rx="2"/>'),
  server: TI('<rect x="3" y="3" width="18" height="7" rx="1.5"/><rect x="3" y="14" width="18" height="7" rx="1.5"/><path d="M7 6.5h.01M7 17.5h.01"/>'),
  computer: TI('<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>'),
  mobile: TI('<rect x="7" y="2" width="10" height="20" rx="2"/><path d="M11 18h2"/>'),
  iot: TI('<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2"/>'),
  unknown: TI('<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6M12 17h.01"/>'),
};
const isAp = (i) => /ap|wap|cap|wifi|wireless|uap|u6|u7|access/i.test(`${i.model} ${i.name}`);

async function loadTopology(d, refresh = false) {
  const card = $("topoCard");
  if (!card) return;
  let t;
  try { t = await api(`/api/devices/${d.id}/topology${refresh ? "?refresh=1" : ""}`); }
  catch (e) { card.innerHTML = `<h2>Network map</h2><p class="status err">${esc(e.message)}</p>`; return; }
  if (!$("topoCard")) return;
  const bubbles = (groups, where) => groups.map((g) => `<button type="button" class="tbub k-${esc(g.kind)}" data-where="${where}" data-kind="${esc(g.kind)}"
      title="${esc(g.label)}: ${g.count}"><span class="tic">${TOPO_ICONS[g.kind] || TOPO_ICONS.unknown}</span><b class="tcnt">${g.count}</b><span class="tlbl">${esc(g.label)}</span></button>`).join("");
  const gw = t.internet.gateways;
  card.innerHTML = `<div class="row"><h2>Network map</h2><span class="spacer"></span>
      <span class="small muted">${t.infra} switch${t.infra === 1 ? "" : "es"} / APs · ${t.devices} devices · read ${ago(t.read_at)}</span>
      <button class="btn" type="button" id="topoRefresh">Refresh</button></div>
    <div class="topo">
      <div class="tnode tcloud"><span class="tic">${TOPO_ICONS.cloud}</span><span><b>Internet</b>${gw.length ? `<small>${gw.map((g) => `via ${esc(g.gateway)}${gw.length > 1 ? (g.active ? " (active)" : " (standby)") : ""}`).join(" · ")}</small>` : ""}</span></div>
      <div class="tstem"></div>
      <div class="trouter-row">
        <div class="tnode trouter"><span class="tic">${TOPO_ICONS.router}</span><span><b>${esc(d.name)}</b><small>${esc(t.internet.wan_ip || "")}${t.internet.interface ? ` · WAN ${esc(t.internet.interface)}` : ""}</small></span></div>
      </div>
      <div class="tstem"></div>
      <div class="tnets ${t.networks.length === 1 ? "single" : ""}">${t.networks.map((n, ni) => `<div class="tcol">
        <div class="tnode tnet"><span class="tic">${TOPO_ICONS.net}</span><span><b>${esc(n.name)}</b><small class="mono">${esc(n.network)}${n.vlan ? ` · VLAN ${esc(n.vlan)}` : ""}</small></span></div>
        ${n.infra.map((i, ii) => `<div class="tbranch"><div class="tnode tinfra"><span class="tic">${isAp(i) ? TOPO_ICONS.ap : TOPO_ICONS.network}</span>
            <span><b>${esc(i.name)}</b><small>${esc([i.model || i.platform, i.ip, i.port ? `port ${i.port}` : ""].filter(Boolean).join(" · "))}</small></span></div>
            ${i.groups.length ? `<div class="tgroups">${bubbles(i.groups, `${ni}.${ii}`)}</div>` : ""}</div>`).join("")}
        ${n.groups.length ? `<div class="tbranch direct">${n.infra.length ? `<div class="small muted tdirect">Directly on the router</div>` : ""}<div class="tgroups">${bubbles(n.groups, `${ni}`)}</div></div>` : ""}
        ${!n.infra.length && !n.groups.length ? `<div class="small muted tempty">No devices seen</div>` : ""}
      </div>`).join("")}</div>
    </div>
    ${t.routes.length ? `<div class="troutes"><div class="small muted">Routes to other networks</div>${t.routes.map((r) => `<div class="troute ${r.active ? "" : "off"}">
          <span class="pill r-${esc(r.kind)}">${esc({ vpn: "VPN", static: "Static", dynamic: "Dynamic" }[r.kind] || r.kind)}</span>
          <span class="mono">${esc(r.dst)}</span><span class="small muted">via ${esc(r.gateway)}${r.comment ? ` · ${esc(r.comment)}` : ""}${r.active ? "" : " · inactive"}</span></div>`).join("")}</div>`
          : t.routes_hidden ? `<div class="troutes small muted">This router also routes to other networks (shown to technicians).</div>` : ""}
    <div id="topoList"></div>
    <p class="small muted">Switches and access points come from neighbour discovery (MNDP / LLDP / CDP); devices from the ARP table and
      DHCP leases, recognised by maker and name - some stay Unidentified. Click a group to list its devices.</p>`;
  const show = (where, kind) => {
    rView.topoSel = [where, kind];
    const [ni, ii] = where.split(".").map(Number);
    const n = t.networks[ni], holder = ii === undefined || Number.isNaN(ii) ? n : n.infra[ii];
    const g = (holder?.groups || []).find((x) => x.kind === kind);
    document.querySelectorAll(".tbub").forEach((b) => b.classList.toggle("on", b.dataset.where === where && b.dataset.kind === kind));
    if (!g) { $("topoList").innerHTML = ""; return; }
    $("topoList").innerHTML = `<div class="topo-list"><div class="row"><b>${esc(g.label)}</b><span class="muted small">${esc(holder.name)} · ${g.count}</span>
        <span class="spacer"></span><button class="btn" type="button" id="topoClose">Close</button></div>
      <div class="table-wrap"><table><thead><tr><th>Name</th><th>IP address</th><th>MAC address</th><th>Port</th></tr></thead>
      <tbody>${g.devices.map((x) => `<tr><td>${esc(x.name)}</td><td class="mono">${esc(x.ip)}</td><td class="mono small">${esc(x.mac)}</td><td class="mono small">${esc(x.port)}</td></tr>`).join("")}</tbody></table></div></div>`;
    $("topoClose").addEventListener("click", () => { rView.topoSel = null; show("-", "-"); });
  };
  card.querySelectorAll(".tbub").forEach((b) => b.addEventListener("click", () => show(b.dataset.where, b.dataset.kind)));
  $("topoRefresh").addEventListener("click", () => loadTopology(d, true));
  if (rView.topoSel) show(...rView.topoSel);
}

// --- firewall filter + NAT rules: changes are tested like RouterOS Safe Mode - the router undoes them unless kept -------
const FW_MATCH = [["protocol", ""], ["src-address", "from "], ["src-address-list", "from list "], ["src-port", "src port "],
  ["dst-address", "to "], ["dst-address-list", "to list "], ["dst-port", "port "], ["in-interface", "in "], ["in-interface-list", "in list "],
  ["out-interface", "out "], ["out-interface-list", "out list "], ["connection-state", "state "], ["connection-nat-state", "nat state "]];
const FW_LABELS = { "src-address": "Source address", "dst-address": "Destination address", "src-port": "Source port", "dst-port": "Destination port",
  "in-interface": "In interface", "out-interface": "Out interface", "in-interface-list": "In interface list", "out-interface-list": "Out interface list",
  "src-address-list": "Source address list", "dst-address-list": "Destination address list", "connection-state": "Connection state",
  "connection-nat-state": "Connection NAT state", protocol: "Protocol", "jump-target": "Jump to chain", "reject-with": "Reject with",
  "address-list": "Add to address list", "address-list-timeout": "List timeout", "to-addresses": "To addresses", "to-ports": "To ports",
  "log-prefix": "Log prefix", comment: "Comment" };
const FW_SHOW = {   // fields that only apply to some actions
  "jump-target": ["jump"], "reject-with": ["reject"], "address-list": ["add-src-to-address-list", "add-dst-to-address-list"],
  "address-list-timeout": ["add-src-to-address-list", "add-dst-to-address-list"], "to-addresses": ["src-nat", "dst-nat", "netmap", "same"],
  "to-ports": ["src-nat", "dst-nat", "redirect", "netmap", "same"] };
let fwTimer = null;
const fwMatch = (r) => FW_MATCH.filter(([k]) => r[k]).map(([k, p]) => `${p}${r[k]}`).join(" · ") || "everything";
const fwClock = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;

async function loadFirewall(d, note) {
  const card = $("fwCard");
  if (!card) return;
  clearInterval(fwTimer);
  const v = rView.fw || (rView.fw = { sec: "filter", chain: "", list: "", q: "" });
  let f, entries = [];
  try {
    f = await api(`/api/devices/${d.id}/firewall`);
    if (v.sec === "address-list") {
      if (!f.address_lists.includes(v.list)) v.list = f.address_lists[0] || "";
      if (v.list) entries = (await api(`/api/devices/${d.id}/firewall/address-list?list=${encodeURIComponent(v.list)}`)).entries;
    }
  } catch (e) { card.innerHTML = `<h2>Firewall &amp; NAT</h2><p class="status err">${esc(e.message)}</p>`; return; }
  if (!$("fwCard")) return;
  const isList = v.sec === "address-list";
  const rules = isList ? [] : f[v.sec], chains = [...new Set(rules.map((r) => r.chain))];
  if (v.chain && !chains.includes(v.chain)) v.chain = "";
  const shown = rules.filter((r) => !v.chain || r.chain === v.chain);
  const ql = v.q.toLowerCase();
  const shownEntries = entries.filter((e) => !ql || `${e.address} ${e.comment || ""}`.toLowerCase().includes(ql));
  const edit = f.can_edit, p = f.pending;
  const tabs = [["filter", "Filter", f.filter.length], ["nat", "NAT", f.nat.length], ["address-list", "Address lists", f.address_lists.length]];
  card.innerHTML = `<div class="row"><h2>Firewall &amp; NAT</h2>
      <div class="seg" role="group" aria-label="Rule set">${tabs.map(([k, l, n]) =>
        `<button type="button" data-fwsec="${k}" class="${v.sec === k ? "on" : ""}">${l} (${n})</button>`).join("")}</div>
      ${isList ? `<select id="fwList" aria-label="Address list">${f.address_lists.map((l) => `<option value="${esc(l)}" ${l === v.list ? "selected" : ""}>${esc(l)} (${f.address_list_counts[l] || 0})</option>`).join("")}</select>
        <input id="fwQ" type="search" placeholder="Search address or comment" aria-label="Search the list" value="${esc(v.q)}">`
        : `<select id="fwChain" aria-label="Chain"><option value="">All chains</option>${chains.map((c) => `<option ${c === v.chain ? "selected" : ""}>${esc(c)}</option>`).join("")}</select>`}
      <span class="spacer"></span>
      ${edit ? `<button class="btn primary" type="button" id="fwAdd">${isList ? "Add address" : "Add rule"}</button>` : ""}
      <button class="btn" type="button" id="fwRefresh">Refresh</button></div>
    ${p ? `<div class="fw-pending"><div><b>Testing ${p.changes.length} change${p.changes.length === 1 ? "" : "s"}</b> -
        <span id="fwLeft">${p.seconds == null ? "the router undoes them soon" : `the router undoes them in <b>${fwClock(p.seconds)}</b>`}</span> unless you keep them.
        <ul class="small">${p.changes.map((c) => `<li>${esc(c)}</li>`).join("")}</ul></div>
        ${edit ? `<div class="fw-pending-acts"><button class="btn primary" type="button" id="fwKeep">Keep changes</button>
          <button class="btn" type="button" id="fwUndo">Undo now</button></div>` : ""}</div>` : ""}
    <p class="status" id="fwStatus"></p>
    ${isList ? `<div class="table-wrap"><table class="fw-table"><thead><tr><th>Address</th><th>Comment</th><th>Timeout</th><th>Added</th>${edit ? "<th></th>" : ""}</tr></thead><tbody>
      ${shownEntries.slice(0, 1000).map((e) => `<tr class="${e.disabled === "true" ? "fw-off" : ""}">
        <td class="mono">${esc(e.address)}${e.disabled === "true" ? ` <span class="small muted">(off)</span>` : ""}</td>
        <td class="muted small">${esc(e.comment || "")}${e.dynamic === "true" ? ` <span class="pill" title="Added by a firewall rule; removed when the timeout runs out">dynamic</span>` : ""}</td>
        <td class="small nowrap">${esc(e.timeout || (e.dynamic === "true" ? "" : "permanent"))}</td>
        <td class="small nowrap muted">${esc(e["creation-time"] || "")}</td>
        ${edit ? `<td class="fw-acts nowrap">${e.dynamic === "true" ? "" : `
          <button class="btn" type="button" data-al="${e.disabled === "true" ? "enable" : "disable"}" data-id="${esc(e[".id"])}">${e.disabled === "true" ? "Enable" : "Disable"}</button>
          <button class="btn" type="button" data-al="edit" data-id="${esc(e[".id"])}">Edit</button>`}
          <button class="btn" type="button" data-al="remove" data-id="${esc(e[".id"])}">Remove</button></td>` : ""}</tr>`).join("")}
      ${shownEntries.length ? "" : `<tr><td colspan="5" class="muted">${f.address_lists.length ? (v.q ? "Nothing matches." : "This list is empty.") : "No address lists on this router yet - Add address creates one."}</td></tr>`}
      </tbody></table></div>
      ${shownEntries.length > 1000 ? `<p class="small muted">Showing the first 1,000 of ${shownEntries.length.toLocaleString()} - search to narrow it down.</p>` : ""}`
    : `<div class="table-wrap"><table class="fw-table"><thead><tr><th>#</th><th>Chain</th><th>Action</th><th>Match</th>${v.sec === "nat" ? "<th>Translate to</th>" : ""}
      <th>Comment</th><th>Traffic</th>${edit ? "<th></th>" : ""}</tr></thead><tbody>
      ${shown.map((r) => { const i = rules.indexOf(r); return `<tr class="${r.disabled === "true" ? "fw-off" : ""} ${r.invalid === "true" ? "fw-bad" : ""}">
        <td class="muted">${i + 1}</td><td class="mono">${esc(r.chain)}</td>
        <td><span class="pill fw-${esc(r.action)}">${esc(r.action)}</span>${r["jump-target"] ? ` <span class="small muted">→ ${esc(r["jump-target"])}</span>` : ""}
          ${r.disabled === "true" ? ` <span class="small muted">(off)</span>` : ""}</td>
        <td class="small">${esc(fwMatch(r))}</td>
        ${v.sec === "nat" ? `<td class="mono small">${esc([r["to-addresses"], r["to-ports"] && `port ${r["to-ports"]}`].filter(Boolean).join(" "))}</td>` : ""}
        <td class="muted small">${esc(r.comment || "")}${r.dynamic === "true" ? ` <span class="pill">dynamic</span>` : ""}</td>
        <td class="small nowrap">${bytes(+r.bytes || 0)} · ${(+r.packets || 0).toLocaleString()} pkts</td>
        ${edit ? `<td class="fw-acts nowrap">${r.protected ? `<span class="small muted" title="Needed by TikManager or made by RouterOS - read-only here">locked</span>` : `
          <button class="btn" type="button" data-fw="up" data-id="${esc(r[".id"])}" title="Move up" aria-label="Move up">↑</button>
          <button class="btn" type="button" data-fw="down" data-id="${esc(r[".id"])}" title="Move down" aria-label="Move down">↓</button>
          <button class="btn" type="button" data-fw="${r.disabled === "true" ? "enable" : "disable"}" data-id="${esc(r[".id"])}">${r.disabled === "true" ? "Enable" : "Disable"}</button>
          <button class="btn" type="button" data-fw="edit" data-id="${esc(r[".id"])}">Edit</button>
          <button class="btn" type="button" data-fw="remove" data-id="${esc(r[".id"])}">Delete</button>`}</td>` : ""}</tr>`; }).join("")}
      ${shown.length ? "" : `<tr><td colspan="8" class="muted">No rules${v.chain ? ` in ${esc(v.chain)}` : ""}.</td></tr>`}</tbody></table></div>`}
    <p class="small muted">Changes are tested first, like Safe Mode in Winbox: before the first one TikManager saves an undo script on the router and
      starts a ${f.test_minutes}-minute timer. Press <b>Keep changes</b> once you've checked everything still works - otherwise (or if a change cuts
      TikManager off) the router undoes the changes by itself. TikManager's own rules and dynamic rules are locked.</p>`;
  const status = (msg, cls = "") => { $("fwStatus").textContent = msg; $("fwStatus").className = `status ${cls}`; };
  if (note) status(note[0], note[1]);
  card.querySelectorAll("[data-fwsec]").forEach((b) => b.addEventListener("click", () => { v.sec = b.dataset.fwsec; v.chain = ""; v.q = ""; loadFirewall(d); }));
  $("fwChain")?.addEventListener("change", () => { v.chain = $("fwChain").value; loadFirewall(d); });
  $("fwList")?.addEventListener("change", () => { v.list = $("fwList").value; v.q = ""; loadFirewall(d); });
  $("fwQ")?.addEventListener("change", () => { v.q = $("fwQ").value.trim(); loadFirewall(d); });
  $("fwRefresh").addEventListener("click", () => loadFirewall(d));
  if (p && p.seconds != null) {
    const end = Date.now() + p.seconds * 1000;
    fwTimer = setInterval(() => {
      if (!$("fwLeft")) { clearInterval(fwTimer); return; }
      const left = Math.max(0, Math.round((end - Date.now()) / 1000));
      $("fwLeft").innerHTML = left ? `the router undoes them in <b>${fwClock(left)}</b>` : "time's up - the router is undoing them";
      if (!left) { clearInterval(fwTimer); setTimeout(() => loadFirewall(d, ["The changes weren't kept, so the router undid them.", "warn"]), 8000); }
    }, 1000);
  }
  const send = async (url, body, busy) => {
    card.querySelectorAll("button").forEach((b) => { b.disabled = true; });
    status(busy);
    try { return await post(url, body); }
    catch (e) { await loadFirewall(d, [e.message, "err"]); return null; }
  };
  const change = async (body, busy) => {
    const r = await send(`/api/devices/${d.id}/firewall`, { section: v.sec, ...body }, busy);
    if (!r) return false;
    await loadFirewall(d, r.reachable ? [`Done - ${r.summary}. Check that everything still works, then press Keep changes.`, "ok"]
      : ["TikManager can't reach the router after this change. Unless it comes back, the router will undo it by itself when the timer runs out.", "err"]);
    return true;
  };
  $("fwKeep")?.addEventListener("click", async () => {
    if (await send(`/api/devices/${d.id}/firewall/keep`, {}, "Keeping the changes...")) loadFirewall(d, ["Changes kept.", "ok"]);
  });
  $("fwUndo")?.addEventListener("click", async () => {
    if (await send(`/api/devices/${d.id}/firewall/undo`, {}, "Undoing the changes...")) loadFirewall(d, ["Undone - everything is back as it was.", "ok"]);
  });
  $("fwAdd")?.addEventListener("click", () => isList ? alDialog(f, v.list, null, (body, busy) => { if (body.rule?.list) v.list = body.rule.list; return change(body, busy); })
    : fwDialog(d, f, v.sec, null, change, v.chain));
  card.querySelectorAll("[data-al]").forEach((b) => b.addEventListener("click", () => {
    const op = b.dataset.al, e = entries.find((x) => x[".id"] === b.dataset.id);
    if (!e) return;
    if (op === "edit") return alDialog(f, v.list, e, (body, busy) => { if (body.rule?.list) v.list = body.rule.list; return change({ ...body, list: e.list }, busy); });
    if (op === "remove") {
      if (b.dataset.confirm !== "1") { b.dataset.confirm = "1"; b.textContent = "Sure?"; return; }
      return change({ op, id: e[".id"], list: e.list }, `Removing ${e.address}...`);
    }
    return change({ op, id: e[".id"], list: e.list }, `${op === "enable" ? "Enabling" : "Disabling"} ${e.address}...`);
  }));
  card.querySelectorAll("[data-fw]").forEach((b) => b.addEventListener("click", async () => {
    const op = b.dataset.fw, r = rules.find((x) => x[".id"] === b.dataset.id);
    if (!r) return;
    if (op === "edit") return fwDialog(d, f, v.sec, r, change);
    if (op === "remove") {
      if (b.dataset.confirm !== "1") { b.dataset.confirm = "1"; b.textContent = "Sure?"; return; }
      return change({ op, id: r[".id"] }, "Deleting the rule...");
    }
    if (op === "enable" || op === "disable") return change({ op, id: r[".id"] }, `${op === "enable" ? "Enabling" : "Disabling"} the rule...`);
    // up / down: past the neighbouring rule in the list as shown (so it stays within the chain being viewed)
    const k = shown.indexOf(r);
    if (op === "up") {
      if (k <= 0) return;
      return change({ op: "move", id: r[".id"], before: shown[k - 1][".id"] }, "Moving the rule...");
    }
    if (k >= shown.length - 1) return;
    const after = rules[rules.indexOf(shown[k + 1]) + 1];
    return change({ op: "move", id: r[".id"], before: after ? after[".id"] : null }, "Moving the rule...");
  }));
}

// an address-list entry: list (pick or new), address, timeout, comment - like WebFig's Address Lists form
function alDialog(f, list, e, change) {
  const cur = e || { list, disabled: "false" };
  const lists = [...new Set([...(f.address_lists || []), ...(cur.list ? [cur.list] : [])])];
  rView.hold = true;
  dialog(`<h2>${e ? "Edit address" : "Add address"}</h2>
    <form id="alForm" class="fw-form">
      <div class="fw-row on"><span class="fw-lbl">Enabled</span><span class="fw-val"><input type="checkbox" name="enabled" ${cur.disabled === "true" ? "" : "checked"} aria-label="Enabled"></span></div>
      <div class="fw-row on"><span class="fw-lbl">List</span><span class="fw-val"><select name="list">${lists.map((l) => `<option value="${esc(l)}" ${l === cur.list ? "selected" : ""}>${esc(l)}</option>`).join("")}
        <option value="__new" ${lists.length ? "" : "selected"}>New list…</option></select>
        <input name="list-new" class="${lists.length ? "hidden" : ""}" placeholder="list name" maxlength="63" spellcheck="false"></span></div>
      <div class="fw-row on"><span class="fw-lbl">Address</span><span class="fw-val"><input name="address" value="${esc(cur.address || "")}" required spellcheck="false"
        placeholder="203.0.113.7, 10.0.0.0/24, 10.0.0.1-10.0.0.9 or a DNS name"></span></div>
      <div class="fw-row on"><span class="fw-lbl">Timeout</span><span class="fw-val"><input name="timeout" value="${esc(e ? "" : "")}" spellcheck="false"
        placeholder="blank = permanent (e.g. 1d, 2h30m)" ${e ? "disabled title=\"Set when the address is added\"" : ""}></span></div>
      <div class="fw-row on"><span class="fw-lbl">Comment</span><span class="fw-val"><input name="comment" value="${esc(cur.comment || "")}" maxlength="200"></span></div>
      <p class="small muted">Rules that use this list match the new address straight away. The change is tested first: the router undoes it in
        ${f.test_minutes} minutes unless you keep it - so removing your own address from an allow list can't lock you out for good.</p>
      <p class="status err" id="alErr"></p>
      <div class="row"><span class="spacer"></span><button class="btn" type="button" data-close>Cancel</button>
        <button class="btn primary" type="submit">${e ? "Save and test" : "Add and test"}</button></div>
    </form>`);
  $("dlg").classList.add("fw-dlg");
  $("dlg").addEventListener("close", () => { rView.hold = false; $("dlg").classList.remove("fw-dlg"); }, { once: true });
  const form = $("alForm");
  form.elements.list.addEventListener("change", () => {
    form.elements["list-new"].classList.toggle("hidden", form.elements.list.value !== "__new");
    if (form.elements.list.value === "__new") form.elements["list-new"].focus();
  });
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const vals = {
      list: form.elements.list.value === "__new" ? form.elements["list-new"].value.trim() : form.elements.list.value,
      address: form.elements.address.value.trim(), comment: form.elements.comment.value.trim(),
      disabled: form.elements.enabled.checked ? "false" : "true",
    };
    if (!vals.list) { $("alErr").textContent = "Type the new list's name."; return; }
    if (!vals.address) { $("alErr").textContent = "Type an address."; return; }
    let body;
    if (e) {
      const diff = {};
      for (const [k, val] of Object.entries(vals)) if (val !== (e[k] ?? (k === "disabled" ? "false" : ""))) diff[k] = val;
      if (!Object.keys(diff).length) { $("alErr").textContent = "Nothing changed."; return; }
      body = { op: "edit", id: e[".id"], rule: diff };
    } else {
      if (form.elements.timeout.value.trim()) vals.timeout = form.elements.timeout.value.trim();
      body = { op: "add", rule: Object.fromEntries(Object.entries(vals).filter(([k, val]) => val !== "" && !(k === "disabled" && val === "false"))) };
    }
    form.querySelector("[type=submit]").disabled = true;
    $("dlg").close();
    await change(body, e ? `Saving ${vals.address}...` : `Adding ${vals.address} to ${vals.list}...`);
  });
}

// the rule editor, laid out like WebFig: match fields are added with +, each with - (remove) and ! (not)
const FW_PORT_PROTOS = ["tcp", "udp", "udp-lite", "sctp", "dccp"];
const FW_PROTOS = ["tcp", "udp", "icmp", "icmpv6", "gre", "ipsec-esp", "ipsec-ah", "ospf", "igmp", "l2tp", "sctp", "udp-lite", "dccp", "vrrp", "pim", "ipip", "ipencap", "etherip"];
const FW_STATES = ["invalid", "established", "related", "new", "untracked"];
const FW_GENERAL = [   // [field, kind]; null = divider
  ["src-address", "text", "e.g. 192.168.1.0/24 or 10.0.0.1-10.0.0.9"], ["dst-address", "text", "e.g. 203.0.113.10"],
  ["src-address-list", "alist"], ["dst-address-list", "alist"], null,
  ["protocol", "proto"], ["src-port", "port", "e.g. 1024-65535"], ["dst-port", "port", "e.g. 80,443"], null,
  ["in-interface", "iface"], ["out-interface", "iface"], null,
  ["in-interface-list", "ilist"], ["out-interface-list", "ilist"], null,
  ["connection-state", "states"], ["connection-nat-state", "nat"]];

function fwDialog(d, f, sec, rule, change, chain = "") {
  const fields = f.fields[sec], rules = f[sec];
  const cur = rule || { chain: chain || (sec === "nat" ? "dstnat" : "input"), action: sec === "nat" ? "dst-nat" : "accept" };
  const chains = [...new Set([...(sec === "nat" ? ["srcnat", "dstnat"] : ["input", "forward", "output"]), ...rules.map((r) => r.chain),
    ...rules.map((r) => r["jump-target"]).filter(Boolean)])];
  // a pulldown of every chain on the router, or "New chain..." to type one
  const chainPick = (name, sel, blank) => `<select name="${name}" data-chain>${blank != null ? opt("", blank, sel || "") : ""}
      ${[...chains, ...(sel && !chains.includes(sel) ? [sel] : [])].map((c) => opt(c, c, sel)).join("")}<option value="__new">New chain…</option></select>
    <input name="${name}-new" class="hidden" placeholder="chain name" spellcheck="false" maxlength="40">`;
  const opt = (v, label, sel) => `<option value="${esc(v)}" ${v === sel ? "selected" : ""}>${esc(label ?? v)}</option>`;
  const choose = (name, values, sel, blank) => {   // a pulldown that keeps a value the router no longer offers
    const list = [...values];
    if (sel && !list.some((x) => (Array.isArray(x) ? x[0] : x) === sel)) list.push([sel, `${sel} (not on the router)`]);
    return `<select name="${name}">${blank != null ? opt("", blank, sel || "") : ""}${list.map((x) => Array.isArray(x) ? opt(x[0], x[1], sel) : opt(x, x, sel)).join("")}</select>`;
  };
  const control = (k, kind, ph, val) => {
    if (kind === "alist") return choose(k, f.address_lists || [], val, "");
    if (kind === "iface") return choose(k, [["all-ethernet", "all ethernet"], ["all-ppp", "all ppp"], ["all-vlan", "all vlan"], ["all-wireless", "all wireless"], ...(f.interfaces || [])], val, "");
    if (kind === "ilist") return choose(k, [...(f.interface_lists || []), "all", "dynamic", "static", "none"], val, "");
    if (kind === "proto") return `<input name="${k}" list="fwProtos" value="${esc(val)}" placeholder="name or number" spellcheck="false">`;
    if (kind === "states" || kind === "nat") {
      const set = val.split(",");
      return `<span class="fw-checks">${(kind === "states" ? FW_STATES : ["srcnat", "dstnat"]).map((s) =>
        `<label class="chk"><input type="checkbox" data-state="${k}" value="${s}" ${set.includes(s) ? "checked" : ""}> ${s}</label>`).join("")}</span>`;
    }
    return `<input name="${k}" value="${esc(val)}" placeholder="${esc(ph || "")}" spellcheck="false">`;
  };
  const row = ([k, kind, ph]) => {
    if (!fields.includes(k)) return "";
    const raw = cur[k] || "", not = raw.startsWith("!"), val = not ? raw.slice(1) : raw;
    return `<div class="fw-row ${raw ? "on" : ""}" data-row="${k}" data-kind="${kind}">
      <span class="fw-lbl">${esc(FW_LABELS[k] || k)}</span>
      <button class="fw-add" type="button" title="Add ${esc(FW_LABELS[k] || k)}" aria-label="Add ${esc(FW_LABELS[k] || k)}">+</button>
      <span class="fw-val"><button class="fw-del" type="button" title="Remove" aria-label="Remove ${esc(FW_LABELS[k] || k)}">−</button>
        <label class="fw-not" title="Not: match everything except this"><input type="checkbox" data-not="${k}" ${not ? "checked" : ""}><span>!</span></label>
        ${control(k, kind, ph, val)}</span></div>`;
  };
  const plain = (k, html) => fields.includes(k) ? `<div class="fw-row on" data-act="${k}"><span class="fw-lbl">${esc(FW_LABELS[k] || k)}</span><span class="fw-val">${html}</span></div>` : "";
  rView.hold = true;
  dialog(`<h2>${rule ? "Edit" : "New"} ${sec === "nat" ? "NAT" : "firewall"} rule</h2>
    <form id="fwForm" class="fw-form">
      <div class="fw-row on"><span class="fw-lbl">Enabled</span><span class="fw-val"><input type="checkbox" name="enabled" ${cur.disabled === "true" ? "" : "checked"} aria-label="Enabled"></span></div>
      <div class="fw-row on"><span class="fw-lbl">Comment</span><span class="fw-val"><input name="comment" value="${esc(cur.comment || "")}" maxlength="200"></span></div>
      <h3 class="fw-sec">General</h3>
      <div class="fw-row on"><span class="fw-lbl">Chain</span><span class="fw-val">${chainPick("chain", cur.chain || "")}</span></div>
      ${FW_GENERAL.map((x) => x ? row(x) : `<hr class="fw-hr">`).join("")}
      <h3 class="fw-sec">Action</h3>
      ${plain("action", choose("action", f.actions[sec], cur.action))}
      ${plain("jump-target", chainPick("jump-target", cur["jump-target"] || "", "pick a chain"))}
      ${plain("reject-with", choose("reject-with", ["icmp-network-unreachable", "icmp-host-unreachable", "icmp-port-unreachable", "icmp-protocol-unreachable",
        "icmp-net-prohibited", "icmp-host-prohibited", "icmp-admin-prohibited", "tcp-reset"], cur["reject-with"] || "", "default"))}
      ${plain("address-list", `<input name="address-list" list="fwLists" value="${esc(cur["address-list"] || "")}" placeholder="pick or type a new list" spellcheck="false">`)}
      ${plain("address-list-timeout", `<input name="address-list-timeout" value="${esc(cur["address-list-timeout"] || "")}" placeholder="none-dynamic, 1d, 00:30:00">`)}
      ${plain("to-addresses", `<input name="to-addresses" value="${esc(cur["to-addresses"] || "")}" placeholder="e.g. 192.168.1.20" spellcheck="false">`)}
      ${plain("to-ports", `<input name="to-ports" value="${esc(cur["to-ports"] || "")}" placeholder="e.g. 3389" spellcheck="false">`)}
      <div class="fw-row on"><span class="fw-lbl">Log</span><span class="fw-val"><input type="checkbox" name="log" ${cur.log === "true" ? "checked" : ""} aria-label="Log"></span></div>
      ${plain("log-prefix", `<input name="log-prefix" value="${esc(cur["log-prefix"] || "")}" maxlength="50">`)}
      ${rule ? "" : `<h3 class="fw-sec">Position</h3><div class="fw-row on"><span class="fw-lbl">Place</span><span class="fw-val"><select name="before"><option value="">At the end</option>
        ${rules.map((r, i) => `<option value="${esc(r[".id"])}">Above #${i + 1}: ${esc(`${r.chain} ${r.action} ${r.comment || fwMatch(r)}`).slice(0, 90)}</option>`).join("")}</select></span></div>`}
      <datalist id="fwLists">${(f.address_lists || []).map((l) => `<option value="${esc(l)}">`).join("")}</datalist>
      <datalist id="fwProtos">${FW_PROTOS.map((x) => `<option value="${x}">`).join("")}</datalist>
      <p class="small muted">Fields left out match anything; tick ! to match everything except the value. The change is tested first: the router puts
        the rules back in ${f.test_minutes} minutes unless you keep it.</p>
      <p class="status err" id="fwFormErr"></p>
      <div class="row"><span class="spacer"></span><button class="btn" type="button" data-close>Cancel</button>
        <button class="btn primary" type="submit">${rule ? "Save and test" : "Add and test"}</button></div>
    </form>`);
  $("dlg").classList.add("fw-dlg");
  $("dlg").addEventListener("close", () => { rView.hold = false; $("dlg").classList.remove("fw-dlg"); }, { once: true });
  const form = $("fwForm");
  const ports = () => FW_PORT_PROTOS.includes((form.elements.protocol?.value || "").trim()) && !form.querySelector("[data-not=protocol]")?.checked
    && form.querySelector("[data-row=protocol]")?.classList.contains("on");
  const refresh = () => {
    const a = form.elements.action.value;
    form.querySelectorAll("[data-act]").forEach((el) => { const k = el.dataset.act; el.classList.toggle("hidden", Boolean(FW_SHOW[k] && !FW_SHOW[k].includes(a))); });
    const p = ports();   // like WebFig: ports only once a protocol with ports is chosen
    form.querySelectorAll("[data-kind=port]").forEach((el) => { el.classList.toggle("disabled", !p); el.querySelector(".fw-add").disabled = !p; if (!p) el.classList.remove("on"); });
  };
  form.querySelectorAll("[data-row]").forEach((el) => {
    el.querySelector(".fw-add").addEventListener("click", () => { el.classList.add("on"); el.querySelector("input:not([type=checkbox]), select")?.focus(); refresh(); });
    el.querySelector(".fw-del").addEventListener("click", () => { el.classList.remove("on"); refresh(); });
  });
  form.querySelectorAll("[data-chain]").forEach((s) => s.addEventListener("change", () => {
    const box = form.elements[`${s.name}-new`];
    box.classList.toggle("hidden", s.value !== "__new");
    if (s.value === "__new") box.focus();
  }));
  const chainVal = (name) => form.elements[name].value === "__new" ? form.elements[`${name}-new`].value.trim() : form.elements[name].value;
  form.elements.action.addEventListener("change", refresh);
  form.elements.protocol?.addEventListener("input", refresh);
  form.querySelector("[data-not=protocol]")?.addEventListener("change", refresh);
  refresh();
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const vals = {};
    form.querySelectorAll("[data-row]").forEach((el) => {
      const k = el.dataset.row;
      let v = "";
      if (el.classList.contains("on")) {
        v = ["states", "nat"].includes(el.dataset.kind) ? [...el.querySelectorAll("[data-state]:checked")].map((c) => c.value).join(",")
          : (form.elements[k]?.value || "").trim();
        if (v && el.querySelector(`[data-not="${k}"]`).checked) v = `!${v}`;
      }
      vals[k] = v;
    });
    form.querySelectorAll("[data-act]").forEach((el) => {
      const k = el.dataset.act;
      vals[k] = el.classList.contains("hidden") ? "" : k === "jump-target" ? chainVal(k) : form.elements[k].value.trim();
    });
    vals.chain = chainVal("chain");
    if (!vals.chain) { $("fwFormErr").textContent = "Type the new chain's name."; return; }
    vals.comment = form.elements.comment.value.trim();
    vals.disabled = form.elements.enabled.checked ? "false" : "true";
    vals.log = form.elements.log.checked ? "true" : "false";
    for (const k of Object.keys(vals)) if (!fields.includes(k)) delete vals[k];
    let body;
    if (rule) {   // send only what changed; a field removed is cleared on the rule
      const diff = {};
      for (const [k, val] of Object.entries(vals)) {
        const was = rule[k] ?? (k === "log" || k === "disabled" ? "false" : "");
        if (val !== was) diff[k] = val;
      }
      if (!Object.keys(diff).length) { $("fwFormErr").textContent = "Nothing changed."; return; }
      body = { op: "edit", id: rule[".id"], rule: diff };
    } else {
      body = { op: "add", rule: Object.fromEntries(Object.entries(vals).filter(([, val]) => val !== "" && val !== "false")), before: form.elements.before.value || null };
    }
    form.querySelector("[type=submit]").disabled = true;
    $("dlg").close();
    await change(body, rule ? "Saving the rule..." : "Adding the rule...");
  });
}

// --- where the router is: shown on a small map; technicians type an address, look it up, or click the spot -------------
function loadLocation(d) {
  const card = $("locCard");
  if (!card) return;
  const has = d.lat != null && d.lon != null;
  const src = d.loc_source === "gps" ? "from the router's GPS" : d.loc_source === "manual" ? "set by hand" : "";
  card.innerHTML = `<div class="row"><h2>Location</h2><span class="spacer"></span>
      ${canWrite() ? `<button class="btn" type="button" id="locEdit">${has ? "Change" : "Set location"}</button>` : ""}</div>
    <p class="${has ? "" : "muted"}">${has ? `${esc(d.location || "")} <span class="mono small muted">${Number(d.lat).toFixed(5)}, ${Number(d.lon).toFixed(5)}</span>
      ${src ? `<span class="small muted">· ${src}</span>` : ""}` : "Not set yet - it won't appear on the map until it is."}</p>
    <div id="locEditor"></div>
    <div class="loc-map" id="locMap"></div>`;
  const map = new GeoMap($("locMap"), { pins: has ? [{ id: d.id, name: d.name, lat: d.lat, lon: d.lon, online: d.online }] : [], fitOnLoad: true });
  $("locEdit")?.addEventListener("click", () => {
    rView.hold = true;   // don't let the page's auto-refresh throw the edit away
    let pick = has ? [d.lat, d.lon] : null;
    $("locEdit").remove();
    $("locEditor").innerHTML = `<div class="loc-edit">
      <label class="field">Address or description (shown on the router page)
        <span class="row"><input id="locAddr" value="${esc(d.location || "")}" maxlength="200" placeholder="e.g. 123 Main St, Wichita, KS">
        <button class="btn" type="button" id="locLook" title="Sends only this text to OpenStreetMap's address search">Look up</button></span></label>
      <div id="locHits"></div>
      <div class="row"><label class="field">Latitude <input id="locLat" inputmode="decimal" value="${has ? d.lat : ""}" placeholder="37.68720"></label>
        <label class="field">Longitude <input id="locLon" inputmode="decimal" value="${has ? d.lon : ""}" placeholder="-97.33010"></label></div>
      <p class="small muted">Or click the spot on the map below (zoom in for towns and streets' worth of detail).</p>
      <div class="actions"><button class="btn primary" type="button" id="locSave">Save location</button>
        ${has ? `<button class="btn danger" type="button" id="locClear">Remove</button>` : ""}
        <button class="btn" type="button" id="locCancel">Cancel</button><span class="status" id="locStatus"></span></div></div>`;
    const setPick = (lat, lon, zoom) => {
      pick = [lat, lon]; $("locLat").value = lat; $("locLon").value = lon; map.setPick(lat, lon);
      if (zoom) { const [x, y] = map.project(lat, lon); map.fitBox(x - 0.05, y - 0.05, x + 0.05, y + 0.05, 600); }
    };
    map.opts.onPick = (lat, lon) => setPick(lat, lon, false);
    if (pick) map.setPick(...pick);
    const typed = () => { const lat = parseFloat($("locLat").value), lon = parseFloat($("locLon").value); if (!Number.isNaN(lat) && !Number.isNaN(lon)) setPick(lat, lon, true); };
    $("locLat").addEventListener("change", typed); $("locLon").addEventListener("change", typed);
    const say = (t, k) => { $("locStatus").textContent = t; $("locStatus").className = `status ${k || ""}`; };
    $("locLook").addEventListener("click", async () => {
      say("Looking up…");
      try {
        const r = await post("/api/geocode", { q: $("locAddr").value });
        say(r.results.length ? "" : "Nothing found - try a simpler address, or click the map.", r.results.length ? "" : "err");
        $("locHits").innerHTML = r.results.map((x, i) => `<button type="button" class="loc-hit" data-i="${i}">${esc(x.label)}</button>`).join("");
        $("locHits").querySelectorAll(".loc-hit").forEach((b) => b.addEventListener("click", () => {
          const x = r.results[Number(b.dataset.i)];
          setPick(Number(x.lat.toFixed(6)), Number(x.lon.toFixed(6)), true);
          $("locHits").innerHTML = "";
        }));
      } catch (e) { say(e.message, "err"); }
    });
    const done = () => { rView.hold = false; router(d.id); };
    $("locCancel").addEventListener("click", done);
    $("locSave").addEventListener("click", async () => {
      try { await post(`/api/devices/${d.id}/location`, { lat: $("locLat").value, lon: $("locLon").value, address: $("locAddr").value }); done(); }
      catch (e) { say(e.message, "err"); }
    });
    $("locClear")?.addEventListener("click", async (e) => {
      if (e.target.dataset.confirm !== "1") { e.target.dataset.confirm = "1"; e.target.textContent = "Click again to remove"; return; }
      await post(`/api/devices/${d.id}/location`, { clear: true }); done();
    });
  });
}

// --- the Map tab of the Site map: every router where it is ---------------------------------------------------------
function geoTab(rows, body) {
  const placed = rows.filter((d) => d.lat != null), missing = rows.filter((d) => d.lat == null);
  const spots = new Map();
  for (const d of placed) { const k = `${d.lat},${d.lon}`; spots.set(k, [...(spots.get(k) || []), d]); }
  const dupes = [...spots.values()].filter((g) => g.length > 1);
  body.innerHTML = `<div class="card geo-card"><div class="geo-wrap" id="geoMap"></div>
      <div class="row small muted geo-legend"><span><span class="dot on"></span>Online</span><span><span class="dot off"></span>Offline (or a group with one offline)</span>
        <span>Numbers are groups of routers - click one to zoom in (or list them, if they're in the same spot).</span><span class="spacer"></span><span>${placed.length} of ${rows.length} routers placed</span></div></div>
    ${dupes.length ? `<div class="card"><h2>Routers sharing a location (${dupes.reduce((n, g) => n + g.length, 0)})</h2>
      <p class="small muted">These routers are set to exactly the same spot, so they show as one group on the map. If one is wrong, open it and use
        <b>Set location</b>.</p>
      ${dupes.map((g) => `<div class="geo-dupe"><span class="small muted">${esc(g[0].location || `${g[0].lat.toFixed(4)}, ${g[0].lon.toFixed(4)}`)}</span>
        <div class="geo-missing">${g.map((d) => `<a href="#router/${d.id}" data-dev="${d.id}"><span class="dot ${d.online ? "on" : "off"}"></span>${esc(d.name)}<span class="small muted"> · ${esc(d.org || "")}</span></a>`).join("")}</div></div>`).join("")}</div>` : ""}
    ${missing.length ? `<div class="card"><h2>No location yet (${missing.length})</h2><p class="small muted">Open a router and use <b>Set location</b>
      (type an address, look it up, or click the spot on the map). Routers with GPS place themselves.</p>
      <div class="geo-missing">${missing.map((d) => `<a href="#router/${d.id}" data-dev="${d.id}"><span class="dot ${d.online ? "on" : "off"}"></span>${esc(d.name)}<span class="small muted"> · ${esc(d.org || "")}</span></a>`).join("")}</div></div>` : ""}`;
  new GeoMap($("geoMap"), { pins: placed.map((d) => ({ id: d.id, name: d.name, lat: d.lat, lon: d.lon, online: d.online, sub: [d.org, d.site].filter(Boolean).join(" · ") })),
                           onSelect: (p) => go("router", p.id) });
  body.querySelectorAll("[data-dev]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); go("router", a.dataset.dev); }));
}

// --- site map (like UniFi's Site Manager): every router with its WAN address and the LAN networks behind it -------------
const sitesView = { org: "", q: "", tab: "map" };

function cidrRange(c) {   // "192.168.1.0/24" -> [first, last] as numbers
  const [ip, bits] = c.split("/"), n = ip.split(".").reduce((a, o) => a * 256 + Number(o), 0), size = 2 ** (32 - Number(bits));
  return [n - (n % size), n - (n % size) + size - 1];
}

async function sites() {
  const rows = await api("/api/sites");
  // networks that overlap another router of the same client can't be joined site-to-site (SD-WAN) without renumbering
  const flat = rows.flatMap((d) => d.networks.map((n) => ({ d, n, r: cidrRange(n.network) })));
  for (const a of flat) {
    a.n.clash = flat.filter((b) => b.d.id !== a.d.id && b.d.org_id === a.d.org_id && b.r[0] <= a.r[1] && a.r[0] <= b.r[1]).map((b) => b.d.name);
  }
  const orgs = [...new Map(rows.map((d) => [d.org_id, d.org || "Unassigned"])).entries()];
  const clashes = flat.filter((x) => x.n.clash.length).length;
  $("main").innerHTML = `<h1>Site map</h1>
    <div class="tabs" role="tablist">${[["map", "Map"], ["sites", "Networks"]].map(([k, l]) =>
      `<button type="button" role="tab" data-smtab="${k}" class="${sitesView.tab === k ? "active" : ""}">${l}</button>`).join("")}</div>
    <div class="row sm-filters"><input id="smQ" type="search" placeholder="Search routers, networks or subnets" value="${esc(sitesView.q)}">
      ${orgs.length > 1 ? `<select id="smOrg"><option value="">All clients</option>${orgs.map(([id, n]) => `<option value="${id}">${esc(n)}</option>`).join("")}</select>` : ""}
      <span class="spacer"></span><span class="small muted">${rows.length} routers · ${flat.length} networks${clashes ? ` · <span class="status warn">${clashes} overlapping</span>` : ""}</span></div>
    <div id="smBody"></div>`;
  if ($("smOrg")) $("smOrg").value = sitesView.org;
  const draw = () => {
    const q = sitesView.q.toLowerCase();
    const shown = rows.filter((d) => (!sitesView.org || String(d.org_id) === sitesView.org) &&
      (!q || [d.name, d.wan_ip, d.site, d.org].concat(d.networks.flatMap((n) => [n.name, n.network])).some((v) => (v || "").toLowerCase().includes(q))));
    if (sitesView.tab === "map") return geoTab(shown, $("smBody"));
    const groups = new Map();
    shown.forEach((d) => { if (!groups.has(d.org_id)) groups.set(d.org_id, []); groups.get(d.org_id).push(d); });
    $("smBody").innerHTML = shown.length ? [...groups.values()].map((list) => `<section class="sm-org"><h2>${esc(list[0].org || "Unassigned")}</h2><div class="sm-tree">
      ${list.map((d) => `<div class="sm-row">
        <a class="sm-dev" href="#router/${d.id}" data-dev="${d.id}"><span class="dot ${d.online ? "on" : "off"}"></span>${thumbImg(d, "thumb-xs")}
          <span><b>${esc(d.name)}</b><span class="mono small muted">${esc(d.wan_ip || d.public_ip || "—")}</span>
          ${d.vpn ? `<span class="small vpn-tag">VPN ${d.vpn_hub ? "hub" : "spoke"} · ${esc(d.vpn)}</span>` : ""}</span></a>
        <div class="sm-nets">${d.networks.length ? d.networks.map((n) => `<div class="sm-net ${n.clash.length ? "clash" : ""}" ${n.clash.length ? `title="Overlaps ${esc(n.clash.join(", "))}"` : ""}>
            <svg viewBox="0 0 16 16" aria-hidden="true"><rect x="1.5" y="2.5" width="13" height="9" rx="1.5"/><path d="M5 14h6M8 11.5V14"/></svg>
            <span><b>${esc(n.name)}</b><span class="mono small muted">${esc(n.network)}</span>${n.clash.length ? `<span class="small status warn">Overlaps ${esc(n.clash.join(", "))}</span>` : ""}</span></div>`).join("")
          : `<div class="sm-net empty small muted">No networks reported yet</div>`}</div></div>`).join("")}</div></section>`).join("")
      : `<p class="muted">No routers match.</p>`;
    document.querySelectorAll("[data-dev]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); go("router", a.dataset.dev); }));
  };
  document.querySelectorAll("[data-smtab]").forEach((b) => b.addEventListener("click", () => { sitesView.tab = b.dataset.smtab; sites(); }));
  $("smQ").addEventListener("input", (e) => { sitesView.q = e.target.value; draw(); });
  $("smOrg")?.addEventListener("change", (e) => { sitesView.org = e.target.value; draw(); });
  draw();
}
// --- subnets in use: every LAN subnet per client, with overlaps and reused ranges flagged ---------------------------------
const subnetsView = { org: "", q: "", problems: false };
const ipNum = (ip) => ip.split(".").reduce((a, o) => a * 256 + Number(o), 0);

// --- Discovered: MikroTik devices your routers see next to them (IP > Neighbors) that aren't in TikManager yet ----------
const discView = { org: "", q: "" };

async function discoveredPage() {
  const r = await api("/api/discovered");
  const orgs = [...new Map(r.devices.flatMap((x) => x.seen.map((s) => [s.org_id, s.org || "Unassigned"]))).entries()].sort((a, b) => a[1].localeCompare(b[1]));
  $("main").innerHTML = `<h1>Discovered</h1>
    <p class="muted">MikroTik devices your routers see next to them (IP &gt; Neighbors: MNDP / LLDP / CDP) that aren't in TikManager. A device counts as
      already here when its MAC, IP or identity matches a router TikManager has (or is waiting to approve).</p>
    <div class="card"><div class="row">
      <select id="dOrg" aria-label="Client"><option value="">All clients</option>${orgs.map(([id, n]) => `<option value="${id}" ${String(id) === discView.org ? "selected" : ""}>${esc(n)}</option>`).join("")}</select>
      <input id="dQ" type="search" placeholder="Search identity, model, IP, MAC" aria-label="Search" value="${esc(discView.q)}">
      <span class="spacer"></span>
      <span class="small muted">${r.read} of ${r.routers} routers read${r.oldest ? ` · oldest ${ago(r.oldest)}` : ""} · every 15 minutes</span>
      <button class="btn primary" type="button" id="dAdopt">Adopt routers</button></div>
      <div id="dList"></div></div>
    <p class="small muted">Routers only see neighbours on their own networks, and only devices that announce themselves (IP &gt; Neighbors &gt;
      Discovery Settings on both ends). Neighbours behind another router or on a port with discovery turned off won't show.</p>`;
  const draw = () => {
    const q = discView.q.toLowerCase();
    const rows = r.devices.filter((x) => (!discView.org || x.seen.some((s) => String(s.org_id) === discView.org))
      && (!q || `${x.identity} ${x.board} ${x.address} ${x.mac} ${x.version}`.toLowerCase().includes(q)));
    $("dList").innerHTML = rows.length ? `<div class="table-wrap"><table><thead><tr><th>Identity</th><th>Model</th><th>RouterOS</th><th>IP address</th>
        <th>MAC address</th><th>Seen by</th><th>Up</th></tr></thead><tbody>
      ${rows.map((x) => `<tr><td><b>${esc(x.identity || "(no identity)")}</b>${x.identity === "MikroTik" ? ` <span class="pill" title="Still has the factory identity">default</span>` : ""}</td>
        <td>${esc(x.board)}</td><td class="small">${esc(x.version)}${/^6\./.test(x.version) ? ` <span class="pill" title="TikManager needs RouterOS 7 (REST API)">needs v7</span>` : ""}</td>
        <td class="mono">${esc(x.address)}</td><td class="mono small">${esc(x.mac)}</td>
        <td class="small">${x.seen.map((s) => `<a href="#router/${s.device_id}" data-dev="${s.device_id}">${esc(s.router)}</a> <span class="muted">· ${esc(s.org)}${s.interface ? ` · ${esc(s.interface)}` : ""}</span>`).join("<br>")}</td>
        <td class="small nowrap">${esc(x.uptime)}</td></tr>`).join("")}</tbody></table></div>`
      : `<p class="muted">${r.devices.length ? "Nothing matches." : r.read ? "Every MikroTik your routers can see is already in TikManager." : "Neighbours are read every 15 minutes - check back shortly."}</p>`;
    $("dList").querySelectorAll("[data-dev]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); go("router", a.dataset.dev); }));
  };
  draw();
  $("dOrg").addEventListener("change", () => { discView.org = $("dOrg").value; draw(); });
  $("dQ").addEventListener("input", () => { discView.q = $("dQ").value.trim(); draw(); });
  $("dAdopt").addEventListener("click", showAdoption);
}

async function subnetsPage() {
  const rows = await api("/api/sites");   // the same client-scoped data as the site map
  const list = rows.flatMap((d) => d.networks.map((n) => {
    const [first, last] = cidrRange(n.network), bits = Number(n.network.split("/")[1]);
    return { d, n, first, last, bits, org: d.org || "Unassigned", hosts: bits >= 31 ? 2 ** (32 - bits) : 2 ** (32 - bits) - 2,
             gateway: (n.address || "").split("/")[0] };
  }));
  for (const a of list) {
    const overlap = (b) => b !== a && b.first <= a.last && a.first <= b.last;
    // same client, another router (or a second network on the same router): a site-to-site VPN couldn't route both
    a.clash = list.filter((b) => overlap(b) && b.d.org_id === a.d.org_id && (b.d.id !== a.d.id || b.n.interface !== a.n.interface));
    // another client: harmless on its own, worth knowing before connecting two clients or merging
    a.elsewhere = [...new Set(list.filter((b) => overlap(b) && b.d.org_id !== a.d.org_id).map((b) => b.org))];
    a.factory = a.n.network === "192.168.88.0/24";
  }
  const orgs = [...new Map(rows.map((d) => [d.org_id, d.org || "Unassigned"])).entries()].sort((x, y) => x[1].localeCompare(y[1]));
  const problems = list.filter((a) => a.clash.length).length;
  $("main").innerHTML = `<h1>Subnets in use</h1>
    <p class="muted">Every LAN subnet on every approved router, grouped by client. Read from the routers each time they're polled.</p>
    <div class="row"><input id="snQ" type="search" placeholder="Search subnets, IPs, names or routers" value="${esc(subnetsView.q)}" aria-label="Search">
      ${orgs.length > 1 ? `<select id="snOrg" aria-label="Client"><option value="">All clients</option>${orgs.map(([id, n]) => `<option value="${id}">${esc(n)}</option>`).join("")}</select>` : ""}
      <label class="chk"><input type="checkbox" id="snProb" ${subnetsView.problems ? "checked" : ""}> Only overlaps</label>
      <span class="spacer"></span><span class="small muted">${list.length} subnets · ${new Set(list.map((a) => a.d.org_id)).size} clients
        ${problems ? ` · <span class="status warn">${problems} overlapping</span>` : ""}</span>
      <button class="btn" type="button" id="snCsv">Export CSV</button></div>
    <div id="snBody"></div>`;
  if ($("snOrg")) $("snOrg").value = subnetsView.org;

  const matches = (a) => {
    const q = subnetsView.q.trim().toLowerCase();
    if (subnetsView.org && String(a.d.org_id) !== subnetsView.org) return false;
    if (subnetsView.problems && !a.clash.length) return false;
    if (!q) return true;
    // an IP address finds the subnet it belongs to
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(q)) { const n = ipNum(q); return n >= a.first && n <= a.last; }
    return [a.n.network, a.n.name, a.n.interface, a.gateway, a.d.name, a.org].some((v) => (v || "").toLowerCase().includes(q));
  };
  const note = (a) => [
    a.clash.length ? `<span class="status warn">Overlaps ${esc([...new Set(a.clash.map((b) => b.d.id === a.d.id ? `${b.n.name} (same router)` : b.d.name))].join(", "))}</span>` : "",
    a.factory ? `<span class="pill">MikroTik default</span>` : "",
    a.elsewhere.length ? `<span class="small muted" title="${esc(a.elsewhere.join(", "))}">Also used at ${a.elsewhere.length} other client${a.elsewhere.length === 1 ? "" : "s"}</span>` : "",
  ].filter(Boolean).join(" ");
  const shown = () => list.filter(matches).sort((x, y) => x.org.localeCompare(y.org) || x.first - y.first || x.bits - y.bits);

  const draw = () => {
    const items = shown();
    const groups = new Map();
    items.forEach((a) => { if (!groups.has(a.org)) groups.set(a.org, []); groups.get(a.org).push(a); });
    $("snBody").innerHTML = items.length ? [...groups.entries()].map(([org, g]) => `<div class="card">
      <div class="row"><h2>${esc(org)}</h2><span class="spacer"></span><span class="small muted">${g.length} subnet${g.length === 1 ? "" : "s"} on ${new Set(g.map((a) => a.d.id)).size} router${new Set(g.map((a) => a.d.id)).size === 1 ? "" : "s"}</span></div>
      <div class="table-wrap"><table><thead><tr><th>Subnet</th><th>Name</th><th>Router</th><th>Interface</th><th>Gateway</th><th class="num">Usable</th><th>Notes</th></tr></thead>
      <tbody>${g.map((a) => `<tr class="${a.clash.length ? "sn-clash" : ""}"><td class="mono"><b>${esc(a.n.network)}</b></td><td>${esc(a.n.name)}</td>
        <td><a href="#router/${a.d.id}"><span class="dot ${a.d.online ? "on" : "off"}"></span>${esc(a.d.name)}</a></td>
        <td class="mono small">${esc(a.n.interface || "")}</td><td class="mono small">${esc(a.gateway)}</td>
        <td class="num">${a.hosts.toLocaleString()}</td><td>${note(a)}</td></tr>`).join("")}</tbody></table></div></div>`).join("")
      : `<p class="muted">No subnets match.</p>`;
  };
  $("snQ").addEventListener("input", (e) => { subnetsView.q = e.target.value; draw(); });
  $("snOrg")?.addEventListener("change", (e) => { subnetsView.org = e.target.value; draw(); });
  $("snProb").addEventListener("change", (e) => { subnetsView.problems = e.target.checked; draw(); });
  $("snCsv").addEventListener("click", () => {
    const cell = (v) => { const s = String(v ?? ""); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
    const lines = [["Client", "Subnet", "Name", "Router", "Interface", "Gateway", "Usable hosts", "Overlaps", "Also used at"].join(",")]
      .concat(shown().map((a) => [a.org, a.n.network, a.n.name, a.d.name, a.n.interface, a.gateway, a.hosts,
        a.clash.map((b) => b.d.name).join("; "), a.elsewhere.join("; ")].map(cell).join(",")));
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([lines.join("\r\n")], { type: "text/csv" }));
    link.download = `subnets-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  });
  draw();
}
// --- site-to-site VPN (WireGuard, hub and spoke) ----------------------------------------------------------------------
const vpnPill = (st) => `<span class="pill ${{ active: "up-done", failed: "up-failed", applying: "up-run", disabled: "up-cancelled" }[st] || ""}">${esc({ draft: "Draft", applying: "Applying...", active: "Active", failed: "Needs attention", disabled: "Disabled" }[st] || st)}</span>`;
function tunnelState(s) {
  if (s.state === "pending") return `<span class="muted small">Not applied yet</span>`;
  if (s.state === "removing") return `<span class="muted small">Being removed</span>`;
  if (s.state === "failed") return `<span class="status err small">${esc(s.last_error || "Failed")}</span>`;
  if (s.handshake_age == null) return `<span class="status err small"><span class="dot off"></span>No handshake yet</span>`;
  const up = s.handshake_age < 180;
  return `<span class="small ${up ? "status ok" : "status err"}"><span class="dot ${up ? "on" : "off"}"></span>${up ? "Up" : "Down"}</span>
    <span class="small muted">handshake ${uptime(`${s.handshake_age}s`, true)} ago${s.ping_ms != null ? ` · ${Math.round(s.ping_ms)} ms to hub` : ""}</span>`;
}

// VPNs already configured on routers (found read-only, not managed by TikManager)
const tunPill = (st) => `<span class="pill ${{ up: "up-done", down: "up-failed", listening: "up-run", disabled: "up-cancelled" }[st] || ""}">${esc({ up: "Up", down: "Down", listening: "Listening", disabled: "Disabled" }[st] || st)}</span>`;
function tunnelRows(list, showRouter) {
  return list.map(({ r, t }) => `<tr>${showRouter ? `<td><a href="#router/${r.id}">${esc(r.name)}</a> <span class="dot ${r.online ? "on" : "off"}"></span></td>` : ""}
    <td class="nowrap">${esc(t.kind)}</td><td>${esc(t.name)}</td>
    <td class="small">${t.peer ? `<a href="#router/${t.peer.id}"><b>${esc(t.peer.name)}</b></a>${t.peer.org && showRouter && t.peer.org !== r.org ? ` <span class="muted">(${esc(t.peer.org)})</span>` : ""}<div class="mono muted">${esc(t.remote)}</div>`
      : `<span class="mono">${esc(t.remote || "—")}</span>`}</td>
    <td>${tunPill(t.status)}${t.since ? `<div class="small muted">${esc(t.since)}</div>` : ""}</td>
    <td class="mono small">${(t.networks || []).slice(0, 6).map(esc).join("<br>")}${(t.networks || []).length > 6 ? `<br>+${t.networks.length - 6} more` : ""}
      ${(t.users || []).length ? `<div class="small">${t.users.slice(0, 8).map(esc).join("<br>")}</div>` : ""}</td>
    <td class="small nowrap">${t.rx || t.tx ? `↓ ${bytes(t.rx)} ↑ ${bytes(t.tx)}` : ""}</td>
    <td class="small ${/insecure|no phase 2/.test(t.notes || "") ? "status warn" : "muted"}">${esc(t.notes || "")}</td></tr>`).join("");
}
const foundView = { org: "", kind: "", problems: false };
async function vpnFound() {
  const rows = await api("/api/vpn-inventory");
  const all = rows.flatMap((r) => (r.tunnels || []).map((t) => ({ r, t })));
  const orgs = [...new Map(rows.map((r) => [r.org_id, r.org || "Unassigned"])).entries()];
  const kinds = [...new Set(all.map((x) => x.t.kind))].sort();
  const unread = rows.filter((r) => r.tunnels == null).length, none = rows.filter((r) => r.tunnels && !r.tunnels.length).length;
  $("vpnBody").innerHTML = `<div class="card"><div class="row">
      ${orgs.length > 1 ? `<select id="fOrg"><option value="">All clients</option>${orgs.map(([id, n]) => `<option value="${id}">${esc(n)}</option>`).join("")}</select>` : ""}
      <select id="fKind"><option value="">All types</option>${kinds.map((k) => `<option>${esc(k)}</option>`).join("")}</select>
      <label class="chk"><input type="checkbox" id="fProb" ${foundView.problems ? "checked" : ""}> Down or needing attention only</label>
      <span class="spacer"></span><button class="btn" type="button" id="fRefresh">Read routers again</button></div>
    <p class="small muted" id="fMsg">${all.length} VPN connections on ${rows.length - none - unread} routers · read every 15 minutes, read-only (no passwords or keys are collected).
      ${none ? `${none} routers have no other VPNs.` : ""} ${unread ? `${unread} not read yet.` : ""} Linked names are other TikManager routers.</p>
    <div class="table-wrap"><table><thead><tr><th>Router</th><th>Type</th><th>Name</th><th>Remote end</th><th>Status</th><th>Networks / users</th><th>Traffic</th><th>Notes</th></tr></thead>
      <tbody id="fRows"></tbody></table></div></div>`;
  if ($("fOrg")) $("fOrg").value = foundView.org;
  $("fKind").value = foundView.kind;
  const draw = () => {
    const list = all.filter(({ r, t }) => (!foundView.org || String(r.org_id) === foundView.org) && (!foundView.kind || t.kind === foundView.kind) &&
      (!foundView.problems || t.status === "down" || /insecure|no phase 2/.test(t.notes || "")));
    $("fRows").innerHTML = tunnelRows(list, true) || `<tr><td colspan="8" class="muted">Nothing matches.</td></tr>`;
  };
  $("fOrg")?.addEventListener("change", (e) => { foundView.org = e.target.value; draw(); });
  $("fKind").addEventListener("change", (e) => { foundView.kind = e.target.value; draw(); });
  $("fProb").addEventListener("change", (e) => { foundView.problems = e.target.checked; draw(); });
  $("fRefresh").addEventListener("click", async () => {
    $("fRefresh").disabled = true;
    const x = await post("/api/vpn-inventory/refresh");
    if (x.background) $("fMsg").textContent = `Reading ${x.count} routers in the background - reopen this tab in a minute.`; else vpnFound();
  });
  draw();
}

let vpnTab = "managed";
async function vpnsView() {
  $("main").innerHTML = `<div class="row"><h1>Site-to-site VPN</h1><span class="spacer"></span>
      ${canWrite() ? `<button class="btn primary" type="button" id="vpnNew">New VPN</button>` : ""}</div>
    <div class="tabs" role="tablist">${[["managed", "Managed by TikManager"], ["found", "Existing VPNs on routers"]].map(([k, l]) =>
      `<button type="button" role="tab" data-vtab="${k}" class="${k === vpnTab ? "active" : ""}">${l}</button>`).join("")}</div>
    <div id="vpnBody"></div>`;
  document.querySelectorAll("[data-vtab]").forEach((b) => b.addEventListener("click", () => { vpnTab = b.dataset.vtab; vpnsView(); }));
  $("vpnNew")?.addEventListener("click", () => go("vpn", "new"));
  if (vpnTab === "found") return vpnFound();
  const rows = await api("/api/vpns");
  $("vpnBody").innerHTML = `<p class="muted">Connect a client's sites with WireGuard: one hub with a public address, every other router dials in to it.
      The routers make their own keys; TikManager backs each one up before changing anything.</p>
    <div class="card">${rows.length ? `<div class="table-wrap"><table><thead><tr><th>VPN</th><th>Client</th><th>Hub</th><th>Sites up</th><th>Status</th><th>Last applied</th></tr></thead><tbody>
      ${rows.map((v) => { const up = v.sites.filter((s) => s.state === "applied" && s.handshake_age != null && s.handshake_age < 180).length;
        return `<tr class="click" data-vpn="${v.id}"><td><b>${esc(v.name)}</b><div class="small muted mono">${esc(v.tunnel_net)}</div></td><td>${esc(v.org)}</td><td>${esc(v.hub || "—")}</td>
          <td>${up} / ${v.sites.length}</td><td>${vpnPill(v.status)}${v.last_error ? `<div class="small status err">${esc(v.last_error)}</div>` : ""}</td><td class="small">${v.last_applied ? ago(v.last_applied) : "never"}</td></tr>`; }).join("")}
      </tbody></table></div>` : `<p class="muted">No VPNs yet.${canWrite() ? " Click New VPN to connect a client's sites." : ""}</p>`}</div>`;
  document.querySelectorAll("[data-vpn]").forEach((r) => r.addEventListener("click", () => go("vpn", r.dataset.vpn)));
}

async function vpnView(id) {
  const isNew = id === "new";
  const orgs = isNew ? await api("/api/orgs") : [];
  let v = null, cands = [];
  if (!isNew) ({ vpn: v, candidates: cands } = await api(`/api/vpns/${id}`));
  const st = { org_id: v ? v.org_id : orgs[0]?.id, hub: v ? v.hub_device_id : null, sites: new Map() };
  if (v) v.sites.filter((s) => s.state !== "removing").forEach((s) => st.sites.set(s.device_id, { subnets: new Set(s.subnets), custom: "" }));
  const ro = !canWrite();
  $("main").innerHTML = `<p><a href="#vpns">← Site-to-site VPN</a></p>
    <div class="row"><h1>${isNew ? "New site-to-site VPN" : esc(v.name)}</h1><span id="vpnPill">${v ? vpnPill(v.status) : ""}</span></div>
    ${v ? `<div class="card" id="vpnStatus"></div>` : ""}
    <div class="card"><h2>${isNew ? "Set up" : "Settings"}</h2>
      <div class="grid2">
        ${isNew ? `<label class="field">Client <select id="vOrg">${orgs.map((o) => `<option value="${o.id}">${esc(o.name)}</option>`).join("")}</select></label>`
          : `<div class="kv"><span>Client</span><span>${esc(v.org)}</span></div>`}
        <label class="field">Name <input id="vName" maxlength="80" value="${esc(v ? v.name : "Site-to-site VPN")}" ${ro ? "disabled" : ""}></label>
      </div>
      <h3>Routers</h3><p class="small muted">Tick the routers to connect, choose the hub, and the subnets each site shares (taken from the site map).</p>
      <div class="table-wrap"><table><thead><tr><th>Include</th><th>Hub</th><th>Router</th><th>Subnets to share</th></tr></thead><tbody id="vRows"></tbody></table></div>
      <div id="vWarn"></div>
      <h3>Hub connection</h3><div class="grid2">
        <label class="field">Public address of the hub <input id="vEp" maxlength="120" value="${esc(v?.endpoint || "")}" ${ro ? "disabled" : ""}></label>
        <label class="field">WireGuard UDP port <input id="vPort" type="number" min="1" max="65535" value="${v ? v.port : 13232}" ${ro ? "disabled" : ""}></label>
        <label class="field">Tunnel network <input id="vNet" value="${esc(v?.tunnel_net || "")}" placeholder="automatic (10.250.x.0/24)" ${ro ? "disabled" : ""}></label>
      </div>
      <p class="small muted">Leave the address blank to use the hub's public WAN IP. If the hub sits behind another router or NAT, enter its public IP or DDNS name
        (IP > Cloud) and forward the UDP port to it. Each router is backed up first; the change replaces only what TikManager added (tagged "TikManager VPN").</p>
      ${ro ? "" : `<div class="actions"><button class="btn primary" type="button" id="vApply">Save and apply</button><button class="btn" type="button" id="vSave">Save draft</button>
        ${v && v.status !== "draft" ? `<button class="btn" type="button" id="vDisable">Disable</button>` : ""}${v ? `<button class="btn danger" type="button" id="vDelete">Delete</button>` : ""}
        <span class="status" id="vStatus"></span></div>`}
    </div>`;
  const say = (m, ok) => { $("vStatus").textContent = m; $("vStatus").className = `status ${ok ? "ok" : "err"}`; };
  const draw = () => {
    $("vRows").innerHTML = cands.length ? cands.map((d) => {
      const s = st.sites.get(d.id), on = !!s, pub = d.wan_ip && !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(d.wan_ip);
      return `<tr class="${d.other_vpn ? "muted" : ""}"><td><input type="checkbox" data-vin="${d.id}" ${on ? "checked" : ""} ${d.other_vpn || ro ? "disabled" : ""} aria-label="Include ${esc(d.name)}"></td>
        <td><input type="radio" name="vHub" value="${d.id}" ${st.hub === d.id ? "checked" : ""} ${!on || ro ? "disabled" : ""} aria-label="${esc(d.name)} is the hub"></td>
        <td><b>${esc(d.name)}</b> <span class="dot ${d.online ? "on" : "off"}"></span><div class="small muted">${esc(d.model || "")} · WAN <span class="mono">${esc(d.wan_ip || "—")}</span>
          ${d.wan_ip ? (pub ? `<span class="pill">public</span>` : `<span class="pill">behind NAT</span>`) : ""}${d.other_vpn ? ` · in "${esc(d.other_vpn)}"` : ""}</div></td>
        <td>${on ? `<div class="vsubs">${d.networks.map((n) => `<label class="chk"><input type="checkbox" data-vsub="${d.id}" value="${esc(n.network)}" ${s.subnets.has(n.network) ? "checked" : ""} ${ro ? "disabled" : ""}>
            ${esc(n.name)} <span class="mono small">${esc(n.network)}</span></label>`).join("")}
            ${[...s.subnets].filter((x) => !d.networks.some((n) => n.network === x)).map((x) => `<label class="chk"><input type="checkbox" data-vsub="${d.id}" value="${esc(x)}" checked ${ro ? "disabled" : ""}> <span class="mono small">${esc(x)}</span></label>`).join("")}
            ${ro ? "" : `<input class="vadd" data-vadd="${d.id}" placeholder="add subnet, e.g. 10.20.0.0/24" aria-label="Add a subnet for ${esc(d.name)}">`}</div>` : `<span class="small muted">${d.networks.length} networks</span>`}</td></tr>`;
    }).join("") : `<tr><td colspan="4" class="muted">This client has no approved routers.</td></tr>`;
    // live overlap check (the server checks again before saving)
    const chosen = [...st.sites.entries()].flatMap(([did, s]) => [...s.subnets].map((n) => ({ did, n, r: cidrRange(n) })));
    const clashes = [];
    chosen.forEach((a, i) => chosen.slice(i + 1).forEach((b) => { if (a.did !== b.did && a.r[0] <= b.r[1] && b.r[0] <= a.r[1]) clashes.push(`${a.n} (${cands.find((d) => d.id === a.did)?.name}) overlaps ${b.n} (${cands.find((d) => d.id === b.did)?.name})`); }));
    const hub = cands.find((d) => d.id === st.hub);
    $("vEp").placeholder = hub ? (hub.wan_ip && !/^(10\.|192\.168\.|172\.|100\.)/.test(hub.wan_ip) ? `${hub.wan_ip} (hub's WAN IP)` : "required - the hub is behind NAT") : "pick a hub first";
    $("vWarn").innerHTML = clashes.length ? `<p class="status err small">Overlapping subnets - renumber one site or untick one: ${clashes.map(esc).join("; ")}</p>` : "";
    document.querySelectorAll("[data-vin]").forEach((c) => c.addEventListener("change", () => {
      const d = cands.find((x) => x.id === +c.dataset.vin);
      if (c.checked) st.sites.set(d.id, { subnets: new Set(d.networks.filter((n) => !/guest/i.test(n.name)).map((n) => n.network)) });
      else { st.sites.delete(d.id); if (st.hub === d.id) st.hub = null; }
      if (!st.hub && st.sites.size) st.hub = (cands.find((x) => st.sites.has(x.id) && x.wan_ip && !/^(10\.|192\.168\.|172\.|100\.)/.test(x.wan_ip)) || {}).id || [...st.sites.keys()][0];
      draw();
    }));
    document.querySelectorAll("[name=vHub]").forEach((r) => r.addEventListener("change", () => { st.hub = +r.value; draw(); }));
    document.querySelectorAll("[data-vsub]").forEach((c) => c.addEventListener("change", () => { const s = st.sites.get(+c.dataset.vsub); c.checked ? s.subnets.add(c.value) : s.subnets.delete(c.value); draw(); }));
    document.querySelectorAll("[data-vadd]").forEach((i) => i.addEventListener("keydown", (e) => {
      if (e.key !== "Enter" || !i.value.trim()) return;
      if (!/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(i.value.trim())) { say("Enter a subnet like 10.20.0.0/24."); return; }
      st.sites.get(+i.dataset.vadd).subnets.add(i.value.trim()); draw();
    }));
  };
  const loadCands = async () => { cands = (await api(`/api/vpn-candidates?org_id=${st.org_id}`)).candidates; st.sites.clear(); st.hub = null; draw(); };
  if (isNew) { if (!orgs.length) { $("vRows").innerHTML = `<tr><td colspan="4" class="muted">Add a client first.</td></tr>`; return; } $("vOrg").addEventListener("change", (e) => { st.org_id = +e.target.value; loadCands(); }); await loadCands(); }
  else draw();
  const save = async (apply) => {
    try {
      const r = await post("/api/vpns", { id: v?.id, org_id: st.org_id, name: $("vName").value, hub_device_id: st.hub, endpoint: $("vEp").value, port: $("vPort").value,
        tunnel_net: $("vNet").value, apply, sites: [...st.sites.entries()].map(([device_id, s]) => ({ device_id, subnets: [...s.subnets] })) });
      if (isNew) go("vpn", r.id); else { say(apply ? "Saved - applying to the routers..." : "Saved.", true); refresh(); }
    } catch (e) { say(e.message); }
  };
  $("vApply")?.addEventListener("click", () => save(true));
  $("vSave")?.addEventListener("click", () => save(false));
  $("vDisable")?.addEventListener("click", async () => { try { await post(`/api/vpns/${v.id}/disable`); say("Removing the VPN from the routers...", true); refresh(); } catch (e) { say(e.message); } });
  $("vDelete")?.addEventListener("click", async (e) => {
    if (e.target.dataset.confirm !== "1") { e.target.dataset.confirm = "1"; e.target.textContent = "Click again to delete"; return; }
    try { const r = await post(`/api/vpns/${v.id}/delete`); if (r.deleted) go("vpns"); else { say("Removing from the routers, then deleting...", true); refresh(); } } catch (err) { say(err.message); }
  });
  // status card refreshes on its own (the form keeps your edits)
  const refresh = async () => {
    if (!v) return;
    let x;
    try { x = await api(`/api/vpns/${v.id}`); } catch { if (view === "vpn") go("vpns"); return; }
    const w = x.vpn;
    $("vpnPill").innerHTML = vpnPill(w.status);
    $("vpnStatus").innerHTML = `<div class="row"><h2>Tunnels</h2><span class="spacer"></span><span class="small muted">${w.last_applied ? `applied ${ago(w.last_applied)}` : "not applied yet"} · tunnel network <span class="mono">${esc(w.tunnel_net)}</span> · port ${w.port}</span>
        ${canWrite() && w.status !== "applying" && w.status !== "draft" ? `<button class="btn" type="button" id="vReapply">Apply again</button>` : ""}</div>
      ${w.last_error ? `<p class="status err small">${esc(w.last_error)}</p>` : ""}
      <div class="table-wrap"><table><thead><tr><th>Role</th><th>Router</th><th>Tunnel IP</th><th>Shares</th><th>Tunnel</th><th>Traffic</th></tr></thead><tbody>
      ${w.sites.map((s) => `<tr><td><span class="pill ${s.role === "hub" ? "up-sched" : ""}">${s.role}</span></td><td><a href="#router/${s.device_id}">${esc(s.name)}</a> <span class="dot ${s.online ? "on" : "off"}"></span></td>
        <td class="mono">${esc(s.tunnel_ip)}</td><td class="mono small">${s.subnets.map(esc).join("<br>")}</td><td>${tunnelState(s)}</td>
        <td class="small nowrap">${s.rx != null ? `↓ ${bytes(s.rx)} ↑ ${bytes(s.tx)}` : ""}</td></tr>`).join("")}</tbody></table></div>`;
    $("vReapply")?.addEventListener("click", async () => { try { await post(`/api/vpns/${v.id}/apply`); refresh(); } catch (e) { say(e.message); } });
  };
  if (v) { await refresh(); clearInterval(timer); timer = setInterval(() => { if (view === "vpn") refresh(); }, 5000); }
}
const VIEWS = { dashboard, routers, sites, subnets: subnetsPage, discovered: discoveredPage, tasks: tasksView, vpns: vpnsView, vpn: vpnView, upgrades: upgradesView, backups: backupsView, clients, users, audit, admin: (tab) => admin(tab || undefined) };
async function go(v, arg) {
  view = v;
  rView.hold = false;
  clearInterval(timer);
  document.querySelectorAll("#nav button").forEach((b) => b.classList.toggle("active", b.dataset.view === v || (v === "router" && b.dataset.view === "routers") || (v === "vpn" && b.dataset.view === "vpns")));
  history.replaceState(null, "", arg != null ? `#${v}/${arg}` : `#${v}`);
  try {
    await (v === "router" ? router(arg) : VIEWS[v](arg));
    // auto-refresh, skipped while someone is typing in a field on the page
    if (v === "dashboard" || v === "router") timer = setInterval(() => { if (rView.hold || document.activeElement?.closest?.("#main input, #main select, #main textarea")) return;
      (v === "router" ? router(arg) : dashboard()).catch(() => {}); }, 30000);
    if (v === "upgrades") timer = setInterval(() => { if (!$("dlg").open) upgradesView().catch(() => {}); }, 20000);
  } catch (e) { $("main").innerHTML = `<p class="status err">${esc(e.message)}</p>`; }
}

async function init() {
  me = await api("/api/me");
  $("who").textContent = `${me.name || me.email}${me.org ? ` · ${me.org}` : ""}`;
  // who's signed in, at the top of the sidebar
  const who = me.name || me.email || "";
  $("navAvatar").textContent = who.split(/[\s@.]+/).filter(Boolean).map((w) => w[0]).slice(0, 2).join("").toUpperCase();
  $("navName").textContent = who;
  $("navRole").textContent = me.kind === "tech" ? { admin: "Administrator", tech: "Technician", readonly: "Read-only" }[me.role] || me.role
    : `${me.org || "Client"} · ${me.role === "admin" ? "admin" : "viewer"}`;
  $("navUser").hidden = false;
  // appearance: the person's saved choice (theme.js already applied this browser's last one)
  if (me.prefs) window.setAppearance(me.prefs);
  $("appearanceBtn").addEventListener("click", showAppearance);
  // phone: the menu slides in; choosing a page or tapping beside it closes it
  $("menuBtn").addEventListener("click", (e) => { e.stopPropagation(); $("nav").classList.toggle("open"); });
  document.querySelector(".content").addEventListener("click", () => $("nav").classList.remove("open"));
  $("devBadge").classList.toggle("hidden", !me.dev);
  $("navVersion").textContent = me.version ? `TikManager ${me.version}` : "";
  // the installed version, next to the logo, for everyone
  $("verChip").textContent = me.version ? `v${me.version}` : "";
  $("verChip").classList.toggle("hidden", !me.version);
  showUpdate(me.update);
  watchUpdates();
  document.querySelectorAll("[data-tech]").forEach((b) => b.classList.toggle("hidden", !isTech()));
  document.querySelectorAll("[data-admin]").forEach((b) => b.classList.toggle("hidden", !(isTech() || me.role === "admin")));
  document.querySelectorAll("[data-techadmin]").forEach((b) => b.classList.toggle("hidden", !(isTech() && me.role === "admin")));
  document.querySelectorAll("#nav button").forEach((b) => b.addEventListener("click", () => { $("nav").classList.remove("open"); go(b.dataset.view); }));
  $("logout").addEventListener("click", async () => {
    const r = await post("/api/logout");
    location.href = r.entra_logout || "/login";
  });
  const route = () => {
    const [h, arg] = location.hash.slice(1).split("/");
    if (h === "router" && arg) go("router", arg); else if (h === "vpn" && arg) go("vpn", arg); else if (h === "admin" && arg) go("admin", arg); else go(VIEWS[h] && h !== "vpn" ? h : "dashboard");
  };
  window.addEventListener("hashchange", route);   // links, typed URLs and Back (go() uses replaceState, which doesn't fire this)
  route();
}
init().catch(() => {});
