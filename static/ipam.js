"use strict";
// IPAM workspace. CSP forbids inline scripts/handlers, so everything binds via addEventListener + data-* delegation.

let me = null, tree = { sections: [], subnets: [], clients: [] }, current = null; // current = {kind:'all'|'section'|'client', id}

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { "Content-Type": "application/json", "X-CSRF-Token": me?.csrf || "", ...(opts.headers || {}) } });
  const body = await r.json().catch(() => ({}));
  if (r.status === 401) { location.href = "/login"; throw new Error("Signed out"); }
  if (!r.ok) throw new Error(body.error || r.statusText);
  return body;
}
const post = (path, data = {}) => api(path, { method: "POST", body: JSON.stringify(data) });

// ---- data model helpers -------------------------------------------------------------------------------------
function ipToInt(ip) { return ip.split(".").reduce((a, o) => (a << 8 >>> 0) + (+o), 0) >>> 0; }
function intToIp(n) { return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join("."); }
function parseCidr(cidr) {
  const [base, pfxs] = String(cidr).split("/");
  const pfx = +pfxs;
  if (base.includes(":")) return { v6: true, cidr, pfx };            // IPv6: no grid math in beta.1
  // `&` returns a SIGNED 32-bit int, so for a first octet >= 128 (192.168.x, 172.x) net goes negative and the grid
  // loop `for (n=first; n<=last; …)` would run billions of times - coerce back to unsigned with >>> 0.
  const net = (ipToInt(base) & (pfx === 0 ? 0 : (0xffffffff << (32 - pfx)) >>> 0)) >>> 0;
  return { v6: false, pfx, net, size: pfx >= 32 ? 1 : 2 ** (32 - pfx), first: net, last: (net + (pfx >= 32 ? 0 : 2 ** (32 - pfx) - 1)) >>> 0 };
}

// ---- left tree ----------------------------------------------------------------------------------------------
function renderTree() {
  const t = $("tree"); t.textContent = "";
  const all = el("div", "tree-item" + (current?.kind === "all" ? " active" : ""), "All subnets");
  all.dataset.kind = "all"; t.appendChild(all);

  const secWrap = el("div", "tree-group");
  secWrap.appendChild(el("div", "tree-label", "Sections"));
  const roots = tree.sections.filter((s) => !s.parent_id);
  const kids = (pid) => tree.sections.filter((s) => s.parent_id === pid);
  const addSec = (s, depth) => {
    const row = el("div", "tree-item" + (current?.kind === "section" && current.id === s.id ? " active" : ""));
    row.style.paddingLeft = (12 + depth * 14) + "px";
    row.dataset.kind = "section"; row.dataset.id = s.id;
    row.appendChild(el("span", "tree-name", s.name));
    const edit = el("button", "tree-edit", "⋯"); edit.dataset.editsection = s.id; edit.title = "Edit section";
    row.appendChild(edit); secWrap.appendChild(row);
    kids(s.id).forEach((k) => addSec(k, depth + 1));
  };
  if (!roots.length) secWrap.appendChild(el("div", "muted tree-empty", "No sections yet."));
  roots.forEach((s) => addSec(s, 0));
  t.appendChild(secWrap);

  const cliWrap = el("div", "tree-group");
  cliWrap.appendChild(el("div", "tree-label", "Clients"));
  if (!tree.clients.length) cliWrap.appendChild(el("div", "muted tree-empty", "No client subnets yet — Sync from routers."));
  tree.clients.forEach((c) => {
    const row = el("div", "tree-item" + (current?.kind === "client" && current.id === c.id ? " active" : ""));
    row.dataset.kind = "client"; row.dataset.id = c.id;
    row.appendChild(el("span", "tree-name", c.name));
    row.appendChild(el("span", "tree-count", String(c.subnets)));
    cliWrap.appendChild(row);
  });
  t.appendChild(cliWrap);
}

// ---- subnet list --------------------------------------------------------------------------------------------
function currentSubnets() {
  if (!current || current.kind === "all") return tree.subnets;
  if (current.kind === "section") return tree.subnets.filter((s) => s.section_id === current.id);
  return tree.subnets.filter((s) => s.org_id === current.id);
}
function usageBar(s) {
  const wrap = el("div", "usebar");
  const fill = el("span", "usebar-fill"); fill.style.width = Math.min(100, s.usage || 0) + "%";
  if ((s.usage || 0) >= 90) fill.classList.add("hot"); else if ((s.usage || 0) >= 70) fill.classList.add("warm");
  wrap.appendChild(fill);
  const lbl = el("span", "usebar-txt", (s.usage || 0) + "%"); wrap.appendChild(lbl);
  return wrap;
}
function showSubnets() {
  const m = $("main"); m.textContent = "";
  const head = el("div", "main-head");
  const title = current?.kind === "client" ? (tree.clients.find((c) => c.id === current.id)?.name || "Client")
    : current?.kind === "section" ? (tree.sections.find((s) => s.id === current.id)?.name || "Section") : "All subnets";
  head.appendChild(el("h1", null, title));
  const actions = el("div", "main-head-actions");
  const addBtn = el("button", "btn primary", "+ Subnet"); addBtn.dataset.newsubnet = "1"; actions.appendChild(addBtn);
  if (current?.kind === "client") { const sb = el("button", "btn", "Sync this client"); sb.dataset.syncorg = current.id; actions.appendChild(sb); }
  head.appendChild(actions); m.appendChild(head);

  const rows = currentSubnets();
  if (!rows.length) { m.appendChild(el("p", "muted pad", "No subnets here yet. Add one, or Sync from routers to discover them.")); return; }
  const tbl = el("table", "ipam-table");
  const thead = el("tr"); ["Subnet", "Name", "Client", "Router", "Usage", "Source", ""].forEach((h) => thead.appendChild(el("th", null, h)));
  const th = el("thead"); th.appendChild(thead); tbl.appendChild(th);
  const tb = el("tbody");
  rows.forEach((s) => {
    const tr = el("tr", "sub-row"); tr.dataset.subnet = s.id;
    const c0 = el("td"); const a = el("a", "cidr", s.cidr); a.dataset.subnet = s.id; c0.appendChild(a);
    if (s.reserved) c0.appendChild(el("span", "pill reserved", "reserved"));
    tr.appendChild(c0);
    tr.appendChild(el("td", null, s.name || ""));
    tr.appendChild(el("td", null, s.org || ""));
    tr.appendChild(el("td", "muted", s.interface || ""));
    const cu = el("td"); cu.appendChild(usageBar(s)); tr.appendChild(cu);
    const cs = el("td"); cs.appendChild(el("span", "pill " + (s.source === "discovered" ? "disc" : "man"), s.source)); tr.appendChild(cs);
    const last = el("td"); const del = el("button", "btn tiny danger", "Delete"); del.dataset.delsubnet = s.id; last.appendChild(del); tr.appendChild(last);
    tb.appendChild(tr);
  });
  tbl.appendChild(tb); m.appendChild(tbl);
}

// ---- subnet detail + visual map ----------------------------------------------------------------------------
const STATUSES = ["free", "used", "reserved", "dhcp", "offline", "gateway"];
async function showSubnet(id) {
  const m = $("main"); m.textContent = "Loading…";
  let d;
  try { d = await api("/api/ipam/subnets/" + id); } catch (e) { m.textContent = e.message; return; }
  m.textContent = "";
  const head = el("div", "main-head");
  const h = el("h1", null, d.cidr); if (d.reserved) h.appendChild(el("span", "pill reserved", " reserved"));
  head.appendChild(h);
  const acts = el("div", "main-head-actions");
  const back = el("button", "btn", "← Subnets"); back.dataset.back = "1"; acts.appendChild(back);
  const edit = el("button", "btn", "Edit"); edit.dataset.editsubnet = d.id; acts.appendChild(edit);
  const split = el("button", "btn", "Split"); split.dataset.splitsubnet = d.id; acts.appendChild(split);
  const addA = el("button", "btn primary", "+ Address"); addA.dataset.newaddr = d.id; acts.appendChild(addA);
  head.appendChild(acts); m.appendChild(head);

  const meta = el("div", "meta-row");
  const chip = (k, v) => { const c = el("span", "chip"); c.appendChild(el("b", null, k + " ")); c.appendChild(document.createTextNode(v)); return c; };
  meta.appendChild(chip("Name", d.name || "—"));
  meta.appendChild(chip("Client", d.org || "—"));
  meta.appendChild(chip("Gateway", d.gateway || "—"));
  meta.appendChild(chip("Usable", String(d.usable)));
  meta.appendChild(chip("Used", (d.used_total || 0) + " (" + (d.usage || 0) + "%)"));
  meta.appendChild(chip("Source", d.source));
  m.appendChild(meta);

  const byIp = {}; (d.addresses || []).forEach((a) => (byIp[a.ip] = a));
  m.appendChild(renderMap(d, byIp));

  // address table
  if ((d.addresses || []).length) {
    const tbl = el("table", "ipam-table");
    const tr = el("tr"); ["IP", "Status", "Hostname", "MAC", "Owner", "Source", ""].forEach((x) => tr.appendChild(el("th", null, x)));
    const th = el("thead"); th.appendChild(tr); tbl.appendChild(th);
    const tb = el("tbody");
    d.addresses.slice().sort((a, b) => (a.ip_sort || 0) - (b.ip_sort || 0)).forEach((a) => {
      const r = el("tr");
      r.appendChild(el("td", "mono", a.ip));
      const st = el("td"); st.appendChild(statusPill(a.status)); r.appendChild(st);
      r.appendChild(el("td", null, a.hostname || ""));
      r.appendChild(el("td", "mono muted", a.mac || ""));
      r.appendChild(el("td", null, a.owner || ""));
      r.appendChild(el("td", "muted", a.source));
      const last = el("td"); const e = el("button", "btn tiny", "Edit"); e.dataset.editaddr = a.id; e.dataset.subnet = d.id; last.appendChild(e);
      const del = el("button", "btn tiny danger", "×"); del.dataset.deladdr = a.id; del.dataset.subnet = d.id; last.appendChild(del);
      r.appendChild(last); tb.appendChild(r);
    });
    tbl.appendChild(tb); m.appendChild(tbl);
  }
  current = { ...current, subnet: d.id };
}
function statusPill(s) { const p = el("span", "pill st-" + s, s); return p; }

function renderMap(d, byIp) {
  const wrap = el("div", "map-wrap");
  const legend = el("div", "legend");
  STATUSES.forEach((s) => { const l = el("span", "legend-item"); l.appendChild(el("span", "dot dot-" + s)); l.appendChild(document.createTextNode(s)); legend.appendChild(l); });
  wrap.appendChild(legend);
  const p = parseCidr(d.cidr);
  if (p.v6) { wrap.appendChild(el("p", "muted", "Visual map is IPv4-only for now.")); return wrap; }
  if (p.size > 4096) {                       // big subnet: /24 occupancy heatmap with drill-down
    wrap.appendChild(heatmap(d, byIp, p));
    return wrap;
  }
  wrap.appendChild(grid(d, byIp, p.first, p.last));
  return wrap;
}
function grid(d, byIp, first, last) {
  const g = el("div", "ipgrid");
  const netIp = intToIp(first), bcast = intToIp(last);
  for (let n = first; n <= last; n++) {
    const ip = intToIp(n);
    let status = "free";
    const a = byIp[ip];
    if (a) status = a.status;
    else if (ip === d.gateway) status = "gateway";
    else if ((last - first) >= 3 && (ip === netIp || ip === bcast)) status = "reserved";
    const cell = el("span", "cell cell-" + status);
    cell.title = ip + (a ? " · " + a.status + (a.hostname ? " · " + a.hostname : "") : " · free");
    cell.dataset.ip = ip; cell.dataset.subnet = d.id; if (a) cell.dataset.addr = a.id;
    g.appendChild(cell);
  }
  return g;
}
function heatmap(d, byIp, p) {
  const wrap = el("div"); wrap.appendChild(el("p", "muted small", "Large subnet — showing /24 blocks by occupancy. Click a block to open it."));
  const blocks = el("div", "heatblocks");
  const used = {};
  Object.values(byIp).forEach((a) => { const b = (ipToInt(a.ip) & 0xffffff00) >>> 0; used[b] = (used[b] || 0) + 1; });
  for (let b = (p.first & 0xffffff00) >>> 0; b <= p.last; b = (b + 256) >>> 0) {
    const n = used[b] || 0;
    const cell = el("span", "heatcell");
    const lvl = n === 0 ? 0 : n < 8 ? 1 : n < 32 ? 2 : n < 128 ? 3 : 4;
    cell.classList.add("heat-" + lvl);
    cell.title = intToIp(b) + "/24 · " + n + " in use";
    cell.textContent = intToIp(b).split(".").slice(2).join(".");
    cell.dataset.block = b; cell.dataset.subnet = d.id;
    blocks.appendChild(cell);
    if (b > 0xffffff00) break;
  }
  wrap.appendChild(blocks);
  return wrap;
}
function showBlock(d, byIp, base) {        // drill into one /24 of a big subnet
  const m = $("main");
  const old = m.querySelector(".block-drill"); if (old) old.remove();
  const wrap = el("div", "block-drill");
  wrap.appendChild(el("h3", null, intToIp(base) + "/24"));
  wrap.appendChild(grid(d, byIp, base, (base + 255) >>> 0));
  m.appendChild(wrap);
  wrap.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// ---- dialogs (sections / subnets / addresses / split / calculator) ------------------------------------------
let dlgSave = null;
function openDlg(title, bodyEl, onSave) {
  $("dlgTitle").textContent = title; const b = $("dlgBody"); b.textContent = ""; b.appendChild(bodyEl);
  $("dlgMsg").classList.add("hidden"); $("dlgSave").classList.toggle("hidden", !onSave); dlgSave = onSave;
  $("dlg").showModal();
}
function field(label, input) { const l = el("label", "field", label + " "); l.appendChild(input); return l; }
function inp(id, val, ph) { const i = el("input"); i.id = id; if (val != null) i.value = val; if (ph) i.placeholder = ph; return i; }
function sel(id, opts, val) { const s = el("select"); s.id = id; opts.forEach((o) => { const op = el("option", null, o.label); op.value = o.value; if (String(o.value) === String(val)) op.selected = true; s.appendChild(op); }); return s; }

function sectionDialog(s) {
  const box = el("div");
  box.appendChild(field("Name", inp("f_name", s?.name || "", "e.g. Core infrastructure")));
  box.appendChild(field("Description", inp("f_desc", s?.description || "")));
  const parents = [{ value: "", label: "(top level)" }, ...tree.sections.filter((x) => x.id !== s?.id).map((x) => ({ value: x.id, label: x.name }))];
  box.appendChild(field("Inside section", sel("f_parent", parents, s?.parent_id || "")));
  let del = null;
  if (s?.id) { del = el("button", "btn danger", "Delete section"); del.type = "button"; del.dataset.delsection = s.id; box.appendChild(del); }
  openDlg(s?.id ? "Edit section" : "New section", box, async () => {
    await post("/api/ipam/sections", { id: s?.id, name: $("f_name").value, description: $("f_desc").value, parent_id: $("f_parent").value || null });
    await reload();
  });
}
function subnetDialog(s) {
  const box = el("div");
  box.appendChild(field("Subnet (CIDR)", inp("f_cidr", s?.cidr || "", "192.168.10.0/24")));
  box.appendChild(field("Name", inp("f_name", s?.name || "")));
  const clientOpts = [{ value: "", label: "(none)" }, ...tree.clients.map((c) => ({ value: c.id, label: c.name }))];
  // clients list only has those with subnets; include the current one regardless
  box.appendChild(field("Client", sel("f_org", clientOpts, s?.org_id || (current?.kind === "client" ? current.id : ""))));
  const secOpts = [{ value: "", label: "(none)" }, ...tree.sections.map((x) => ({ value: x.id, label: x.name }))];
  box.appendChild(field("Section", sel("f_section", secOpts, s?.section_id || (current?.kind === "section" ? current.id : ""))));
  box.appendChild(field("Gateway", inp("f_gw", s?.gateway || "")));
  box.appendChild(field("Notes", inp("f_notes", s?.notes || "")));
  openDlg(s?.id ? "Edit subnet" : "New subnet", box, async () => {
    await post("/api/ipam/subnets", { id: s?.id, cidr: $("f_cidr").value, name: $("f_name").value, org_id: $("f_org").value || null,
      section_id: $("f_section").value || null, gateway: $("f_gw").value, notes: $("f_notes").value });
    await reload();
  });
}
function addrDialog(subnetId, a, ip) {
  const box = el("div");
  box.appendChild(field("IP", inp("f_ip", a?.ip || ip || "")));
  box.appendChild(field("Status", sel("f_status", ["used", "reserved", "dhcp", "offline", "gateway"].map((x) => ({ value: x, label: x })), a?.status || "used")));
  box.appendChild(field("Hostname", inp("f_host", a?.hostname || "")));
  box.appendChild(field("MAC", inp("f_mac", a?.mac || "")));
  box.appendChild(field("Owner", inp("f_owner", a?.owner || "")));
  box.appendChild(field("DNS name", inp("f_dns", a?.dns_name || "")));
  box.appendChild(field("Notes", inp("f_notes", a?.notes || "")));
  openDlg(a?.id ? "Edit " + a.ip : "New address", box, async () => {
    await post("/api/ipam/addresses", { id: a?.id, subnet_id: subnetId, ip: $("f_ip").value, status: $("f_status").value,
      hostname: $("f_host").value, mac: $("f_mac").value, owner: $("f_owner").value, dns_name: $("f_dns").value, notes: $("f_notes").value });
    await showSubnet(subnetId);
  });
}
function splitDialog(s) {
  const box = el("div");
  box.appendChild(el("p", "muted", "Split " + s.cidr + " into equal smaller subnets."));
  const cur = parseCidr(s.cidr).pfx;
  box.appendChild(field("New prefix", inp("f_pfx", cur + 1)));
  openDlg("Split " + s.cidr, box, async () => {
    const r = await post("/api/ipam/subnets/" + s.id + "/split", { prefix: +$("f_pfx").value });
    await reload(); toast("Created " + r.created + " of " + r.children + " subnets.");
  });
}
function calcDialog() {
  const box = el("div", "calc");
  box.appendChild(field("Subnet (CIDR)", inp("c_cidr", "192.168.1.0/24")));
  const out = el("pre", "calc-out"); out.id = "c_out"; box.appendChild(out);
  const run = () => {
    try {
      const p = parseCidr($("c_cidr").value.trim());
      if (p.v6) { out.textContent = "IPv6 — calculator is IPv4-only for now."; return; }
      const mask = intToIp((p.pfx === 0 ? 0 : (0xffffffff << (32 - p.pfx)) >>> 0));
      const usable = p.pfx >= 31 ? p.size : p.size - 2;
      out.textContent = `Network:   ${intToIp(p.net)}/${p.pfx}\nNetmask:   ${mask}\nFirst host: ${intToIp(p.pfx >= 31 ? p.first : (p.first + 1) >>> 0)}\nLast host:  ${intToIp(p.pfx >= 31 ? p.last : (p.last - 1) >>> 0)}\nBroadcast: ${intToIp(p.last)}\nAddresses: ${p.size}  ·  Usable: ${usable}`;
    } catch (e) { out.textContent = "Enter a valid CIDR, e.g. 10.0.0.0/24"; }
  };
  box.querySelector("input").addEventListener("input", run);
  openDlg("Subnet calculator", box, null); run();
}

// ---- sync + search ------------------------------------------------------------------------------------------
async function syncOrg(orgId, label) {
  toast("Syncing" + (label ? " " + label : "") + "…");
  try { const r = await post("/api/ipam/sync", { org_id: orgId });
    toast(`Synced ${r.routers} router(s): +${r.subnets_added} subnets, +${r.addresses_added} addresses${r.unifi ? " (" + r.unifi + " from UniFi)" : ""}${r.offline ? ", " + r.offline + " offline" : ""}.`);
    await reload();
  } catch (e) { toast(e.message); }
}
async function syncPicker() {
  const box = el("div");
  box.appendChild(el("p", "muted", "Pick a client to discover its subnets and live IP usage from its routers."));
  let orgs = [];
  try { orgs = (await api("/api/ipam/orgs")).orgs || []; } catch (e) { /* fall back to clients already in IPAM */ }
  if (!orgs.length) orgs = tree.clients.map((c) => ({ id: c.id, name: c.name, routers: "" }));
  const opts = orgs.length ? orgs.map((o) => ({ value: o.id, label: o.name + (o.routers ? ` (${o.routers} router${o.routers === 1 ? "" : "s"})` : o.unifi_sites ? " (UniFi)" : "") }))
    : [{ value: "", label: "(no clients with routers)" }];
  box.appendChild(field("Client", sel("f_org", opts)));
  openDlg("Sync from routers", box, async () => { const id = $("f_org").value; if (id) await syncOrg(+id); });
}
let searchTimer = null;
async function doSearch(q) {
  const m = $("main");
  if (!q.trim()) return showSubnets();
  let r; try { r = await api("/api/ipam/search?q=" + encodeURIComponent(q)); } catch (e) { return; }
  m.textContent = ""; m.appendChild(el("h1", null, "Search: " + q));
  if (r.subnets.length) { m.appendChild(el("h3", null, "Subnets"));
    r.subnets.forEach((s) => { const a = el("a", "result cidr", s.cidr + (s.name ? " — " + s.name : "")); a.dataset.subnet = s.id; m.appendChild(a); }); }
  if (r.addresses.length) { m.appendChild(el("h3", null, "Addresses"));
    r.addresses.forEach((a) => { const d = el("a", "result"); d.textContent = a.ip + " — " + (a.hostname || a.owner || a.status) + " (in " + a.subnet_cidr + ")";
      d.dataset.subnet = a.subnet_id; m.appendChild(d); }); }
  if (!r.subnets.length && !r.addresses.length) m.appendChild(el("p", "muted", "Nothing found."));
}

// ---- toast --------------------------------------------------------------------------------------------------
let toastTimer = null;
function toast(msg) {
  let t = $("toast"); if (!t) { t = el("div", "toast"); t.id = "toast"; document.body.appendChild(t); }
  t.textContent = msg; t.classList.add("show"); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove("show"), 4000);
}

// ---- load / route -------------------------------------------------------------------------------------------
async function reload() { tree = await api("/api/ipam/tree"); renderTree(); if (current?.subnet) await showSubnet(current.subnet); else showSubnets(); }

async function init() {
  try { me = await api("/api/me"); } catch (e) { return; }
  if (window.BRAND && window.BRAND.company) document.title = "IPAM · " + window.BRAND.company;
  current = { kind: "all" };
  try { tree = await api("/api/ipam/tree"); } catch (e) { $("main").textContent = e.message; return; }
  renderTree(); showSubnets();

  // top bar
  $("newSection").addEventListener("click", () => sectionDialog(null));
  $("syncBtn").addEventListener("click", syncPicker);
  $("calcBtn").addEventListener("click", calcDialog);
  $("search").addEventListener("input", (e) => { clearTimeout(searchTimer); const v = e.target.value; searchTimer = setTimeout(() => doSearch(v), 250); });

  // dialog save
  $("dlgForm").addEventListener("submit", async (e) => {
    if (e.submitter && e.submitter.value === "save" && dlgSave) {
      e.preventDefault();
      try { await dlgSave(); $("dlg").close(); }
      catch (err) { const m = $("dlgMsg"); m.textContent = err.message; m.classList.remove("hidden"); }
    } // cancel: let the dialog close normally
  });

  // tree clicks
  $("tree").addEventListener("click", (e) => {
    const es = e.target.closest("[data-editsection]"); if (es) { e.stopPropagation(); const s = tree.sections.find((x) => x.id === +es.dataset.editsection); return sectionDialog(s); }
    const item = e.target.closest(".tree-item"); if (!item) return;
    current = item.dataset.kind === "all" ? { kind: "all" } : { kind: item.dataset.kind, id: +item.dataset.id };
    renderTree(); showSubnets();
  });

  // main delegation
  $("main").addEventListener("click", async (e) => {
    const t = e.target;
    const sub = t.closest("[data-subnet]");
    if (t.dataset.back != null) return showSubnets();
    if (t.dataset.newsubnet != null) return subnetDialog(null);
    if (t.dataset.editsubnet != null) return subnetDialog(tree.subnets.find((x) => x.id === +t.dataset.editsubnet));
    if (t.dataset.splitsubnet != null) return splitDialog(tree.subnets.find((x) => x.id === +t.dataset.splitsubnet) || { id: +t.dataset.splitsubnet, cidr: "" });
    if (t.dataset.newaddr != null) return addrDialog(+t.dataset.newaddr, null, null);
    if (t.dataset.syncorg != null) return syncOrg(+t.dataset.syncorg, tree.clients.find((c) => c.id === +t.dataset.syncorg)?.name);
    if (t.dataset.delsubnet != null) { if (confirm("Delete this subnet and its addresses?")) { await post("/api/ipam/subnets/" + t.dataset.delsubnet + "/delete"); current = { ...current, subnet: null }; await reload(); } return; }
    if (t.dataset.editaddr != null) { const d = await api("/api/ipam/subnets/" + t.dataset.subnet); return addrDialog(+t.dataset.subnet, (d.addresses || []).find((a) => a.id === +t.dataset.editaddr)); }
    if (t.dataset.deladdr != null) { if (confirm("Delete this address?")) { await post("/api/ipam/addresses/" + t.dataset.deladdr + "/delete"); await showSubnet(+t.dataset.subnet); } return; }
    if (t.dataset.block != null) {   // heatmap drill-down
      const d = await api("/api/ipam/subnets/" + t.dataset.subnet); const byIp = {}; (d.addresses || []).forEach((a) => (byIp[a.ip] = a));
      return showBlock(d, byIp, (+t.dataset.block) >>> 0);
    }
    if (t.classList.contains("cell")) { const aid = t.dataset.addr; const d = await api("/api/ipam/subnets/" + t.dataset.subnet);
      return addrDialog(+t.dataset.subnet, aid ? (d.addresses || []).find((a) => a.id === +aid) : null, t.dataset.ip); }
    if (t.dataset.subnet != null && (t.classList.contains("cidr") || t.classList.contains("result") || t.closest(".sub-row"))) {
      return showSubnet(+t.dataset.subnet);
    }
  });

  // dialog body delegation (delete buttons inside a form)
  $("dlgBody").addEventListener("click", async (e) => {
    const ds = e.target.closest("[data-delsection]"); if (ds) { e.preventDefault(); if (confirm("Delete this section? Its subnets stay but lose the folder.")) { await post("/api/ipam/sections/" + ds.dataset.delsection + "/delete"); $("dlg").close(); await reload(); } }
  });
}
document.addEventListener("DOMContentLoaded", init);
