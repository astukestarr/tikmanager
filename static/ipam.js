"use strict";
// IPAM workspace. CSP forbids inline scripts/handlers, so everything binds via addEventListener + data-* delegation.

let me = null, tree = { sections: [], subnets: [], clients: [] }, current = null; // current = {kind:'all'|'section'|'client', id}
let readonly = false;   // client users may VIEW their own IPAM but change nothing (writes are technician-only)
// Global "Customer" selector, shared with the main app via localStorage: "" = all, else an org id (techs only)
let appOrg = "";
try { appOrg = localStorage.getItem("tm.customer") || ""; } catch { /* private window */ }

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(path, opts = {}) {
  // follow the shared Customer selection on reads, so IPAM shows the same customer as the rest of the app
  if ((opts.method || "GET").toUpperCase() === "GET" && appOrg && me?.kind === "tech" && !/^\/api\/(me|orgs)\b/.test(path)) {
    path += (path.includes("?") ? "&" : "?") + "org=" + encodeURIComponent(appOrg);
  }
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
  if (!readonly) {
    const addBtn = el("button", "btn primary", "+ Subnet"); addBtn.dataset.newsubnet = "1"; actions.appendChild(addBtn);
    if (current?.kind === "client") { const sb = el("button", "btn", "Sync this client"); sb.dataset.syncorg = current.id; actions.appendChild(sb); }
  }
  head.appendChild(actions); m.appendChild(head);

  const rows = currentSubnets();
  if (!rows.length) { m.appendChild(el("p", "muted pad", "No subnets here yet. Add one, or Sync from routers to discover them.")); return; }
  const tbl = el("table", "ipam-table");
  const cols = ["Subnet", "Name", "Client", "Router", "Usage", "Source"]; if (!readonly) cols.push("");
  const thead = el("tr"); cols.forEach((h) => thead.appendChild(el("th", null, h)));
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
    if (!readonly) { const last = el("td"); const del = el("button", "btn tiny danger", "Delete"); del.dataset.delsubnet = s.id; last.appendChild(del); tr.appendChild(last); }
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
  if (!readonly) {
    const edit = el("button", "btn", "Edit"); edit.dataset.editsubnet = d.id; acts.appendChild(edit);
    const split = el("button", "btn", "Split"); split.dataset.splitsubnet = d.id; acts.appendChild(split);
    const addA = el("button", "btn primary", "+ Address"); addA.dataset.newaddr = d.id; acts.appendChild(addA);
  }
  head.appendChild(acts); m.appendChild(head);

  const meta = el("div", "meta-row");
  const chip = (k, v) => { const c = el("span", "chip"); c.appendChild(el("b", null, k + " ")); c.appendChild(document.createTextNode(v)); return c; };
  meta.appendChild(chip("Name", d.name || "—"));
  meta.appendChild(chip("Client", d.org || "—"));
  if (d.vlan) meta.appendChild(chip("VLAN", d.vlan));
  if (d.vrf) meta.appendChild(chip("VRF", d.vrf));
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
    const acols = ["IP", "Status", "Hostname", "MAC", "Owner", "Source"]; if (!readonly) acols.push("");
    const tr = el("tr"); acols.forEach((x) => tr.appendChild(el("th", null, x)));
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
      if (!readonly) {
        const last = el("td"); const e = el("button", "btn tiny", "Edit"); e.dataset.editaddr = a.id; e.dataset.subnet = d.id; last.appendChild(e);
        const del = el("button", "btn tiny danger", "×"); del.dataset.deladdr = a.id; del.dataset.subnet = d.id; last.appendChild(del);
        r.appendChild(last);
      }
      tb.appendChild(r);
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
  const vlanOpts = [{ value: "", label: "(none)" }, ...vlansCache.map((v) => ({ value: v.id, label: `VLAN ${v.number}` + (v.name ? ` · ${v.name}` : "") }))];
  box.appendChild(field("VLAN", sel("f_vlan", vlanOpts, s?.vlan_id || "")));
  const vrfOpts = [{ value: "", label: "(none)" }, ...vrfsCache.map((v) => ({ value: v.id, label: `${v.name} (${v.rd})` }))];
  box.appendChild(field("VRF", sel("f_vrf", vrfOpts, s?.vrf_id || "")));
  box.appendChild(field("Gateway", inp("f_gw", s?.gateway || "")));
  box.appendChild(field("Notes", inp("f_notes", s?.notes || "")));
  openDlg(s?.id ? "Edit subnet" : "New subnet", box, async () => {
    await post("/api/ipam/subnets", { id: s?.id, cidr: $("f_cidr").value, name: $("f_name").value, org_id: $("f_org").value || null,
      section_id: $("f_section").value || null, vlan_id: $("f_vlan").value || null, vrf_id: $("f_vrf").value || null, gateway: $("f_gw").value, notes: $("f_notes").value });
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
  box.appendChild(field("PTR (reverse DNS)", inp("f_ptr", a?.ptr || "")));
  box.appendChild(field("Notes", inp("f_notes", a?.notes || "")));
  openDlg(a?.id ? "Edit " + a.ip : "New address", box, async () => {
    await post("/api/ipam/addresses", { id: a?.id, subnet_id: subnetId, ip: $("f_ip").value, status: $("f_status").value,
      hostname: $("f_host").value, mac: $("f_mac").value, owner: $("f_owner").value, dns_name: $("f_dns").value, ptr: $("f_ptr").value, notes: $("f_notes").value });
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
function exportDialog() {
  const box = el("div");
  box.appendChild(el("p", "muted", "Download the current view as CSV (headers are phpIPAM-compatible)."));
  const q = (kind) => "/api/ipam/export.csv?kind=" + kind + (current?.kind === "client" ? "&org=" + current.id : "");
  const row = el("div", "main-head-actions");
  const mk = (kind, label) => { const a = el("a", "btn", label); a.href = q(kind); a.setAttribute("download", ""); return a; };
  row.appendChild(mk("subnets", "Subnets CSV")); row.appendChild(mk("addresses", "Addresses CSV"));
  box.appendChild(row);
  openDlg("Export CSV", box, null);
}
function importDialog() {
  const box = el("div");
  box.appendChild(field("What", sel("f_kind", [{ value: "subnets", label: "Subnets" }, { value: "addresses", label: "IP addresses" }], "subnets")));
  box.appendChild(field("Client (optional)", sel("f_org", clientOpts(), current?.kind === "client" ? current.id : "")));
  const fileL = el("label", "field", "CSV file "); const file = el("input"); file.type = "file"; file.accept = ".csv,text/csv"; file.id = "f_file"; fileL.appendChild(file); box.appendChild(fileL);
  const ta = el("textarea"); ta.id = "f_csv"; ta.rows = 8; ta.placeholder = "…or paste CSV here. Headers like 'Subnet','Description' (subnets) or 'IP address','State','Hostname','MAC' (addresses).";
  box.appendChild(field("CSV", ta));
  box.appendChild(el("p", "muted small", "Import only adds new rows — it never changes or removes anything you already have."));
  const prev = el("button", "btn", "Preview"); prev.type = "button"; prev.dataset.ipampreview = "1"; box.appendChild(prev);
  const out = el("pre", "calc-out"); out.id = "imp_out"; out.hidden = true; box.appendChild(out);
  file.addEventListener("change", () => { const f = file.files[0]; if (!f) return; const rd = new FileReader(); rd.onload = () => { ta.value = rd.result; }; rd.readAsText(f); });
  openDlg("Import from CSV", box, async () => {
    const r = await post("/api/ipam/import", { kind: $("f_kind").value, org_id: $("f_org").value || null, csv: $("f_csv").value, commit: true });
    toast(`Imported ${r.to_add} ${r.kind}; skipped ${r.skipped_existing} already present${r.errors.length ? ", " + r.errors.length + " errors" : ""}.`);
    await loadLookups(); await reload();
  });
}

// ---- sync + search ------------------------------------------------------------------------------------------
async function syncOrg(orgId, label) {
  toast("Syncing" + (label ? " " + label : "") + "…");
  try { const r = await post("/api/ipam/sync", { org_id: orgId });
    let msg = `Synced ${r.routers} router(s): +${r.subnets_added} subnets, +${r.addresses_added} addresses`;
    if (r.unifi) msg += ` (${r.unifi} from UniFi${r.unifi_networks ? ", " + r.unifi_networks + " networks" : ""})`;
    if (r.offline) msg += `, ${r.offline} offline`;
    if (r.unifi_error) msg += ` — UniFi: ${r.unifi_error}`;
    toast(msg + ".", r.unifi_error ? 12000 : 4000);   // leave an actionable UniFi note up long enough to read
    await reload();
  } catch (e) { toast(e.message); }
}
async function syncAll() {
  let r; try { r = await post("/api/ipam/sync", { org_id: "all" }); } catch (e) { return toast(e.message); }
  toast(`Syncing all ${r.clients} client${r.clients === 1 ? "" : "s"} in the background…`, 60000);
  const poll = async () => {
    let st; try { st = await api("/api/ipam/sync-status"); } catch (e) { return; }
    if (st.running) { toast(`Syncing clients… ${st.done}/${st.total}`, 60000); return setTimeout(poll, 3000); }
    const s = st.summary || {};
    toast(`Synced ${s.clients != null ? s.clients : st.done} clients: +${s.subnets_added || 0} subnets, +${s.addresses_added || 0} addresses across ${s.routers || 0} routers.`, 9000);
    await reload();
  };
  setTimeout(poll, 3000);
}
async function syncPicker() {
  const box = el("div");
  box.appendChild(el("p", "muted", "Pick a client to discover its subnets and live IP usage from its routers - or sync every client at once."));
  let orgs = [];
  try { orgs = (await api("/api/ipam/orgs")).orgs || []; } catch (e) { /* fall back to clients already in IPAM */ }
  if (!orgs.length) orgs = tree.clients.map((c) => ({ id: c.id, name: c.name, routers: "" }));
  const opts = [{ value: "all", label: "All clients (every router)" }].concat(
    orgs.map((o) => ({ value: o.id, label: o.name + (o.routers ? ` (${o.routers} router${o.routers === 1 ? "" : "s"})` : o.unifi_sites ? " (UniFi)" : "") })));
  box.appendChild(field("Client", sel("f_org", opts)));
  openDlg("Sync from routers", box, async () => { const id = $("f_org").value; if (id === "all") await syncAll(); else if (id) await syncOrg(+id); });
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
function toast(msg, ms) {
  let t = $("toast"); if (!t) { t = el("div", "toast"); t.id = "toast"; document.body.appendChild(t); }
  t.textContent = msg; t.classList.add("show"); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove("show"), ms || 4000);
}

// ---- tabs: VLANs / VRFs / Devices / Locations ---------------------------------------------------------------
let tab = "dashboard";
let allOrgs = [], vlansCache = [], vrfsCache = [], typesCache = [], locsCache = [];
function clientOpts(selId) { return [{ value: "", label: "(none)" }, ...allOrgs.map((o) => ({ value: o.id, label: o.name }))]; }
async function loadLookups() {
  try { allOrgs = (await api("/api/ipam/orgs")).orgs || []; } catch (e) { allOrgs = tree.clients || []; }
  try { vlansCache = (await api("/api/ipam/vlans")).vlans || []; } catch (e) { vlansCache = []; }
  try { vrfsCache = (await api("/api/ipam/vrfs")).vrfs || []; } catch (e) { vrfsCache = []; }
  try { typesCache = (await api("/api/ipam/device-types")).types || []; } catch (e) { typesCache = []; }
  try { locsCache = (await api("/api/ipam/locations")).locations || []; } catch (e) { locsCache = []; }
}
function setTab(t) {
  tab = t;
  document.querySelectorAll("#tabs .tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === t));
  document.body.classList.toggle("tab-subnets", t === "subnets");   // mobile: only the subnets tab has a tree drawer
  const body = $("side").closest(".ipam-body");
  body.classList.toggle("no-side", t !== "subnets");
  body.classList.remove("side-open");   // close the mobile drawer on any tab switch
  if (t === "subnets") { current = { kind: "all" }; renderTree(); showSubnets(); }
  else if (t === "dashboard") showDashboard();
  else if (t === "vlans") showVlans();
  else if (t === "vrfs") showVrfs();
  else if (t === "devices") showDevices();
  else if (t === "racks") showRacks();
  else if (t === "locations") showLocations();
}
// Jump to a subnet's detail from anywhere (e.g. a dashboard widget): switch to the Subnets tab, then open it.
function openSubnet(id) {
  tab = "subnets";
  document.querySelectorAll("#tabs .tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === "subnets"));
  document.body.classList.add("tab-subnets");
  const body = $("side").closest(".ipam-body"); body.classList.remove("no-side", "side-open");
  current = { kind: "all" }; renderTree(); showSubnet(id);
}
function listHead(title, addLabel, addAttr) {
  const head = el("div", "main-head"); head.appendChild(el("h1", null, title));
  const acts = el("div", "main-head-actions");
  if (!readonly) { const add = el("button", "btn primary", addLabel); add.dataset[addAttr] = "1"; acts.appendChild(add); }
  head.appendChild(acts); return head;
}
function table(cols, rows, rowFn) {
  const tbl = el("table", "ipam-table"); const tr = el("tr"); cols.forEach((h) => tr.appendChild(el("th", null, h)));
  const th = el("thead"); th.appendChild(tr); tbl.appendChild(th); const tb = el("tbody");
  rows.forEach((r) => tb.appendChild(rowFn(r))); tbl.appendChild(tb); return tbl;
}
// A table whose columns can be clicked to sort. `columns` = [{label, cls?, cell(row)->string|Node, sort?(row)->value}].
// A column with a `sort` accessor gets a clickable header (first click ascending, then toggles). The chosen column and
// direction are remembered per `key`, so a re-render (e.g. after an edit) keeps the same order.
const sortState = {};
function sortableTable(key, columns, rows) {
  const st = sortState[key] || (sortState[key] = { col: null, dir: 1 });
  const wrap = el("div");
  const val = (v) => (v == null ? "" : v);
  const cmp = (a, b) => (typeof a === "number" && typeof b === "number"
    ? a - b : String(val(a)).localeCompare(String(val(b)), undefined, { numeric: true, sensitivity: "base" }));
  const draw = () => {
    wrap.textContent = "";
    const tbl = el("table", "ipam-table"); const head = el("thead"); const tr = el("tr");
    columns.forEach((c, i) => {
      const th = el("th", c.cls);
      if (c.sort) {
        const b = el("button", "th-sort" + (st.col === i ? " sorted" : ""), c.label); b.type = "button";
        if (st.col === i) b.appendChild(el("span", "th-arrow", st.dir > 0 ? "▲" : "▼"));
        b.addEventListener("click", () => { if (st.col === i) st.dir = -st.dir; else { st.col = i; st.dir = 1; } draw(); });
        th.appendChild(b);
      } else th.textContent = c.label;
      tr.appendChild(th);
    });
    head.appendChild(tr); tbl.appendChild(head); const tb = el("tbody");
    let data = rows;
    if (st.col != null && columns[st.col] && columns[st.col].sort) {
      const sf = columns[st.col].sort; data = rows.slice().sort((a, b) => cmp(sf(a), sf(b)) * st.dir);
    }
    data.forEach((r) => {
      const row = el("tr");
      columns.forEach((c) => { const td = el("td", c.cls); const v = c.cell(r); if (v instanceof Node) td.appendChild(v); else if (v != null) td.textContent = String(v); row.appendChild(td); });
      tb.appendChild(row);
    });
    tbl.appendChild(tb); wrap.appendChild(tbl);
  };
  draw();
  return wrap;
}
// The Edit / Delete buttons shared by the VLAN / VRF / Device / Location rows (wired by delegation on #main via data-*).
function rowActions(editAttr, delAttr, id, delLabel) {
  const span = el("span", "row-actions");
  const e = el("button", "btn tiny", "Edit"); e.dataset[editAttr] = id; span.appendChild(e);
  const d = el("button", "btn tiny danger", delLabel || "Delete"); d.dataset[delAttr] = id; span.appendChild(d);
  return span;
}
// ---- dashboard ----------------------------------------------------------------------------------------------
function dashCard(title, bodyNode, wide) {
  const c = el("div", "dash-card" + (wide ? " wide" : "")); c.appendChild(el("div", "dash-head", title));
  const b = el("div", "dash-body"); if (bodyNode) b.appendChild(bodyNode); c.appendChild(b); return c;
}
function dashStat(label, value, gotab) {
  const row = el("div", "dash-stat"); const name = el("span", "dash-stat-label", label);
  if (gotab != null && value) { name.dataset.gotab = gotab; name.classList.add("dash-link"); }
  row.appendChild(name); row.appendChild(el("span", "dash-stat-n", String(value ?? 0))); return row;
}
function cidrLink(id, cidr) { const a = el("a", "cidr", cidr); a.dataset.dashsubnet = id; return a; }
// ---- dashboard chart primitives (CSP-safe: SVG geometry via attributes, colour via classes, bar widths via .style) ----
const SVGNS = "http://www.w3.org/2000/svg";
function svgEl(tag, attrs) { const e = document.createElementNS(SVGNS, tag); for (const k in attrs || {}) e.setAttribute(k, attrs[k]); return e; }
function fmtNum(n) { return (n == null ? 0 : n).toLocaleString(); }
function fmtBig(n) {   // compact for hero tiles: 1.2k, 3.4M
  n = n || 0; if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + "M";
  if (n >= 1e4) return Math.round(n / 1e3) + "k"; if (n >= 1e3) return (n / 1e3).toFixed(1) + "k"; return String(n);
}
function donut(segments, total, opts) {
  opts = opts || {}; const r = 52, cx = 64, cy = 64, C = 2 * Math.PI * r;
  const svg = svgEl("svg", { viewBox: "0 0 128 128", class: "donut" });
  svg.appendChild(svgEl("circle", { cx, cy, r, fill: "none", class: "donut-bg" }));
  let off = 0;
  if (total > 0) segments.forEach((s) => {
    if (!s.value) return; const frac = s.value / total;
    svg.appendChild(svgEl("circle", { cx, cy, r, fill: "none", class: "donut-seg " + s.cls,
      "stroke-dasharray": (frac * C).toFixed(2) + " " + (C - frac * C).toFixed(2),
      "stroke-dashoffset": (-off * C).toFixed(2), transform: "rotate(-90 " + cx + " " + cy + ")" }));
    off += frac;
  });
  if (opts.center != null) { const t = svgEl("text", { x: cx, y: cy - 1, class: "donut-center", "text-anchor": "middle" }); t.textContent = opts.center; svg.appendChild(t); }
  if (opts.sub != null) { const t = svgEl("text", { x: cx, y: cy + 17, class: "donut-sub", "text-anchor": "middle" }); t.textContent = opts.sub; svg.appendChild(t); }
  return svg;
}
function legend(items) {
  const L = el("div", "legend");
  items.forEach((it) => { if (!it.value && it.hideZero) return;
    const w = el("span", "legend-item"); w.appendChild(el("span", "legend-dot " + it.cls));
    w.appendChild(el("span", "legend-txt", it.label + (it.value != null ? " · " + fmtNum(it.value) : ""))); L.appendChild(w); });
  return L;
}
function segBar(parts, total) {
  const bar = el("div", "seg-bar");
  if (total > 0) parts.forEach((p) => { if (!p.value) return;
    const s = el("div", "seg " + p.cls); s.style.width = (100 * p.value / total) + "%"; s.title = p.label + ": " + p.value; bar.appendChild(s); });
  else bar.appendChild(el("div", "seg band-free w-100"));
  return bar;
}
function hbarRow(label, value, max, cls, suffix, sub) {
  const row = el("div", "hbar-row");
  const lab = el("span", "hbar-label ellip", label); if (sub) lab.title = sub; row.appendChild(lab);
  const track = el("div", "hbar-track"); const fill = el("div", "hbar-fill " + (cls || ""));
  fill.style.width = (max ? Math.max(2, Math.round(100 * value / max)) : 0) + "%"; track.appendChild(fill); row.appendChild(track);
  row.appendChild(el("span", "hbar-n", suffix != null ? suffix : fmtNum(value))); return row;
}
function heroTile(value, label, sub, tone, gotab) {
  const t = el("div", "hero-tile" + (tone ? " " + tone : "")); if (gotab) { t.dataset.gotab = gotab; t.classList.add("clk"); }
  t.appendChild(el("div", "hero-n", value)); t.appendChild(el("div", "hero-label", label));
  if (sub != null) t.appendChild(el("div", "hero-sub", sub)); return t;
}
function trendChart(points) {
  const W = 600, H = 130, pad = 8;
  const svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, class: "trend", preserveAspectRatio: "none" });
  const n = points.length, maxV = Math.max(10, ...points.map((p) => p.usage));   // floor at 10% so a low-usage line isn't a spike
  const X = (i) => pad + (n <= 1 ? (W - 2 * pad) / 2 : i * (W - 2 * pad) / (n - 1));
  const Y = (v) => H - pad - (v / maxV) * (H - 2 * pad);
  for (let g = 1; g <= 3; g++) { const gy = (H - 2 * pad) * g / 4 + pad; svg.appendChild(svgEl("line", { x1: pad, y1: gy, x2: W - pad, y2: gy, class: "trend-grid" })); }
  let line = ""; points.forEach((p, i) => { line += (i ? "L" : "M") + X(i).toFixed(1) + " " + Y(p.usage).toFixed(1) + " "; });
  if (n >= 2) {
    svg.appendChild(svgEl("path", { d: "M" + X(0).toFixed(1) + " " + (H - pad) + " " + line.replace(/^M/, "L") + "L" + X(n - 1).toFixed(1) + " " + (H - pad) + " Z", class: "trend-area" }));
    svg.appendChild(svgEl("path", { d: line.trim(), class: "trend-line" }));
  }
  points.forEach((p, i) => { if (n <= 14 || i === n - 1) svg.appendChild(svgEl("circle", { cx: X(i).toFixed(1), cy: Y(p.usage).toFixed(1), r: i === n - 1 ? 4 : 2.5, class: "trend-dot" })); });
  return svg;
}
function utilTone(p) { return p >= 90 ? "hot" : p >= 75 ? "warm" : ""; }
function fmtAgo(ts) {
  if (!ts) return "—";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 90) return "just now";
  const m = s / 60; if (m < 90) return Math.round(m) + "m ago";
  const h = m / 60; if (h < 36) return Math.round(h) + "h ago";
  const d = h / 24; if (d < 45) return Math.round(d) + "d ago";
  return Math.round(d / 30) + "mo ago";
}
async function showDashboard() {
  const m = $("main"); m.textContent = "Loading…";
  let r; try { r = await api("/api/ipam/dashboard"); } catch (e) { m.textContent = e.message; return; }
  m.textContent = "";
  const c = r.counts, cap = r.capacity, al = r.alerts;
  const head = el("div", "main-head"); head.appendChild(el("h1", null, "Dashboard"));
  head.appendChild(el("span", "muted small", r.scoped ? "This client" : fmtNum(c.clients) + " clients · " + fmtNum(c.subnets) + " subnets · " + fmtNum(cap.usable) + " addressable IPs"));
  m.appendChild(head);

  // ---- Hero KPI row ----
  const hero = el("div", "ipam-hero");
  const alertN = al.over_threshold_n + al.full + al.offline + al.stale;
  if (!r.scoped) hero.appendChild(heroTile(fmtNum(c.clients), "Clients", fmtNum(c.sections) + " sections", "", "subnets"));
  hero.appendChild(heroTile(fmtNum(c.subnets), "Subnets", fmtNum(cap.v6_subnets) + " IPv6", "", "subnets"));
  hero.appendChild(heroTile(cap.usage + "%", "IP utilization", fmtBig(cap.used) + " of " + fmtBig(cap.usable), cap.usage >= 85 ? "hot" : cap.usage >= 70 ? "warm" : "ok"));
  hero.appendChild(heroTile(fmtNum(c.addresses), "Addresses tracked", (r.change.new_addresses ? "+" + fmtNum(r.change.new_addresses) + " this week" : "live overlay"), ""));
  hero.appendChild(heroTile(fmtNum(c.devices), "Devices", fmtNum(c.vlans) + " VLANs · " + fmtNum(c.vrfs) + " VRFs", "", "devices"));
  hero.appendChild(heroTile(fmtNum(alertN), "Attention", alertN ? "needs a look" : "all clear", alertN ? "hot" : "ok"));
  m.appendChild(hero);

  const grid = el("div", "dash-grid");

  // ---- Capacity gauge ----
  const capBody = el("div", "cap-wrap");
  capBody.appendChild(donut([{ value: cap.used, cls: "seg-used" }, { value: cap.free, cls: "seg-free" }], cap.usable || 1,
    { center: cap.usage + "%", sub: "used" }));
  const capStats = el("div", "cap-stats");
  const chip = (lab, val, cls) => { const d = el("div", "cap-chip " + (cls || "")); d.appendChild(el("div", "cap-chip-n", fmtNum(val))); d.appendChild(el("div", "cap-chip-l", lab)); return d; };
  capStats.appendChild(chip("IPs in use", cap.used, "ok"));
  capStats.appendChild(chip("Free", cap.free, ""));
  capStats.appendChild(chip("Addressable", cap.usable, ""));
  capBody.appendChild(capStats);
  grid.appendChild(dashCard("IP capacity", capBody));

  // ---- Utilization trend (daily snapshots) ----
  const tr = r.trend || [];
  const trBody = el("div", "trend-wrap");
  if (tr.length >= 2) {
    const first = tr[0], last = tr[tr.length - 1], delta = last.usage - first.usage;
    const cap2 = el("div", "trend-cap");
    cap2.appendChild(el("span", "trend-now", last.usage + "%"));
    const dChip = el("span", "trend-delta " + (delta > 0 ? "up" : delta < 0 ? "down" : ""), (delta > 0 ? "▲ +" : delta < 0 ? "▼ " : "±") + delta + "% over " + tr.length + " days");
    cap2.appendChild(dChip); trBody.appendChild(cap2);
    trBody.appendChild(trendChart(tr));
    const ax = el("div", "trend-axis"); ax.appendChild(el("span", "muted small", (first.day || "").slice(5))); ax.appendChild(el("span", "muted small", (last.day || "").slice(5))); trBody.appendChild(ax);
  } else {
    trBody.appendChild(el("p", "muted small", "Collecting history — the utilization trend records one point per day. Check back tomorrow to see the line build."));
  }
  grid.appendChild(dashCard("Utilization trend", trBody, true));

  // ---- Subnet health ----
  const h = r.health, htot = Object.values(h).reduce((a, b) => a + b, 0);
  const hBody = el("div");
  hBody.appendChild(segBar([
    { value: h.free, cls: "band-free", label: "Empty" }, { value: h.low, cls: "band-low", label: "Light" },
    { value: h.moderate, cls: "band-moderate", label: "Moderate" }, { value: h.high, cls: "band-high", label: "High" },
    { value: h.critical, cls: "band-critical", label: "Critical" }, { value: h.full, cls: "band-full", label: "Full" },
  ], htot));
  hBody.appendChild(legend([
    { label: "Empty", value: h.free, cls: "band-free" }, { label: "Light <50%", value: h.low, cls: "band-low" },
    { label: "Moderate", value: h.moderate, cls: "band-moderate" }, { label: "High 75%+", value: h.high, cls: "band-high" },
    { label: "Critical 90%+", value: h.critical, cls: "band-critical" }, { label: "Full", value: h.full, cls: "band-full" },
  ]));
  grid.appendChild(dashCard("Subnet health · " + fmtNum(htot) + " subnets", hBody));

  // ---- Address status mix ----
  const sm = r.status_mix, smOrder = [["used", "seg-used", "Used"], ["dhcp", "seg-dhcp", "DHCP"],
    ["reserved", "seg-reserved", "Reserved"], ["gateway", "seg-gateway", "Gateway"], ["offline", "seg-offline", "Offline"]];
  const smTotal = Object.values(sm).reduce((a, b) => a + b, 0);
  const smBody = el("div", "mix-wrap");
  if (smTotal) {
    smBody.appendChild(donut(smOrder.map(([k, cls]) => ({ value: sm[k] || 0, cls })), smTotal, { center: fmtBig(smTotal), sub: "hosts" }));
    smBody.appendChild(legend(smOrder.map(([k, cls, lab]) => ({ label: lab, value: sm[k] || 0, cls, hideZero: true }))));
  } else smBody.appendChild(el("p", "muted small", "No host records yet — run Sync or add addresses."));
  grid.appendChild(dashCard("Address status", smBody));

  // ---- Alerts ----
  const aBody = el("div");
  const aRow = el("div", "alert-tiles");
  const aTile = (n, lab, cls) => { const d = el("div", "alert-tile " + (n ? cls : "ok")); d.appendChild(el("div", "alert-n", fmtNum(n))); d.appendChild(el("div", "alert-l", lab)); return d; };
  aRow.appendChild(aTile(al.over_threshold_n, "Over threshold", "warn"));
  aRow.appendChild(aTile(al.full, "Full", "hot"));
  aRow.appendChild(aTile(al.offline, "Offline hosts", "warn"));
  aRow.appendChild(aTile(al.stale, "Stale subnets", "warn"));
  aBody.appendChild(aRow);
  if (al.over_threshold.length) {
    const t = el("table", "ipam-table dash-table"); const tb = el("tbody");
    al.over_threshold.forEach((s) => {
      const row = el("tr");
      const c0 = el("td"); c0.appendChild(cidrLink(s.id, s.cidr)); if (!r.scoped && s.org) c0.appendChild(el("span", "muted small", " " + s.org)); row.appendChild(c0);
      const bc = el("td", "nowrap"); const bar = el("div", "dash-bar mini"); const f = el("div", "dash-bar-fill " + utilTone(s.usage)); f.style.width = Math.min(100, s.usage) + "%"; bar.appendChild(f); bc.appendChild(bar); row.appendChild(bc);
      row.appendChild(el("td", "mono small right", s.usage + "%")); tb.appendChild(row);
    });
    t.appendChild(tb); aBody.appendChild(t);
  } else aBody.appendChild(el("p", "muted small", "Nothing over threshold. 🎉"));
  grid.appendChild(dashCard("Alerts", aBody));

  // ---- Top clients rollup (wide) ----
  if (!r.scoped && r.clients.length) {
    const cBody = el("div");
    const t = el("table", "ipam-table dash-table"); const thead = el("thead"), tr = el("tr");
    ["Client", "Subnets", "IPs used", "Utilization", "Devices"].forEach((hd, i) => tr.appendChild(el("th", i >= 1 ? "right" : null, hd)));
    thead.appendChild(tr); t.appendChild(thead); const tb = el("tbody");
    r.clients.forEach((cl) => {
      const row = el("tr");
      const nm = el("td"); const link = el("span", "dash-link", cl.name); link.dataset.gotabclient = cl.org_id || ""; nm.appendChild(link); row.appendChild(nm);
      row.appendChild(el("td", "mono small right", fmtNum(cl.subnets)));
      row.appendChild(el("td", "mono small right", fmtNum(cl.used) + " / " + fmtBig(cl.usable)));
      const uc = el("td", "util-cell"); const wrap = el("div", "util-inline"); const bar = el("div", "dash-bar mini"); const f = el("div", "dash-bar-fill " + utilTone(cl.usage)); f.style.width = Math.min(100, cl.usage) + "%"; bar.appendChild(f); wrap.appendChild(bar); wrap.appendChild(el("span", "mono small", cl.usage + "%")); uc.appendChild(wrap); row.appendChild(uc);
      row.appendChild(el("td", "mono small right", fmtNum(cl.devices))); tb.appendChild(row);
    });
    t.appendChild(tb); cBody.appendChild(t);
    if (r.client_total > r.clients.length) cBody.appendChild(el("p", "muted small pad", "Showing the top " + r.clients.length + " of " + r.client_total + " clients by size."));
    grid.appendChild(dashCard("Clients by footprint", cBody, true));
  }

  // ---- Devices by type ----
  if (r.devices_by_type.length) {
    const dBody = el("div", "hbars"); const dmax = Math.max(...r.devices_by_type.map((d) => d.n), 1);
    r.devices_by_type.slice(0, 8).forEach((d) => dBody.appendChild(hbarRow(d.name, d.n, dmax, "bar-accent")));
    grid.appendChild(dashCard("Devices by type", dBody));
  }

  // ---- Subnet size spread ----
  if (r.prefix_sizes.length) {
    const pBody = el("div", "hbars"); const pmax = Math.max(...r.prefix_sizes.map((p) => p.n), 1);
    r.prefix_sizes.slice(-10).forEach((p) => pBody.appendChild(hbarRow("/" + p.pfx, p.n, pmax, "bar-info")));
    grid.appendChild(dashCard("Subnet sizes", pBody));
  }

  // ---- Discovery mix ----
  const sx = r.source_mix; const subT = (sx.subnets.discovered || 0) + (sx.subnets.manual || 0);
  const adS = sx.addresses || {}; const adT = Object.values(adS).reduce((a, b) => a + b, 0);
  const sxBody = el("div");
  sxBody.appendChild(el("div", "mix-label", "Subnets"));
  sxBody.appendChild(segBar([{ value: sx.subnets.discovered || 0, cls: "seg-disc", label: "Discovered" }, { value: sx.subnets.manual || 0, cls: "seg-man", label: "Manual" }], subT));
  sxBody.appendChild(legend([{ label: "Discovered", value: sx.subnets.discovered || 0, cls: "seg-disc" }, { label: "Manual", value: sx.subnets.manual || 0, cls: "seg-man" }]));
  sxBody.appendChild(el("div", "mix-label", "Addresses by source"));
  sxBody.appendChild(segBar([
    { value: adS.arp || 0, cls: "seg-used", label: "ARP" }, { value: adS.lease || 0, cls: "seg-dhcp", label: "DHCP lease" },
    { value: adS.neighbor || 0, cls: "seg-gateway", label: "Neighbor" }, { value: adS.address || 0, cls: "seg-reserved", label: "Router addr" },
    { value: adS.manual || 0, cls: "seg-man", label: "Manual" }], adT));
  sxBody.appendChild(legend([
    { label: "ARP", value: adS.arp || 0, cls: "seg-used", hideZero: true }, { label: "DHCP", value: adS.lease || 0, cls: "seg-dhcp", hideZero: true },
    { label: "Neighbor", value: adS.neighbor || 0, cls: "seg-gateway", hideZero: true }, { label: "Router", value: adS.address || 0, cls: "seg-reserved", hideZero: true },
    { label: "Manual", value: adS.manual || 0, cls: "seg-man", hideZero: true }]));
  grid.appendChild(dashCard("Discovery vs manual", sxBody));

  // ---- Busiest subnets ----
  if (r.utilization.length) {
    const ul = el("div", "dash-util");
    r.utilization.forEach((s) => {
      const row = el("div", "dash-util-row");
      const top = el("div", "dash-util-top"); top.appendChild(cidrLink(s.id, s.cidr));
      if (s.name) top.appendChild(el("span", "muted small ellip", s.name));
      top.appendChild(el("span", "dash-util-pct", s.usage + "%")); row.appendChild(top);
      const bar = el("div", "dash-bar"); const f = el("div", "dash-bar-fill " + utilTone(s.usage)); f.style.width = Math.min(100, Math.max(0, s.usage)) + "%"; bar.appendChild(f); row.appendChild(bar);
      row.appendChild(el("div", "muted small", fmtNum(s.used) + " of " + fmtNum(s.usable) + " used" + (!r.scoped && s.org ? " · " + s.org : "")));
      ul.appendChild(row);
    });
    grid.appendChild(dashCard("Busiest subnets", ul));
  }

  // ---- Recently seen subnets ----
  const recentBody = el("div");
  if (r.recent.length) {
    const t = el("table", "ipam-table dash-table"); const thead = el("thead"), tr = el("tr");
    ["Subnet", "Name", ...(r.scoped ? [] : ["Client"]), "Source", "Seen"].forEach((hd) => tr.appendChild(el("th", null, hd)));
    thead.appendChild(tr); t.appendChild(thead); const tb = el("tbody");
    r.recent.forEach((s) => {
      const row = el("tr");
      const c0 = el("td"); c0.appendChild(cidrLink(s.id, s.cidr)); row.appendChild(c0);
      row.appendChild(el("td", "small", s.name || "—"));
      if (!r.scoped) row.appendChild(el("td", "small", s.org || "—"));
      const src = el("td"); src.appendChild(el("span", "pill " + (s.source === "discovered" ? "disc" : "man"), s.source === "discovered" ? "discovered" : "manual")); row.appendChild(src);
      row.appendChild(el("td", "muted small", fmtAgo(s.seen))); tb.appendChild(row);
    });
    t.appendChild(tb); recentBody.appendChild(t);
  } else recentBody.appendChild(el("p", "muted small", "No subnets yet."));
  grid.appendChild(dashCard("Recently seen subnets", recentBody));

  // ---- Hosts offline ----
  const offBody = el("div");
  if (r.offline.length) {
    const t = el("table", "ipam-table dash-table"); const thead = el("thead"), tr = el("tr");
    ["Address", "Hostname", "Subnet", "Last seen"].forEach((hd) => tr.appendChild(el("th", null, hd)));
    thead.appendChild(tr); t.appendChild(thead); const tb = el("tbody");
    r.offline.forEach((a) => {
      const row = el("tr");
      row.appendChild(el("td", "mono small", a.ip));
      row.appendChild(el("td", "small ellip", a.hostname || "—"));
      const sc = el("td"); sc.appendChild(cidrLink(a.subnet_id, a.subnet)); row.appendChild(sc);
      row.appendChild(el("td", "muted small", fmtAgo(a.last_seen))); tb.appendChild(row);
    });
    t.appendChild(tb); offBody.appendChild(t);
  } else offBody.appendChild(el("p", "muted small", "No hosts are marked offline. 🎉"));
  grid.appendChild(dashCard("Hosts offline", offBody));

  m.appendChild(grid);
}
async function showVlans() {
  const m = $("main"); m.textContent = "Loading…";
  let r; try { r = await api("/api/ipam/vlans"); } catch (e) { m.textContent = e.message; return; }
  vlansCache = r.vlans; m.textContent = ""; m.appendChild(listHead("VLANs", "+ VLAN", "newvlan"));
  if (!r.vlans.length) { m.appendChild(el("p", "muted pad", "No VLANs yet — add one, or they appear as Sync discovers them from routers and UniFi.")); return; }
  const cols = [
    { label: "VLAN", cls: "mono", cell: (v) => String(v.number), sort: (v) => v.number },
    { label: "Name", cell: (v) => v.name || "", sort: (v) => (v.name || "").toLowerCase() },
    { label: "L2 domain", cls: "muted", cell: (v) => v.l2domain, sort: (v) => (v.l2domain || "").toLowerCase() },
    { label: "Client", cell: (v) => v.org || "", sort: (v) => (v.org || "").toLowerCase() },
    { label: "Subnets", cell: (v) => String(v.subnets), sort: (v) => v.subnets },
  ];
  if (!readonly) cols.push({ label: "", cell: (v) => rowActions("editvlan", "delvlan", v.id) });
  m.appendChild(sortableTable("vlans", cols, r.vlans));
}
function vlanDialog(v) {
  const box = el("div");
  box.appendChild(field("VLAN number", inp("f_num", v?.number || "", "1-4094")));
  box.appendChild(field("Name", inp("f_name", v?.name || "")));
  box.appendChild(field("L2 domain", inp("f_l2", v?.l2domain || "default")));
  box.appendChild(field("Client", sel("f_org", clientOpts(), v?.org_id || "")));
  box.appendChild(field("Notes", inp("f_notes", v?.notes || "")));
  openDlg(v?.id ? "Edit VLAN " + v.number : "New VLAN", box, async () => {
    await post("/api/ipam/vlans", { id: v?.id, number: +$("f_num").value, name: $("f_name").value, l2domain: $("f_l2").value, org_id: $("f_org").value || null, notes: $("f_notes").value });
    await loadLookups(); await showVlans();
  });
}
async function showVrfs() {
  const m = $("main"); m.textContent = "Loading…";
  let r; try { r = await api("/api/ipam/vrfs"); } catch (e) { m.textContent = e.message; return; }
  vrfsCache = r.vrfs; m.textContent = ""; m.appendChild(listHead("VRFs", "+ VRF", "newvrf"));
  if (!r.vrfs.length) { m.appendChild(el("p", "muted pad", "No VRFs yet.")); return; }
  m.appendChild(table(["RD", "Name", "Description", "Client", "Subnets", ...(readonly ? [] : [""])], r.vrfs, (v) => {
    const row = el("tr");
    row.appendChild(el("td", "mono", v.rd));
    row.appendChild(el("td", null, v.name));
    row.appendChild(el("td", "muted", v.description || ""));
    row.appendChild(el("td", null, v.org || ""));
    row.appendChild(el("td", null, String(v.subnets)));
    if (!readonly) {
      const last = el("td"); const e = el("button", "btn tiny", "Edit"); e.dataset.editvrf = v.id; last.appendChild(e);
      const d = el("button", "btn tiny danger", "Delete"); d.dataset.delvrf = v.id; last.appendChild(d); row.appendChild(last);
    }
    return row;
  }));
}
function vrfDialog(v) {
  const box = el("div");
  box.appendChild(field("Route distinguisher (RD)", inp("f_rd", v?.rd || "", "65000:1")));
  box.appendChild(field("Name", inp("f_name", v?.name || "")));
  box.appendChild(field("Description", inp("f_desc", v?.description || "")));
  box.appendChild(field("Client", sel("f_org", clientOpts(), v?.org_id || "")));
  openDlg(v?.id ? "Edit VRF" : "New VRF", box, async () => {
    await post("/api/ipam/vrfs", { id: v?.id, rd: $("f_rd").value, name: $("f_name").value, description: $("f_desc").value, org_id: $("f_org").value || null });
    await loadLookups(); await showVrfs();
  });
}
async function showDevices() {
  const m = $("main"); m.textContent = "Loading…";
  let r; try { r = await api("/api/ipam/devices"); } catch (e) { m.textContent = e.message; return; }
  if (!locsCache.length || !typesCache.length) await loadLookups();
  m.textContent = ""; m.appendChild(listHead("Devices", "+ Device", "newdevice"));
  m.appendChild(el("p", "muted small pad", "Infrastructure — routers, switches, access points, gateways and the like. Sync adds managed MikroTiks and UniFi devices automatically; add others by hand."));
  if (!r.devices.length) { m.appendChild(el("p", "muted pad", "No devices yet — add one, or Sync a client to discover its infrastructure.")); return; }
  const cols = [
    { label: "Device", cell: (d) => d.name, sort: (d) => (d.name || "").toLowerCase() },
    { label: "Type", cell: (d) => d.type || "—", sort: (d) => (d.type || "").toLowerCase() },
    { label: "Management IP", cls: "mono", cell: (d) => d.management_ip || "", sort: (d) => ipKey(d.management_ip) },
    { label: "Location", cell: (d) => d.location || "", sort: (d) => (d.location || "").toLowerCase() },
    { label: "Client", cell: (d) => d.org || "", sort: (d) => (d.org || "").toLowerCase() },
    { label: "Source", cell: (d) => el("span", "pill " + (d.source_auto ? "disc" : "man"), d.source_auto ? "discovered" : "manual"), sort: (d) => (d.source_auto ? "discovered" : "manual") },
  ];
  if (!readonly) cols.push({ label: "", cell: (d) => rowActions("editdevice", "deldevice", d.id) });
  m.appendChild(sortableTable("devices", cols, r.devices));
}
// Sort key for an IPv4 address so .10 sorts after .9 (empty sorts last).
function ipKey(ip) {
  const m = String(ip || "").match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/);
  return m ? (((+m[1] * 256 + +m[2]) * 256 + +m[3]) * 256 + +m[4]) : Number.MAX_SAFE_INTEGER;
}
function deviceDialog(d) {
  const box = el("div");
  box.appendChild(field("Name", inp("f_name", d?.name || "")));
  const typeOpts = [{ value: "", label: "(none)" }, ...typesCache.map((t) => ({ value: t.id, label: t.name }))];
  box.appendChild(field("Type", sel("f_type", typeOpts, d?.type_id || "")));
  box.appendChild(field("Management IP", inp("f_mip", d?.management_ip || "")));
  const locOpts = [{ value: "", label: "(none)" }, ...locsCache.map((l) => ({ value: l.id, label: l.name }))];
  box.appendChild(field("Location", sel("f_loc", locOpts, d?.location_id || "")));
  box.appendChild(field("Client", sel("f_org", clientOpts(), d?.org_id || "")));
  box.appendChild(field("Description", inp("f_desc", d?.description || "")));
  box.appendChild(field("Notes", inp("f_notes", d?.notes || "")));
  openDlg(d?.id ? "Edit device" : "New device", box, async () => {
    await post("/api/ipam/devices", { id: d?.id, name: $("f_name").value, type_id: $("f_type").value || null, management_ip: $("f_mip").value,
      location_id: $("f_loc").value || null, org_id: $("f_org").value || null, description: $("f_desc").value, notes: $("f_notes").value });
    await showDevices();
  });
}
async function showLocations() {
  const m = $("main"); m.textContent = "Loading…";
  let r; try { r = await api("/api/ipam/locations"); } catch (e) { m.textContent = e.message; return; }
  locsCache = r.locations; m.textContent = ""; m.appendChild(listHead("Locations", "+ Location", "newlocation"));
  m.appendChild(el("p", "muted small pad", "Sites where infrastructure lives. Sync adds a location for each UniFi / UISP site automatically."));
  if (!r.locations.length) { m.appendChild(el("p", "muted pad", "No locations yet.")); return; }
  m.appendChild(table(["Location", "Address", "Client", "Devices", ...(readonly ? [] : [""])], r.locations, (l) => {
    const row = el("tr");
    row.appendChild(el("td", null, l.name));
    row.appendChild(el("td", "muted", l.address || ""));
    row.appendChild(el("td", null, l.org || ""));
    row.appendChild(el("td", null, String(l.devices)));
    if (!readonly) {
      const last = el("td"); const e = el("button", "btn tiny", "Edit"); e.dataset.editlocation = l.id; last.appendChild(e);
      const x = el("button", "btn tiny danger", "Delete"); x.dataset.dellocation = l.id; last.appendChild(x); row.appendChild(last);
    }
    return row;
  }));
}
function locationDialog(l) {
  const box = el("div");
  box.appendChild(field("Name", inp("f_name", l?.name || "")));
  box.appendChild(field("Address", inp("f_addr", l?.address || "")));
  box.appendChild(field("Client", sel("f_org", clientOpts(), l?.org_id || "")));
  box.appendChild(field("Notes", inp("f_notes", l?.notes || "")));
  openDlg(l?.id ? "Edit location" : "New location", box, async () => {
    await post("/api/ipam/locations", { id: l?.id, name: $("f_name").value, address: $("f_addr").value, org_id: $("f_org").value || null, notes: $("f_notes").value });
    await showLocations();
  });
}

// ---- racks --------------------------------------------------------------------------------------------------
let rackOpen = null;   // the rack id whose elevation is showing (so edits/placements re-render it)
async function showRacks() {
  rackOpen = null;
  const m = $("main"); m.textContent = "Loading…";
  let r; try { r = await api("/api/ipam/racks"); } catch (e) { m.textContent = e.message; return; }
  m.textContent = ""; m.appendChild(listHead("Racks", "+ Rack", "newrack"));
  m.appendChild(el("p", "muted small pad", "Equipment racks. Open a rack to see its elevation and place devices (from the Devices inventory) into rack units."));
  if (!r.racks.length) { m.appendChild(el("p", "muted pad", "No racks yet — add one, then place devices into it.")); return; }
  const cols = [
    { label: "Rack", cell: (k) => { const a = el("a", "cidr", k.name); a.dataset.openrack = k.id; return a; }, sort: (k) => (k.name || "").toLowerCase() },
    { label: "Size", cls: "mono", cell: (k) => k.size_u + "U", sort: (k) => k.size_u },
    { label: "Filled", cell: (k) => k.used_u + " / " + k.size_u + "U", sort: (k) => k.used_u },
    { label: "Devices", cell: (k) => String(k.devices), sort: (k) => k.devices },
    { label: "Location", cell: (k) => k.location || "", sort: (k) => (k.location || "").toLowerCase() },
    { label: "Client", cell: (k) => k.org || "", sort: (k) => (k.org || "").toLowerCase() },
    { label: "Description", cell: (k) => k.description || "", sort: (k) => (k.description || "").toLowerCase() },
  ];
  if (!readonly) cols.push({ label: "", cell: (k) => rowActions("editrack", "delrack", k.id) });
  m.appendChild(sortableTable("racks", cols, r.racks));
}
// A rack elevation drawn as a table: one row per U (top-numbered down to 1); a device is a cell spanning its height
// with rowspan, so no dynamic inline styles are needed. Covered units below a device emit no slot cell.
function rackElevation(r) {
  const byTop = {}, covered = {};
  (r.units || []).forEach((d) => {
    const h = Math.max(1, d.rack_height || 1), top = d.rack_u + h - 1;
    byTop[top] = d; for (let u = d.rack_u; u <= top; u++) covered[u] = d;
  });
  const wrap = el("div", "rack-wrap"); const tbl = el("table", "rack"); const tb = el("tbody");
  for (let u = r.size_u; u >= 1; u--) {
    const tr = el("tr");
    tr.appendChild(el("td", "rack-u", String(u)));
    if (byTop[u]) {
      const d = byTop[u]; const td = el("td", "rack-dev"); td.rowSpan = Math.max(1, d.rack_height || 1);
      td.appendChild(el("span", "rack-dev-name", d.name));
      td.appendChild(el("span", "rack-dev-info", (d.rack_height || 1) + "U" + (d.type ? " · " + d.type : "") + (d.management_ip ? " · " + d.management_ip : "")));
      if (!readonly) { const x = el("button", "rack-remove", "×"); x.dataset.unplace = d.id; x.title = "Remove from rack"; td.appendChild(x); }
      tr.appendChild(td);
    } else if (!covered[u]) { const s = el("td", "rack-slot"); s.dataset.dropu = u; tr.appendChild(s); }
    tb.appendChild(tr);
  }
  tbl.appendChild(tb); wrap.appendChild(tbl); return wrap;
}
async function showRack(id) {
  const m = $("main"); m.textContent = "Loading…";
  let r; try { r = await api("/api/ipam/racks/" + id); } catch (e) { m.textContent = e.message; return; }
  rackOpen = r.id; m.textContent = "";
  const head = el("div", "main-head");
  const back = el("button", "btn", "← Racks"); back.dataset.racksback = "1"; head.appendChild(back);
  head.appendChild(el("h1", null, r.name));
  const acts = el("div", "main-head-actions");
  if (!readonly) {
    const place = el("button", "btn primary", "+ Place device"); place.dataset.placedev = r.id; acts.appendChild(place);
    const ed = el("button", "btn", "Edit rack"); ed.dataset.editrack = r.id; acts.appendChild(ed);
  }
  head.appendChild(acts); m.appendChild(head);
  const meta = el("div", "meta-row");
  const chip = (label, val) => { const c = el("span", "chip"); c.appendChild(el("b", null, label + " ")); c.appendChild(document.createTextNode(val)); return c; };
  const usedU = (r.units || []).reduce((s, d) => s + (d.rack_height || 1), 0);
  meta.appendChild(chip("Size", r.size_u + "U")); meta.appendChild(chip("Filled", usedU + " / " + r.size_u + "U"));
  if (r.location) meta.appendChild(chip("Location", r.location));
  if (r.org) meta.appendChild(chip("Client", r.org));
  m.appendChild(meta);
  if (r.description) m.appendChild(el("p", "muted", r.description));

  let avail = [];
  if (!readonly) { try { avail = (await api("/api/ipam/racks/" + id + "/placeable")).devices; } catch (e) { avail = []; } }
  const layout = el("div", "rack-layout");
  const elev = rackElevation(r); layout.appendChild(elev);
  if (!readonly) layout.appendChild(devicePalette(avail));
  m.appendChild(layout);

  if (!readonly) {   // drag a device chip from the palette onto a free unit to place it there
    const place = async (deviceId, h, u) => {
      try { await post("/api/ipam/racks/place", { rack_id: id, device_id: deviceId, rack_u: u, rack_height: h }); await showRack(id); }
      catch (e) { toast(e.message); }
    };
    layout.addEventListener("dragstart", (e) => {
      const grip = e.target.closest(".pal-grip"); if (!grip) return;
      const chip = grip.closest(".pal-dev");
      e.dataTransfer.setData("text/plain", JSON.stringify({ id: +chip.dataset.dev, h: +(chip.querySelector(".pal-h")?.value || 1) }));
      e.dataTransfer.effectAllowed = "move"; chip.classList.add("dragging");
    });
    layout.addEventListener("dragend", (e) => { const chip = e.target.closest(".pal-dev"); if (chip) chip.classList.remove("dragging"); });
    elev.addEventListener("dragover", (e) => { const s = e.target.closest(".rack-slot[data-dropu]"); if (s) { e.preventDefault(); s.classList.add("drop-hi"); } });
    elev.addEventListener("dragleave", (e) => { const s = e.target.closest(".rack-slot[data-dropu]"); if (s) s.classList.remove("drop-hi"); });
    elev.addEventListener("drop", (e) => {
      const s = e.target.closest(".rack-slot[data-dropu]"); if (!s) return;
      e.preventDefault(); s.classList.remove("drop-hi");
      let d; try { d = JSON.parse(e.dataTransfer.getData("text/plain")); } catch (x) { return; }
      if (d && d.id) place(d.id, d.h || 1, +s.dataset.dropu);
    });
  }
}
// The palette of unplaced devices beside the elevation: drag a chip onto a free unit (set its height on the chip first).
function devicePalette(devices) {
  const box = el("div", "rack-palette");
  box.appendChild(el("div", "rack-palette-head", "Devices"));
  if (!devices.length) {
    box.appendChild(el("p", "muted small", "No unplaced devices for this rack. Add some on the Devices tab (or assign them to this rack's client)."));
    return box;
  }
  box.appendChild(el("p", "muted small", "Drag a device onto a free unit. Set its height first if it's taller than 1U."));
  devices.forEach((d) => {
    const chip = el("div", "pal-dev"); chip.dataset.dev = d.id;
    const grip = el("span", "pal-grip", "⠿"); grip.draggable = true; grip.title = "Drag onto the rack"; chip.appendChild(grip);
    const nm = el("span", "pal-main"); nm.appendChild(el("span", "pal-name", d.name));
    if (d.type) nm.appendChild(el("span", "muted small", d.type)); chip.appendChild(nm);
    const h = el("select", "pal-h"); [1, 2, 3, 4, 6, 8, 10, 12].forEach((n) => { const o = el("option", null, n + "U"); o.value = n; h.appendChild(o); });
    h.title = "Height in rack units"; chip.appendChild(h);
    box.appendChild(chip);
  });
  return box;
}
function rackDialog(k) {
  const box = el("div");
  box.appendChild(field("Name", inp("f_name", k?.name || "")));
  box.appendChild(field("Size (U)", inp("f_size", k?.size_u || 42, "e.g. 42")));
  const locOpts = [{ value: "", label: "(none)" }, ...locsCache.map((l) => ({ value: l.id, label: l.name }))];
  box.appendChild(field("Location", sel("f_loc", locOpts, k?.location_id || "")));
  box.appendChild(field("Client", sel("f_org", clientOpts(), k?.org_id || "")));
  box.appendChild(field("Description", inp("f_desc", k?.description || "")));
  box.appendChild(field("Notes", inp("f_notes", k?.notes || "")));
  openDlg(k?.id ? "Edit rack" : "New rack", box, async () => {
    await post("/api/ipam/racks", { id: k?.id, name: $("f_name").value, size_u: +$("f_size").value, location_id: $("f_loc").value || null,
      org_id: $("f_org").value || null, description: $("f_desc").value, notes: $("f_notes").value });
    if (rackOpen) await showRack(rackOpen); else await showRacks();
  });
}
async function placeDialog(rackId) {
  let avail; try { avail = (await api("/api/ipam/racks/" + rackId + "/placeable")).devices; } catch (e) { toast(e.message); return; }
  const box = el("div");
  if (!avail.length) { box.appendChild(el("p", "muted small", "No unplaced devices for this rack. Add devices on the Devices tab first (or assign them to this rack's client).")); openDlg("Place device", box, null); return; }
  const devOpts = avail.map((d) => ({ value: d.id, label: d.name + (d.type ? " (" + d.type + ")" : "") }));
  box.appendChild(field("Device", sel("f_dev", devOpts, "")));
  box.appendChild(field("Bottom unit (U)", inp("f_u", "1", "lowest U it occupies")));
  box.appendChild(field("Height (U)", inp("f_h", "1", "how many U tall")));
  openDlg("Place device", box, async () => {
    await post("/api/ipam/racks/place", { rack_id: rackId, device_id: +$("f_dev").value, rack_u: +$("f_u").value, rack_height: +$("f_h").value });
    await showRack(rackId);
  });
}

// ---- load / route -------------------------------------------------------------------------------------------
async function reload() { tree = await api("/api/ipam/tree"); renderTree(); if (tab !== "subnets") return setTab(tab); if (current?.subnet) await showSubnet(current.subnet); else showSubnets(); }

// Top-bar "Customer" pulldown, shared with the main app: pick one customer and IPAM shows only theirs.
async function setupCustomerPicker() {
  if (me.kind !== "tech") return;   // client users see only their own org; no picker
  const sel = $("custSel"); if (!sel) return;
  let orgs = [];
  try { orgs = await api("/api/orgs"); } catch { return; }
  sel.innerHTML = `<option value="">All customers</option>` + orgs.map((o) => `<option value="${o.id}">${esc(o.name)}</option>`).join("");
  if (appOrg && !orgs.some((o) => String(o.id) === appOrg)) { appOrg = ""; try { localStorage.setItem("tm.customer", ""); } catch { /* private */ } }
  sel.value = appOrg;
  $("custWrap").classList.remove("hidden");
  $("custWrap").classList.toggle("allcust", !appOrg);
  sel.addEventListener("change", async () => {
    appOrg = sel.value;
    try { localStorage.setItem("tm.customer", appOrg); } catch { /* private */ }
    $("custWrap").classList.toggle("allcust", !appOrg);
    current = { kind: "all" };
    await reload();
  });
}

async function init() {
  try { me = await api("/api/me"); } catch (e) { return; }
  readonly = me.kind !== "tech";   // a client user: read-only
  if (readonly) { $("newSection").hidden = true; $("syncBtn").hidden = true; $("importBtn").hidden = true; }
  if (window.BRAND && window.BRAND.company) document.title = "IPAM · " + window.BRAND.company;
  current = { kind: "all" };
  try { tree = await api("/api/ipam/tree"); } catch (e) { $("main").textContent = e.message; return; }
  renderTree(); setTab("dashboard");
  loadLookups();
  setupCustomerPicker();

  // tabs
  $("tabs").addEventListener("click", (e) => { const b = e.target.closest("[data-tab]"); if (b) setTab(b.dataset.tab); });

  // mobile sections/clients drawer
  const ipamBody = document.querySelector(".ipam-body");
  $("sideToggle").addEventListener("click", () => ipamBody.classList.toggle("side-open"));
  $("sideBackdrop").addEventListener("click", () => ipamBody.classList.remove("side-open"));

  // top bar
  $("newSection").addEventListener("click", () => sectionDialog(null));
  $("syncBtn").addEventListener("click", syncPicker);
  $("calcBtn").addEventListener("click", calcDialog);
  $("exportBtn").addEventListener("click", exportDialog);
  $("importBtn").addEventListener("click", importDialog);
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
    e.currentTarget.closest(".ipam-body").classList.remove("side-open");   // mobile: close the drawer after picking
    renderTree(); showSubnets();
  });

  // main delegation
  $("main").addEventListener("click", async (e) => {
    const t = e.target;
    const sub = t.closest("[data-subnet]");
    // read-only client: ignore every write/edit affordance (map cells open the address editor otherwise)
    if (readonly && (t.classList.contains("cell") || ["newvlan", "editvlan", "delvlan", "newvrf", "editvrf", "delvrf",
      "newsubnet", "editsubnet", "splitsubnet", "newaddr", "syncorg", "delsubnet", "editaddr", "deladdr",
      "newdevice", "editdevice", "deldevice", "newlocation", "editlocation", "dellocation",
      "newrack", "editrack", "delrack", "placedev", "unplace"].some((k) => t.dataset[k] != null))) return;
    // Racks
    if (t.dataset.openrack != null) return showRack(+t.dataset.openrack);
    if (t.dataset.racksback != null) return showRacks();
    if (t.dataset.newrack != null) return rackDialog(null);
    if (t.dataset.editrack != null) { const k = await api("/api/ipam/racks/" + t.dataset.editrack); return rackDialog(k); }
    if (t.dataset.delrack != null) { if (confirm("Delete this rack? Devices in it are kept but unplaced.")) { await post("/api/ipam/racks/" + t.dataset.delrack + "/delete"); await showRacks(); } return; }
    if (t.dataset.placedev != null) return placeDialog(+t.dataset.placedev);
    if (t.dataset.unplace != null) { await post("/api/ipam/racks/unplace", { device_id: +t.dataset.unplace }); if (rackOpen) await showRack(rackOpen); return; }
    // Dashboard widgets
    if (t.dataset.gotab != null) return setTab(t.dataset.gotab);
    if (t.dataset.gotabclient != null) { const id = +t.dataset.gotabclient || null; setTab("subnets"); if (id) { current = { kind: "client", id }; renderTree(); showSubnets(); } return; }
    if (t.dataset.dashsubnet != null) return openSubnet(+t.dataset.dashsubnet);
    // Devices / Locations
    if (t.dataset.newdevice != null) return deviceDialog(null);
    if (t.dataset.editdevice != null) { const r = await api("/api/ipam/devices"); return deviceDialog((r.devices || []).find((x) => x.id === +t.dataset.editdevice)); }
    if (t.dataset.deldevice != null) { if (confirm("Delete this device?")) { await post("/api/ipam/devices/" + t.dataset.deldevice + "/delete"); await showDevices(); } return; }
    if (t.dataset.newlocation != null) return locationDialog(null);
    if (t.dataset.editlocation != null) return locationDialog(locsCache.find((x) => x.id === +t.dataset.editlocation));
    if (t.dataset.dellocation != null) { if (confirm("Delete this location? Devices keep their data but lose the location.")) { await post("/api/ipam/locations/" + t.dataset.dellocation + "/delete"); await loadLookups(); await showLocations(); } return; }
    // VLANs / VRFs
    if (t.dataset.newvlan != null) return vlanDialog(null);
    if (t.dataset.editvlan != null) return vlanDialog(vlansCache.find((v) => v.id === +t.dataset.editvlan));
    if (t.dataset.delvlan != null) { if (confirm("Delete this VLAN? Subnets keep their data but lose the VLAN link.")) { await post("/api/ipam/vlans/" + t.dataset.delvlan + "/delete"); await loadLookups(); await showVlans(); } return; }
    if (t.dataset.newvrf != null) return vrfDialog(null);
    if (t.dataset.editvrf != null) return vrfDialog(vrfsCache.find((v) => v.id === +t.dataset.editvrf));
    if (t.dataset.delvrf != null) { if (confirm("Delete this VRF?")) { await post("/api/ipam/vrfs/" + t.dataset.delvrf + "/delete"); await loadLookups(); await showVrfs(); } return; }
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
    const ds = e.target.closest("[data-delsection]"); if (ds) { e.preventDefault(); if (confirm("Delete this section? Its subnets stay but lose the folder.")) { await post("/api/ipam/sections/" + ds.dataset.delsection + "/delete"); $("dlg").close(); await reload(); } return; }
    const pv = e.target.closest("[data-ipampreview]"); if (pv) {
      e.preventDefault(); const out = $("imp_out"); out.hidden = false; out.textContent = "Checking…";
      try {
        const r = await post("/api/ipam/import", { kind: $("f_kind").value, org_id: $("f_org").value || null, csv: $("f_csv").value, commit: false });
        out.textContent = `Would add ${r.to_add} ${r.kind}.\nAlready present (skipped): ${r.skipped_existing}.`
          + (r.sample.length ? `\nFirst: ${r.sample.join(", ")}` : "")
          + (r.errors.length ? `\n\n${r.errors.length} row(s) with problems:\n- ${r.errors.join("\n- ")}` : "");
      } catch (err) { out.textContent = err.message; }
    }
  });
}
document.addEventListener("DOMContentLoaded", init);
