"use strict";
// IPAM workspace. CSP forbids inline scripts/handlers, so everything binds via addEventListener + data-* delegation.

let me = null, tree = { sections: [], subnets: [], clients: [] }, current = null; // current = {kind:'all'|'section'|'client', id}
let readonly = false;   // client users may VIEW their own IPAM but change nothing (writes are technician-only)

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
function toast(msg, ms) {
  let t = $("toast"); if (!t) { t = el("div", "toast"); t.id = "toast"; document.body.appendChild(t); }
  t.textContent = msg; t.classList.add("show"); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove("show"), ms || 4000);
}

// ---- tabs: VLANs / VRFs / Devices / Locations ---------------------------------------------------------------
let tab = "subnets";
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
  else if (t === "vlans") showVlans();
  else if (t === "vrfs") showVrfs();
  else if (t === "devices") showDevices();
  else if (t === "locations") showLocations();
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
async function showVlans() {
  const m = $("main"); m.textContent = "Loading…";
  let r; try { r = await api("/api/ipam/vlans"); } catch (e) { m.textContent = e.message; return; }
  vlansCache = r.vlans; m.textContent = ""; m.appendChild(listHead("VLANs", "+ VLAN", "newvlan"));
  if (!r.vlans.length) { m.appendChild(el("p", "muted pad", "No VLANs yet — add one, or they appear as Sync discovers them from routers and UniFi.")); return; }
  m.appendChild(table(["VLAN", "Name", "L2 domain", "Client", "Subnets", ...(readonly ? [] : [""])], r.vlans, (v) => {
    const row = el("tr");
    row.appendChild(el("td", "mono", String(v.number)));
    row.appendChild(el("td", null, v.name || ""));
    row.appendChild(el("td", "muted", v.l2domain));
    row.appendChild(el("td", null, v.org || ""));
    row.appendChild(el("td", null, String(v.subnets)));
    if (!readonly) {
      const last = el("td"); const e = el("button", "btn tiny", "Edit"); e.dataset.editvlan = v.id; last.appendChild(e);
      const d = el("button", "btn tiny danger", "Delete"); d.dataset.delvlan = v.id; last.appendChild(d); row.appendChild(last);
    }
    return row;
  }));
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
  m.appendChild(table(["Device", "Type", "Management IP", "Location", "Client", "Source", ...(readonly ? [] : [""])], r.devices, (d) => {
    const row = el("tr");
    row.appendChild(el("td", null, d.name + (d.linked_device ? "" : "")));
    row.appendChild(el("td", null, d.type || "—"));
    row.appendChild(el("td", "mono", d.management_ip || ""));
    row.appendChild(el("td", null, d.location || ""));
    row.appendChild(el("td", null, d.org || ""));
    const cs = el("td"); cs.appendChild(el("span", "pill " + (d.source_auto ? "disc" : "man"), d.source_auto ? "discovered" : "manual")); row.appendChild(cs);
    if (!readonly) {
      const last = el("td"); const e = el("button", "btn tiny", "Edit"); e.dataset.editdevice = d.id; last.appendChild(e);
      const x = el("button", "btn tiny danger", "Delete"); x.dataset.deldevice = d.id; last.appendChild(x); row.appendChild(last);
    }
    return row;
  }));
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

// ---- load / route -------------------------------------------------------------------------------------------
async function reload() { tree = await api("/api/ipam/tree"); renderTree(); if (tab !== "subnets") return setTab(tab); if (current?.subnet) await showSubnet(current.subnet); else showSubnets(); }

async function init() {
  try { me = await api("/api/me"); } catch (e) { return; }
  readonly = me.kind !== "tech";   // a client user: read-only
  if (readonly) { $("newSection").hidden = true; $("syncBtn").hidden = true; $("importBtn").hidden = true; }
  if (window.BRAND && window.BRAND.company) document.title = "IPAM · " + window.BRAND.company;
  current = { kind: "all" };
  try { tree = await api("/api/ipam/tree"); } catch (e) { $("main").textContent = e.message; return; }
  renderTree(); showSubnets();
  loadLookups();

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
      "newdevice", "editdevice", "deldevice", "newlocation", "editlocation", "dellocation"].some((k) => t.dataset[k] != null))) return;
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
