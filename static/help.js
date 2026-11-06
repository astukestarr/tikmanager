"use strict";
// Help Center: the Manual (written below, static) and the Knowledge Base (kb.py, administrators edit it).
// CSP forbids inline scripts/handlers, so everything binds via addEventListener + data-* delegation.

let me = null, kb = { articles: [], can_edit: false };
let tab = "manual";                 // "manual" | "kb"
let kbCat = "";                     // Knowledge Base category filter ("" = all)
let query = "";                     // search text (both tabs)

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { "Content-Type": "application/json", "X-CSRF-Token": me?.csrf || "", ...(opts.headers || {}) } });
  const body = await r.json().catch(() => ({}));
  if (r.status === 401) { location.href = "/login"; throw new Error("Signed out"); }
  if (!r.ok) throw new Error(body.error || r.statusText);
  return body;
}
const post = (path, data = {}) => api(path, { method: "POST", body: JSON.stringify(data) });

// --- light markup: **bold**, `code`, [text](href) ------------------------------------------------------------
function mdInline(s) {
  return esc(s)
    .replace(/\[([^\]]+)\]\((\/[^)\s]+|https?:\/\/[^)\s]+)\)/g, '<a href="$2">$1</a>')
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/`(.+?)`/g, "<code>$1</code>");
}
// server-side _blocks output (KB bodies): [{kind:'p'|'li', text}]
function blocksHtml(blocks) {
  let out = "", ul = false;
  for (const b of blocks || []) {
    if (b.kind === "li") { if (!ul) { out += "<ul>"; ul = true; } out += `<li>${mdInline(b.text)}</li>`; }
    else { if (ul) { out += "</ul>"; ul = false; } out += `<p>${mdInline(b.text)}</p>`; }
  }
  return out + (ul ? "</ul>" : "");
}
// Manual body: array of strings (paragraph) | {h} (subhead) | {ul:[...]}
function bodyHtml(body) {
  return body.map((b) => {
    if (typeof b === "string") return `<p>${mdInline(b)}</p>`;
    if (b.h) return `<h3>${esc(b.h)}</h3>`;
    if (b.ul) return `<ul>${b.ul.map((li) => `<li>${mdInline(li)}</li>`).join("")}</ul>`;
    return "";
  }).join("");
}

// =====================================================================================================
//  THE MANUAL  — grouped to match the left sidebar in the app. Generic by design (no client names).
// =====================================================================================================
const MANUAL = [
  { group: "Getting started", items: [
    { id: "welcome", title: "Welcome to TikManager", body: [
      "TikManager is a management platform for a fleet of networks. It adopts your MikroTik routers, switches and access points, pulls in UniFi / UISP gear, and discovers everything else on each site's LAN — then gives you one place to monitor, back up, upgrade, secure and document all of it, per client.",
      { h: "How it's organised" },
      "The left sidebar groups every page by what it's for: **Devices** (your gear), **Network** (how sites connect, plus IPAM), **Monitoring** (health, checks, alerts, logs), **Security**, **Maintenance** (backups, upgrades, tasks) and **Clients & users**. **Admin** holds settings, integrations and the audit log.",
      "The top bar carries the global **Customer** selector, the **?** Help menu, the **bell** (Message Center) and appearance (light / dark and colour).",
      "Not every page is shown to everyone — your role decides what you can see and change, and client users see a trimmed, read-only view of only their own gear.",
    ] },
    { id: "basics", title: "Signing in & the basics", body: [
      "Sign in with your Microsoft account (if your company turned that on) or your TikManager password. A new technician account waits for an administrator to give it a role before it can do anything.",
      { h: "The Customer selector" },
      "The **Customer** pull-down in the top bar floats across the whole app. Leave it on **All customers** to see the fleet, or pick one client and every page — dashboards, devices, IPAM, reports — narrows to just that customer until you change it back. Your choice follows you from page to page, including into IPAM.",
      { h: "Appearance & your phone" },
      "The appearance button switches light / dark mode and the accent colour. TikManager also installs as an app: open it in your phone's browser and use **Add to Home Screen** (iPhone) or **Install app** (Android) for a full-screen, phone-sized view. See the bell for the full how-to.",
    ] },
  ] },

  { group: "Devices", items: [
    { id: "dashboard", title: "Dashboard", body: [
      "The Dashboard is the fleet at a glance, with tabs for **Overview**, **Network**, **Security** and **Maintenance**. Each tile is a count that matters — routers offline, alerts open, backups overdue, updates waiting — and clicking a tile jumps to the list or page behind it.",
      "With a customer selected, the Dashboard shows only that client's numbers.",
    ] },
    { id: "wizards", title: "Router Wizard", body: [
      "Wizards build a piece of configuration for you and push it, instead of hand-typing it on each router.",
      { ul: [
        "**WireGuard Builder** — a point-to-point WireGuard tunnel between two routers (hub and client end, which can even be a different customer). TikManager generates the keys, addresses and peers, tags the tunnel so it can be tracked and removed cleanly, and names each peer after the router at the far end.",
        "**IPsec Tunnel** — the MikroTik end of an IPsec tunnel to an any-brand remote end (one-sided), for connecting to a firewall that isn't a MikroTik.",
      ] },
      "Anything a wizard builds is tracked, so you can see it and remove it later without hunting through the config.",
    ] },
    { id: "diagnostics", title: "Diagnostics", body: [
      "Diagnostics runs on-demand tests against one router and saves the report.",
      { ul: [
        "**Traffic Watch** — a live look at who is using the connection right now (a torch-style capture), with a short who's-using-it report.",
        "**Speed Test** — a download / latency check from the router.",
      ] },
      "Diagnostics is technician-only. Each run is kept so you can compare before and after a change.",
    ] },
    { id: "devices", title: "Devices (routers, switches, APs)", body: [
      "The **Devices** group lists everything TikManager manages, filtered by kind — All devices, Access points, Routers, Switches. Each row shows the model, site, firmware, uptime and health at a glance.",
      { h: "Adopting a router" },
      "To bring a new MikroTik under management, run the adoption one-liner on it (TikManager shows the exact command). Once adopted, TikManager polls it, charts its traffic and health, backs it up and can upgrade it.",
      { h: "The router page" },
      "Click any device to open its page: an overview, interfaces and traffic charts, an **Uptime** history bar (how much of the last day / week / month it was online), its backups, and a **Console** tab that runs a single RouterOS command through the API (audited — it is a command runner, not a full SSH session; Winbox stays the place for interactive work).",
    ] },
    { id: "unifi", title: "UniFi / UISP", body: [
      "If you connect a UniFi or UISP controller (Admin > Integrations), its sites, gateways, switches and access points show up here alongside your MikroTiks, and their networks flow into IPAM. TikManager reads this gear; it doesn't reconfigure it.",
    ] },
  ] },

  { group: "Network", items: [
    { id: "sitemap", title: "Site map", body: [
      "The Site map plots every site on a map so you can see the fleet geographically and spot a whole site that's down. Device locations come from what TikManager can discover plus any you set.",
    ] },
    { id: "isps", title: "ISPs & outages", body: [
      "**Network > ISPs** shows which provider each router's internet links use. When several routers on the same ISP drop at once, TikManager raises a possible-outage warning (and an alert) — so you know whether to call the ISP or drive to the site. ISP and outage data is enriched from public sources and, optionally, Cloudflare Radar.",
    ] },
    { id: "discovered", title: "Discovered", body: [
      "**Discovered** is everything TikManager has seen on your sites' networks that isn't yet a managed device — turned up by router neighbour discovery, UniFi, and the on-site collectors. It's the pool you promote from: adopt a MikroTik, or note a device in IPAM.",
    ] },
    { id: "ipam", title: "IPAM — IP address management", body: [
      "**Subnets (IPAM)** opens the IPAM workspace: a phpIPAM-style home for every subnet, IP, VLAN, VRF, device and location across your clients. Open it from the sidebar or at **/ipam**; it has its own **?** Help button too.",
      { h: "What's in it" },
      { ul: [
        "**Dashboard** — utilisation, a 30-day trend, and what needs attention.",
        "**Subnets** — grouped into sections and by client, each with a visual IP map; free IPs are shown by absence, never materialised.",
        "**VLANs / VRFs**, **Devices** and **Locations** — auto-populated from your routers, switches (incl. L2 bridge VLANs) and UniFi.",
        "**DNS / PTR**, and add-only **CSV import / export**.",
      ] },
      { h: "Where the data comes from" },
      "IPAM fills itself from live router and UniFi syncs and from the on-site collectors, and **never clobbers anything you entered by hand** — manual edits always win. Use **Sync from routers** to refresh now; the badge on each subnet / address shows its source (manual, discovered, router, unifi, collector).",
      { h: "Make an IP a device" },
      "Found an IP that's really a piece of infrastructure? Open the address and choose **Make this IP a device** — it opens the device form pre-filled with the name, IP and client, and links the address to the new device.",
      "Client users whose organisation has IPAM turned on can view their own IPAM, read-only.",
    ] },
    { id: "collectors", title: "Network collectors", body: [
      "Collectors reach the sites where you have no MikroTik or UniFi. A collector is a lightweight **PowerShell agent** that runs as a scheduled task on any Windows box at the client — easy to push with an RMM — and scans the local network, reporting what it finds straight into IPAM under that client.",
      { ul: [
        "It sweeps with ping, ARP and reverse-DNS, and (optional) uses **SNMP** to identify devices and pull VLANs off managed switches.",
        "Each collector is tied to one client by an enrol key; create it under **Admin > Collectors**, which shows a one-time key and a copy-paste install command.",
        "You can turn SNMP on at install time or later, and set the scan ranges and interval per collector.",
      ] },
      "Managing collectors is administrator-only; what they discover shows up for anyone who can see that client's IPAM.",
    ] },
    { id: "vpn", title: "Site-to-site VPN", body: [
      "**Site-to-site VPN** manages hub-and-spoke WireGuard between sites — one client per tunnel. For a quick one-off link between two routers, reach for the **WireGuard Builder** wizard instead; this page is for the standing, multi-site picture.",
    ] },
  ] },

  { group: "Monitoring", items: [
    { id: "health", title: "Router health", body: [
      "Router health collects board sensors and fibre (SFP) readings — temperature, voltage, CPU, memory, optical levels — every few minutes and keeps 30 days, so you can catch a router cooking or an SFP degrading before it fails.",
    ] },
    { id: "checks", title: "Critical checks", body: [
      "A critical check makes sure a client's routers can always reach an address that matters — a server, a phone system, the far end of a VPN. Every router pings it each minute (you can exclude routers, or target by tag), and an alert fires the moment one can't.",
    ] },
    { id: "alerts", title: "Alerts & webhooks", body: [
      "**Alerts** is the running list of what's wrong — offline routers, failed checks, possible ISP outages, overdue backups, health thresholds. Acknowledge one to quiet it.",
      "Under Admin you can send alerts out by **webhook** (to Teams, Slack or anything that takes a POST), choosing the format and which kinds of alert go where.",
    ] },
    { id: "logs", title: "Logs", body: [
      "Routers can forward their log lines to TikManager, kept for 14 days and searchable in one place across the fleet — handy for tracing an event without logging into each router.",
    ] },
  ] },

  { group: "Security", items: [
    { id: "signins", title: "Sign-ins & events", body: [
      "The security page tracks sign-ins to TikManager and notable events, so you can see who did what and spot a login that shouldn't have happened. Every change that matters is also written to the **Audit log** (Admin).",
    ] },
    { id: "blocking", title: "Blocking", body: [
      "**Security > Blocking** drops unwanted traffic on a client's routers.",
      { ul: [
        "**Region blocking** stops connections to or from whole countries (Block, or Allow-only; incoming, outgoing or both) — like UniFi. Country data is updated daily.",
        "The block list lives in **router memory only** — no flash writes, not in backups — loaded gently and backing off when the CPU is busy, and skipped on a router too small to hold it safely. TikManager, your routers and addresses your people used recently are never blocked.",
        "You can leave a router out, or let some countries through on just one site.",
      ] },
    ] },
    { id: "vulns", title: "Vulnerabilities", body: [
      "The Vulnerabilities page flags routers running firmware with known issues, or settings that leave a router exposed, so you can prioritise what to patch — and tie straight into **Upgrades** to fix it.",
    ] },
    { id: "compliance", title: "Compliance", body: [
      "Compliance checks your routers against a framework — CIS v8, NIST 800-171, PCI DSS 4.0, HIPAA — and shows pass / fail / manual per control, with a client-facing report. Where a finding is fine on a given router, accept it with a reason so it stops counting.",
    ] },
  ] },

  { group: "Maintenance", items: [
    { id: "backups", title: "Backups", body: [
      "TikManager backs up every adopted router on a schedule and keeps a history, so you can see what changed and restore a known-good config. Backups are encrypted at rest. Set the hour and how many versions to keep under Admin > System.",
    ] },
    { id: "upgrades", title: "Upgrades", body: [
      "**Upgrades** runs RouterOS / RouterBOARD upgrades — now or scheduled, one router or many.",
      { h: "Safe by design" },
      "A batch upgrade watches each router come back. The **safety stop** only counts a real failure — a router that changed but didn't come back — not one that was simply offline or whose backup failed first, so a flaky site doesn't halt the whole run. If the server restarts mid-run, in-flight jobs are re-checked and re-queued, and **Resume** runs held jobs straight away.",
    ] },
    { id: "tasks", title: "Tasks & scripts", body: [
      "Keep a library of RouterOS scripts and run them against one router or a group, now or on a schedule. **Tasks** is the record of those scheduled runs and firmware jobs, with the result from each router.",
    ] },
  ] },

  { group: "Clients & users", items: [
    { id: "clients", title: "Clients", body: [
      "A client (organisation) groups a customer's sites, devices, subnets and users. Most pages can be narrowed to one client with the top-bar **Customer** selector; the Clients page is where you manage the list itself.",
    ] },
    { id: "billing", title: "ConnectWise billing", body: [
      "If you connect ConnectWise, TikManager reconciles the MikroTiks it manages against your ConnectWise configurations and agreements — surfacing **managed-but-not-billed** gear — and can create or match a configuration in ConnectWise. It can also open, attach a backup to, and close a ticket for a firmware upgrade.",
    ] },
    { id: "users", title: "Users, roles & client access", body: [
      "**Users** (administrators) manages who can sign in.",
      { ul: [
        "**Technicians** get a **role**, and the role's permissions decide which pages they see and what they can change (Admin > Technicians).",
        "**Client users** sign in to a trimmed, read-only view of only their own organisation — optionally including their IPAM. Invite them by email; you can also allow client sign-in with Microsoft.",
        "**View as** lets an administrator see TikManager exactly as a chosen client user does (read-only), to check what they'll see before you hand it over.",
      ] },
    ] },
  ] },

  { group: "Administration", items: [
    { id: "admin", title: "The Admin area", body: [
      "**Admin** (sidebar → Admin → Settings, or the gear icon) is where you configure TikManager itself. It's split into tabs — **Branding**, **Technicians**, **Integrations**, **API access**, **Collectors** and **Settings** — and you only see the tabs your role's permissions allow, so a technician without administrator rights sees a subset (or none).",
      "**Every change made in Admin is written to the Audit log** (who, what, when and from where), so there's always a record.",
      "The sections below walk through each tab in turn.",
    ] },
    { id: "admin-branding", title: "Admin · Branding", body: [
      "Branding is what everyone sees, including clients on the sign-in page. It makes TikManager look like your own tool.",
      { h: "What you can set" },
      { ul: [
        "**Product name** and **Company name** — shown in the top bar and on sign-in.",
        "**Accent colour** — the theme colour across the app (a live preview updates as you pick).",
        "**Support email** and **Support phone** — shown to client users so they know how to reach you.",
        "**Message on the sign-in page** — a short note (maintenance window, a welcome line) shown under the sign-in box.",
      ] },
      { h: "Logo" },
      "Upload a **PNG, JPEG or WebP up to 512 KB**; wide logos (about 4:1) look best, as it sits next to the product name. You can replace or remove it any time. Save branding and the change is live immediately for everyone.",
    ] },
    { id: "admin-techs", title: "Admin · Technicians & roles", body: [
      "Technicians are your own staff. This tab lists them and controls what each can do.",
      { h: "How someone becomes a technician" },
      "Anyone who signs in with Microsoft from one of your **staff email domains** (set on the Settings tab) is created as a technician automatically. A brand-new account has **no role** and can't do anything until an administrator gives it one — it sits on a \"waiting for a role\" screen. Emails listed as **Administrator emails** (Settings tab) are always full administrators.",
      { h: "Roles & permissions" },
      "A **role** is a named set of permissions, and every technician has exactly one. Permissions gate each part of the app — for example devices, configuration changes, alerts, integrations, managing other technicians, and settings. Build the roles that match how your team works (for example a read-only \"Help Desk\" role, a \"Network\" role that can change configuration, and a full \"Admin\" role) and assign one to each person. Change a person's role here any time; it takes effect at their next page load.",
      "Because permissions decide which **sidebar items and Admin tabs** appear, a role is also how you keep juniors out of destructive actions while still letting them see what they need.",
    ] },
    { id: "admin-integrations", title: "Admin · Integrations", body: [
      "Integrations is the catalog of other systems TikManager pulls from or pushes to. Each system is a card with just the fields it needs — a URL, an API key, an account id — and a short note on where to get them.",
      { ul: [
        "Examples: **UniFi / UISP** (pull in their gear and networks), **ConnectWise** (billing reconciliation and tickets), **Cloudflare Radar** (ISP outage data), IP-geolocation, security tools and more.",
        "**Secrets are encrypted at rest** — on Windows with the machine's DPAPI, on Linux with a key file — and written to `data/secrets.dat`. They never appear in code, logs, the changelog or backups.",
        "**Blank means off.** A card you don't fill in simply leaves that feature disabled, and the rest of TikManager works without it. Fill a card in and its reports and features light up.",
      ] },
      "After entering a key, most cards have a **Test** button so you can confirm the connection before relying on it.",
    ] },
    { id: "admin-api", title: "Admin · API access", body: [
      "API access lets **other systems read from TikManager** over a small HTTP API (`/api/v1`) — for an RMM, a dashboard, or a billing / reporting tool.",
      { ul: [
        "Create a **bearer token**; it's shown **once** at creation, so copy it then. Store it in the other system as a secret.",
        "Each token has its own **scopes** (for example devices, clients, alerts, fleet health) — grant only what that integration needs.",
        "It is **read-only**: nothing in the API can change a router or a setting. Requests are **rate-limited**, and you can **revoke** a token any time, which immediately stops it working.",
      ] },
      "The README's \"Outbound API\" section lists the endpoints and example requests.",
    ] },
    { id: "admin-collectors", title: "Admin · Collectors", body: [
      "Collectors are the on-site network agents for clients with no MikroTik or UniFi (see the **Network collectors** chapter for the full picture).",
      "On this tab you **create one collector per client**. TikManager shows a **one-time enrol key** and a **copy-paste install command** to run from your RMM or a PowerShell prompt on any Windows box at that client. Afterwards you can set each collector's **scan ranges**, how often it runs, and whether to turn on **SNMP** (with a read-only community string, which is sent only to the agent and never shown back here), or disable it.",
    ] },
    { id: "admin-settings", title: "Admin · Settings (system)", body: [
      "The **Settings** tab holds the server-wide configuration. It's the longest tab; here's each card.",
      { h: "Version & updates" },
      "Shows the version you're running against the **newest release on GitHub**, and the changelog for anything newer. Administrators get a one-click **Upgrade now** (also offered as a banner across the app when an update is out). On Linux this pulls and restarts; on Windows it applies what's waiting in the update folder.",
      { h: "Staff sign-in (Microsoft / Entra ID)" },
      "Your technicians sign in with Microsoft. Set your **staff email domains** (anyone from these becomes a technician at first sign-in) and your **administrator emails** (always full admins). The **Entra ID** fields — Directory (tenant) ID, Application (client) ID and a client secret — come from an App registration in the Entra admin center; TikManager shows the exact **redirect URI** to paste into that registration.",
      { h: "Client (customer) Microsoft sign-in" },
      "**Off by default** — clients use a password and authenticator app. You can instead let client users sign in with Microsoft, either as **guests in your tenant** (B2B-invited, so your Conditional Access applies) or with **their own Microsoft** (needs a multi-tenant app registration). Either way you first invite the client user on the **Users** tab with the \"Microsoft sign-in\" option, which locks them to their email's domain. Your staff sign-in is unaffected.",
      { h: "Routers" },
      "The **WireGuard address routers connect to** is baked into the adoption command, so routers know how to reach this server; change it only if that differs from the web address (routers already adopted keep the address they were given). The **latency test target** is the address diagnostics pings for its speed/latency checks.",
      { h: "Backups" },
      "Set the **nightly backup time** (server clock) and how many **versions to keep per router** — a new version is saved only when the configuration actually changes, and the oldest is dropped past the limit. Stored configurations are **encrypted**. Optionally keep a **plain-text mirror** of each router's latest config in a folder you choose: handy to `git init` for a free change history, but note those copies are **unencrypted and contain passwords**, so protect that folder.",
      { h: "Off-site backup, replacement suggestions & about" },
      "**Off-site backup** copies your backups off the server. **Replacement suggestions** tunes the end-of-life guidance shown per router model. **About this installation** lists the public address, the controller's WireGuard key and network, the data folder, and how many routers and backups are stored.",
    ] },
    { id: "admin-audit", title: "Admin · Audit log", body: [
      "The **Audit log** (sidebar → Admin → Audit log) is the record of **every sign-in and every change**, newest first (the last 500). Each row shows when it happened, who did it, the action, what it affected, the address it came from, and a detail line. Nothing here can be edited — it's your accountability trail for who changed what.",
    ] },
  ] },

  { group: "Staying current", items: [
    { id: "messages", title: "Message Center (the bell)", body: [
      "The **bell** in the top bar is the Message Center: each new TikManager version's release notes (added automatically) and any notices your administrators post. A number on the bell is how many you haven't read. Acknowledge a message and it stops counting; it stays under **All**. Administrators can post a notice to technicians or to everyone.",
    ] },
    { id: "help", title: "This Help Center", body: [
      "You're in it. The **Manual** (this tab) explains the app page by page and ships with TikManager. The **Knowledge Base** is your team's own growing set of how-to articles — a client quirk, a workaround, a step list — that administrators add and edit right here. Reach both from the **?** menu in the top bar anywhere in the app, including IPAM.",
    ] },
  ] },
];

// =====================================================================================================
//  Rendering
// =====================================================================================================
function flatSections() { return MANUAL.flatMap((g) => g.items.map((it) => ({ ...it, group: g.group }))); }

function manualMatch(sec) {
  if (!query) return true;
  const hay = (sec.title + " " + sec.group + " " + sec.body.map((b) => typeof b === "string" ? b : (b.h || (b.ul || []).join(" "))).join(" ")).toLowerCase();
  return hay.includes(query);
}

function renderToc() {
  const toc = $("toc");
  if (tab !== "manual") { toc.innerHTML = ""; return; }
  toc.innerHTML = MANUAL.map((g) => {
    const items = g.items.filter(manualMatch);
    if (!items.length) return "";
    return `<div class="toc-group"><div class="toc-label">${esc(g.group)}</div>
      ${items.map((it) => `<button class="toc-item" type="button" data-goto="${it.id}">${esc(it.title)}</button>`).join("")}</div>`;
  }).join("") || `<p class="muted pad">No manual topics match “${esc(query)}”.</p>`;
}

function renderManual() {
  const secs = flatSections().filter(manualMatch);
  const main = $("main");
  main.innerHTML = `<p class="manual-intro">The TikManager manual, page by page. Use the contents on the left or search above.${me?.kind === "client" ? "" : ""}</p>`
    + (secs.length ? secs.map((s) => `<section class="manual-sec" id="sec-${s.id}">
        <div class="sec-group">${esc(s.group)}</div><h2>${esc(s.title)}</h2>${bodyHtml(s.body)}</section>`).join("")
      : `<p class="muted">Nothing in the manual matches “${esc(query)}”. Try the Knowledge Base tab.</p>`);
  if (query) highlight(main);
}

function kbCategories() {
  const cats = [...new Set(kb.articles.map((a) => a.category).filter(Boolean))].sort((a, b) => a.localeCompare(b));
  return cats;
}
function kbMatch(a) {
  if (kbCat && a.category !== kbCat) return false;
  if (!query) return true;
  const hay = (a.title + " " + a.category + " " + a.blocks.map((b) => b.text).join(" ")).toLowerCase();
  return hay.includes(query);
}
function kbDay(ts) { return new Date((ts || 0) * 1000).toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" }); }

function renderKb() {
  $("toc").innerHTML = "";
  const main = $("main");
  const cats = kbCategories();
  const arts = kb.articles.filter(kbMatch);
  main.innerHTML = `<div class="kb-head"><h2>Knowledge Base</h2><span class="spacer"></span>
      ${kb.can_edit ? `<button class="btn primary" type="button" id="kbNew">New article</button>` : ""}</div>
    ${cats.length ? `<div class="kb-cats"><button class="kb-cat ${kbCat ? "" : "active"}" type="button" data-cat="">All</button>
      ${cats.map((c) => `<button class="kb-cat ${kbCat === c ? "active" : ""}" type="button" data-cat="${esc(c)}">${esc(c)}</button>`).join("")}</div>` : ""}
    ${arts.length ? `<div class="kb-list">${arts.map(kbCard).join("")}</div>`
      : `<div class="kb-empty card"><p class="muted">${kb.articles.length
          ? `No articles match ${query ? `“${esc(query)}”` : "this category"}.`
          : "No articles yet." + (kb.can_edit ? " Add the first one with <b>New article</b> — a client quirk, a workaround, a step list the Manual doesn't cover." : " Your administrators will add how-to articles here.")}</p></div>`}`;
  if (query) highlight(main);
}
function kbCard(a) {
  return `<div class="kb-art" data-art="${a.id}">
    <button class="kb-art-head" type="button" data-arttoggle="${a.id}">
      ${a.pinned ? `<span class="kb-pin" title="Pinned" aria-hidden="true">★</span>` : ""}
      <span class="kb-t">${esc(a.title)}</span>
      ${a.category ? `<span class="kb-pill">${esc(a.category)}</span>` : ""}
      <span class="kb-chev" aria-hidden="true">›</span></button>
    <div class="kb-art-body" hidden>
      ${blocksHtml(a.blocks) || `<p class="muted">No details.</p>`}
      <div class="kb-meta"><span>By ${esc(a.created_by || "TikManager")} · updated ${kbDay(a.updated_at || a.ts)}</span><span class="spacer"></span>
        ${kb.can_edit ? `<button class="linkish small" type="button" data-artedit="${a.id}">Edit</button>
          <button class="linkish small" type="button" data-artdel="${a.id}">Delete</button>` : ""}</div>
    </div></div>`;
}

function highlight(root) {
  const rx = new RegExp("(" + query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")", "gi");
  const walk = (node) => {
    for (const child of [...node.childNodes]) {
      if (child.nodeType === 3) {
        if (rx.test(child.nodeValue)) {
          const span = document.createElement("span");
          span.innerHTML = esc(child.nodeValue).replace(rx, "<mark>$1</mark>");
          child.replaceWith(span);
        }
      } else if (child.nodeType === 1 && !["A", "CODE", "MARK", "BUTTON"].includes(child.tagName)) {
        walk(child);
      }
    }
  };
  walk(root);
}

function render() {
  document.querySelectorAll("#tabs .tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  renderToc();
  if (tab === "manual") renderManual(); else renderKb();
}

// --- KB editing (administrators) -----------------------------------------------------------------------------
function kbDialog(a) {
  $("dlgTitle").textContent = a ? "Edit article" : "New article";
  $("dlgBody").innerHTML = `
    <label class="kb-dlg-field"><span>Title</span><input id="fTitle" maxlength="150" value="${esc(a?.title || "")}"></label>
    <label class="kb-dlg-field"><span>Category <span class="muted">(optional — groups articles)</span></span>
      <input id="fCat" maxlength="60" list="catList" value="${esc(a?.category || "")}" placeholder="e.g. ConnectWise, Onboarding">
      <datalist id="catList">${kbCategories().map((c) => `<option value="${esc(c)}">`).join("")}</datalist></label>
    <label class="kb-dlg-field"><span>Article</span>
      <textarea id="fBody" rows="12" placeholder="Plain text. Lines starting with '- ' become bullets; **bold**, \`code\` and [links](/page) work.">${esc(a?.body || "")}</textarea></label>
    <label class="chk"><input type="checkbox" id="fPin" ${a?.pinned ? "checked" : ""}> Pin to the top</label>`;
  $("dlgMsg").classList.add("hidden");
  dlgSave = async () => {
    const payload = { title: $("fTitle").value, category: $("fCat").value, body: $("fBody").value, pinned: $("fPin").checked };
    const r = a ? await post(`/api/kb/${a.id}`, payload) : await post("/api/kb", payload);
    await loadKb();
    render();
    // re-open the saved article
    const card = document.querySelector(`.kb-art[data-art="${r.article.id}"]`);
    if (card) { card.classList.add("open"); card.querySelector(".kb-art-body").hidden = false; card.scrollIntoView({ block: "center" }); }
  };
  $("dlg").showModal();
}
let dlgSave = null;

async function loadKb() { kb = await api("/api/kb"); }

// --- wiring --------------------------------------------------------------------------------------------------
function setTab(t) {
  tab = t;
  history.replaceState(null, "", "#" + t);
  render();
  if (t === "kb" && !kb.loaded) loadKb().then(() => { kb.loaded = true; render(); }).catch(() => {});
}

async function init() {
  try { me = await api("/api/me"); } catch { return; }
  const body = document.querySelector(".help-body");
  $("tabs").addEventListener("click", (e) => { const b = e.target.closest("[data-tab]"); if (b) { kbCat = ""; setTab(b.dataset.tab); } });
  $("sideToggle").addEventListener("click", () => body.classList.toggle("side-open"));
  $("sideBackdrop").addEventListener("click", () => body.classList.remove("side-open"));

  let timer;
  $("search").addEventListener("input", (e) => {
    clearTimeout(timer); const v = e.target.value.trim().toLowerCase();
    timer = setTimeout(() => { query = v; render(); }, 180);
  });

  $("toc").addEventListener("click", (e) => {
    const b = e.target.closest("[data-goto]"); if (!b) return;
    const sec = $("sec-" + b.dataset.goto);
    if (sec) sec.scrollIntoView({ behavior: "smooth", block: "start" });
    document.querySelectorAll(".toc-item").forEach((i) => i.classList.toggle("active", i === b));
    body.classList.remove("side-open");
  });

  $("main").addEventListener("click", async (e) => {
    const t = e.target.closest("[data-arttoggle], [data-artedit], [data-artdel], [data-cat], #kbNew");
    if (!t) return;
    if (t.id === "kbNew") return kbDialog(null);
    if (t.dataset.cat !== undefined) { kbCat = t.dataset.cat; return render(); }
    const id = +(t.dataset.arttoggle || t.dataset.artedit || t.dataset.artdel);
    const art = kb.articles.find((a) => a.id === id);
    if (t.dataset.arttoggle) {
      const card = t.closest(".kb-art"); const open = card.classList.toggle("open");
      card.querySelector(".kb-art-body").hidden = !open;
    } else if (t.dataset.artedit) {
      kbDialog(art);
    } else if (t.dataset.artdel) {
      if (confirm(`Delete “${art.title}”? This can't be undone.`)) { await post(`/api/kb/${id}/delete`); await loadKb(); render(); }
    }
  });

  $("dlgForm").addEventListener("submit", async (e) => {
    if (e.submitter && e.submitter.value === "save" && dlgSave) {
      e.preventDefault();
      try { await dlgSave(); $("dlg").close(); }
      catch (err) { const m = $("dlgMsg"); m.textContent = err.message; m.classList.remove("hidden"); }
    }
  });

  // open on the tab from the hash (#manual / #kb)
  const h = location.hash.slice(1);
  tab = h === "kb" ? "kb" : "manual";
  render();
  if (tab === "kb") { await loadKb(); kb.loaded = true; render(); }
}

init().catch(() => {});
