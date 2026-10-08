"use strict";
// Sign-in: Microsoft for the MSP's own staff; email + password + authenticator code for client users. Also drives the invite page.
const $ = (id) => document.getElementById(id);
let ticket = null;

function status(text, kind) { $("status").textContent = text; $("status").className = `status ${kind || ""}`; }
function show(step) { for (const s of ["stepStart", "stepVerify", "stepEnroll", "stepPassword"]) if ($(s)) $(s).classList.toggle("hidden", s !== step); }

async function post(path, data) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || r.statusText);
  return body;
}

async function afterPassword(res) {
  ticket = res.ticket;
  if (res.mfa === "verify") { show("stepVerify"); $("code").focus(); return; }
  const e = await post("/api/login/mfa", { ticket, want_secret: true });
  $("secret").textContent = e.secret.replace(/(.{4})/g, "$1 ").trim();
  $("uri").href = e.uri;
  show("stepEnroll");
  $("enrollCode").focus();
}

async function finish(code) {
  await post("/api/login/mfa", { ticket, code });
  location.href = "/";
}

function bind(form, fn) {
  if (!$(form)) return;
  $(form).addEventListener("submit", async (ev) => {
    ev.preventDefault();
    status("");
    const btn = $(form).querySelector("button[type=submit]");
    btn.disabled = true;
    try { await fn(); } catch (err) { status(err.message, "err"); } finally { btn.disabled = false; }
  });
}

bind("pwForm", async () => afterPassword(await post("/api/login", { email: $("email").value, password: $("password").value })));
bind("codeForm", async () => finish($("code").value));
bind("enrollForm", async () => finish($("enrollCode").value));

// invite page: set a password, then set up MFA
const inviteToken = location.pathname.startsWith("/invite/") ? location.pathname.split("/")[2] : null;
if (inviteToken) {
  fetch(`/api/invite?token=${encodeURIComponent(inviteToken)}`).then((r) => r.json().then((b) => ({ r, b }))).then(({ r, b }) => {
    if (!r.ok) { status(b.error, "err"); $("stepPassword").classList.add("hidden"); return; }
    $("inviteEmail").textContent = b.email;
    $("name").value = b.name || "";
  });
  bind("setForm", async () => {
    if ($("newPassword").value !== $("newPassword2").value) throw new Error("The two passwords don't match.");
    afterPassword(await post("/api/invite", { token: inviteToken, name: $("name").value, password: $("newPassword").value }));
  });
} else {
  fetch("/api/login/options").then((r) => r.json()).then((o) => {
    $("ms").classList.toggle("hidden", !o.entra);
    $("dev").classList.toggle("hidden", !o.dev);
    $("or").textContent = o.entra || o.dev ? "Clients: sign in with your email" : "Sign in with your email";
  });
  $("ms").addEventListener("click", () => { location.href = "/auth/login"; });
  $("dev").addEventListener("click", async () => { try { await post("/api/login/dev", {}); location.href = "/"; } catch (e) { status(e.message, "err"); } });
}
