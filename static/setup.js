"use strict";
// First-run setup: create the first administrator (the authenticator app is set up at their first sign-in).
(function () {
  const $ = (id) => document.getElementById(id);
  const token = location.pathname.split("/").pop();
  const say = (m, ok) => { $("status").textContent = m; $("status").className = `status ${ok ? "ok" : "err"}`; };
  $("email").addEventListener("change", () => {
    if (!$("domains").value && $("email").value.includes("@")) $("domains").placeholder = $("email").value.split("@").pop();
  });
  $("setupForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    if ($("password").value !== $("password2").value) return say("The passwords don't match.");
    say("Creating…", true);
    try {
      const r = await fetch("/api/setup", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, company: $("company").value, name: $("name").value, email: $("email").value,
                               password: $("password").value, domains: $("domains").value }) });
      const body = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(body.error || r.statusText);
      say("Done - sign in now; you'll set up your authenticator app on the way in.", true);
      setTimeout(() => { location.href = "/login"; }, 1800);
    } catch (err) { say(err.message); }
  });
})();
