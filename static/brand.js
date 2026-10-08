"use strict";
// Applies Admin > Branding to any page: accent colour, logo (default: the TikManager wordmark) and product name, page title, sign-in message, support contact.
(function () {
  function hexToRgb(h) { const n = parseInt(h.slice(1), 16); return [(n >> 16) & 255, (n >> 8) & 255, n & 255]; }
  window.applyBrand = function (b) {
    if (!b) return;
    const root = document.documentElement.style;
    if (/^#[0-9a-f]{6}$/i.test(b.accent || "")) {
      const [r, g, bl] = hexToRgb(b.accent);
      root.setProperty("--accent", b.accent);
      root.setProperty("--accent-soft", `rgba(${r}, ${g}, ${bl}, 0.12)`);
    }
    document.querySelectorAll(".brand").forEach((el) => {
      el.textContent = "";
      const img = document.createElement("img");
      img.className = "brand-logo";
      if (!b.logo_url && b.product === "TikManager") {   // built-in logo: the name itself, with the T drawn as a tiki torch
        img.src = "/wordmark.svg"; img.alt = b.product; img.classList.add("brand-wordmark");
        el.appendChild(img);
        return;
      }
      img.src = b.logo_url || "/logo.svg"; img.alt = "";   // uploaded logo, or the torch next to a renamed product
      el.appendChild(img);
      const name = document.createElement("span");
      name.textContent = b.product;
      el.appendChild(name);
    });
    const page = document.title.includes("·") ? document.title.split("·")[0].trim() : "";
    document.title = page && page !== "TikManager" ? `${page} · ${b.product}` : b.product;
    const ms = document.getElementById("ms");
    if (ms) ms.textContent = `Sign in with Microsoft (${b.company ? `${b.company} staff` : "staff"})`;
    const msg = document.getElementById("loginMessage");
    if (msg) { msg.textContent = b.login_message || ""; msg.classList.toggle("hidden", !b.login_message); }
    const sup = document.getElementById("support");
    if (sup) {
      const parts = [b.support_email, b.support_phone].filter(Boolean);
      sup.textContent = parts.length ? `Need help? ${b.company ? `${b.company}: ` : ""}${parts.join(" · ")}` : "";
    }
  };
  fetch("/api/branding").then((r) => r.json()).then((b) => { window.BRAND = b; window.applyBrand(b); }).catch(() => {});
})();
