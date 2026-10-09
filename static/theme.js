"use strict";
// Appearance: colour theme + light/dark mode, chosen per person (the palette button in the top bar). Loaded in <head>
// so the page draws in the right colours from the start: this browser's last choice is applied straight away, and the
// signed-in person's saved choice (from /api/me, kept on the server so it follows them to any device) replaces it.
(function () {
  const THEMES = ["company", "navy", "slate", "ocean", "forest", "plum", "tiki"];
  const MODES = ["system", "light", "dark"];
  const apply = (p) => {
    const root = document.documentElement;
    root.dataset.theme = THEMES.includes(p && p.theme) ? p.theme : "company";
    root.dataset.mode = MODES.includes(p && p.mode) ? p.mode : "system";
  };
  let saved = null;
  try { saved = JSON.parse(localStorage.getItem("tm-appearance") || "null"); } catch (e) { saved = null; }
  apply(saved);
  window.TM_THEMES = THEMES;
  window.TM_MODES = MODES;
  // set (and remember in this browser) an appearance; the caller saves it to the server
  window.setAppearance = function (p) {
    apply(p);
    try { localStorage.setItem("tm-appearance", JSON.stringify({ theme: document.documentElement.dataset.theme, mode: document.documentElement.dataset.mode })); } catch (e) { /* private window */ }
  };
})();
