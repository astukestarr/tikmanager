"use strict";
// TikManager's own geographic map: drawn on a <canvas> from the built-in data in /map/*.json (tools/build_map.py) -
// no map tiles or scripts from other sites. Pan by dragging, zoom with the wheel / pinch / buttons. From the whole
// country down to towns: state borders always, county lines, interstates and town names appear as you zoom in.
//   const map = new GeoMap(containerEl, { pins, onSelect(pin), onPick(lat, lon) });
//   map.setPins([...{id, name, lat, lon, online, sub}]); map.fit(); map.setPick(lat, lon)
(function () {
  const K = Math.cos(38.5 * Math.PI / 180);   // longitude squeeze so the US isn't stretched (fine down to street level)
  const Q = 1000;
  let BASE = null, DETAIL = null, loading = null;

  function decode(flat, closed) {   // [x0, y0, dx, dy, ...] (1/1000 degree) -> projected Float32Array + bounding box
    const n = flat.length / 2, out = new Float32Array(flat.length);
    let x = 0, y = 0, minx = Infinity, miny = Infinity, maxx = -Infinity, maxy = -Infinity;
    for (let i = 0; i < n; i++) {
      x += flat[2 * i]; y += flat[2 * i + 1];
      const px = (x / Q) * K, py = -y / Q;
      out[2 * i] = px; out[2 * i + 1] = py;
      if (px < minx) minx = px; if (px > maxx) maxx = px; if (py < miny) miny = py; if (py > maxy) maxy = py;
    }
    return { p: out, b: [minx, miny, maxx, maxy], closed };
  }

  function loadData() {
    if (loading) return loading;
    const get = (u) => fetch(u, { credentials: "same-origin" }).then((r) => { if (!r.ok) throw new Error(`Map data missing (${u})`); return r.json(); });
    loading = get("/map/base.json").then((b) => {
      BASE = {
        countries: b.countries.map((r) => decode(r, true)),
        states: b.states.map((s) => {
          const shapes = s.s.map((r) => decode(r, true));
          const big = shapes.reduce((a, c) => ((c.b[2] - c.b[0]) * (c.b[3] - c.b[1]) > (a.b[2] - a.b[0]) * (a.b[3] - a.b[1]) ? c : a));
          return { n: s.n, c: s.c, us: s.us, shapes, label: [(big.b[0] + big.b[2]) / 2, (big.b[1] + big.b[3]) / 2] };
        }),
      };
      // detail (counties, roads, towns) is bigger: load it after the base is on screen
      return get("/map/detail.json").then((d) => {
        DETAIL = {
          counties: d.counties.flatMap((c) => c.s.map((r) => decode(r, true))),
          roads: d.roads.map((r) => decode(r, false)),
          places: d.places.map(([n, st, x, y, t]) => ({ n, st, x: (x / Q) * K, y: -y / Q, t })),
        };
      });
    });
    return loading;
  }

  // town tiers (0 = biggest) appear from these zoom levels (pixels per degree)
  const TIER_SCALE = [0, 10, 24, 60, 130, 260];
  const css = (el, name) => getComputedStyle(el).getPropertyValue(name).trim() || "#888";

  class GeoMap {
    constructor(el, opts = {}) {
      this.el = el;
      this.opts = opts;
      this.pins = opts.pins || [];
      this.pick = null;
      el.classList.add("geomap");
      el.innerHTML = `<canvas></canvas>
        <div class="gm-ctl"><button type="button" data-z="in" aria-label="Zoom in">+</button><button type="button" data-z="out" aria-label="Zoom out">−</button>
          <button type="button" data-z="fit" aria-label="Show all routers" title="Show all routers">⤢</button></div>
        <div class="gm-tip hidden"></div><div class="gm-list hidden"></div><div class="gm-msg small muted">Loading map…</div>`;
      this.cv = el.querySelector("canvas");
      this.tip = el.querySelector(".gm-tip");
      this.list = el.querySelector(".gm-list");
      // start on the lower 48
      this.cx = -96.5 * K; this.cy = -38.5; this.s = 13;
      this.bind();
      new ResizeObserver(() => this.resize()).observe(el);
      this.resize();
      loadData().then(() => { el.querySelector(".gm-msg").remove(); if (opts.fitOnLoad !== false) this.fit(); else this.draw(); })
        .catch((e) => { el.querySelector(".gm-msg").textContent = e.message; });
      // redraw once the town/county detail arrives
      const wait = setInterval(() => { if (DETAIL) { clearInterval(wait); this.draw(); } }, 300);
      this.themeObs = new MutationObserver(() => this.draw());
      this.themeObs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme", "data-mode"] });
    }

    // --- view ---------------------------------------------------------------------------------------------
    resize() {
      const r = this.el.getBoundingClientRect(), dpr = window.devicePixelRatio || 1;
      this.w = Math.max(200, r.width); this.h = Math.max(200, r.height);
      this.cv.width = this.w * dpr; this.cv.height = this.h * dpr;
      this.cv.style.width = `${this.w}px`; this.cv.style.height = `${this.h}px`;
      this.dpr = dpr;
      this.draw();
    }
    toScreen(px, py) { return [(px - this.cx) * this.s + this.w / 2, (py - this.cy) * this.s + this.h / 2]; }
    toMap(sx, sy) { return [(sx - this.w / 2) / this.s + this.cx, (sy - this.h / 2) / this.s + this.cy]; }
    project(lat, lon) { return [lon * K, -lat]; }
    zoomAt(f, sx = this.w / 2, sy = this.h / 2) {
      const [mx, my] = this.toMap(sx, sy);
      this.s = Math.min(6000, Math.max(3, this.s * f));
      this.cx = mx - (sx - this.w / 2) / this.s; this.cy = my - (sy - this.h / 2) / this.s;
      this.draw();
    }
    fitBox(minx, miny, maxx, maxy, maxScale = 900) {
      const pad = 60;
      this.s = Math.min(maxScale, Math.max(3, Math.min((this.w - pad) / Math.max(maxx - minx, 0.001), (this.h - pad) / Math.max(maxy - miny, 0.001))));
      this.cx = (minx + maxx) / 2; this.cy = (miny + maxy) / 2;
      this.draw();
    }
    fit() {   // all routers with a location, else the lower 48
      const pts = this.pins.filter((p) => p.lat != null).map((p) => this.project(p.lat, p.lon));
      if (this.pick) pts.push(this.project(this.pick[0], this.pick[1]));
      if (!pts.length) { this.cx = -96.5 * K; this.cy = -38.5; this.s = Math.min(this.w / (58 * K), this.h / 27); return this.draw(); }
      const xs = pts.map((p) => p[0]), ys = pts.map((p) => p[1]);
      this.fitBox(Math.min(...xs) - 0.05, Math.min(...ys) - 0.05, Math.max(...xs) + 0.05, Math.max(...ys) + 0.05, pts.length === 1 ? 400 : 900);
    }
    setPins(pins) { this.pins = pins; this.draw(); }
    setPick(lat, lon) { this.pick = lat == null ? null : [lat, lon]; this.draw(); }

    // --- input: drag to pan, wheel / pinch / double-click to zoom, click a pin or (pick mode) a spot --------------
    bind() {
      const ptrs = new Map();
      let start = null, moved = false, pinch = null;
      this.cv.addEventListener("wheel", (e) => { e.preventDefault(); const r = this.cv.getBoundingClientRect(); this.zoomAt(e.deltaY < 0 ? 1.25 : 0.8, e.clientX - r.left, e.clientY - r.top); }, { passive: false });
      this.cv.addEventListener("pointerdown", (e) => {
        this.cv.setPointerCapture(e.pointerId);
        ptrs.set(e.pointerId, [e.clientX, e.clientY]);
        start = { x: e.clientX, y: e.clientY, cx: this.cx, cy: this.cy }; moved = false;
        if (ptrs.size === 2) { const [a, b] = [...ptrs.values()]; pinch = { d: Math.hypot(a[0] - b[0], a[1] - b[1]), s: this.s }; }
      });
      this.cv.addEventListener("pointermove", (e) => {
        const r = this.cv.getBoundingClientRect();
        if (!ptrs.has(e.pointerId)) return this.hover(e.clientX - r.left, e.clientY - r.top);
        ptrs.set(e.pointerId, [e.clientX, e.clientY]);
        if (pinch && ptrs.size === 2) {
          const [a, b] = [...ptrs.values()];
          const f = (Math.hypot(a[0] - b[0], a[1] - b[1]) / pinch.d) * pinch.s / this.s;
          this.zoomAt(f, (a[0] + b[0]) / 2 - r.left, (a[1] + b[1]) / 2 - r.top);
          moved = true;
          return;
        }
        const dx = e.clientX - start.x, dy = e.clientY - start.y;
        if (Math.abs(dx) + Math.abs(dy) > 4) moved = true;
        this.cx = start.cx - dx / this.s; this.cy = start.cy - dy / this.s;
        this.draw();
      });
      const up = (e) => {
        ptrs.delete(e.pointerId);
        if (ptrs.size < 2) pinch = null;
        if (!moved && ptrs.size === 0) { const r = this.cv.getBoundingClientRect(); this.click(e.clientX - r.left, e.clientY - r.top); }
        if (ptrs.size === 0) start = null;
      };
      this.cv.addEventListener("pointerup", up);
      this.cv.addEventListener("pointercancel", (e) => { ptrs.delete(e.pointerId); pinch = null; });
      this.cv.addEventListener("pointerleave", () => this.tip.classList.add("hidden"));
      this.cv.addEventListener("dblclick", (e) => { const r = this.cv.getBoundingClientRect(); this.zoomAt(2, e.clientX - r.left, e.clientY - r.top); });
      this.el.querySelector(".gm-ctl").addEventListener("click", (e) => {
        const z = e.target.closest("[data-z]")?.dataset.z;
        if (z === "in") this.zoomAt(1.6); else if (z === "out") this.zoomAt(1 / 1.6); else if (z === "fit") this.fit();
      });
    }
    hit(sx, sy) { return (this.clusters || []).find((c) => Math.hypot(c.x - sx, c.y - sy) <= c.r + 3); }
    hover(sx, sy) {
      const c = this.hit(sx, sy);
      this.cv.classList.toggle("gm-pointer", Boolean(c) || Boolean(this.opts.onPick));
      if (!c) return this.tip.classList.add("hidden");
      this.tip.textContent = c.pins.length === 1 ? `${c.pins[0].name}${c.pins[0].sub ? ` · ${c.pins[0].sub}` : ""}${c.pins[0].online ? "" : " · offline"}`
        : `${c.pins.length} routers${c.off ? ` · ${c.off} offline` : ""} - click to ${this.stacked(c) ? "list them" : "zoom in"}`;
      this.tip.classList.remove("hidden");
      this.tip.style.left = `${Math.min(sx + 14, this.w - 220)}px`; this.tip.style.top = `${sy + 14}px`;
    }
    // routers so close together (or set to the same spot) that zooming in can't separate them
    stacked(c) {
      const pts = c.pins.map((p) => this.project(p.lat, p.lon)), xs = pts.map((p) => p[0]), ys = pts.map((p) => p[1]);
      return this.s >= 2900 || Math.max(Math.max(...xs) - Math.min(...xs), Math.max(...ys) - Math.min(...ys)) < 0.0003;
    }
    showList(c, sx, sy) {
      const e = (s) => String(s ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
      const same = c.pins.every((p) => p.lat === c.pins[0].lat && p.lon === c.pins[0].lon);
      this.list.innerHTML = `<div class="gm-list-head"><b>${c.pins.length} routers ${same ? "at exactly the same spot" : "very close together"}</b>
          <button type="button" class="gm-list-x" aria-label="Close">×</button></div>
        ${same ? `<div class="small muted">If one of them is in the wrong place, open it and use Set location.</div>` : ""}
        ${c.pins.map((p, i) => `<button type="button" class="gm-list-item" data-i="${i}"><span class="dot ${p.online ? "on" : "off"}"></span>
          <span><b>${e(p.name)}</b>${p.sub ? `<small>${e(p.sub)}</small>` : ""}</span></button>`).join("")}`;
      this.list.classList.remove("hidden");
      this.list.style.left = `${Math.max(8, Math.min(sx + 12, this.w - 290))}px`;
      this.list.style.top = `${Math.max(8, Math.min(sy - 20, this.h - Math.min(this.h - 16, 60 + c.pins.length * 44)))}px`;
      this.list.querySelector(".gm-list-x").addEventListener("click", () => this.list.classList.add("hidden"));
      this.list.querySelectorAll("[data-i]").forEach((b) => b.addEventListener("click", () => {
        this.list.classList.add("hidden");
        if (this.opts.onSelect) this.opts.onSelect(c.pins[Number(b.dataset.i)]);
      }));
    }
    click(sx, sy) {
      const c = this.hit(sx, sy);
      this.list.classList.add("hidden");
      if (c && c.pins.length > 1 && this.stacked(c)) return this.showList(c, sx, sy);
      if (c && c.pins.length > 1) {   // a cluster: zoom to its routers
        const pts = c.pins.map((p) => this.project(p.lat, p.lon)), xs = pts.map((p) => p[0]), ys = pts.map((p) => p[1]);
        return this.fitBox(Math.min(...xs) - 0.02, Math.min(...ys) - 0.02, Math.max(...xs) + 0.02, Math.max(...ys) + 0.02, 3000);
      }
      if (c && this.opts.onSelect) return this.opts.onSelect(c.pins[0]);
      if (this.opts.onPick) {
        const [mx, my] = this.toMap(sx, sy);
        const lat = -my, lon = mx / K;
        this.setPick(lat, lon);
        this.opts.onPick(Number(lat.toFixed(6)), Number(lon.toFixed(6)));
      }
    }

    // --- drawing --------------------------------------------------------------------------------------------
    path(ctx, shape) {
      const p = shape.p;
      const [sx, sy] = this.toScreen(p[0], p[1]);
      ctx.moveTo(sx, sy);
      for (let i = 2; i < p.length; i += 2) ctx.lineTo((p[i] - this.cx) * this.s + this.w / 2, (p[i + 1] - this.cy) * this.s + this.h / 2);
      if (shape.closed) ctx.closePath();
    }
    visible(b) {
      const [x0, y0] = this.toMap(0, 0), [x1, y1] = this.toMap(this.w, this.h);
      return b[2] >= x0 && b[0] <= x1 && b[3] >= y0 && b[1] <= y1;
    }
    draw() {
      if (this._raf) return;
      this._raf = requestAnimationFrame(() => { this._raf = null; this.render(); });
    }
    render() {
      const ctx = this.cv.getContext("2d"), root = document.documentElement;
      const col = { water: css(root, "--bg"), land: css(root, "--panel"), line: css(root, "--border"), text: css(root, "--text"),
                    muted: css(root, "--muted"), accent: css(root, "--accent"), good: css(root, "--good"), bad: css(root, "--bad"),
                    road: css(root, "--warn") };
      ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      ctx.fillStyle = col.water; ctx.fillRect(0, 0, this.w, this.h);
      if (!BASE) return;
      ctx.lineJoin = "round";
      // land: countries, then US states a touch brighter
      ctx.fillStyle = col.land; ctx.strokeStyle = col.line; ctx.lineWidth = 1;
      ctx.beginPath();
      for (const c of BASE.countries) if (this.visible(c.b)) this.path(ctx, c);
      ctx.fill(); ctx.stroke();
      // counties
      if (DETAIL && this.s >= 45) {
        ctx.beginPath();
        for (const c of DETAIL.counties) if (this.visible(c.b)) this.path(ctx, c);
        ctx.strokeStyle = col.line; ctx.globalAlpha = Math.min(1, (this.s - 45) / 60) * 0.9; ctx.lineWidth = 0.7; ctx.stroke(); ctx.globalAlpha = 1;
      }
      // roads (interstates and major highways)
      if (DETAIL && this.s >= 18) {
        ctx.beginPath();
        for (const r of DETAIL.roads) if (this.visible(r.b)) this.path(ctx, r);
        ctx.strokeStyle = col.road; ctx.globalAlpha = 0.45; ctx.lineWidth = this.s > 200 ? 2.2 : this.s > 60 ? 1.5 : 0.9; ctx.stroke(); ctx.globalAlpha = 1;
      }
      // state / province borders
      ctx.beginPath();
      for (const st of BASE.states) for (const sh of st.shapes) if (this.visible(sh.b)) this.path(ctx, sh);
      ctx.strokeStyle = col.muted; ctx.globalAlpha = 0.55; ctx.lineWidth = this.s > 60 ? 1.6 : 1.1; ctx.stroke(); ctx.globalAlpha = 1;

      const taken = [];   // label boxes, so labels don't pile up
      const free = (x, y, w, h) => { if (taken.some((t) => x < t[2] && x + w > t[0] && y < t[3] && y + h > t[1])) return false; taken.push([x, y, x + w, y + h]); return true; };
      // routers: grouped into numbered clusters when they'd overlap
      const R = 9, cell = 38, groups = new Map();
      for (const p of this.pins) {
        if (p.lat == null) continue;
        const [px, py] = this.project(p.lat, p.lon), [x, y] = this.toScreen(px, py);
        if (x < -30 || x > this.w + 30 || y < -30 || y > this.h + 30) continue;
        const k = `${Math.floor(x / cell)}:${Math.floor(y / cell)}`;
        if (!groups.has(k)) groups.set(k, { x: 0, y: 0, pins: [] });
        const g = groups.get(k); g.pins.push(p); g.x += x; g.y += y;
      }
      this.clusters = [...groups.values()].map((g) => ({ x: g.x / g.pins.length, y: g.y / g.pins.length, pins: g.pins, off: g.pins.filter((p) => !p.online).length,
                                                         r: g.pins.length > 1 ? R + Math.min(8, Math.log2(g.pins.length) * 3) : R }));
      ctx.font = "600 12px system-ui, sans-serif";
      for (const c of this.clusters) {
        // reserved outright (not via free(), which refuses boxes that touch - a pin's label touches its own pin)
        taken.push([c.x - c.r - 3, c.y - c.r - 3, c.x + c.r + 3, c.y + c.r + 3]);
        if (c.pins.length === 1 && this.s > 150) taken.push([c.x + c.r + 2, c.y - 10, c.x + c.r + 14 + ctx.measureText(c.pins[0].name).width, c.y + 10]);
      }
      ctx.textBaseline = "middle";
      // state names (codes when zoomed out)
      if (this.s < 90) {
        ctx.font = `600 ${this.s > 30 ? 13 : 11}px system-ui, "Segoe UI", sans-serif`;
        ctx.fillStyle = col.muted; ctx.textAlign = "center";
        for (const st of BASE.states) {
          if (!st.us && this.s < 25) continue;
          const [x, y] = this.toScreen(st.label[0], st.label[1]);
          if (x < -50 || x > this.w + 50 || y < -20 || y > this.h + 20) continue;
          const t = this.s > 30 ? st.n : st.c, w = ctx.measureText(t).width;
          if (free(x - w / 2, y - 8, w, 16)) ctx.fillText(t, x, y);
        }
      }
      // towns and cities
      if (DETAIL) {
        let shown = 0;
        ctx.textAlign = "left";
        for (const pl of DETAIL.places) {
          if (this.s < TIER_SCALE[pl.t]) continue;
          const [x, y] = this.toScreen(pl.x, pl.y);
          if (x < -10 || x > this.w + 10 || y < -10 || y > this.h + 10) continue;
          const big = pl.t <= 1 || (pl.t === 2 && this.s > 60);
          ctx.font = `${big ? "600 13px" : "12px"} system-ui, "Segoe UI", sans-serif`;
          const w = ctx.measureText(pl.n).width;
          if (!free(x - 3, y - 8, w + 10, 16)) continue;
          ctx.fillStyle = col.muted; ctx.beginPath(); ctx.arc(x, y, big ? 3 : 2.2, 0, 7); ctx.fill();
          ctx.fillStyle = col.text; ctx.fillText(pl.n, x + 6, y);
          if (++shown > 400) break;
        }
      }
      for (const c of this.clusters) {
        ctx.beginPath(); ctx.arc(c.x, c.y, c.r + 3, 0, 7); ctx.fillStyle = "rgba(0,0,0,.18)"; ctx.fill();
        ctx.beginPath(); ctx.arc(c.x, c.y, c.r, 0, 7);
        ctx.fillStyle = c.off ? col.bad : col.good; ctx.fill();
        ctx.lineWidth = 2.5; ctx.strokeStyle = "#fff"; ctx.stroke();
        if (c.pins.length > 1) {
          ctx.fillStyle = "#fff"; ctx.font = "700 12px system-ui, sans-serif"; ctx.textAlign = "center"; ctx.fillText(String(c.pins.length), c.x, c.y + 0.5);
        } else if (this.s > 150) {
          ctx.font = "600 12px system-ui, sans-serif"; ctx.textAlign = "left";
          const t = c.pins[0].name, w = ctx.measureText(t).width;
          ctx.fillStyle = col.land; ctx.globalAlpha = 0.9; ctx.fillRect(c.x + c.r + 4, c.y - 9, w + 8, 18); ctx.globalAlpha = 1;
          ctx.fillStyle = col.text; ctx.fillText(t, c.x + c.r + 8, c.y);
        }
      }
      // the spot being picked
      if (this.pick) {
        const [px, py] = this.project(this.pick[0], this.pick[1]), [x, y] = this.toScreen(px, py);
        ctx.beginPath(); ctx.moveTo(x, y); ctx.arc(x, y - 22, 9, Math.PI * 0.75, Math.PI * 2.25); ctx.closePath();
        ctx.fillStyle = col.accent; ctx.fill(); ctx.lineWidth = 2; ctx.strokeStyle = "#fff"; ctx.stroke();
        ctx.beginPath(); ctx.arc(x, y - 22, 3.5, 0, 7); ctx.fillStyle = "#fff"; ctx.fill();
      }
      // scale bar
      const km = 111.32 / this.s * 120, nice = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000].find((v) => v >= km / 2) || 2000;
      const px = nice / (111.32 / this.s);
      ctx.strokeStyle = col.muted; ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(12, this.h - 14); ctx.lineTo(12 + px, this.h - 14); ctx.stroke();
      ctx.fillStyle = col.muted; ctx.font = "11px system-ui, sans-serif"; ctx.textAlign = "left"; ctx.fillText(`${nice} km / ${Math.round(nice * 0.621)} mi`, 12, this.h - 26);
    }
  }
  window.GeoMap = GeoMap;
})();
