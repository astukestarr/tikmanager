"use strict";
// Minimal, dependency-free QR Code generator (byte mode, error-correction level L, versions 1-10) - enough for an
// otpauth:// enrolment URI. Exposes window.tmQrSvg(text) -> an SVG string (dark-on-white so it scans in any theme), or
// null if the text is too long. No network, no libraries - safe under TikManager's strict CSP.
(function () {
  // --- GF(256) for Reed-Solomon -----------------------------------------------------------------------------------
  const EXP = new Array(512), LOG = new Array(256);
  (function () { let x = 1; for (let i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; } for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]; })();
  const mul = (a, b) => (a === 0 || b === 0) ? 0 : EXP[LOG[a] + LOG[b]];
  function rsGen(deg) {
    let poly = [1];
    for (let i = 0; i < deg; i++) {
      const np = new Array(poly.length + 1).fill(0);
      for (let j = 0; j < poly.length; j++) { np[j] ^= mul(poly[j], EXP[i]); np[j + 1] ^= poly[j]; }
      poly = np;
    }
    return poly;   // length deg+1, poly[0] === 1
  }
  function rsEnc(data, ecLen) {
    const gen = rsGen(ecLen), rem = new Array(ecLen).fill(0);
    for (const b of data) {
      const f = b ^ rem[0];
      rem.shift(); rem.push(0);
      if (f !== 0) for (let i = 0; i < ecLen; i++) rem[i] ^= mul(gen[i + 1], f);
    }
    return rem;
  }

  // --- per-version tables, error-correction level L ---------------------------------------------------------------
  // [ecPerBlock, blocksG1, dataCwG1, blocksG2, dataCwG2]
  const ECL = {
    1: [7, 1, 19, 0, 0], 2: [10, 1, 34, 0, 0], 3: [15, 1, 55, 0, 0], 4: [20, 1, 80, 0, 0], 5: [26, 1, 108, 0, 0],
    6: [18, 2, 68, 0, 0], 7: [20, 2, 78, 0, 0], 8: [24, 2, 97, 0, 0], 9: [30, 2, 116, 0, 0], 10: [18, 2, 68, 2, 69],
  };
  const ALIGN = { 1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50] };
  const dataCw = (v) => { const [, b1, d1, b2, d2] = ECL[v]; return b1 * d1 + b2 * d2; };
  const countBits = (v) => v <= 9 ? 8 : 16;

  // --- bitstream / codewords --------------------------------------------------------------------------------------
  function codewords(bytes, v) {
    const bits = [];
    const push = (val, n) => { for (let i = n - 1; i >= 0; i--) bits.push((val >> i) & 1); };
    push(0b0100, 4);                       // byte mode
    push(bytes.length, countBits(v));
    for (const b of bytes) push(b, 8);
    const cap = dataCw(v) * 8;
    for (let i = 0; i < 4 && bits.length < cap; i++) bits.push(0);   // terminator
    while (bits.length % 8) bits.push(0);
    const data = [];
    for (let i = 0; i < bits.length; i += 8) data.push(parseInt(bits.slice(i, i + 8).join(""), 2));
    const pad = [0xec, 0x11];
    for (let i = 0; data.length < dataCw(v); i++) data.push(pad[i % 2]);
    // split into blocks, RS each, then interleave
    const [ec, b1, d1, b2, d2] = ECL[v];
    const blocks = [];
    let p = 0;
    for (let i = 0; i < b1; i++) { blocks.push(data.slice(p, p + d1)); p += d1; }
    for (let i = 0; i < b2; i++) { blocks.push(data.slice(p, p + d2)); p += d2; }
    const ecs = blocks.map((b) => rsEnc(b, ec));
    const out = [];
    const maxD = Math.max(d1, d2);
    for (let i = 0; i < maxD; i++) for (const b of blocks) if (i < b.length) out.push(b[i]);
    for (let i = 0; i < ec; i++) for (const e of ecs) out.push(e[i]);
    return out;
  }

  // --- matrix -----------------------------------------------------------------------------------------------------
  function fmtInfo(mask) {   // ECC level L = bits 01
    let data = (0b01 << 3) | mask, rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ (((rem >> 9) & 1) * 0x537);
    return ((data << 10) | rem) ^ 0x5412;   // 15 bits
  }
  function verInfo(v) {
    let rem = v;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ (((rem >> 11) & 1) * 0x1f25);
    return (v << 12) | rem;   // 18 bits
  }

  function build(v, cw) {
    const n = 17 + 4 * v;
    const m = Array.from({ length: n }, () => new Array(n).fill(null));   // null = empty data module
    const res = Array.from({ length: n }, () => new Array(n).fill(false)); // true = function/reserved
    const set = (r, c, val) => { m[r][c] = val ? 1 : 0; res[r][c] = true; };
    const finder = (r, c) => { for (let i = -1; i <= 7; i++) for (let j = -1; j <= 7; j++) { const rr = r + i, cc = c + j; if (rr < 0 || cc < 0 || rr >= n || cc >= n) continue; const on = i >= 0 && i <= 6 && j >= 0 && j <= 6 && (i === 0 || i === 6 || j === 0 || j === 6 || (i >= 2 && i <= 4 && j >= 2 && j <= 4)); set(rr, cc, on); } };
    finder(0, 0); finder(0, n - 7); finder(n - 7, 0);
    for (let i = 8; i < n - 8; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }   // timing
    const ap = ALIGN[v];
    for (const r of ap) for (const c of ap) {
      if ((r <= 7 && c <= 7) || (r <= 7 && c >= n - 8) || (r >= n - 8 && c <= 7)) continue;
      for (let i = -2; i <= 2; i++) for (let j = -2; j <= 2; j++) set(r + i, c + j, Math.max(Math.abs(i), Math.abs(j)) !== 1);
    }
    set(n - 8, 8, true);   // dark module
    for (let i = 0; i < 9; i++) { if (!res[8][i] || true) { } }   // reserve format areas
    for (let i = 0; i <= 8; i++) { if (i !== 6) { res[8][i] = true; res[i][8] = true; } }
    for (let i = 0; i < 8; i++) { res[8][n - 1 - i] = true; res[n - 1 - i][8] = true; }
    if (v >= 7) for (let i = 0; i < 6; i++) for (let j = 0; j < 3; j++) { res[i][n - 11 + j] = true; res[n - 11 + j][i] = true; }

    // place data codewords (zigzag, right to left, skipping the vertical timing column)
    let bit = 0; const bitAt = (i) => (cw[i >> 3] >> (7 - (i & 7))) & 1;
    let up = true;
    for (let col = n - 1; col > 0; col -= 2) {
      if (col === 6) col--;
      for (let k = 0; k < n; k++) {
        const row = up ? n - 1 - k : k;
        for (let c2 = 0; c2 < 2; c2++) {
          const c = col - c2;
          if (res[row][c]) continue;
          m[row][c] = bit < cw.length * 8 ? bitAt(bit) : 0;
          bit++;
        }
      }
      up = !up;
    }

    // masks
    const MASKS = [(r, c) => (r + c) % 2 === 0, (r, c) => r % 2 === 0, (r, c) => c % 3 === 0, (r, c) => (r + c) % 3 === 0,
      (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0, (r, c) => (r * c) % 2 + (r * c) % 3 === 0,
      (r, c) => ((r * c) % 2 + (r * c) % 3) % 2 === 0, (r, c) => ((r + c) % 2 + (r * c) % 3) % 2 === 0];

    function placeInfo(grid, mask) {
      const f = fmtInfo(mask);
      for (let i = 0; i < 15; i++) {
        const b = (f >> i) & 1;
        // around top-left
        if (i < 6) grid[8][i] = b; else if (i === 6) grid[8][7] = b; else if (i === 7) grid[8][8] = b;
        else if (i === 8) grid[7][8] = b; else grid[14 - i][8] = b;
        // the split copy
        if (i < 8) grid[n - 1 - i][8] = b; else grid[8][n - 15 + i] = b;
      }
      grid[n - 8][8] = 1;   // dark module (kept)
      if (v >= 7) { const vi = verInfo(v); for (let i = 0; i < 18; i++) { const b = (vi >> i) & 1; const a = Math.floor(i / 3), bb = i % 3; grid[a][n - 11 + bb] = b; grid[n - 11 + bb][a] = b; } }
    }
    function penalty(g) {
      let p = 0;
      for (let r = 0; r < n; r++) for (const line of [g[r], g.map((row) => row[r])]) {
        let run = 1; for (let i = 1; i < n; i++) { if (line[i] === line[i - 1]) { run++; if (run === 5) p += 3; else if (run > 5) p++; } else run = 1; }
      }
      for (let r = 0; r < n - 1; r++) for (let c = 0; c < n - 1; c++) if (g[r][c] === g[r][c + 1] && g[r][c] === g[r + 1][c] && g[r][c] === g[r + 1][c + 1]) p += 3;
      const pat = [1, 0, 1, 1, 1, 0, 1];
      const hit = (line, i) => { for (let k = 0; k < 7; k++) if (line[i + k] !== pat[k]) return false; const a = line.slice(i - 4, i), b = line.slice(i + 7, i + 11); return (i >= 4 && a.every((x) => x === 0)) || (i + 11 <= n && b.every((x) => x === 0)); };
      for (let r = 0; r < n; r++) { const row = g[r], col = g.map((x) => x[r]); for (let i = 0; i + 7 <= n; i++) { if (hit(row, i)) p += 40; if (hit(col, i)) p += 40; } }
      let dark = 0; for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) dark += g[r][c]; const pct = dark * 100 / (n * n); p += Math.floor(Math.abs(pct - 50) / 5) * 10;
      return p;
    }

    let best = null, bestP = Infinity;
    for (let mask = 0; mask < 8; mask++) {
      const g = m.map((row) => row.slice());
      for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (!res[r][c] && MASKS[mask](r, c)) g[r][c] ^= 1;
      placeInfo(g, mask);
      const pen = penalty(g);
      if (pen < bestP) { bestP = pen; best = g; }
    }
    return best;
  }

  function matrix(text) {
    const bytes = Array.from(new TextEncoder().encode(text));
    let v = 0;
    for (let i = 1; i <= 10; i++) if (dataCw(i) * 8 >= 4 + countBits(i) + bytes.length * 8) { v = i; break; }
    if (!v) return null;   // too long for v10 at ECC L
    return build(v, codewords(bytes, v));
  }

  window.tmQrSvg = function (text) {
    const g = matrix(text);
    if (!g) return null;
    const n = g.length, q = 4, size = n + 2 * q;
    let d = "";
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (g[r][c]) d += `M${c + q} ${r + q}h1v1h-1z`;
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges" role="img" aria-label="Authenticator QR code">` +
      `<rect width="${size}" height="${size}" fill="#fff"/><path d="${d}" fill="#000"/></svg>`;
  };
})();
