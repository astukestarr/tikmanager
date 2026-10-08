"""Branding (Admin > Branding): names, accent colour, logo, sign-in message and support contact.
Stored in the settings table; the logo in data/branding/. Logos must be PNG, JPEG or WebP - SVG is refused because it
can carry script."""
import base64
import json
import re
from pathlib import Path

# company name: set at first-run setup or on Admin > Branding
DEFAULTS = {"product": "TikManager", "company": "", "accent": "#e2462f", "login_message": "",
            "support_email": "", "support_phone": "", "logo": ""}
TYPES = {b"\x89PNG\r\n\x1a\n": ("png", "image/png"), b"\xff\xd8\xff": ("jpg", "image/jpeg")}
MAX_LOGO = 512 * 1024


def sniff(data: bytes):
    for magic, t in TYPES.items():
        if data.startswith(magic):
            return t
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ("webp", "image/webp")
    return None


class Branding:
    def __init__(self, db, data_dir: Path):
        self.db = db
        self.dir = data_dir / "branding"
        self.dir.mkdir(parents=True, exist_ok=True)

    def get(self) -> dict:
        try:
            saved = json.loads(self.db.setting("branding", "{}") or "{}")
        except ValueError:
            saved = {}
        return {**DEFAULTS, **{k: v for k, v in saved.items() if k in DEFAULTS}}

    def public(self) -> dict:
        b = self.get()
        return {**{k: v for k, v in b.items() if k != "logo"}, "logo_url": f"/branding/logo?v={b['logo']}" if b["logo"] else None}

    def save(self, raw: dict) -> dict:
        b = self.get()
        for k in ("product", "company"):
            v = str(raw.get(k, b[k]) or "").strip()[:60]
            if not v:
                raise ValueError(f"The {k} name can't be empty.")
            b[k] = v
        accent = str(raw.get("accent", b["accent"]) or "").strip().lower()
        if not re.fullmatch(r"#[0-9a-f]{6}", accent):
            raise ValueError("Pick the accent colour as #rrggbb.")
        b["accent"] = accent
        b["login_message"] = str(raw.get("login_message", b["login_message"]) or "").strip()[:500]
        email = str(raw.get("support_email", b["support_email"]) or "").strip()[:120]
        if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", email, re.I):
            raise ValueError("The support email doesn't look right.")
        b["support_email"] = email
        b["support_phone"] = re.sub(r"[^0-9+().\-\s x]", "", str(raw.get("support_phone", b["support_phone"]) or ""))[:40].strip()
        self.db.set_setting("branding", json.dumps(b))
        return self.public()

    def set_logo(self, data_url: str) -> dict:
        b = self.get()
        if not data_url:   # remove
            for p in self.dir.glob("logo.*"):
                p.unlink(missing_ok=True)
            b["logo"] = ""
        else:
            try:
                data = base64.b64decode(str(data_url).split(",", 1)[-1], validate=True)
            except ValueError:
                raise ValueError("That file couldn't be read.") from None
            if len(data) > MAX_LOGO:
                raise ValueError("The logo must be under 512 KB.")
            t = sniff(data)
            if not t:
                raise ValueError("Use a PNG, JPEG or WebP image (SVG isn't allowed).")
            for p in self.dir.glob("logo.*"):
                p.unlink(missing_ok=True)
            (self.dir / f"logo.{t[0]}").write_bytes(data)
            b["logo"] = str(abs(hash(data)) % 10 ** 8)   # cache-buster
        self.db.set_setting("branding", json.dumps(b))
        return self.public()

    def logo(self):
        for p in self.dir.glob("logo.*"):
            t = sniff(p.read_bytes()[:16])
            if t:
                return p.read_bytes(), t[1]
        return None, None
