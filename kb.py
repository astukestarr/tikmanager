"""Knowledge Base (the Help Center's second tab): short how-to articles technicians write for each other - a client
quirk, a workaround, a step list for a task the Manual doesn't cover. Anyone signed in can read them; administrators
add, edit and delete. Bodies use the same plain-text markup as the Message Center ('- ' bullets, **bold**, `code`).

The Manual (the first tab) is written into the app itself (static/help.js) and isn't stored here - this is only the
part that grows over time.
"""
import re
import time

from whatsnew import _blocks

MAX_TITLE = 150
MAX_CATEGORY = 60
MAX_BODY = 20000

# A Knowledge Base article is a how-to note, never a place for live credentials (anyone on staff reads it, and a stray
# key here never rotates). We refuse to save a body that looks like it carries a real secret. High precision on purpose:
# better to let the odd one through than to block a legitimate article - so we flag only unmistakable token formats and
# labelled assignments whose value is clearly random, and we skip placeholders ("YOUR_KEY", "<secret>", "$env:X").
_SECRET_TOKENS = re.compile(r"""
      AKIA[0-9A-Z]{16}                                             # AWS access key id
    | ghp_[0-9A-Za-z]{36} | gho_[0-9A-Za-z]{36} | github_pat_[0-9A-Za-z_]{22,}   # GitHub tokens
    | AIza[0-9A-Za-z_\-]{35}                                       # Google API key
    | xox[baprs]-[0-9A-Za-z-]{10,}                                 # Slack token
    | eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,} # JWT (header.payload.signature)
    | -----BEGIN[A-Z ]*PRIVATE\ KEY-----                          # PEM private key block
""", re.VERBOSE)
_LABELLED = re.compile(
    r"\b(pass(?:word|wd)?|pwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token|token|bearer)\b"
    r"\s*[:=]\s*(\S+)", re.IGNORECASE)


def _is_placeholder(val):
    """True if this value is an example/reference, not a real secret - so we don't block normal how-to text."""
    v = val.strip().strip("`'\"<>(){}[]")
    if not v or v[0] in "$%{<":                                    # env-var / template reference ($KEY, %KEY%, {{key}})
        return True
    low = v.lower()
    if any(w in low for w in ("your", "example", "changeme", "placeholder", "paste", "redact", "dummy",
                              "sample", "token", "secret", "password", "apikey", "api_key", "xxxx")):
        return True
    if re.fullmatch(r"[A-Z0-9]+(_[A-Z0-9]+)+", v):                 # YOUR_PASSWORD, PASTE_CODA_WU_SECRET
        return True
    if re.fullmatch(r"[*•.xX\-]+", v):                        # masked: ****, ••••, xxxx, ----
        return True
    return False


def _secret_reason(body):
    """A reason string if the body looks like it contains a live credential, else '' (no value is ever echoed back)."""
    if _SECRET_TOKENS.search(body):
        return "it contains what looks like a live API key, token or private key"
    for m in _LABELLED.finditer(body):
        val = m.group(2).strip().strip("`'\"")
        if len(val) < 8 or _is_placeholder(val):
            continue
        looks_random = len(val) >= 20 or (len(val) >= 12 and re.search(r"[A-Za-z]", val) and re.search(r"\d", val))
        if looks_random:
            return f'it looks like it contains a real credential (near "{m.group(1).lower()}=")'
    return ""


class Kb:
    def __init__(self, db):
        self.db = db

    def list(self):
        """Every article, pinned first then newest, bodies parsed into blocks for the page to render."""
        rows = self.db.q("""SELECT id, ts, updated_at, title, category, body, pinned, created_by FROM kb_articles
                            ORDER BY pinned DESC, COALESCE(updated_at, ts) DESC, id DESC""")
        for r in rows:
            r["blocks"] = _blocks(r["body"].splitlines())   # for display; raw body stays for the editor
            r["pinned"] = bool(r["pinned"])
        return rows

    def get(self, aid):
        r = self.db.one("SELECT id, ts, updated_at, title, category, body, pinned, created_by FROM kb_articles WHERE id=?", (aid,))
        return r

    @staticmethod
    def _clean(title, category, body):
        title = str(title or "").strip()[:MAX_TITLE]
        category = str(category or "").strip()[:MAX_CATEGORY]
        body = str(body or "").strip()[:MAX_BODY]
        if not title:
            raise ValueError("Give the article a title.")
        reason = _secret_reason(body)
        if reason:
            raise ValueError(f"This article can't be saved because {reason}. Don't keep passwords or keys in the "
                             "Knowledge Base - store them in Admin > Integrations (encrypted) and refer to them by name.")
        return title, category, body

    def create(self, title, category, body, by, pinned=False):
        title, category, body = self._clean(title, category, body)
        aid = self.db.run("INSERT INTO kb_articles (ts, updated_at, title, category, body, pinned, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
                          (time.time(), time.time(), title, category, body, 1 if pinned else 0, by))
        return self.get(aid)

    def update(self, aid, title=None, category=None, body=None, pinned=None):
        cur = self.get(aid)
        if not cur:
            return None
        title, category, body = self._clean(
            cur["title"] if title is None else title,
            cur["category"] if category is None else category,
            cur["body"] if body is None else body)
        pin = cur["pinned"] if pinned is None else (1 if pinned else 0)
        self.db.run("UPDATE kb_articles SET title=?, category=?, body=?, pinned=?, updated_at=? WHERE id=?",
                    (title, category, body, pin, time.time(), aid))
        return self.get(aid)

    def delete(self, aid):
        self.db.run("DELETE FROM kb_articles WHERE id=?", (aid,))
