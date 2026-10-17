"""Message Center (the bell, top right): news about TikManager for each person - every new version's release notes
(added automatically when the server starts on a version it hasn't announced) and notices administrators post.

Each person acknowledges messages - one, several or all at once - and acknowledged ones stop counting on the bell (they
stay in the Message Center under All). Release notes go to technicians; a notice goes to technicians or to everyone.
A new account doesn't get the history: only messages from the 14 days before it was created onwards.
"""
import re
import time

from version import __version__
from whatsnew import CHANGELOG, _blocks, _vt

SECTION = re.compile(r"^## (\d+\.\d+\.\d+(?:-beta\.\d+)?)(?: - (\S+))?\s*$")
BACKLOG = 14 * 86400
AUDIENCES = ("tech", "all")


class Messages:
    def __init__(self, db):
        self.db = db

    # --- release notes -------------------------------------------------------------------------------------------
    @staticmethod
    def sections():
        try:
            lines = CHANGELOG.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        out, cur = [], None
        for line in lines:
            if line.startswith("## "):
                m = SECTION.match(line)
                cur = {"version": m.group(1), "date": m.group(2) or "", "lines": []} if m else None
                if cur:
                    out.append(cur)
            elif cur is not None:
                cur["lines"].append(line)
        return out

    def sync_releases(self):
        """Announce every version between the last one announced and this one (the first time: only this one)."""
        last = self.db.setting("messages_version")
        mine = _vt(__version__)
        if last == __version__:
            return
        new = [s for s in self.sections() if _vt(s["version"]) <= mine and (last is None and s["version"] == __version__ or last and _vt(s["version"]) > _vt(last))]
        for s in sorted(new, key=lambda s: _vt(s["version"])):
            if self.db.one("SELECT 1 FROM messages WHERE kind='release' AND version=?", (s["version"],)):
                continue
            body = "\n".join(s["lines"]).strip()
            first = next((b["text"] for b in _blocks(s["lines"]) if b["kind"] == "li"), "")
            hint = re.sub(r"\*\*(.+?)\*\*.*", r"\1", first).strip(" -") if first.startswith("**") else ""
            self.db.run("INSERT INTO messages (ts, kind, title, body, version, audience, created_by) VALUES (?, 'release', ?, ?, ?, 'tech', 'TikManager')",
                        (time.time(), f"TikManager {s['version']}" + (f": {hint}" if hint else ""), body, s["version"]))
        self.db.set_setting("messages_version", __version__)

    # --- reading -------------------------------------------------------------------------------------------------
    def _visible(self, s):
        user = self.db.one("SELECT created_at FROM users WHERE id=?", (s["user_id"],)) or {"created_at": 0}
        aud = "('tech','all')" if s["kind"] == "tech" else "('all')"
        return f"m.audience IN {aud} AND m.ts >= ?", [user["created_at"] - BACKLOG]

    def list(self, s, everything=False):
        where, args = self._visible(s)
        rows = self.db.q(f"""SELECT m.id, m.ts, m.kind, m.title, m.body, m.version, m.audience, m.created_by, a.acked_at FROM messages m
                             LEFT JOIN message_acks a ON a.message_id = m.id AND a.user_id = ?
                             WHERE {where} {"" if everything else "AND a.acked_at IS NULL"} ORDER BY m.ts DESC, m.id DESC LIMIT 300""", [s["user_id"], *args])
        for r in rows:
            r["blocks"] = _blocks(r.pop("body").splitlines())
            r["acked"] = r.pop("acked_at") is not None
        return rows

    def unread(self, s):
        where, args = self._visible(s)
        return self.db.one(f"""SELECT COUNT(*) AS n FROM messages m LEFT JOIN message_acks a ON a.message_id = m.id AND a.user_id = ?
                               WHERE {where} AND a.acked_at IS NULL""", [s["user_id"], *args])["n"]

    # --- acknowledging -------------------------------------------------------------------------------------------
    def ack(self, s, ids=None):
        """Acknowledge these messages - or, with ids None, every message this person can see."""
        if ids is None:
            where, args = self._visible(s)
            ids = [r["id"] for r in self.db.q(f"SELECT m.id FROM messages m WHERE {where}", args)]
        now = time.time()
        self.db.many("INSERT OR IGNORE INTO message_acks (user_id, message_id, acked_at) VALUES (?, ?, ?)", [(s["user_id"], int(i), now) for i in ids])
        return len(ids)

    def unack(self, s, ids):
        for i in ids:
            self.db.run("DELETE FROM message_acks WHERE user_id=? AND message_id=?", (s["user_id"], int(i)))

    # --- notices (administrators) ----------------------------------------------------------------------------------
    def post(self, title, body, audience, by):
        title, body = str(title or "").strip()[:150], str(body or "").strip()[:8000]
        if not title:
            raise ValueError("Give the message a title.")
        if audience not in AUDIENCES:
            raise ValueError("Pick who it's for.")
        return self.db.run("INSERT INTO messages (ts, kind, title, body, version, audience, created_by) VALUES (?, 'notice', ?, ?, NULL, ?, ?)",
                           (time.time(), title, body, audience, by))

    def delete(self, mid):
        self.db.run("DELETE FROM message_acks WHERE message_id=?", (mid,))
        self.db.run("DELETE FROM messages WHERE id=?", (mid,))
