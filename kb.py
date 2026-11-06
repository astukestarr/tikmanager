"""Knowledge Base (the Help Center's second tab): short how-to articles technicians write for each other - a client
quirk, a workaround, a step list for a task the Manual doesn't cover. Anyone signed in can read them; administrators
add, edit and delete. Bodies use the same plain-text markup as the Message Center ('- ' bullets, **bold**, `code`).

The Manual (the first tab) is written into the app itself (static/help.js) and isn't stored here - this is only the
part that grows over time.
"""
import time

from whatsnew import _blocks

MAX_TITLE = 150
MAX_CATEGORY = 60
MAX_BODY = 20000


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
