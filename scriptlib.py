"""Community RouterOS script library on GitHub (Tasks > Scripts > Community library).

- The library is a public GitHub repository (Admin > Integrations > GitHub; default astukestarr/routeros-scripts) of
  `.rsc` files, each starting with a header:
      # name: Block SSH brute force
      # description: Adds an address list + drop rule for repeated SSH failures
      # author: github-user
      # tags: security, ssh
      # routeros: 7.12+
  Browsing needs no GitHub account (one API call an hour for the file list; the files come from raw.githubusercontent.com).
- Importing copies a script into this TikManager's own library - it never runs anything. Before that, the full script is
  shown with warnings for commands that deserve a second look (factory reset, users, deleting files, downloads,
  schedulers, anything touching TikManager's own access ...).
- Sharing opens a pull request on the library (fork -> branch -> commit -> PR), so its owner reviews it before anyone else
  gets it. A GitHub token is needed for that (classic token with only the public_repo scope), saved encrypted on Admin >
  Integrations. Before anything is sent, the script is scanned for secrets (passwords, keys, pre-shared keys, public IP
  addresses, e-mail addresses, client names) and each finding must be fixed or confirmed.
"""
import base64
import ipaddress
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from version import __version__

DEFAULT_LIBRARY = "astukestarr/routeros-scripts"
MAX_FILES = 300
CACHE = 3600
HEADER = re.compile(r"^#\s*(name|description|author|tags|routeros)\s*:\s*(.*?)\s*$", re.I)

DANGER = [   # (pattern, why it deserves a look) - shown before import, never blocks it
    (r"/system[\s/]+reset-configuration", "resets the router to factory settings"),
    (r"/system[\s/]+scheduler", "adds a scheduled job that keeps running later"),
    (r"/system[\s/]+(reboot|shutdown)", "reboots or shuts down the router"),
    (r"/user[\s/]+(add|set|remove)|/user[\s/]+group|/user[\s/]+ssh-keys", "changes router users, groups or SSH keys"),
    (r"/file[\s/]+remove|/file[\s/]+set", "deletes or changes files on the router"),
    (r"/tool[\s/]+fetch", "downloads or uploads data from / to the internet"),
    (r"/tool[\s/]+e-mail|/tool[\s/]+sms", "sends e-mail / SMS from the router"),
    (r"/system[\s/]+script[\s/]+(add|run)|:execute|\[:parse", "runs or stores other code"),
    (r"/ip[\s/]+service", "changes management services (Winbox / SSH / WebFig / API)"),
    (r"/ip[\s/]+firewall[\s/]+(filter|nat|raw|mangle)[\s/]+(remove|disable)", "removes or disables firewall rules"),
    (r"/interface[\s/]+wireguard|tikmanager", "touches WireGuard or TikManager's own settings (could cut TikManager off)"),
    (r"/certificate", "changes certificates"),
    (r"/system[\s/]+package[\s/]+(update[\s/]+install|downgrade|uninstall)|/system[\s/]+routerboard[\s/]+upgrade", "installs RouterOS / firmware updates (the router reboots)"),
    (r"/export|/system[\s/]+backup", "exports the configuration (which can contain secrets)"),
]
SECRETS = [   # (pattern, what it looks like) - must be fixed or confirmed before sharing
    (r"\b(password|passphrase|secret|pre-shared-key|wpa2?-pre-shared-key|authentication-key|private-key|psk|key)\s*=\s*\"?(?!\"|\$|\{)[^\s\"]{3,}",
     "a password / key / secret value"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "a private key"),
    (r"\b[A-Za-z0-9+/]{43}=", "what looks like a WireGuard key"),
    (r"[\w.+-]+@[\w-]+\.[\w.-]+", "an e-mail address"),
]


class LibraryError(ValueError):
    pass


def parse(text, path=""):
    meta = {"name": "", "description": "", "author": "", "tags": "", "routeros": ""}
    for line in text.splitlines()[:25]:
        if m := HEADER.match(line.strip()):
            meta[m.group(1).lower()] = m.group(2)[:200]
    if not meta["name"]:
        meta["name"] = re.sub(r"[-_]+", " ", path.rsplit("/", 1)[-1].rsplit(".", 1)[0]).strip().capitalize() or "Script"
    meta["tags"] = [t.strip().lower() for t in meta["tags"].split(",") if t.strip()][:10]
    return meta


def body_without_header(text):
    lines = text.splitlines()
    i = 0
    while i < len(lines) and (HEADER.match(lines[i].strip()) or lines[i].strip() in ("#", "# shared from TikManager")):
        i += 1
    return "\n".join(lines[i:]).strip() + "\n"


def danger(text):
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        code = line.split("#", 1)[0] if not line.lstrip().startswith("#") else ""
        for pat, why in DANGER:
            if re.search(pat, code, re.I):
                out.append({"line": n, "text": why, "code": line.strip()[:160]})
                break
    return out


def secrets(text, names=()):
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        for pat, what in SECRETS:
            if re.search(pat, line, re.I):
                out.append({"line": n, "text": what, "code": line.strip()[:160]})
                break
        else:
            for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line):
                try:
                    a = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if a.is_global:
                    out.append({"line": n, "text": f"a public IP address ({ip})", "code": line.strip()[:160]})
                    break
            else:
                low = line.lower()
                hit = next((nm for nm in names if len(nm) > 3 and nm.lower() in low), None)
                if hit:
                    out.append({"line": n, "text": f"a client name ({hit})", "code": line.strip()[:160]})
    return out


def slug(name):
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", name.lower())).strip("-")[:60] or "script"


class ScriptLibrary:
    def __init__(self, db, integ):
        self.db, self.integ = db, integ
        self._cache = None
        self.lock = threading.Lock()

    @property
    def repo(self):
        r = (self.integ.config("github").get("library") or DEFAULT_LIBRARY).strip().strip("/")
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", r):
            raise LibraryError("The library must look like owner/repository.")
        return r

    def _token(self):
        return self.integ.config("github").get("token") or ""

    def _gh(self, method, path, body=None, auth=False):
        headers = {"Accept": "application/vnd.github+json", "User-Agent": f"TikManager/{__version__}", "X-GitHub-Api-Version": "2022-11-28"}
        tok = self._token()
        if tok:   # also for browsing when saved: GitHub then allows 5,000 requests an hour instead of 60
            headers["Authorization"] = f"Bearer {tok}"
        elif auth:
            raise LibraryError("Save a GitHub token on Admin > Integrations to share scripts.")
        req = urllib.request.Request("https://api.github.com" + path, method=method, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read(4 * 1024 * 1024)
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            msg = e.read(2000).decode("utf-8", "replace")
            try:
                msg = json.loads(msg).get("message") or msg
            except ValueError:
                pass
            hint = {401: " - check the GitHub token", 403: " - the token lacks permission, or GitHub's hourly limit was reached",
                    404: " - check the library repository exists and is public"}.get(e.code, "")
            raise LibraryError(f"GitHub said {e.code}: {str(msg)[:200]}{hint}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise LibraryError(f"Couldn't reach GitHub: {getattr(e, 'reason', e)}") from None

    def _raw(self, branch, path):
        url = f"https://raw.githubusercontent.com/{self.repo}/{urllib.parse.quote(branch)}/{urllib.parse.quote(path)}"
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": f"TikManager/{__version__}"}), timeout=30) as r:
                return r.read(256 * 1024).decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise LibraryError(f"Couldn't download {path}: {getattr(e, 'reason', e)}") from None

    # --- browsing ------------------------------------------------------------------------------------------
    def listing(self, refresh=False):
        with self.lock:
            if self._cache and not refresh and time.time() - self._cache["at"] < CACHE and self._cache["repo"] == self.repo:
                return self._cache
            info = self._gh("GET", f"/repos/{self.repo}")
            branch = info.get("default_branch") or "main"
            if not info.get("size"):   # a brand-new repository has no files (GitHub answers 409 for its tree)
                tree = {}
            else:
                tree = self._gh("GET", f"/repos/{self.repo}/git/trees/{urllib.parse.quote(branch)}?recursive=1") or {}
            paths = [t["path"] for t in tree.get("tree") or [] if t.get("type") == "blob" and t["path"].lower().endswith(".rsc")
                     and not any(p.startswith(".") for p in t["path"].split("/"))][:MAX_FILES]
            items = []
            for p in paths:
                try:
                    text = self._raw(branch, p)
                except LibraryError:
                    continue
                items.append({"path": p, **parse(text, p), "lines": text.count("\n") + 1})
            self._cache = {"at": time.time(), "repo": self.repo, "branch": branch, "items": sorted(items, key=lambda x: x["name"].lower()),
                           "url": f"https://github.com/{self.repo}"}
            return self._cache

    def get(self, path):
        lst = self.listing()
        if path not in {i["path"] for i in lst["items"]}:
            raise LibraryError("That script isn't in the library (refresh the list).")
        text = self._raw(lst["branch"], path)
        return {"path": path, **parse(text, path), "body": body_without_header(text), "warnings": danger(text),
                "url": f"https://github.com/{self.repo}/blob/{lst['branch']}/{path}"}

    # --- sharing (pull request) ----------------------------------------------------------------------------
    def share(self, name, description, tags, routeros, body):
        if not self._token():
            raise LibraryError("Save a GitHub token on Admin > Integrations to share scripts.")
        me = (self._gh("GET", "/user", auth=True) or {}).get("login")
        if not me:
            raise LibraryError("The GitHub token didn't identify a user.")
        upstream = self._gh("GET", f"/repos/{self.repo}")
        base = upstream.get("default_branch") or "main"
        owner = self.repo.split("/")[0]
        if me.lower() == owner.lower():   # the library's own owner: a branch in the library itself
            target = self.repo
        else:   # everyone else: their fork (created / brought up to date here)
            fork = self._gh("POST", f"/repos/{self.repo}/forks", {"default_branch_only": True}, auth=True)
            target = fork["full_name"]
            for _ in range(15):   # a new fork takes a few seconds to appear
                try:
                    self._gh("GET", f"/repos/{target}/git/ref/heads/{urllib.parse.quote(base)}", auth=True)
                    break
                except LibraryError:
                    time.sleep(2)
            try:
                self._gh("POST", f"/repos/{target}/merge-upstream", {"branch": base}, auth=True)
            except LibraryError:
                pass
        sha = self._gh("GET", f"/repos/{target}/git/ref/heads/{urllib.parse.quote(base)}", auth=True)["object"]["sha"]
        s = slug(name)
        branch = f"tikmanager/{s}-{int(time.time())}"
        self._gh("POST", f"/repos/{target}/git/refs", {"ref": f"refs/heads/{branch}", "sha": sha}, auth=True)
        path = f"scripts/{s}.rsc"
        header = "\n".join([f"# name: {name}", f"# description: {description}", f"# author: {me}",
                            f"# tags: {', '.join(tags)}", f"# routeros: {routeros}", "# shared from TikManager", ""])
        content = header + body_without_header(body)
        put = {"message": f"Add {name}", "content": base64.b64encode(content.encode()).decode(), "branch": branch}
        try:   # replacing an existing script of the same name: GitHub needs its current version
            existing = self._gh("GET", f"/repos/{target}/contents/{path}?ref={urllib.parse.quote(branch)}", auth=True)
            put["sha"] = existing.get("sha")
            put["message"] = f"Update {name}"
        except LibraryError:
            pass
        self._gh("PUT", f"/repos/{target}/contents/{path}", put, auth=True)
        head = branch if target == self.repo else f"{target.split('/')[0]}:{branch}"
        pr = self._gh("POST", f"/repos/{self.repo}/pulls", {"title": put["message"], "head": head, "base": base,
                                                             "body": f"{description}\n\nRouterOS: {routeros or 'not stated'}\n"
                                                                     f"Tags: {', '.join(tags) or 'none'}\n\nShared from TikManager {__version__}. "
                                                                     "Please review before merging - scripts run on routers with full rights."}, auth=True)
        return pr.get("html_url")
