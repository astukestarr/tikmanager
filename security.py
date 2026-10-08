"""Passwords (scrypt), TOTP (RFC 6238), tokens, sessions with CSRF, login rate limiting and key derivation."""
import base64
import hashlib
import hmac
import secrets
import struct
import threading
import time
import urllib.parse
from http.cookies import SimpleCookie

SESSION_COOKIE = "tm_session"
SESSION_SECONDS = 10 * 3600
IDLE_SECONDS = 60 * 60
MAX_FAILS, LOCK_SECONDS = 5, 15 * 60


# --- passwords -------------------------------------------------------------------------------------------
def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)
    return f"scrypt$15$8$1${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def check_password(pw: str, stored: str | None) -> bool:
    try:
        _, n, r, p, salt, dk = (stored or "").split("$")
        got = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), n=2 ** int(n), r=int(r), p=int(p),
                             maxmem=64 * 1024 * 1024, dklen=32)
        return hmac.compare_digest(got, base64.b64decode(dk))
    except (ValueError, TypeError):
        hashlib.scrypt(b"x", salt=b"0" * 16, n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)   # same timing
        return False


def password_problem(pw: str) -> str | None:
    if len(pw) < 14:
        return "Use at least 14 characters (a passphrase of a few words works well)."
    if len(set(pw)) < 6:
        return "That password is too repetitive."
    return None


# --- TOTP ------------------------------------------------------------------------------------------------
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_uri(secret: str, email: str, issuer="TikManager") -> str:
    return f"otpauth://totp/{urllib.parse.quote(issuer)}:{urllib.parse.quote(email)}?secret={secret}&issuer={urllib.parse.quote(issuer)}&period=30&digits=6"


def _totp_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    h = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def check_totp(secret: str, code: str, window=1) -> bool:
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(code) != 6 or not secret:
        return False
    step = int(time.time() // 30)
    return any(hmac.compare_digest(_totp_at(secret, step + d), code) for d in range(-window, window + 1))


# --- tokens and derivation ---------------------------------------------------------------------------------
def token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


def derive(key: bytes, purpose: str, length=24) -> str:
    """A stable secret derived from the master key - e.g. a router's API password ('router-api:<device id>').
    Nothing derived this way is stored anywhere."""
    raw = hmac.new(key, purpose.encode(), hashlib.sha256).digest()
    alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no quotes/symbols: safe inside RouterOS scripts
    return "".join(alphabet[b % len(alphabet)] for b in raw)[:length]


def read_cookie(header: str | None, name: str) -> str | None:
    if not header:
        return None
    jar = SimpleCookie()
    try:
        jar.load(header)
    except Exception:  # noqa: BLE001
        return None
    return jar[name].value if name in jar else None


def cookie(name, value, max_age, secure) -> str:
    return f"{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}" + ("; Secure" if secure else "")


# --- sessions (stored hashed in the database) ----------------------------------------------------------------
class Sessions:
    def __init__(self, db):
        self.db = db

    def create(self, user_id, ip) -> tuple[str, str]:
        sid, csrf, now = token(), token(), time.time()
        self.db.run("DELETE FROM sessions WHERE expires < ? OR last_seen < ?", (now, now - IDLE_SECONDS))
        self.db.run("INSERT INTO sessions (id_hash, user_id, csrf, created_at, expires, last_seen, ip) VALUES (?,?,?,?,?,?,?)",
                    (token_hash(sid), user_id, csrf, now, now + SESSION_SECONDS, now, ip))
        return sid, csrf

    def get(self, sid):
        if not sid:
            return None
        now = time.time()
        s = self.db.one("SELECT s.*, u.email, u.name, u.kind, u.role, u.org_id, u.disabled FROM sessions s JOIN users u ON u.id = s.user_id "
                        "WHERE s.id_hash = ?", (token_hash(sid),))
        if not s or s["expires"] < now or s["last_seen"] < now - IDLE_SECONDS or s["disabled"]:
            if s:
                self.db.run("DELETE FROM sessions WHERE id_hash = ?", (token_hash(sid),))
            return None
        if now - s["last_seen"] > 60:
            self.db.run("UPDATE sessions SET last_seen = ? WHERE id_hash = ?", (now, token_hash(sid)))
        return s

    def end(self, sid):
        if sid:
            self.db.run("DELETE FROM sessions WHERE id_hash = ?", (token_hash(sid),))

    def end_all_for(self, user_id):
        self.db.run("DELETE FROM sessions WHERE user_id = ?", (user_id,))


class RateLimiter:
    """Simple in-memory sliding window, e.g. per IP on the login and adoption endpoints."""

    def __init__(self, limit, seconds):
        self.limit, self.seconds = limit, seconds
        self.hits: dict = {}
        self.lock = threading.Lock()

    def allow(self, key) -> bool:
        now = time.time()
        with self.lock:
            hits = [t for t in self.hits.get(key, []) if now - t < self.seconds]
            if len(hits) >= self.limit:
                self.hits[key] = hits
                return False
            hits.append(now)
            self.hits[key] = hits
            if len(self.hits) > 10000:   # don't grow forever under a flood
                self.hits = {k: v for k, v in self.hits.items() if v and now - v[-1] < self.seconds}
            return True
