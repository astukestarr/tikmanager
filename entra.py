"""Microsoft Entra sign-in for technicians (your own tenant): OIDC authorization-code flow with PKCE, standard library only.

The ID token comes straight from Microsoft's token endpoint over TLS in exchange for our client secret, so (OIDC Core
3.1.3.7) we validate its claims - issuer, audience, tenant, nonce, expiry - rather than its signature.
"""
import base64
import hashlib
import json
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

STATE_COOKIE = "tm_auth_state"
PENDING_SECONDS = 600


class AuthError(Exception):
    pass


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _claims(tok: str) -> dict:
    try:
        payload = tok.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError) as e:
        raise AuthError("Microsoft returned an unreadable ID token.") from e


class Entra:
    def __init__(self, s):
        self.s = s
        self.redirect_uri = f"{s.public_url}/auth/callback"
        self._pending: dict = {}
        self._lock = threading.Lock()

    @property
    def authority(self):
        return f"https://login.microsoftonline.com/{self.s.entra_tenant_id}/oauth2/v2.0"

    def begin(self, return_to="/"):
        """Returns (authorize URL, state value to bind to the browser with a cookie)."""
        state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        now = time.time()
        with self._lock:
            self._pending = {k: v for k, v in self._pending.items() if now - v["created"] < PENDING_SECONDS}
            self._pending[state] = {"nonce": nonce, "verifier": verifier, "return_to": return_to, "created": now}
        q = {"client_id": self.s.entra_client_id, "response_type": "code", "redirect_uri": self.redirect_uri,
             "response_mode": "query", "scope": "openid profile email", "state": state, "nonce": nonce,
             "code_challenge": _b64url(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256",
             "prompt": "select_account"}
        return f"{self.authority}/authorize?{urllib.parse.urlencode(q)}", state

    def complete(self, query: dict, cookie_state: str | None) -> tuple[dict, str]:
        """Returns ({email, name, oid}, return path)."""
        if query.get("error"):
            raise AuthError(query.get("error_description") or query["error"])
        state = query.get("state", "")
        with self._lock:
            pending = self._pending.pop(state, None)
        if not pending or time.time() - pending["created"] > PENDING_SECONDS:
            raise AuthError("That sign-in attempt expired. Please try again.")
        if not secrets.compare_digest(cookie_state or "", state):
            raise AuthError("Sign-in was started in a different browser. Please try again.")
        form = urllib.parse.urlencode({
            "client_id": self.s.entra_client_id, "client_secret": self.s.entra_client_secret, "grant_type": "authorization_code",
            "code": query.get("code", ""), "redirect_uri": self.redirect_uri, "code_verifier": pending["verifier"],
            "scope": "openid profile email"}).encode()
        req = urllib.request.Request(f"{self.authority}/token", data=form,
                                     headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                tokens = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            detail = json.loads(e.read() or b"{}").get("error_description", "")
            raise AuthError(f"Microsoft rejected the sign-in: {detail.splitlines()[0] if detail else e.code}") from None
        except urllib.error.URLError as e:
            raise AuthError(f"Couldn't reach Microsoft: {e.reason}") from None
        c = _claims(tokens.get("id_token", ""))
        tid = self.s.entra_tenant_id
        if c.get("aud") != self.s.entra_client_id:
            raise AuthError("ID token was issued for a different application.")
        if c.get("tid") != tid or c.get("iss") != f"https://login.microsoftonline.com/{tid}/v2.0":
            raise AuthError("That account belongs to a different organization.")
        if c.get("nonce") != pending["nonce"]:
            raise AuthError("Sign-in response didn't match this request. Please try again.")
        if c.get("exp", 0) < time.time() - 60:
            raise AuthError("ID token has expired. Please try again.")
        if not c.get("oid"):
            raise AuthError("Microsoft didn't say who signed in (no user ID in the token).")
        # guests (B2B / personal accounts invited into your tenant) carry an 'idp' claim naming their home directory;
        # only your own organization's accounts may be technicians
        idp = str(c.get("idp") or "")
        if idp and tid.lower() not in idp.lower():
            raise AuthError("Guest accounts can't sign in to TikManager - use an account from your own organization.")
        email = (c.get("preferred_username") or c.get("email") or "").lower()
        return {"email": email, "name": c.get("name") or email, "oid": c["oid"]}, pending["return_to"]

    def logout_url(self):
        return f"{self.authority}/logout?{urllib.parse.urlencode({'post_logout_redirect_uri': self.s.public_url + '/login'})}"
