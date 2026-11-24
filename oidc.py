"""Generic OIDC sign-in for any standards-compliant identity provider (Pocket ID, Authentik, Keycloak, Okta,
Google...): OIDC authorization-code flow with PKCE, standard library only.

Unlike entra.py (which trusts Microsoft's own token endpoint over TLS and validates the ID token's claims only), a
generic IdP is less implicitly trusted - so the ID token's RS256 signature is verified against the provider's
published JWKS, on top of the issuer / audience / nonce / expiry / email_verified claim checks. Discovery and the
signing keys are fetched over TLS from the configured issuer and cached; TikManager fails closed if it can't verify.
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

from entra import STATE_COOKIE, AuthError  # reuse the same error type and sign-in state-cookie name

PENDING_SECONDS = 600
DISCOVERY_TTL = 86400
JWKS_TTL = 3600
# PKCS#1 v1.5 DigestInfo prefix for SHA-256 (RFC 8017) - the bytes that precede the hash inside an RS256 signature
SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_dec(s) -> bytes:
    s = s.encode() if isinstance(s, str) else s
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def _b64url_int(s: str) -> int:
    return int.from_bytes(_b64url_dec(s), "big")


def _get_json(url: str, timeout: int = 15):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "TikManager"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read() or b"null")


def _rs256_ok(signing_input: bytes, sig: bytes, jwk: dict) -> bool:
    """Verify an RS256 (RSASSA-PKCS1-v1_5, SHA-256) signature with the RSA public key from a JWK - stdlib only.
    Rebuilds the expected PKCS#1 v1.5 EMSA block and compares it in full (constant time)."""
    try:
        n, e = _b64url_int(jwk["n"]), _b64url_int(jwk["e"])
    except (KeyError, ValueError):
        return False
    k = (n.bit_length() + 7) // 8
    if len(sig) != k or k < 62:   # 0x00 01 + >=8 FF + 00 + 51-byte T needs a >=496-bit modulus
        return False
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    t = SHA256_DIGESTINFO + hashlib.sha256(signing_input).digest()
    want = b"\x00\x01" + b"\xff" * (k - 3 - len(t)) + b"\x00" + t
    return secrets.compare_digest(em, want)


class Oidc:
    def __init__(self, s):
        self.s = s
        self.redirect_uri = f"{s.public_url}/auth/callback"
        self._pending: dict = {}
        self._lock = threading.Lock()
        self._disc = None
        self._disc_at = 0.0
        self._jwks: dict = {}
        self._jwks_at = 0.0

    @property
    def issuer(self) -> str:
        return (getattr(self.s, "oidc_issuer", "") or "").rstrip("/")

    def _discovery(self) -> dict:
        now = time.time()
        if self._disc and now - self._disc_at < DISCOVERY_TTL and str(self._disc.get("issuer") or "").rstrip("/") == self.issuer:
            return self._disc
        self._jwks = {}   # issuer may have changed (settings edited): drop the cached keys too
        try:
            d = _get_json(self.issuer + "/.well-known/openid-configuration")
        except (urllib.error.URLError, ValueError) as e:
            raise AuthError(f"Couldn't read the OIDC provider's configuration: {e}") from None
        if not (d.get("authorization_endpoint") and d.get("token_endpoint") and d.get("jwks_uri")):
            raise AuthError("The OIDC provider's discovery document is incomplete.")
        if str(d.get("issuer") or "").rstrip("/") != self.issuer:   # stops pointing TikManager at someone else's endpoints
            raise AuthError("The OIDC provider's issuer doesn't match the configured issuer.")
        self._disc, self._disc_at = d, now
        return d

    def _jwk_for(self, kid, force=False):
        now = time.time()
        if force or not self._jwks or now - self._jwks_at > JWKS_TTL:
            try:
                keys = (_get_json(self._discovery()["jwks_uri"]).get("keys") or [])
            except (urllib.error.URLError, ValueError) as e:
                raise AuthError(f"Couldn't read the OIDC provider's signing keys: {e}") from None
            self._jwks = {k.get("kid"): k for k in keys if k.get("kty") == "RSA"}
            self._jwks_at = now
        if kid in self._jwks:
            return self._jwks[kid]
        return next(iter(self._jwks.values())) if len(self._jwks) == 1 else None   # single-key sets often omit kid

    def begin(self, return_to="/"):
        """Returns (authorize URL, state value to bind to the browser with a cookie)."""
        d = self._discovery()
        state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        now = time.time()
        with self._lock:
            self._pending = {k: v for k, v in self._pending.items() if now - v["created"] < PENDING_SECONDS}
            self._pending[state] = {"nonce": nonce, "verifier": verifier, "return_to": return_to, "created": now}
        q = {"client_id": self.s.oidc_client_id, "response_type": "code", "redirect_uri": self.redirect_uri,
             "scope": (self.s.oidc_scopes or "openid profile email"), "state": state, "nonce": nonce,
             "code_challenge": _b64url(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"}
        return f"{d['authorization_endpoint']}?{urllib.parse.urlencode(q)}", state

    def owns_state(self, state) -> bool:
        """Whether this provider started the sign-in the callback is completing (so /auth/callback can route it)."""
        with self._lock:
            return bool(state) and state in self._pending

    def complete(self, query: dict, cookie_state):
        """Returns ({email, name, sub, provider}, return path)."""
        if query.get("error"):
            raise AuthError(query.get("error_description") or query["error"])
        state = query.get("state", "")
        with self._lock:
            pending = self._pending.pop(state, None)
        if not pending or time.time() - pending["created"] > PENDING_SECONDS:
            raise AuthError("That sign-in attempt expired. Please try again.")
        if not secrets.compare_digest(cookie_state or "", state):
            raise AuthError("Sign-in was started in a different browser. Please try again.")
        d = self._discovery()
        form = urllib.parse.urlencode({
            "client_id": self.s.oidc_client_id, "client_secret": self.s.oidc_client_secret, "grant_type": "authorization_code",
            "code": query.get("code", ""), "redirect_uri": self.redirect_uri, "code_verifier": pending["verifier"]}).encode()
        req = urllib.request.Request(d["token_endpoint"], data=form,
                                     headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json", "User-Agent": "TikManager"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                tokens = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = json.loads(e.read() or b"{}").get("error_description") or ""
            except ValueError:
                pass
            raise AuthError(f"The OIDC provider rejected the sign-in: {detail or e.code}.") from None
        except urllib.error.URLError as e:
            raise AuthError(f"Couldn't reach the OIDC provider: {e.reason}") from None
        c = self._verify(tokens.get("id_token") or "", pending["nonce"])
        email = str(c.get("email") or c.get("preferred_username") or "").lower()
        if not email:
            raise AuthError("The OIDC provider didn't return an email address (add the 'email' scope/claim).")
        if "email_verified" in c and not c.get("email_verified"):
            raise AuthError("Your email address isn't verified with the identity provider.")
        if not c.get("sub"):
            raise AuthError("The OIDC provider didn't say who signed in (no subject in the token).")
        return {"email": email, "name": c.get("name") or c.get("preferred_username") or email,
                "sub": str(c["sub"]), "provider": "oidc"}, pending["return_to"]

    def _verify(self, idt: str, nonce: str) -> dict:
        parts = idt.split(".")
        if len(parts) != 3:
            raise AuthError("The OIDC provider returned an unreadable ID token.")
        try:
            header = json.loads(_b64url_dec(parts[0]))
            claims = json.loads(_b64url_dec(parts[1]))
            sig = _b64url_dec(parts[2])
        except (ValueError, json.JSONDecodeError) as e:
            raise AuthError("The OIDC provider returned an unreadable ID token.") from e
        if header.get("alg") != "RS256":
            raise AuthError(f"Unsupported ID-token signature algorithm ({header.get('alg')}); TikManager verifies RS256.")
        jwk = self._jwk_for(header.get("kid")) or self._jwk_for(header.get("kid"), force=True)   # refetch once on an unknown key id
        if not jwk:
            raise AuthError("Couldn't find the provider's signing key to verify the token.")
        if not _rs256_ok(f"{parts[0]}.{parts[1]}".encode(), sig, jwk):
            raise AuthError("The ID token's signature didn't verify.")
        if str(claims.get("iss") or "").rstrip("/") != self.issuer:
            raise AuthError("The ID token was issued by a different provider.")
        aud = claims.get("aud")
        if not (aud == self.s.oidc_client_id or (isinstance(aud, list) and self.s.oidc_client_id in aud)):
            raise AuthError("The ID token was issued for a different application.")
        if claims.get("nonce") != nonce:
            raise AuthError("Sign-in response didn't match this request. Please try again.")
        now = time.time()
        if float(claims.get("exp") or 0) < now - 60:
            raise AuthError("The ID token has expired. Please try again.")
        if float(claims.get("iat") or now) > now + 300:
            raise AuthError("The ID token's issue time is in the future - check the server's clock.")
        return claims

    def logout_url(self):
        try:
            end = self._discovery().get("end_session_endpoint")
        except AuthError:
            end = None
        return f"{end}?{urllib.parse.urlencode({'post_logout_redirect_uri': self.s.public_url + '/login'})}" if end else None
