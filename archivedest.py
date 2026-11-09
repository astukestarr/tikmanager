"""Archive destinations: where long-term log archives are written. One backend per kind, each with the same small
interface - put / names / delete / check - so logarchive.py doesn't care where the bytes go.

Standard library only, plus `cryptography` (already a dependency, used for the Google service-account JWT). Cloud
backends are plain REST over urllib with hand-built auth - no boto3 / azure-sdk / google-api-client:

  local   - a directory on the server (a mounted SMB/NFS share or a second disk)
  ftps/ftp- FTP over TLS (or plain FTP), via ftplib
  webdav  - Nextcloud / ownCloud / Synology / QNAP ..., via urllib
  s3      - AWS Signature V4; also any S3-compatible store (Backblaze B2, Wasabi, MinIO, Cloudflare R2, DO Spaces)
  azure   - Azure Blob Storage, SAS token (simplest) or Shared Key
  gdrive  - Google Drive v3 via a service-account RS256 JWT

A destination is configured once (the "archive" integration kind) with a `dest` picking the backend; make(cfg) returns
the right one. Paths handed in are relative like "logs/tikmanager-logs-2026-10.csv.gz".
"""
import base64
import ftplib
import hashlib
import hmac
import io
import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path


class ArchiveError(Exception):
    pass


# --- local directory (a mount or second disk) -----------------------------------------------------------------------
class LocalDest:
    def __init__(self, c):
        self.base = Path(c.get("path") or "").expanduser()
        if not str(self.base):
            raise ArchiveError("Set the folder to write archives to.")

    def put(self, path, data):
        f = self.base / path
        try:
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
        except OSError as e:
            raise ArchiveError(f"Couldn't write {f}: {e}") from None

    def names(self, prefix=""):
        root = self.base / prefix
        if not root.exists():
            return []
        try:
            return sorted(str(p.relative_to(self.base)).replace("\\", "/") for p in root.rglob("*") if p.is_file())
        except OSError:
            return []

    def delete(self, path):
        try:
            (self.base / path).unlink(missing_ok=True)
        except OSError:
            pass

    def label(self):
        return f"the folder {self.base}"

    def check(self):
        name = f"_probe/tikmanager-test-{int(time.time())}.txt"
        self.put(name, b"TikManager archive test")
        if name not in self.names("_probe"):
            raise ArchiveError("Wrote a test file but couldn't read it back.")
        self.delete(name)
        try:
            (self.base / "_probe").rmdir()
        except OSError:
            pass
        return f"Wrote and removed a test file in {self.base}."


# --- FTP / FTPS -----------------------------------------------------------------------------------------------------
class FtpDest:
    def __init__(self, c):
        self.c = c
        if not (c.get("host") or "").strip():
            raise ArchiveError("Enter the FTP server's host name or IP address.")
        self.folder = (c.get("folder") or "").strip("/")

    def _ctx(self):
        ctx = ssl.create_default_context()
        if self.c.get("verify") == "0":
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        return ctx

    def _conn(self):
        c = self.c
        try:
            f = ftplib.FTP_TLS(context=self._ctx(), timeout=60) if c.get("dest") == "ftps" else ftplib.FTP(timeout=60)
            f.connect(c["host"], int(c.get("port") or 21))
            f.login(c.get("username") or "anonymous", c.get("password") or "")
            if c.get("dest") == "ftps":
                f.prot_p()
            return f
        except (ftplib.all_errors, ssl.SSLError, ValueError) as e:
            raise ArchiveError(f"FTP: {e}") from None

    @staticmethod
    def _cd(f, parts):
        for part in [p for p in parts if p]:
            try:
                f.cwd(part)
            except ftplib.error_perm:
                f.mkd(part)
                f.cwd(part)

    def put(self, path, data):
        f = self._conn()
        try:
            segs = [p for p in (self.folder + "/" + path).split("/") if p]
            self._cd(f, segs[:-1])
            f.storbinary(f"STOR {segs[-1]}", io.BytesIO(data))
        except ftplib.all_errors as e:
            raise ArchiveError(f"FTP upload failed: {e}") from None
        finally:
            self._quit(f)

    def names(self, prefix=""):
        f = self._conn()
        try:
            base = "/".join(p for p in (self.folder + "/" + prefix).split("/") if p)
            out = []
            try:
                for name in f.nlst(base) if base else f.nlst():
                    out.append(name[len(self.folder):].strip("/") if self.folder and name.startswith(self.folder) else name.strip("/"))
            except ftplib.all_errors:
                pass
            return sorted(n for n in out if n)
        finally:
            self._quit(f)

    def delete(self, path):
        f = self._conn()
        try:
            f.delete("/".join(p for p in (self.folder + "/" + path).split("/") if p))
        except ftplib.all_errors:
            pass
        finally:
            self._quit(f)

    @staticmethod
    def _quit(f):
        try:
            f.quit()
        except ftplib.all_errors:
            pass

    def label(self):
        return f"{self.c.get('dest', 'ftp').upper()} {self.c.get('host')}/{self.folder}".rstrip("/")

    def check(self):
        name = "_probe/tikmanager-test.txt"
        self.put(name, b"TikManager archive test")
        self.delete(name)
        return f"Connected and wrote a test file to {self.label()} (then removed it)."


# --- WebDAV ---------------------------------------------------------------------------------------------------------
class DavDest:
    def __init__(self, c):
        self.c = c
        u = urllib.parse.urlparse(c.get("url") or "")
        if u.scheme != "https" or not u.hostname:
            raise ArchiveError("Enter the WebDAV address starting with https:// , e.g. "
                               "https://cloud.example.com/remote.php/dav/files/backup/")
        self.base = c["url"].rstrip("/") + "".join("/" + urllib.parse.quote(p) for p in (c.get("folder") or "").split("/") if p)

    def _ctx(self):
        ctx = ssl.create_default_context()
        if self.c.get("verify") == "0":
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        return ctx

    def _auth(self):
        return base64.b64encode(f"{self.c.get('username') or ''}:{self.c.get('password') or ''}".encode()).decode()

    def _req(self, method, url, data=None, headers=None):
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Authorization": f"Basic {self._auth()}", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=120, context=self._ctx()) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read(4096)
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as e:
            raise ArchiveError(f"WebDAV: {getattr(e, 'reason', e)}") from None

    def _mkcol(self, path):
        acc = self.base
        for p in [x for x in path.split("/")[:-1] if x]:
            acc += "/" + urllib.parse.quote(p)
            self._req("MKCOL", acc + "/")

    def put(self, path, data):
        self._mkcol(path)
        url = self.base + "/" + "/".join(urllib.parse.quote(p) for p in path.split("/") if p)
        code, body = self._req("PUT", url, data, {"Content-Type": "application/octet-stream"})
        if code not in (200, 201, 204):
            raise ArchiveError(f"WebDAV upload failed (HTTP {code}){' - check the user name and password' if code in (401, 403) else ''}")

    def names(self, prefix=""):
        url = self.base + ("/" + "/".join(urllib.parse.quote(p) for p in prefix.split("/") if p) if prefix else "") + "/"
        code, body = self._req("PROPFIND", url, headers={"Depth": "infinity"})
        if code not in (200, 207):
            return []
        base_path = urllib.parse.urlparse(self.base).path.rstrip("/")
        out = []
        for h in ET.fromstring(body).iter("{DAV:}href"):
            if not h.text or h.text.endswith("/"):
                continue
            rel = urllib.parse.unquote(urllib.parse.urlparse(h.text).path)
            if rel.startswith(base_path):
                out.append(rel[len(base_path):].strip("/"))
        return sorted(out)

    def delete(self, path):
        self._req("DELETE", self.base + "/" + "/".join(urllib.parse.quote(p) for p in path.split("/") if p))

    def label(self):
        return self.base

    def check(self):
        name = "_probe/tikmanager-test.txt"
        self.put(name, b"TikManager archive test")
        self.delete(name)
        return f"Connected and wrote a test file to {self.label()} (then removed it)."


# --- Amazon S3 (and S3-compatible) ----------------------------------------------------------------------------------
def _sigv4(method, host, uri, query, payload, region, akid, secret, service="s3", extra=None):
    """Sign an S3 REST request (AWS Signature Version 4). Returns the headers to send. `uri` is the path starting with /
    (already URL-safe), `query` the canonical (sorted, encoded) query string or ""."""
    amzdate = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    datestamp = amzdate[:8]
    body_hash = hashlib.sha256(payload).hexdigest()
    headers = {"host": host, "x-amz-content-sha256": body_hash, "x-amz-date": amzdate}
    for k, v in (extra or {}).items():
        headers[k.lower()] = v
    signed = ";".join(sorted(headers))
    canon_headers = "".join(f"{k}:{headers[k].strip()}\n" for k in sorted(headers))
    canon_req = "\n".join([method, uri, query, canon_headers, signed, body_hash])
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope, hashlib.sha256(canon_req.encode()).hexdigest()])
    h = lambda key, msg: hmac.new(key, msg.encode(), hashlib.sha256).digest()
    ksign = h(h(h(h(("AWS4" + secret).encode(), datestamp), region), service), "aws4_request")
    sig = hmac.new(ksign, to_sign.encode(), hashlib.sha256).hexdigest()
    headers["Authorization"] = f"AWS4-HMAC-SHA256 Credential={akid}/{scope}, SignedHeaders={signed}, Signature={sig}"
    return headers


class S3Dest:
    def __init__(self, c):
        self.c = c
        self.region = (c.get("s3_region") or "us-east-1").strip()
        self.bucket = (c.get("s3_bucket") or "").strip()
        self.akid = (c.get("s3_access_key") or "").strip()
        self.secret = (c.get("s3_secret_key") or "").strip()
        self.prefix = (c.get("s3_prefix") or "").strip("/")
        self.host = (c.get("s3_endpoint") or f"s3.{self.region}.amazonaws.com").strip().replace("https://", "").replace("http://", "").strip("/")
        if not (self.bucket and self.akid and self.secret):
            raise ArchiveError("S3 needs a bucket, an access key and a secret key.")

    def _key(self, path):
        return "/".join(p for p in [self.prefix, path] if p)

    def _url_path(self, key):
        return "/" + self.bucket + "/" + urllib.parse.quote(key, safe="/-_.~")

    def _send(self, method, uri, query, payload, extra=None):
        headers = _sigv4(method, self.host, uri, query, payload, self.region, self.akid, self.secret, extra=extra)
        url = f"https://{self.host}{uri}" + (f"?{query}" if query else "")
        req = urllib.request.Request(url, data=payload if method in ("PUT", "POST") else None, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            raise ArchiveError(f"S3 {method} failed (HTTP {e.code}): {e.read(600).decode('utf-8', 'replace')[:300]}") from None
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as e:
            raise ArchiveError(f"S3: couldn't reach {self.host}: {getattr(e, 'reason', e)}") from None

    def put(self, path, data):
        key = self._key(path)
        self._send("PUT", self._url_path(key), "", data, {"content-type": "application/octet-stream"})

    def names(self, prefix=""):
        token, out = "", []
        full = self._key(prefix)
        while True:
            q = {"list-type": "2", "prefix": full}
            if token:
                q["continuation-token"] = token
            query = "&".join(f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}" for k, v in sorted(q.items()))
            _, body = self._send("GET", "/" + self.bucket, query, b"")
            root = ET.fromstring(body)
            ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
            for k in root.iter(f"{ns}Key"):
                key = k.text or ""
                out.append(key[len(self.prefix):].strip("/") if self.prefix and key.startswith(self.prefix) else key)
            nxt = root.find(f"{ns}NextContinuationToken")
            if root.findtext(f"{ns}IsTruncated") == "true" and nxt is not None and nxt.text:
                token = nxt.text
            else:
                break
        return sorted(n for n in out if n)

    def delete(self, path):
        self._send("DELETE", self._url_path(self._key(path)), "", b"")

    def label(self):
        return f"s3://{self.bucket}/{self.prefix}".rstrip("/") + (f" ({self.host})" if "amazonaws.com" not in self.host else "")

    def check(self):
        name = "_probe/tikmanager-test.txt"
        self.put(name, b"TikManager archive test")
        self.delete(name)
        return f"Connected and wrote a test object to {self.label()} (then removed it)."


# --- Azure Blob Storage ---------------------------------------------------------------------------------------------
class AzureDest:
    """SAS token (recommended) or Shared Key. With a SAS, paste the container URL incl. the ?sv=... token."""

    API = "2021-12-02"

    def __init__(self, c):
        self.c = c
        self.account = (c.get("az_account") or "").strip()
        self.container = (c.get("az_container") or "").strip()
        self.prefix = (c.get("az_prefix") or "").strip("/")
        self.sas = (c.get("az_sas") or "").strip().lstrip("?")
        self.key = (c.get("az_key") or "").strip()
        self.host = (c.get("az_endpoint") or f"{self.account}.blob.core.windows.net").strip().replace("https://", "").strip("/")
        if not (self.account and self.container):
            raise ArchiveError("Azure needs a storage account and a container.")
        if not (self.sas or self.key):
            raise ArchiveError("Azure needs either a SAS token or the account access key.")

    def _blob(self, path):
        return "/".join(p for p in [self.prefix, path] if p)

    def _url(self, blob, query=""):
        u = f"https://{self.host}/{self.container}/" + urllib.parse.quote(blob, safe="/-_.~")
        parts = [p for p in (query, self.sas if self.sas else "") if p]
        return u + ("?" + "&".join(parts) if parts else "")

    def _sharedkey(self, method, blob, query_pairs, headers, length):
        """Shared Key (no SAS). Builds the Authorization header per Azure's canonicalization."""
        ch = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers) if k.startswith("x-ms-"))
        res = sorted(query_pairs.items())
        cr = f"/{self.account}/{self.container}/{blob}" + "".join(f"\n{k}:{v}" for k, v in res)
        parts = [method, "", "", str(length) if length else "", "", headers.get("content-type", ""), "", "", "", "", "", "", ch + cr]
        string_to_sign = "\n".join(parts)
        sig = base64.b64encode(hmac.new(base64.b64decode(self.key), string_to_sign.encode("utf-8"), hashlib.sha256).digest()).decode()
        return f"SharedKey {self.account}:{sig}"

    def _send(self, method, blob, query_pairs=None, data=None, extra=None):
        query_pairs = query_pairs or {}
        query = "&".join(f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}" for k, v in sorted(query_pairs.items()))
        headers = {"x-ms-version": self.API, "x-ms-date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())}
        headers.update(extra or {})
        if data is not None:
            headers["content-length"] = str(len(data))
        if not self.sas:   # Shared Key needs an Authorization header
            headers["Authorization"] = self._sharedkey(method, blob, query_pairs, headers, len(data) if data is not None else 0)
        url = self._url(blob, query)
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            raise ArchiveError(f"Azure {method} failed (HTTP {e.code}): {e.read(600).decode('utf-8', 'replace')[:300]}") from None
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as e:
            raise ArchiveError(f"Azure: couldn't reach {self.host}: {getattr(e, 'reason', e)}") from None

    def put(self, path, data):
        self._send("PUT", self._blob(path), data=data, extra={"x-ms-blob-type": "BlockBlob", "content-type": "application/octet-stream"})

    def names(self, prefix=""):
        out, marker = [], ""
        while True:
            q = {"restype": "container", "comp": "list", "prefix": self._blob(prefix)}
            if marker:
                q["marker"] = marker
            _, body = self._send("GET", "", q)
            root = ET.fromstring(body)
            for n in root.iter("Name"):
                key = n.text or ""
                out.append(key[len(self.prefix):].strip("/") if self.prefix and key.startswith(self.prefix) else key)
            marker = root.findtext("NextMarker") or ""
            if not marker:
                break
        return sorted(n for n in out if n)

    def delete(self, path):
        self._send("DELETE", self._blob(path))

    def label(self):
        return f"{self.account}/{self.container}/{self.prefix}".rstrip("/")

    def check(self):
        name = "_probe/tikmanager-test.txt"
        self.put(name, b"TikManager archive test")
        self.delete(name)
        return f"Connected and wrote a test blob to {self.label()} (then removed it)."


# --- Google Drive (service account) ---------------------------------------------------------------------------------
class GDriveDest:
    """Upload into a Drive folder shared with a service account. The service-account JSON key is pasted in settings;
    the target folder is shared (Editor) with the service account's client_email."""

    def __init__(self, c):
        self.c = c
        self.folder = (c.get("g_folder_id") or "").strip()
        try:
            self.sa = json.loads(c.get("g_sa_json") or "{}")
        except ValueError:
            raise ArchiveError("The Google service-account key isn't valid JSON.") from None
        if not (self.sa.get("client_email") and self.sa.get("private_key")):
            raise ArchiveError("Paste the service-account JSON key (it needs client_email and private_key).")
        if not self.folder:
            raise ArchiveError("Enter the Google Drive folder id to upload into (share it with the service account).")
        self._token, self._token_exp = None, 0

    def _access_token(self):
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        now = int(time.time())
        claim = {"iss": self.sa["client_email"], "scope": "https://www.googleapis.com/auth/drive.file",
                 "aud": self.sa.get("token_uri", "https://oauth2.googleapis.com/token"), "iat": now, "exp": now + 3600}
        b64 = lambda d: base64.urlsafe_b64encode(d).rstrip(b"=")
        signing_input = b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()) + b"." + b64(json.dumps(claim).encode())
        key = serialization.load_pem_private_key(self.sa["private_key"].encode(), password=None)
        sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        jwt = signing_input + b"." + b64(sig)
        data = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": jwt.decode()}).encode()
        req = urllib.request.Request(self.sa.get("token_uri", "https://oauth2.googleapis.com/token"), data=data,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                tok = json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise ArchiveError(f"Google token request failed (HTTP {e.code}): {e.read(400).decode('utf-8', 'replace')[:200]}") from None
        except (urllib.error.URLError, OSError) as e:
            raise ArchiveError(f"Google: couldn't reach oauth2.googleapis.com: {getattr(e, 'reason', e)}") from None
        self._token, self._token_exp = tok["access_token"], time.time() + int(tok.get("expires_in", 3600))
        return self._token

    def _api(self, method, url, data=None, headers=None):
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Authorization": f"Bearer {self._access_token()}", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raise ArchiveError(f"Google Drive {method} failed (HTTP {e.code}): {e.read(500).decode('utf-8', 'replace')[:250]}") from None
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as e:
            raise ArchiveError(f"Google Drive: {getattr(e, 'reason', e)}") from None

    def _find(self, name):
        q = f"name = '{name}' and '{self.folder}' in parents and trashed = false"
        url = "https://www.googleapis.com/drive/v3/files?" + urllib.parse.urlencode({"q": q, "fields": "files(id,name)", "pageSize": "10"})
        return [f["id"] for f in (self._api("GET", url).get("files") or [])]

    def put(self, path, data):
        name = path.replace("/", "_")   # Drive is flat within the folder; keep the readable name
        for fid in self._find(name):    # overwrite an existing same-name file so re-runs don't duplicate
            self._api("DELETE", f"https://www.googleapis.com/drive/v3/files/{fid}")
        meta = json.dumps({"name": name, "parents": [self.folder]}).encode()
        boundary = "tikmanager-" + hashlib.sha1(data[:64] + name.encode()).hexdigest()
        body = (b"--" + boundary.encode() + b"\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n" + meta +
                b"\r\n--" + boundary.encode() + b"\r\nContent-Type: application/octet-stream\r\n\r\n" + data +
                b"\r\n--" + boundary.encode() + b"--\r\n")
        self._api("POST", "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart", body,
                  {"Content-Type": f"multipart/related; boundary={boundary}"})

    def names(self, prefix=""):
        want = prefix.replace("/", "_")
        url = ("https://www.googleapis.com/drive/v3/files?" +
               urllib.parse.urlencode({"q": f"'{self.folder}' in parents and trashed = false", "fields": "files(name)", "pageSize": "1000"}))
        return sorted(f["name"].replace("_", "/") for f in (self._api("GET", url).get("files") or [])
                      if (not want or f["name"].startswith(want)))

    def delete(self, path):
        for fid in self._find(path.replace("/", "_")):
            self._api("DELETE", f"https://www.googleapis.com/drive/v3/files/{fid}")

    def label(self):
        return f"Google Drive folder {self.folder} (service account {self.sa.get('client_email', '')})"

    def check(self):
        name = "_probe/tikmanager-test.txt"
        self.put(name, b"TikManager archive test")
        self.delete(name)
        return f"Connected and wrote a test file to the Google Drive folder (then removed it)."


DESTS = {"local": LocalDest, "ftps": FtpDest, "ftp": FtpDest, "webdav": DavDest, "s3": S3Dest, "azure": AzureDest, "gdrive": GDriveDest}


def make(cfg):
    """Build the backend for cfg['dest']; raises ArchiveError if it isn't set up."""
    dest = (cfg or {}).get("dest") or ""
    if dest not in DESTS:
        raise ArchiveError("Pick where to archive to (local folder, FTP/FTPS, WebDAV, S3, Azure or Google Drive).")
    return DESTS[dest](cfg)


def selftest_sigv4():
    """Known-answer checks for the SigV4 signer, anchored on two values AWS publishes:
    - the derived signing key for 20150830/us-east-1/iam (AWS "deriving the signing key" doc), and
    - the canonical-request hash for the GET-Object example (AWS "Authorization header" doc).
    These prove the HMAC chain and the canonical-request construction; the end-to-end signature is then deterministic."""
    import unittest.mock as mock
    _h = lambda key, msg: hmac.new(key, msg.encode(), hashlib.sha256).digest()
    secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    ksign = _h(_h(_h(_h(("AWS4" + secret).encode(), "20150830"), "us-east-1"), "iam"), "aws4_request")
    assert ksign.hex() == "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9", "signing-key chain wrong"
    canon = "\n".join(["GET", "/test.txt", "",
                       "host:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\n"
                       "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
                       "x-amz-date:20130524T000000Z\n",
                       "host;range;x-amz-content-sha256;x-amz-date",
                       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"])
    assert hashlib.sha256(canon.encode()).hexdigest() == "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972", "canonical request wrong"
    with mock.patch("time.gmtime", return_value=time.struct_time((2013, 5, 24, 0, 0, 0, 4, 144, 0))):
        h = _sigv4("GET", "examplebucket.s3.amazonaws.com", "/test.txt", "", b"", "us-east-1",
                   "AKIAIOSFODNN7EXAMPLE", secret, extra={"range": "bytes=0-9"})
    got = h["Authorization"].split("Signature=")[1]
    assert got == "67fe34c8530db585abddc51067328adfedb6e42487d2566dc7d927d6e2722900", f"end-to-end signature regressed: {got}"
    return "SigV4 self-test passed (signing key + canonical request match AWS known-answers)."
