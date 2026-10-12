"""Sending email from TikManager (Admin > Integrations > Email): alerts, client invitations, tests.

- Microsoft 365 (recommended for Microsoft 365 tenants): the Graph API's sendMail with an app registration's client
  credentials (application permission Mail.Send). Limit that app to the one sending mailbox with an Exchange
  application access policy / RBAC for Applications - otherwise Mail.Send can send as anyone in the tenant. Microsoft
  is retiring basic-auth SMTP for Microsoft 365, so this is the way that keeps working there.
- SMTP: any provider (Google Workspace, SendGrid, Mailgun, your own server) with STARTTLS (587) or TLS (465); the
  certificate is checked. Unencrypted SMTP is only allowed to a relay on this server itself (localhost).
- Credentials are stored encrypted (integrations.py, "mail"); never sent back to the browser. Addresses and subjects are
  validated so nothing can be injected into the message headers. At most MAX_PER_HOUR messages an hour.
"""
import json
import re
import smtplib
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

from version import __version__

ADDRESS = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
MAX_PER_HOUR = 200


class MailError(Exception):
    pass


def addresses(value):
    """'a@x.com, b@y.org' -> ['a@x.com', 'b@y.org']; refuses anything that isn't a plain address."""
    out = [a.strip() for a in re.split(r"[,;\s]+", str(value or "")) if a.strip()]
    bad = [a for a in out if not ADDRESS.match(a) or len(a) > 254]
    if bad:
        raise MailError(f"Not an email address: {bad[0][:60]}")
    return out


class Mailer:
    def __init__(self, integ, settings):
        self.integ, self.s = integ, settings
        self._sent = []
        self._token = (None, 0)
        self.lock = threading.Lock()

    def config(self):
        c = self.integ.config("mail")
        c.setdefault("provider", "graph")
        c.setdefault("security", "starttls")
        return c

    def configured(self):
        return self.integ.configured("mail")

    @staticmethod
    def validate(c):
        if c.get("provider") not in ("graph", "smtp"):
            raise ValueError("Pick Microsoft 365 or SMTP.")
        try:
            if c.get("from_address"):
                addresses(c["from_address"])
        except MailError as e:
            raise ValueError(str(e)) from None
        if re.search(r"[\r\n<>\"]", c.get("from_name") or ""):
            raise ValueError("The sender name can't contain quotes, < > or line breaks.")
        if c.get("provider") == "graph":
            for k in ("tenant_id", "client_id"):
                if c.get(k) and not re.fullmatch(r"[0-9a-fA-F-]{36}", c[k]):
                    raise ValueError("Tenant and client IDs look like 00000000-0000-0000-0000-000000000000.")
        else:
            if c.get("host") and not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", c["host"]):
                raise ValueError("The SMTP server is a host name, e.g. smtp.example.com.")
            if c.get("port") and not (str(c["port"]).isdigit() and 0 < int(c["port"]) < 65536):
                raise ValueError("The port is a number, usually 587 (STARTTLS) or 465 (TLS).")
            if c.get("security") not in ("starttls", "tls", "none"):
                raise ValueError("Pick STARTTLS, TLS or none.")
            if c.get("security") == "none" and (c.get("host") or "") not in ("localhost", "127.0.0.1", "::1"):
                raise ValueError("Unencrypted SMTP is only allowed to a mail relay on this server (localhost).")

    # --- sending --------------------------------------------------------------------------------------------------
    def send(self, to, subject, text, html=None):
        if not self.configured():
            raise MailError("Email isn't set up (Admin > Integrations > Email).")
        rcpt = addresses(to) if isinstance(to, str) else addresses(",".join(to))
        if not rcpt:
            raise MailError("No recipients.")
        subject = re.sub(r"[\r\n]+", " ", str(subject))[:200]
        with self.lock:
            now = time.time()
            self._sent = [t for t in self._sent if now - t < 3600]
            if len(self._sent) >= MAX_PER_HOUR:
                raise MailError(f"Not sent: more than {MAX_PER_HOUR} emails in the last hour.")
            self._sent.append(now)
        c = self.config()
        (self._graph if c["provider"] == "graph" else self._smtp)(c, rcpt, subject, text, html)
        return len(rcpt)

    def _smtp(self, c, rcpt, subject, text, html):
        sender = c.get("from_address") or c.get("username")
        if not sender:
            raise MailError("Set the From address.")
        m = EmailMessage()
        m["From"] = formataddr((c.get("from_name") or "TikManager", sender))
        m["To"] = ", ".join(rcpt)
        m["Subject"] = subject
        m["Message-ID"] = make_msgid(domain=sender.split("@")[-1])
        m["X-Mailer"] = f"TikManager {__version__}"
        m.set_content(text)
        if html:
            m.add_alternative(html, subtype="html")
        port = int(c.get("port") or (465 if c.get("security") == "tls" else 587))
        ctx = ssl.create_default_context()
        try:
            if c.get("security") == "tls":
                srv = smtplib.SMTP_SSL(c["host"], port, context=ctx, timeout=30)
            else:
                srv = smtplib.SMTP(c["host"], port, timeout=30)
                if c.get("security") == "starttls":
                    srv.starttls(context=ctx)
            with srv:
                if c.get("username"):
                    srv.login(c["username"], c.get("password") or "")
                srv.send_message(m)
        except (smtplib.SMTPException, OSError, ssl.SSLError) as e:
            raise MailError(f"SMTP: {e}") from None

    def _graph_token(self, c):
        tok, exp = self._token
        if tok and time.time() < exp - 60:
            return tok
        body = urllib.parse.urlencode({"client_id": c.get("client_id"), "client_secret": c.get("client_secret") or "",
                                       "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"}).encode()
        req = urllib.request.Request(f"https://login.microsoftonline.com/{urllib.parse.quote(c.get('tenant_id') or '')}/oauth2/v2.0/token", data=body)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                d = json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise MailError(f"Microsoft sign-in failed: {json.loads(e.read() or b'{}').get('error_description', e.code)}"[:300]) from None
        except (urllib.error.URLError, OSError) as e:
            raise MailError(f"Couldn't reach Microsoft: {getattr(e, 'reason', e)}") from None
        self._token = (d["access_token"], time.time() + int(d.get("expires_in") or 3600))
        return d["access_token"]

    def _graph(self, c, rcpt, subject, text, html):
        sender = c.get("from_address")
        if not sender:
            raise MailError("Set the mailbox to send from.")
        msg = {"message": {"subject": subject, "body": {"contentType": "HTML" if html else "Text", "content": html or text},
                           "toRecipients": [{"emailAddress": {"address": a}} for a in rcpt]}, "saveToSentItems": False}
        req = urllib.request.Request(f"https://graph.microsoft.com/v1.0/users/{urllib.parse.quote(sender)}/sendMail",
                                     data=json.dumps(msg).encode(), method="POST",
                                     headers={"Authorization": f"Bearer {self._graph_token(c)}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30):
                pass
        except urllib.error.HTTPError as e:
            detail = (json.loads(e.read() or b"{}").get("error") or {}).get("message", "")
            hint = {401: " - check the client secret", 403: " - the app needs the Mail.Send application permission (with admin consent) "
                                                             "and access to this mailbox", 404: " - check the sending mailbox exists"}.get(e.code, "")
            raise MailError(f"Microsoft 365 said {e.code}: {detail[:200]}{hint}") from None
        except (urllib.error.URLError, OSError) as e:
            raise MailError(f"Couldn't reach Microsoft: {getattr(e, 'reason', e)}") from None
