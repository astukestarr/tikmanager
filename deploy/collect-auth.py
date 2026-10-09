#!/usr/bin/env python3
"""Collect sign-in attempts on this Ubuntu server for TikManager's Security page - read-only, run as root every 5
minutes by tikmanager-authlog.timer (the web app can't read the system journal or fail2ban's log itself).

Reads, since the last run: SSH sign-ins (failed and accepted) and sudo password failures from the systemd journal, and
fail2ban's bans from /var/log/fail2ban.log. Writes the newest events (up to 5000) to
/var/lib/tikmanager-update/auth-events.json (readable by the tikmanager service; TikManager imports them and skips
ones it already has). Where it got to is kept in a root-only state file. It changes nothing else.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time

STATE_DIR = "/var/lib/tikmanager-update"
OUT = f"{STATE_DIR}/auth-events.json"
STATE = f"{STATE_DIR}/.authlog-state.json"
F2B_LOG = "/var/log/fail2ban.log"
KEEP = 5000

SSH_FAIL = re.compile(r"Failed (password|publickey|keyboard-interactive/pam) for (\S+) from (\S+) port")
SSH_INVALID = re.compile(r"Invalid user (\S*) from (\S+)")
SSH_OK = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port")
SUDO_FAIL = re.compile(r"^\s*(\S+) : (\d+) incorrect password attempts?")
F2B_BAN = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d).*\[(\S+)\] Ban (\S+)")


def load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def journal(state):
    """New sshd / sudo journal entries -> events; remembers the journal cursor."""
    cmd = ["journalctl", "-o", "json", "--no-pager", "-t", "sshd", "-t", "sshd-session", "-t", "sudo"]
    cmd += ["--after-cursor", state["cursor"]] if state.get("cursor") else ["--since", "-24h"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    events = []
    for line in out.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        state["cursor"] = e.get("__CURSOR") or state.get("cursor")
        msg = e.get("MESSAGE")
        if isinstance(msg, list):   # non-UTF-8 messages come as byte lists
            msg = bytes(msg).decode("utf-8", "replace")
        msg = str(msg or "")
        ts = int(e.get("__REALTIME_TIMESTAMP") or 0) / 1e6 or time.time()
        if m := SSH_INVALID.search(msg):   # no such account (the "Failed password for invalid user" line after it is the same attempt)
            events.append({"ts": ts, "kind": "login_failed", "user": m.group(1), "ip": m.group(2), "via": "ssh", "detail": "no such user"})
        elif (m := SSH_FAIL.search(msg)) and m.group(2) != "invalid":
            events.append({"ts": ts, "kind": "login_failed", "user": m.group(2), "ip": m.group(3), "via": "ssh", "detail": m.group(1)})
        elif m := SSH_OK.search(msg):
            events.append({"ts": ts, "kind": "login_ok", "user": m.group(2), "ip": m.group(3), "via": "ssh", "detail": m.group(1)})
        elif m := SUDO_FAIL.search(msg):
            events.append({"ts": ts, "kind": "sudo_failed", "user": m.group(1), "ip": "", "via": "sudo", "detail": f"{m.group(2)} wrong password(s)"})
    return events


def fail2ban(state):
    """New "Ban" lines in fail2ban's log -> events; follows the file across log rotation."""
    try:
        st = os.stat(F2B_LOG)
    except OSError:
        return []
    pos = state.get("f2b_pos", 0) if state.get("f2b_inode") == st.st_ino and state.get("f2b_pos", 0) <= st.st_size else 0
    events = []
    with open(F2B_LOG, encoding="utf-8", errors="replace") as f:
        f.seek(pos)
        for line in f:
            if m := F2B_BAN.search(line):
                ts = time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"))
                events.append({"ts": ts, "kind": "banned", "user": "", "ip": m.group(3), "via": "fail2ban", "detail": f"blocked by fail2ban ({m.group(2)})"})
        state["f2b_pos"], state["f2b_inode"] = f.tell(), st.st_ino
    return events


def main():
    if os.geteuid() != 0:
        sys.exit("Run as root (it reads the system journal).")
    os.makedirs(STATE_DIR, exist_ok=True)
    state = load(STATE, {})
    new = journal(state) + fail2ban(state)
    old = load(OUT, {}).get("events") or []
    events = (old + new)[-KEEP:]
    fd, tmp = tempfile.mkstemp(dir=STATE_DIR, prefix=".auth-events.")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"at": time.time(), "events": events}, f)
    try:
        import grp
        os.chown(tmp, 0, grp.getgrnam("tikmanager").gr_gid)
    except (KeyError, OSError):
        pass
    os.chmod(tmp, 0o640)
    os.replace(tmp, OUT)
    fd, tmp = tempfile.mkstemp(dir=STATE_DIR, prefix=".authlog-state.")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE)


if __name__ == "__main__":
    main()
