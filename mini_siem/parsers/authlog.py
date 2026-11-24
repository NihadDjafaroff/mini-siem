"""Linux auth.log / syslog plain-text lines (RFC 3164 style, or rsyslog ISO timestamps).

Modeled after: Filebeat `system` module (auth/syslog filesets), Wazuh logcollector.
Also exports ``parse_message`` which the syslog (RFC 5424) parser reuses for sshd/sudo text.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from ..ecs import build, fmt_ts, parse_ts
from ..models import ParseError
from . import Parser, register

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

_LINE_3164 = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
_LINE_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s+(?P<tag>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")

_FAILED = re.compile(r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
_SUDO = re.compile(r"^\s*(?P<user>\S+)\s*:.*?USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$")
_SESSION = re.compile(r"session (?P<what>opened|closed) for user (?P<user>\S+)")


def parse_message(tag: str, msg: str) -> dict:
    """Extract ECS fields from the free-text part of sshd/sudo/etc. messages (flat dotted keys)."""
    f: dict = {}
    if tag.startswith("sshd"):
        if m := _FAILED.match(msg):
            f.update({"event.category": ["authentication"], "event.type": ["start"],
                      "event.action": "ssh_login", "event.outcome": "failure",
                      "user.name": m["user"], "source.ip": m["ip"], "source.port": int(m["port"]),
                      "labels.auth_method": m["method"]})
            if m["invalid"]:
                f["labels.invalid_user"] = "true"
        elif m := _ACCEPTED.match(msg):
            f.update({"event.category": ["authentication"], "event.type": ["start"],
                      "event.action": "ssh_login", "event.outcome": "success",
                      "user.name": m["user"], "source.ip": m["ip"], "source.port": int(m["port"]),
                      "labels.auth_method": m["method"]})
        elif m := _INVALID.match(msg):
            f.update({"event.category": ["authentication"], "event.action": "invalid_user",
                      "event.outcome": "failure", "user.name": m["user"] or None, "source.ip": m["ip"],
                      "source.port": int(m["port"]) if m["port"] else None})
    elif tag.startswith("sudo"):
        if m := _SUDO.match(msg):
            f.update({"event.category": ["process", "iam"], "event.action": "sudo", "event.outcome": "success",
                      "user.name": m["user"], "user.effective.name": m["target"],
                      "process.command_line": m["cmd"].strip()})
    if not f and (m := _SESSION.search(msg)):
        f.update({"event.category": ["authentication"], "event.action": f"session_{m['what']}",
                  "user.name": m["user"]})
    return f


def _validate_ip(flat: dict) -> None:
    import ipaddress
    ip = flat.get("source.ip")
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ParseError(f"invalid source.ip {ip!r}")


@register
class AuthLogParser(Parser):
    name = "authlog"
    dataset = "system.auth"
    description = "Linux auth.log / syslog text lines (sshd, sudo, ...)"

    def can_parse(self, raw: str) -> bool:
        return bool(_LINE_3164.match(raw) or _LINE_ISO.match(raw))

    def parse(self, raw: str, ctx: dict | None = None) -> dict:
        ctx = ctx or {}
        if m := _LINE_ISO.match(raw):
            ts = parse_ts(m["ts"])
        elif m := _LINE_3164.match(raw):
            year = ctx.get("default_year") or datetime.now(timezone.utc).year
            mon = MONTHS.get(m["mon"])
            if not mon:
                raise ParseError(f"bad month {m['mon']!r}")
            h, mi, s = map(int, m["time"].split(":"))
            ts = datetime(year, mon, int(m["day"]), h, mi, s, tzinfo=timezone.utc)
        else:
            raise ParseError("not an auth.log/syslog line")
        flat = {"@timestamp": fmt_ts(ts), "host.name": m["host"], "process.name": m["tag"],
                "process.pid": int(m["pid"]) if m["pid"] else None, "message": m["msg"]}
        flat.update(parse_message(m["tag"], m["msg"]))
        _validate_ip(flat)
        return build(flat)
