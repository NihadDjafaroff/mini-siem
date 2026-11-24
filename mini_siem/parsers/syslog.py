"""RFC 5424 syslog messages (what the UDP/TCP receiver feeds in); RFC 3164 accepted as fallback.

Modeled after: rsyslog/syslog-ng forwarding, Filebeat `syslog` input, Wazuh remote syslog.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from ..ecs import build, fmt_ts, parse_ts
from ..models import ParseError
from . import Parser, register
from .authlog import MONTHS, parse_message, _validate_ip

NIL = "-"
_5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>[1-9]\d{0,2}) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) "
    r"(?P<procid>\S+) (?P<msgid>\S+) (?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (?P<msg>.*))?$", re.S)
_3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
_SD_ELEM = re.compile(r"\[(?P<id>[^\s\]=]+)(?P<params>(?:\s+[^\s=]+=\"(?:[^\"\\]|\\.)*\")*)\]")
_SD_PARAM = re.compile(r"([^\s=]+)=\"((?:[^\"\\]|\\.)*)\"")

FACILITIES = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
              "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2",
              "local3", "local4", "local5", "local6", "local7"]


def _pri(pri: str) -> dict:
    p = int(pri)
    if p > 191:
        raise ParseError(f"invalid PRI {p} (max 191)")
    fac, sev = divmod(p, 8)
    return {"log.syslog.priority": p, "log.syslog.facility.code": fac,
            "log.syslog.facility.name": FACILITIES[fac], "log.syslog.severity.code": sev}


def _nil(v: str | None):
    return None if v in (None, NIL) else v


def parse_sd(sd: str) -> dict:
    out: dict = {}
    if sd == NIL:
        return out
    for m in _SD_ELEM.finditer(sd):
        out[m["id"]] = {k: v.replace('\\"', '"').replace("\\]", "]").replace("\\\\", "\\")
                        for k, v in _SD_PARAM.findall(m["params"])}
    return out


@register
class SyslogParser(Parser):
    name = "syslog"
    dataset = "syslog"
    description = "RFC 5424 syslog (RFC 3164 fallback)"

    def can_parse(self, raw: str) -> bool:
        return bool(_5424.match(raw) or _3164.match(raw))

    def parse(self, raw: str, ctx: dict | None = None) -> dict:
        ctx = ctx or {}
        if m := _5424.match(raw):
            if m["ts"] == NIL:
                raise ParseError("RFC 5424 record has NILVALUE timestamp")
            flat = {"@timestamp": fmt_ts(parse_ts(m["ts"])), "host.name": _nil(m["host"]),
                    "process.name": _nil(m["app"]), "event.code": _nil(m["msgid"]),
                    "message": (m["msg"] or "").lstrip("\ufeff")}
            pid = _nil(m["procid"])
            if pid and pid.isdigit():
                flat["process.pid"] = int(pid)
            flat.update(_pri(m["pri"]))
            tag = flat.get("process.name") or ""
            out = build(flat)
            sd = parse_sd(m["sd"])
            if sd:
                out["log"]["syslog"]["structured_data"] = sd
        elif m := _3164.match(raw):
            year = ctx.get("default_year") or datetime.now(timezone.utc).year
            h, mi, s = map(int, m["time"].split(":"))
            try:
                ts = datetime(year, MONTHS[m["mon"]], int(m["day"]), h, mi, s, tzinfo=timezone.utc)
            except (KeyError, ValueError) as exc:
                raise ParseError(f"bad RFC 3164 timestamp: {exc}")
            flat = {"@timestamp": fmt_ts(ts), "host.name": m["host"], "process.name": m["tag"],
                    "process.pid": int(m["pid"]) if m["pid"] else None, "message": m["msg"]}
            flat.update(_pri(m["pri"]))
            tag = m["tag"]
            out = build(flat)
        else:
            raise ParseError("not an RFC 5424 / RFC 3164 syslog message")
        extra = parse_message(tag, out.get("message", ""))
        _validate_ip(extra)
        for k, v in build(extra).items():
            if isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k].update(v)
            else:
                out[k] = v
        if ctx.get("sender"):
            out.setdefault("observer", {})["ip"] = ctx["sender"]
        return out
