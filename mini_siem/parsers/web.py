"""Apache / Nginx access logs, combined and common format.

Modeled after: Filebeat `apache`/`nginx` modules.
"""
from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urlsplit

from ..ecs import build, fmt_ts
from ..models import ParseError
from . import Parser, register

_LINE = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?\s*$')


@register
class WebAccessParser(Parser):
    name = "web"
    dataset = "web.access"
    description = "Apache/Nginx combined or common access log"

    def can_parse(self, raw: str) -> bool:
        return bool(_LINE.match(raw))

    def parse(self, raw: str, ctx: dict | None = None) -> dict:
        m = _LINE.match(raw)
        if not m:
            raise ParseError("not an Apache/Nginx common/combined log line")
        try:
            ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError as exc:
            raise ParseError(f"bad timestamp: {exc}")
        parts = m["req"].split(" ")
        if len(parts) == 3:
            method, url, ver = parts
        elif len(parts) == 2:
            (method, url), ver = parts, None
        else:  # e.g. binary junk / TLS probe on port 80 -> still a real record
            method, url, ver = None, m["req"], None
        status = int(m["status"])
        sp = urlsplit(url) if url else None
        flat = {
            "@timestamp": fmt_ts(ts), "source.ip": m["ip"],
            "user.name": None if m["user"] == "-" else m["user"],
            "event.category": ["web"], "event.type": ["access"], "event.action": "http_request",
            "event.outcome": "success" if status < 400 else "failure",
            "http.request.method": method, "http.version": ver.replace("HTTP/", "") if ver else None,
            "http.response.status_code": status,
            "http.response.body.bytes": None if m["bytes"] == "-" else int(m["bytes"]),
            "http.request.referrer": None if m["ref"] in (None, "-") else m["ref"],
            "user_agent.original": None if m["ua"] in (None, "-") else m["ua"],
            "url.original": url, "url.path": sp.path if sp else None,
            "url.query": sp.query if sp and sp.query else None,
        }
        import ipaddress
        try:
            ipaddress.ip_address(m["ip"])
        except ValueError:
            raise ParseError(f"invalid client ip {m['ip']!r}")
        return build(flat)
