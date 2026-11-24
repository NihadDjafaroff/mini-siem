"""ECS helpers: dotted-path <-> nested dict mapping and timestamp handling."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any


def get_path(d: dict, path: str) -> Any:
    """Read ``a.b.c`` from a nested dict (a literal flat key 'a.b.c' also works)."""
    if path in d:
        return d[path]
    cur: Any = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def set_path(d: dict, path: str, value: Any) -> None:
    parts = path.split(".")
    cur = d
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[p] = nxt
        cur = nxt
    cur[parts[-1]] = value


def build(flat: dict) -> dict:
    """Turn {'source.ip': x} into {'source': {'ip': x}}, skipping None/empty values."""
    out: dict = {}
    for k, v in flat.items():
        if v is None or v == "":
            continue
        set_path(out, k, v)
    return out


def fmt_ts(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


_TS_FIX = re.compile(r"^(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}:\d{2})(\.\d+)?\s*(Z|[+-]\d{2}:?\d{2})?)?$")


def parse_ts(value: Any) -> datetime:
    """Parse ISO-8601 / Sysmon UtcTime / epoch into an aware UTC datetime."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    s = str(value).strip()
    m = _TS_FIX.match(s)
    if not m:
        raise ValueError(f"unparseable timestamp: {value!r}")
    date, tm, frac, tz = m.groups()
    frac = (frac or ".0")[:7]
    dt = datetime.strptime(f"{date} {tm or '00:00:00'}{frac}", "%Y-%m-%d %H:%M:%S.%f")
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        off = timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
        return (dt - sign * off).replace(tzinfo=timezone.utc)
    return dt.replace(tzinfo=timezone.utc)


def event_ts(ev: dict) -> datetime:
    return parse_ts(ev["@timestamp"])


_SPAN = re.compile(r"^\s*(\d+)\s*([smhd])\s*$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_span(s: str) -> timedelta:
    m = _SPAN.match(str(s))
    if not m:
        raise ValueError(f"invalid time span {s!r} (use e.g. 30s, 5m, 1h, 1d)")
    return timedelta(seconds=int(m.group(1)) * _UNITS[m.group(2)])


def parse_since(s: str, now: datetime | None = None) -> datetime:
    """'1h' / '2d' (relative to now), 'today', or an ISO timestamp."""
    now = now or datetime.now(timezone.utc)
    s = s.strip()
    if s == "today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    if _SPAN.match(s):
        return now - parse_span(s)
    return parse_ts(s)
