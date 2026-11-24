"""Filtering over normalized events (not just alerts)."""
from __future__ import annotations

from datetime import datetime

from .ecs import event_ts, get_path


def _as_list(v):
    return v if isinstance(v, list) else [v]


def filter_events(events, user=None, ip=None, since: datetime | None = None, until: datetime | None = None,
                  event_type=None, limit: int | None = None):
    out = []
    for ev in events:
        if user and str(get_path(ev, "user.name") or "").lower() != user.lower():
            continue
        if ip and ip not in (str(get_path(ev, "source.ip") or ""), str(get_path(ev, "destination.ip") or "")):
            continue
        ts = event_ts(ev)
        if since and ts < since:
            continue
        if until and ts > until:
            continue
        if event_type:
            et = event_type.lower()
            vals = [*_as_list(get_path(ev, "event.action")), *_as_list(get_path(ev, "event.category")),
                    *_as_list(get_path(ev, "event.type")), *_as_list(get_path(ev, "event.code"))]
            if et not in {str(v).lower() for v in vals if v is not None}:
                continue
        out.append(ev)
    out.sort(key=event_ts)
    return out[:limit] if limit else out
