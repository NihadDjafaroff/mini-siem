"""Explainable per-user/per-host login baseline. Rules, not ML: every flag carries its reasoning.

Cold start: a subject with fewer than ``min_samples`` training logins has NO baseline, and
logins for it are never flagged (counted in ``cold_start_skips``) -- better silent than noisy.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .ecs import event_ts, get_path
from .models import Alert, Severity


def is_successful_login(ev: dict) -> bool:
    cat = get_path(ev, "event.category") or []
    cat = cat if isinstance(cat, list) else [cat]
    return "authentication" in cat and get_path(ev, "event.outcome") == "success"


def subject_of(ev: dict) -> str | None:
    u = get_path(ev, "user.name")
    if u:
        return f"user:{u}"
    h = get_path(ev, "host.name")
    return f"host:{h}" if h else None


def hour_ranges(hours) -> str:
    hs = sorted(set(hours))
    runs, start, prev = [], None, None
    for h in hs:
        if start is None:
            start = prev = h
        elif h == prev + 1:
            prev = h
        else:
            runs.append((start, prev))
            start = prev = h
    if start is not None:
        runs.append((start, prev))
    return ", ".join(f"{a:02d}:00–{b:02d}:59" for a, b in runs)


class Baseline:
    def __init__(self, min_samples: int = 5):
        self.min_samples = min_samples
        self.subjects: dict[str, dict] = {}
        self.cold_start_skips = 0

    def train(self, events, until: datetime | None = None) -> int:
        n = 0
        for ev in events:
            if not is_successful_login(ev):
                continue
            ts = event_ts(ev)
            if until and ts >= until:
                continue
            s = subject_of(ev)
            if not s:
                continue
            rec = self.subjects.setdefault(s, {"logins": 0, "hours": {}, "countries": {}, "ips": {}})
            rec["logins"] += 1
            rec["hours"][str(ts.hour)] = rec["hours"].get(str(ts.hour), 0) + 1
            cc = get_path(ev, "source.geo.country_iso_code")
            if cc:
                rec["countries"][cc] = rec["countries"].get(cc, 0) + 1
            ip = get_path(ev, "source.ip")
            if ip:
                rec["ips"][ip] = rec["ips"].get(ip, 0) + 1
            n += 1
        return n

    def check(self, ev: dict) -> list[Alert]:
        if not is_successful_login(ev):
            return []
        s = subject_of(ev)
        rec = self.subjects.get(s) if s else None
        if not rec or rec["logins"] < self.min_samples:
            self.cold_start_skips += 1
            return []
        ts, name, out = event_ts(ev), s.split(":", 1)[1], []
        kind = s.split(":", 1)[0]
        if str(ts.hour) not in rec["hours"]:
            normal = hour_ranges(int(h) for h in rec["hours"])
            why = (f"{kind} {name} normally logs in {normal} UTC ({rec['logins']} logins observed); "
                   f"this login was at {ts:%H:%M} UTC")
            out.append(Alert("baseline.unusual_hour", "Login at unusual hour", Severity.LOW, ts, "anomaly",
                             f"{kind} {name}: login at never-seen hour {ts:%H}:00 UTC",
                             group={f"{kind}": name}, event=ev, reasoning=why, tags=["anomaly", "baseline"]))
        cc = get_path(ev, "source.geo.country_iso_code")
        if cc and rec["countries"] and cc not in rec["countries"]:
            known = ", ".join(sorted(rec["countries"]))
            why = (f"{kind} {name} has only logged in from {known} ({rec['logins']} logins observed); "
                   f"this login came from {cc} (source.ip {get_path(ev, 'source.ip')})")
            out.append(Alert("baseline.new_country", "Login from new country", Severity.MEDIUM, ts, "anomaly",
                             f"{kind} {name}: login from never-seen country {cc}",
                             group={f"{kind}": name}, event=ev, reasoning=why, tags=["anomaly", "baseline"]))
        return out

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps({"min_samples": self.min_samples, "subjects": self.subjects},
                                         indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "Baseline":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        b = cls(d.get("min_samples", 5))
        b.subjects = d["subjects"]
        return b
