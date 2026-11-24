"""Sigma Correlation Rules: event_count, value_count, temporal, temporal_ordered.

Targets the SigmaHQ correlation-rule schema (``correlation:`` block with ``type``, ``rules``,
``group-by``, ``timespan``, ``condition``). Window semantics: an event belongs to the window if
``event_ts >= trigger_ts - timespan`` (boundary inclusive).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from .ecs import get_path, parse_span
from .models import Severity
from .sigma import RuleError

TYPES = {"event_count", "value_count", "temporal", "temporal_ordered"}
OPS = {"gte": lambda a, b: a >= b, "gt": lambda a, b: a > b, "lte": lambda a, b: a <= b,
       "lt": lambda a, b: a < b, "eq": lambda a, b: a == b}


@dataclass
class Entry:
    ts: datetime
    ref: str
    value: object
    ev: dict


@dataclass
class CorrMatch:
    correlation: "Correlation"
    group: dict
    count: int
    first_ts: datetime
    last_ts: datetime
    events: list
    message: str


class Correlation:
    kind = "correlation"

    def __init__(self, doc: dict, path: str = ""):
        c = doc.get("correlation")
        if not isinstance(c, dict):
            raise RuleError(f"{path}: missing 'correlation' block")
        self.path = path
        self.title = doc.get("title") or ""
        if not self.title:
            raise RuleError(f"{path}: correlation needs a title")
        self.id, self.name = str(doc.get("id", "")), doc.get("name")
        self.description = doc.get("description", "")
        self.tags = doc.get("tags", []) or []
        try:
            self.level = Severity.from_level(doc.get("level"))
        except ValueError as exc:
            raise RuleError(f"{path}: {exc}")
        self.type = c.get("type")
        if self.type not in TYPES:
            raise RuleError(f"{path}: correlation type must be one of {sorted(TYPES)}, got {self.type!r}")
        refs = c.get("rules", c.get("rule"))
        self.ref_names = [refs] if isinstance(refs, str) else list(refs or [])
        if not self.ref_names:
            raise RuleError(f"{path}: correlation needs 'rules'")
        gb = c.get("group-by", [])
        self.group_by = [gb] if isinstance(gb, str) else list(gb or [])
        if "timespan" not in c:
            raise RuleError(f"{path}: correlation needs 'timespan'")
        try:
            self.timespan: timedelta = parse_span(c["timespan"])
        except ValueError as exc:
            raise RuleError(f"{path}: {exc}")
        self.generate = bool(c.get("generate", False))
        self.cond = c.get("condition") or {}
        if self.type in ("event_count", "value_count"):
            ops = {k: v for k, v in self.cond.items() if k != "field"}
            if not ops:
                raise RuleError(f"{path}: {self.type} needs a condition (gte/gt/lte/lt/eq)")
            for k, v in ops.items():
                if k not in OPS:
                    raise RuleError(f"{path}: unknown condition operator '{k}'")
                if not isinstance(v, int) or isinstance(v, bool):
                    raise RuleError(f"{path}: condition '{k}' must be an integer")
            if self.type == "value_count" and not self.cond.get("field"):
                raise RuleError(f"{path}: value_count needs condition.field")
        self.refs: list = []          # resolved by the loader
        self._state: dict = {}

    @property
    def uid(self) -> str:
        return self.name or self.id or self.title

    def reset(self) -> None:
        self._state.clear()

    def _check(self, n: int) -> bool:
        return all(OPS[k](n, v) for k, v in self.cond.items() if k != "field")

    def feed(self, ref_uid: str, ev: dict, ts: datetime) -> CorrMatch | None:
        group = tuple(get_path(ev, f) for f in self.group_by)
        if any(g is None for g in group):
            return None  # event lacks a group-by field: cannot be attributed to a group
        value = None
        if self.type == "value_count":
            value = get_path(ev, self.cond["field"])
            if value is None:
                return None
        dq = self._state.setdefault(group, deque())
        dq.append(Entry(ts, ref_uid, value, ev))
        cutoff = ts - self.timespan
        while dq and dq[0].ts < cutoff:
            dq.popleft()
        gdict = dict(zip(self.group_by, group))
        label = ", ".join(f"{k}={v}" for k, v in gdict.items()) or "all events"
        span = self.cond and self.timespan
        win = _fmt(self.timespan)

        if self.type == "event_count":
            n = len(dq)
            if self._check(n):
                return CorrMatch(self, gdict, n, dq[0].ts, ts, [e.ev for e in dq],
                                 f"{n} matching events ({', '.join(self.ref_names)}) for {label} within {win}")
            return None
        if self.type == "value_count":
            vals = {str(e.value) for e in dq}
            n = len(vals)
            if self._check(n):
                return CorrMatch(self, gdict, n, dq[0].ts, ts, [e.ev for e in dq],
                                 f"{n} distinct values of {self.cond['field']} for {label} within {win}")
            return None
        # temporal / temporal_ordered
        want = [r.uid for r in self.refs]
        if self.type == "temporal_ordered":
            if ref_uid != want[-1]:
                return None
            idx, picked = 0, []
            for e in dq:
                if idx < len(want) and e.ref == want[idx]:
                    picked.append(e)
                    idx += 1
            ok = idx == len(want)
            how = "in order"
        else:
            picked = []
            for w in want:
                e = next((x for x in dq if x.ref == w), None)
                if e is None:
                    break
                picked.append(e)
            ok = len(picked) == len(want)
            how = "any order"
        if not ok:
            return None
        dq.clear()
        names = " -> ".join(r.title for r in self.refs) if self.type == "temporal_ordered" \
            else " + ".join(r.title for r in self.refs)
        return CorrMatch(self, gdict, len(picked), picked[0].ts, ts, [e.ev for e in picked],
                         f"sequence ({how}) for {label} within {win}: {names}")


def _fmt(td: timedelta) -> str:
    s = int(td.total_seconds())
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if s % n == 0:
            return f"{s // n}{unit}"
    return f"{s}s"
