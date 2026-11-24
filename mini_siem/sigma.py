"""Single-event Sigma evaluation over ECS-normalized events.

Supports: field matching with wildcards, modifiers (contains, startswith, endswith, all, re, cidr,
lt/lte/gt/gte, exists), keyword selections, and conditions with and/or/not, parentheses,
'1 of x*', 'all of x*', '1 of them', 'all of them'. Aggregation ('| count()') is NOT supported
here: use Sigma correlation rules instead (see correlation.py).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .ecs import get_path
from .models import Severity


class RuleError(Exception):
    pass


def _wild_regex(pat: str) -> re.Pattern:
    out, i = [], 0
    while i < len(pat):
        c = pat[i]
        if c == "\\" and i + 1 < len(pat) and pat[i + 1] in "*?\\":
            out.append(re.escape(pat[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return re.compile("".join(out), re.I | re.S)


def _compile_value(mods: list[str], value: Any) -> Callable[[Any], bool]:
    cmp_ops = {"lt": lambda a, b: a < b, "lte": lambda a, b: a <= b,
               "gt": lambda a, b: a > b, "gte": lambda a, b: a >= b}
    for op, fn in cmp_ops.items():
        if op in mods:
            try:
                num = float(value)
            except (TypeError, ValueError):
                raise RuleError(f"modifier '{op}' needs a numeric value, got {value!r}")

            def pred(v, fn=fn, num=num):
                try:
                    return fn(float(v), num)
                except (TypeError, ValueError):
                    return False
            return pred
    if "re" in mods:
        flags = (re.I if "i" in mods else 0) | (re.M if "m" in mods else 0) | (re.S if "s" in mods else 0)
        try:
            rx = re.compile(str(value), flags)
        except re.error as exc:
            raise RuleError(f"bad regex {value!r}: {exc}")
        return lambda v: rx.search(str(v)) is not None
    if "cidr" in mods:
        try:
            net = ipaddress.ip_network(str(value), strict=False)
        except ValueError as exc:
            raise RuleError(f"bad cidr {value!r}: {exc}")

        def pred(v):
            try:
                return ipaddress.ip_address(str(v)) in net
            except ValueError:
                return False
        return pred
    s = str(value)
    if "contains" in mods:
        s = f"*{s}*"
    if "startswith" in mods:
        s = f"{s}*"
    if "endswith" in mods:
        s = f"*{s}"
    rx = _wild_regex(s)
    return lambda v: rx.fullmatch(str(v)) is not None


KNOWN_MODS = {"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cidr",
              "lt", "lte", "gt", "gte", "exists"}


@dataclass
class FieldCond:
    field: str
    mods: list
    values: list
    preds: list = None

    def __post_init__(self):
        bad = [m for m in self.mods if m not in KNOWN_MODS]
        if bad:
            raise RuleError(f"unsupported modifier(s) {bad} on field '{self.field}'")
        self.preds = [None if v is None else _compile_value(self.mods, v) for v in self.values]

    def matches(self, ev: dict) -> bool:
        fv = get_path(ev, self.field)
        if "exists" in self.mods:
            return (fv is not None) == bool(self.values[0])
        cands = [x for x in (fv if isinstance(fv, list) else [fv]) if x is not None]
        results = []
        for p in self.preds:
            results.append((not cands) if p is None else any(p(c) for c in cands))
        return all(results) if "all" in self.mods else any(results)


@dataclass
class Selection:
    groups: list = field(default_factory=list)   # list of list[FieldCond]; OR of ANDs
    keywords: list = field(default_factory=list)

    def matches(self, ev: dict) -> bool:
        if self.keywords:
            hay = " ".join(str(x) for x in (get_path(ev, "log.original"), get_path(ev, "message")) if x)
            if any(k.search(hay) for k in self.keywords):
                return True
        return any(all(fc.matches(ev) for fc in g) for g in self.groups)


def parse_selection(name: str, body: Any) -> Selection:
    sel = Selection()

    def one(d: dict):
        if not d:
            raise RuleError(f"selection '{name}' has an empty map")
        conds = []
        for key, val in d.items():
            field_, *mods = str(key).split("|")
            vals = val if isinstance(val, list) else [val]
            conds.append(FieldCond(field_, mods, vals))
        sel.groups.append(conds)

    if isinstance(body, dict):
        one(body)
    elif isinstance(body, list):
        for item in body:
            if isinstance(item, dict):
                one(item)
            else:
                sel.keywords.append(_wild_regex(f"*{item}*"))
    elif isinstance(body, str):
        sel.keywords.append(_wild_regex(f"*{body}*"))
    else:
        raise RuleError(f"selection '{name}' must be a map or list")
    return sel


# ---- condition grammar -----------------------------------------------------------------------
_TOK = re.compile(r"\(|\)|[^\s()]+")


def _tokens(s: str) -> list[str]:
    return _TOK.findall(s)


class _CondParser:
    def __init__(self, text: str, names: list[str]):
        if "|" in text:
            raise RuleError("aggregation conditions ('|') are unsupported; use a correlation rule")
        self.t, self.i, self.names = _tokens(text), 0, names
        self.used: set[str] = set()

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self):
        tok = self.peek()
        self.i += 1
        return tok

    def parse(self):
        node = self.or_()
        if self.peek() is not None:
            raise RuleError(f"unexpected token {self.peek()!r} in condition")
        return node

    def or_(self):
        parts = [self.and_()]
        while (self.peek() or "").lower() == "or":
            self.take()
            parts.append(self.and_())
        return parts[0] if len(parts) == 1 else ("or", parts)

    def and_(self):
        parts = [self.not_()]
        while (self.peek() or "").lower() == "and":
            self.take()
            parts.append(self.not_())
        return parts[0] if len(parts) == 1 else ("and", parts)

    def not_(self):
        if (self.peek() or "").lower() == "not":
            self.take()
            return ("not", self.not_())
        return self.atom()

    def atom(self):
        tok = self.take()
        if tok is None:
            raise RuleError("condition ended unexpectedly")
        if tok == "(":
            node = self.or_()
            if self.take() != ")":
                raise RuleError("missing ')' in condition")
            return node
        if tok.lower() in ("1", "all") and (self.peek() or "").lower() == "of":
            self.take()
            pat = self.take()
            if pat is None:
                raise RuleError("'of' needs a selection pattern")
            matched = self.names if pat == "them" else [n for n in self.names if _wild_regex(pat).fullmatch(n)]
            if not matched:
                raise RuleError(f"'{tok} of {pat}' matches no selection")
            self.used.update(matched)
            return ("of", tok.lower(), matched)
        if tok not in self.names:
            raise RuleError(f"condition references unknown selection '{tok}'")
        self.used.add(tok)
        return ("sel", tok)


def _eval(node, res: dict) -> bool:
    k = node[0]
    if k == "sel":
        return res[node[1]]
    if k == "not":
        return not _eval(node[1], res)
    if k == "and":
        return all(_eval(n, res) for n in node[1])
    if k == "or":
        return any(_eval(n, res) for n in node[1])
    vals = [res[n] for n in node[2]]
    return all(vals) if node[1] == "all" else any(vals)


@dataclass
class SigmaRule:
    id: str
    name: str | None
    title: str
    level: Severity
    description: str = ""
    tags: list = field(default_factory=list)
    selections: dict = field(default_factory=dict)
    condition: Any = None
    path: str = ""
    kind: str = "rule"

    @property
    def uid(self) -> str:
        return self.name or self.id or self.title

    def matches(self, ev: dict) -> bool:
        res = {n: s.matches(ev) for n, s in self.selections.items()}
        return _eval(self.condition, res)


def parse_rule(doc: dict, path: str = "") -> SigmaRule:
    det = doc.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        raise RuleError(f"{path}: rule needs detection.condition")
    title = doc.get("title")
    if not title:
        raise RuleError(f"{path}: rule needs a title")
    sels = {k: parse_selection(k, v) for k, v in det.items() if k not in ("condition", "timeframe")}
    if not sels:
        raise RuleError(f"{path}: detection has no selections")
    conds = det["condition"]
    if isinstance(conds, list):  # Sigma: list of conditions = OR
        conds = " or ".join(f"({c})" for c in conds)
    try:
        p = _CondParser(str(conds), list(sels))
        node = p.parse()
        level = Severity.from_level(doc.get("level"))
    except (RuleError, ValueError) as exc:
        raise RuleError(f"{path}: {exc}")
    return SigmaRule(id=str(doc.get("id", "")), name=doc.get("name"), title=title, level=level,
                     description=doc.get("description", ""), tags=doc.get("tags", []) or [],
                     selections=sels, condition=node, path=path)
