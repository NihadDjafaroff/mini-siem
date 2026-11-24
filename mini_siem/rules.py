"""Rule loading (multi-document YAML), reference resolution and the streaming rule engine."""
from __future__ import annotations

from pathlib import Path

import yaml

from .correlation import Correlation
from .ecs import event_ts
from .models import Alert, Severity
from .sigma import RuleError, SigmaRule, parse_rule


class RuleSet:
    def __init__(self, rules: list[SigmaRule], correlations: list[Correlation]):
        self.rules, self.correlations = rules, correlations
        index: dict[str, object] = {}
        for obj in [*rules, *correlations]:
            for key in filter(None, {obj.id, obj.name}):
                if key in index and index[key] is not obj:
                    raise RuleError(f"duplicate rule id/name '{key}'")
                index[key] = obj
        for c in correlations:
            c.refs = []
            for ref in c.ref_names:
                if ref not in index:
                    raise RuleError(f"{c.path}: correlation '{c.title}' references unknown rule '{ref}'")
                if index[ref] is c:
                    raise RuleError(f"{c.path}: correlation '{c.title}' references itself")
                c.refs.append(index[ref])
        self._check_cycles()
        # base rules referenced by a correlation are not alerted on their own unless generate: true
        self.referenced = {id(r) for c in correlations for r in c.refs}
        self.generate = {id(r) for c in correlations if c.generate for r in c.refs}
        self.referrers: dict[int, list[Correlation]] = {}
        for c in correlations:
            for r in c.refs:
                self.referrers.setdefault(id(r), []).append(c)

    def _check_cycles(self):
        def visit(c, stack):
            if id(c) in stack:
                raise RuleError(f"correlation cycle involving '{c.title}'")
            for r in c.refs:
                if isinstance(r, Correlation):
                    visit(r, stack | {id(c)})
        for c in self.correlations:
            visit(c, frozenset())

    def __len__(self):
        return len(self.rules) + len(self.correlations)


def load_rules(path: str | Path) -> RuleSet:
    p = Path(path)
    if not p.exists():
        raise RuleError(f"rules path not found: {p}")
    files = [p] if p.is_file() else sorted([*p.rglob("*.yml"), *p.rglob("*.yaml")])
    rules, corrs = [], []
    for f in files:
        try:
            docs = [d for d in yaml.safe_load_all(f.read_text(encoding="utf-8")) if d is not None]
        except yaml.YAMLError as exc:
            raise RuleError(f"{f}: invalid YAML: {exc}")
        for d in docs:
            if not isinstance(d, dict):
                raise RuleError(f"{f}: rule documents must be maps")
            (corrs if "correlation" in d else rules).append(
                Correlation(d, str(f)) if "correlation" in d else parse_rule(d, str(f)))
    if not files or not (rules or corrs):
        raise RuleError(f"no rules found under {p}")
    return RuleSet(rules, corrs)


def load_rules_from_text(text: str) -> RuleSet:
    rules, corrs = [], []
    for d in yaml.safe_load_all(text):
        if d is None:
            continue
        (corrs if "correlation" in d else rules).append(
            Correlation(d, "<text>") if "correlation" in d else parse_rule(d, "<text>"))
    return RuleSet(rules, corrs)


class Engine:
    """Streaming evaluator. Feed events in timestamp order via ``process``."""

    def __init__(self, ruleset: RuleSet):
        self.rs = ruleset
        for c in ruleset.correlations:
            c.reset()

    def process(self, ev: dict) -> list[Alert]:
        ts = event_ts(ev)
        alerts: list[Alert] = []
        for rule in self.rs.rules:
            if not rule.matches(ev):
                continue
            if id(rule) not in self.rs.referenced or id(rule) in self.rs.generate:
                alerts.append(Alert(rule.uid, rule.title, rule.level, ts, "single",
                                    rule.description or rule.title, event=ev, tags=rule.tags,
                                    context={"rule_name": rule.name}))
            self._dispatch(rule, ev, ts, alerts)
        return alerts

    def _dispatch(self, obj, ev, ts, alerts):
        for corr in self.rs.referrers.get(id(obj), []):
            m = corr.feed(obj.uid, ev, ts)
            if not m:
                continue
            ips = sorted({str(x) for e in m.events for x in [(e.get("source") or {}).get("ip")] if x})
            alerts.append(Alert(
                corr.uid, corr.title, corr.level, ts, "correlation", m.message, group=m.group, event=ev,
                tags=corr.tags,
                context={"type": corr.type, "match_count": m.count, "window_start": m.first_ts.isoformat(),
                         "window_end": m.last_ts.isoformat(), "distinct_source_ips": ips,
                         "sample": [e.get("log", {}).get("original") for e in m.events[:5]]}))
            self._dispatch(corr, ev, ts, alerts)
