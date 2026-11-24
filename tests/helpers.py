"""Shared test helpers."""
from datetime import datetime, timedelta, timezone

from mini_siem.ecs import build, fmt_ts
from mini_siem.rules import Engine, load_rules_from_text

T0 = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)

FAILED_RULE = """---
title: SSH Failed
name: ssh_failed
level: low
detection:
  sel: {event.action: ssh_login, event.outcome: failure}
  condition: sel
"""
OK_RULE = """---
title: SSH OK
name: ssh_ok
level: informational
detection:
  sel: {event.action: ssh_login, event.outcome: success}
  condition: sel
"""


def ev(offset_s=0, ip="203.0.113.50", outcome="failure", user="root", action="ssh_login", **extra):
    flat = {"@timestamp": fmt_ts(T0 + timedelta(seconds=offset_s)), "source.ip": ip, "user.name": user,
            "event.action": action, "event.outcome": outcome, "event.category": ["authentication"],
            "host.name": "web01", "log.original": f"raw {offset_s} {ip}"}
    flat.update(extra)
    return build(flat)


def corr(kind="event_count", cond="gte: 10", span="5m", group="[source.ip]", rules="[ssh_failed]", name="c1",
         level="high", extra=""):
    return f"""
---
title: Corr {name}
name: {name}
level: {level}
correlation:
  type: {kind}
  rules: {rules}
  group-by: {group}
  timespan: {span}
  condition:
    {cond}
{extra}
"""


def run(rules_text, events):
    eng = Engine(load_rules_from_text(rules_text))
    out = []
    for e in events:
        out.extend(eng.process(e))
    return out


class FakeRunner:
    """Captures firewall commands instead of running them."""

    def __init__(self, rc=0):
        self.calls, self.rc = [], rc

    def __call__(self, cmd, **kw):
        self.calls.append(list(cmd))

        class R:
            returncode, stderr, stdout = self.rc, "", ""
        return R()
