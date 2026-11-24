import pytest

from mini_siem.rules import load_rules_from_text
from mini_siem.sigma import RuleError, parse_rule
from tests.helpers import ev, run


def rule(detection: str, level="medium"):
    import yaml
    return parse_rule({"title": "t", "level": level, "detection": yaml.safe_load(detection)})


def E(**f):
    return ev(**f)


@pytest.mark.parametrize("det,event,expected", [
    ("{sel: {process.name: powershell.exe}, condition: sel}", E(**{"process.name": "PowerShell.EXE"}), True),
    ("{sel: {process.name: powershell.exe}, condition: sel}", E(**{"process.name": "cmd.exe"}), False),
    ("{sel: {process.command_line|contains: -enc}, condition: sel}", E(**{"process.command_line": "ps -ENC abc"}), True),
    ("{sel: {process.command_line|startswith: ps}, condition: sel}", E(**{"process.command_line": "xps"}), False),
    ("{sel: {process.command_line|endswith: .exe}, condition: sel}", E(**{"process.command_line": "a.exe"}), True),
    ("{sel: {process.name: 'power*.exe'}, condition: sel}", E(**{"process.name": "powershell.exe"}), True),
    ("{sel: {process.name: 'p?.exe'}, condition: sel}", E(**{"process.name": "ps.exe"}), True),
    ("{sel: {process.name: 'p?.exe'}, condition: sel}", E(**{"process.name": "pss.exe"}), False),
    ("{sel: {process.command_line|re: 'a\\d+b'}, condition: sel}", E(**{"process.command_line": "xa123b"}), True),
    ("{sel: {source.ip|cidr: 10.0.0.0/8}, condition: sel}", E(ip="10.2.3.4"), True),
    ("{sel: {source.ip|cidr: 10.0.0.0/8}, condition: sel}", E(ip="11.2.3.4"), False),
    ("{sel: {http.response.status_code|gte: 400}, condition: sel}", E(**{"http.response.status_code": 404}), True),
    ("{sel: {http.response.status_code|lt: 400}, condition: sel}", E(**{"http.response.status_code": 404}), False),
    ("{sel: {event.category: authentication}, condition: sel}", E(), True),      # list-valued field
    ("{sel: {user.name: [root, admin]}, condition: sel}", E(user="admin"), True),   # list = OR
    ("{sel: {user.name|all: [ro, ot]}, condition: sel}", E(user="root"), False),    # 'all' needs exact each
    ("{sel: {process.command_line|contains|all: [a, b]}, condition: sel}", E(**{"process.command_line": "ab"}), True),
    ("{sel: {process.command_line|contains|all: [a, z]}, condition: sel}", E(**{"process.command_line": "ab"}), False),
    ("{sel: {no.such.field: null}, condition: sel}", E(), True),                  # null == absent
    ("{sel: {user.name|exists: true}, condition: sel}", E(), True),
    ("{sel: {no.such|exists: true}, condition: sel}", E(), False),
    ("{sel: [{user.name: root}, {user.name: zed}], condition: sel}", E(user="zed"), True),  # list of maps = OR
    ("{sel: ['raw 0'], condition: sel}", E(), True),                                # keyword search in log.original
])
def test_field_matching(det, event, expected):
    assert rule(det).matches(event) is expected


@pytest.mark.parametrize("cond,expected", [
    ("a and b", False), ("a or b", True), ("a and not b", True), ("not a", False), ("not (a and b)", True),
    ("(a or b) and not b", True), ("1 of sel*", True), ("all of sel*", False), ("1 of them", True),
    ("all of them", False), ("a and 1 of s*", True), ("not 1 of x*", True),
])
def test_condition_grammar(cond, expected):
    det = {"a": {"user.name": "root"}, "b": {"user.name": "nobody"}, "sel1": {"user.name": "root"},
           "sel2": {"user.name": "nobody"}, "xx": {"user.name": "nobody"}, "condition": cond}
    import yaml
    r = parse_rule({"title": "t", "detection": det})
    assert r.matches(E(user="root")) is expected


@pytest.mark.parametrize("bad", [
    "{sel: {a: 1}, condition: other}",              # unknown selection
    "{sel: {a: 1}, condition: 'sel and'}",          # truncated
    "{sel: {a: 1}, condition: '(sel'}",             # unbalanced
    "{sel: {a: 1}, condition: 'sel | count() > 5'}",  # aggregation unsupported
    "{sel: {a|bogus: 1}, condition: sel}",          # unknown modifier
    "{sel: {a|re: '('}, condition: sel}",           # bad regex
    "{sel: {a|cidr: nope}, condition: sel}",
    "{sel: {a|gt: abc}, condition: sel}",
    "{sel: {a: 1}, condition: '1 of zzz*'}",
])
def test_invalid_rules_fail_loudly(bad):
    with pytest.raises(RuleError):
        rule(bad)


def test_single_event_rule_yields_alert_with_level_and_event():
    text = """
title: Root SSH success
name: root_ok
level: high
detection:
  s: {user.name: root, event.outcome: success}
  condition: s
"""
    alerts = run(text, [ev(outcome="failure"), ev(1, outcome="success")])
    assert len(alerts) == 1 and alerts[0].severity.name == "HIGH" and alerts[0].kind == "single"
    assert alerts[0].event["log"]["original"] == "raw 1 203.0.113.50"


def test_rule_files_with_missing_fields_rejected():
    with pytest.raises(RuleError):
        load_rules_from_text("title: x\nlevel: low\n")
    with pytest.raises(RuleError):
        load_rules_from_text("detection: {s: {a: 1}, condition: s}\n")
    with pytest.raises(RuleError):
        parse_rule({"title": "t", "level": "spicy", "detection": {"s": {"a": 1}, "condition": "s"}})
