import pytest

from mini_siem.rules import load_rules_from_text
from mini_siem.sigma import RuleError
from tests.helpers import FAILED_RULE, OK_RULE, corr, ev, run

BASE = FAILED_RULE + OK_RULE


def corr_alerts(alerts, name="c1"):
    return [a for a in alerts if a.kind == "correlation" and a.rule_id == name]


# ---- event_count threshold ------------------------------------------------------------------------
@pytest.mark.parametrize("n,should_fire", [(9, False), (10, True), (11, True)])
def test_event_count_fires_exactly_at_threshold(n, should_fire):
    alerts = run(BASE + corr(), [ev(i) for i in range(n)])
    assert bool(corr_alerts(alerts)) is should_fire


def test_event_count_first_fire_is_on_nth_event():
    alerts = corr_alerts(run(BASE + corr(), [ev(i) for i in range(15)]))
    assert alerts[0].context["match_count"] == 10 and alerts[0].group == {"source.ip": "203.0.113.50"}


def test_referenced_base_rule_is_not_alerted_on_its_own_by_default():
    alerts = run(BASE + corr(), [ev(i) for i in range(3)])
    assert alerts == []  # ssh_failed matched but is only a building block


def test_generate_flag_inside_correlation_block():
    text = BASE + """
---
title: Corr gen
name: cg
correlation:
  type: event_count
  rules: [ssh_failed]
  timespan: 5m
  generate: true
  condition: {gte: 99}
"""
    alerts = run(text, [ev(0)])
    assert [a.rule_id for a in alerts] == ["ssh_failed"]


# ---- window edges ---------------------------------------------------------------------------------
def test_events_just_inside_window_fire():
    # first at t=0, tenth at t=300 == timespan -> boundary inclusive
    events = [ev(0)] + [ev(10 + i) for i in range(8)] + [ev(300)]
    assert corr_alerts(run(BASE + corr(), events))


def test_event_just_outside_window_does_not_count():
    events = [ev(0)] + [ev(10 + i) for i in range(8)] + [ev(301)]  # first one aged out by 1s
    assert not corr_alerts(run(BASE + corr(), events))


def test_sliding_window_drops_old_events():
    # 9 events early, 1 event 10 minutes later -> never 10 in any 5m window
    events = [ev(i) for i in range(9)] + [ev(600)]
    assert not corr_alerts(run(BASE + corr(), events))


# ---- group-by isolation -----------------------------------------------------------------------------
def test_group_by_isolates_source_ips():
    events = []
    for i in range(6):
        events += [ev(i * 2, ip="203.0.113.1"), ev(i * 2 + 1, ip="203.0.113.2")]
    # 12 failed logins in total but only 6 per IP -> nothing fires
    assert not corr_alerts(run(BASE + corr(), sorted(events, key=lambda e: e["@timestamp"])))


def test_group_by_fires_only_for_offending_group():
    events = [ev(i, ip="203.0.113.1") for i in range(10)] + [ev(i, ip="203.0.113.2") for i in range(3)]
    events.sort(key=lambda e: e["@timestamp"])
    alerts = corr_alerts(run(BASE + corr(), events))
    assert alerts and {a.group["source.ip"] for a in alerts} == {"203.0.113.1"}


def test_group_by_multiple_fields_and_configurable():
    text = BASE + corr(group="[source.ip, user.name]")
    events = [ev(i, user="root" if i % 2 else "admin") for i in range(18)]
    assert not corr_alerts(run(text, events))  # 9 per (ip,user) pair
    events = [ev(i, user="root") for i in range(10)]
    assert corr_alerts(run(text, events))[0].group == {"source.ip": "203.0.113.50", "user.name": "root"}
    # group by user only: different IPs combine
    text = BASE + corr(group="[user.name]")
    events = [ev(i, ip=f"203.0.113.{i}") for i in range(10)]
    assert corr_alerts(run(text, events))


def test_no_group_by_counts_everything_together():
    text = BASE + corr(group="[]")
    events = [ev(i, ip=f"203.0.113.{i}") for i in range(10)]
    assert corr_alerts(run(text, events))


def test_event_missing_group_field_is_ignored_not_crash():
    e = ev(0)
    del e["source"]
    assert run(BASE + corr(cond="gte: 1"), [e]) == []


# ---- other operators -------------------------------------------------------------------------------------
def test_gt_and_range_conditions():
    assert not corr_alerts(run(BASE + corr(cond="gt: 10"), [ev(i) for i in range(10)]))
    assert corr_alerts(run(BASE + corr(cond="gt: 10"), [ev(i) for i in range(11)]))
    text = BASE + corr(cond="gte: 3\n    lte: 4")
    alerts = corr_alerts(run(text, [ev(i) for i in range(6)]))
    assert [a.context["match_count"] for a in alerts] == [3, 4]  # not 1,2 and not 5,6


# ---- value_count ---------------------------------------------------------------------------------------------
def test_value_count_distinct_ports():
    base = """
title: conn
name: conn
detection:
  s: {event.action: network_connection}
  condition: s
"""
    text = base + corr(kind="value_count", cond="gte: 5\n    field: destination.port", rules="[conn]", span="1m")
    mk = lambda i, port: ev(i, action="network_connection", **{"destination.port": port})
    assert not corr_alerts(run(text, [mk(i, 80) for i in range(20)]))                 # same port x20
    assert not corr_alerts(run(text, [mk(i, 1000 + i) for i in range(4)]))            # 4 distinct
    assert corr_alerts(run(text, [mk(i, 1000 + i) for i in range(5)]))                # 5 distinct


# ---- temporal --------------------------------------------------------------------------------------------------
SEQ = BASE + corr(kind="temporal_ordered", cond="", rules="[ssh_failed, ssh_ok]", span="5m", name="seq")


def test_temporal_ordered_fires_in_correct_order():
    alerts = corr_alerts(run(SEQ, [ev(0), ev(30, outcome="success")]), "seq")
    assert len(alerts) == 1 and "in order" in alerts[0].message


def test_temporal_ordered_does_not_fire_in_wrong_order():
    assert not corr_alerts(run(SEQ, [ev(0, outcome="success"), ev(30)]), "seq")


def test_temporal_ordered_respects_window_and_group():
    assert not corr_alerts(run(SEQ, [ev(0), ev(301, outcome="success")]), "seq")
    assert not corr_alerts(run(SEQ, [ev(0, ip="203.0.113.1"), ev(5, ip="203.0.113.2", outcome="success")]), "seq")


def test_temporal_unordered_fires_in_either_order():
    text = BASE + corr(kind="temporal", cond="", rules="[ssh_failed, ssh_ok]", name="any")
    assert corr_alerts(run(text, [ev(0, outcome="success"), ev(30)]), "any")
    assert corr_alerts(run(text, [ev(0), ev(30, outcome="success")]), "any")
    assert not corr_alerts(run(text, [ev(0), ev(30)]), "any")


def test_bruteforce_then_success_escalation_chain_of_correlations():
    text = BASE + corr(name="bf") + corr(kind="temporal_ordered", cond="", rules="[bf, ssh_ok]", span="10m",
                                         name="bf_then_ok", level="critical")
    fails = [ev(i) for i in range(12)]
    only_bf = run(text, fails)
    assert corr_alerts(only_bf, "bf") and not corr_alerts(only_bf, "bf_then_ok")
    chain = run(text, fails + [ev(60, outcome="success")])
    esc = corr_alerts(chain, "bf_then_ok")
    assert len(esc) == 1 and esc[0].severity.name == "CRITICAL"
    # success from a DIFFERENT ip must not escalate
    other = run(text, fails + [ev(60, ip="203.0.113.99", outcome="success")])
    assert not corr_alerts(other, "bf_then_ok")
    # success BEFORE the failures must not escalate
    before = run(text, [ev(-30, outcome="success")] + fails)
    assert not corr_alerts(before, "bf_then_ok")


# ---- rule validation / config in YAML ----------------------------------------------------------------------------
@pytest.mark.parametrize("text", [
    BASE + corr(kind="bogus"),
    BASE + corr(span="5 parsecs"),
    BASE + corr(rules="[nonexistent]"),
    BASE + corr(cond="gte: ten"),
    BASE + corr(cond="gigantic: 3"),
    BASE + corr(kind="value_count", cond="gte: 3"),               # missing field
    BASE + "\n---\ntitle: x\ncorrelation: {type: event_count, rules: [ssh_failed], condition: {gte: 1}}\n",  # no timespan
    BASE + corr(rules="[c1]"),                                     # self reference
])
def test_invalid_correlation_rules_rejected(text):
    with pytest.raises(RuleError):
        load_rules_from_text(text)


def test_threshold_and_window_come_from_yaml_not_code():
    text = BASE + corr(cond="gte: 3", span="30s")
    assert corr_alerts(run(text, [ev(0), ev(10), ev(30)]))
    assert not corr_alerts(run(text, [ev(0), ev(10), ev(31)]))


def test_shipped_rules_load_and_detect_bruteforce_chain():
    from mini_siem.rules import load_rules
    rs = load_rules("rules")
    assert len(rs.correlations) >= 4
    from mini_siem.rules import Engine
    eng = Engine(rs)
    out = []
    for e in [ev(i) for i in range(10)] + [ev(70, outcome="success")]:
        out += eng.process(e)
    names = {a.rule_id for a in out}
    assert {"ssh_bruteforce", "ssh_bruteforce_then_success"} <= names
