import logging
from datetime import datetime, timedelta, timezone

import pytest

from mini_siem.models import Alert, Severity
from mini_siem.pipeline import Pipeline
from mini_siem.response import (AllowList, IptablesBackend, NetshBackend, NftBackend, ResponseManager,
                                choose_backend)
from mini_siem.rules import load_rules_from_text
from tests.helpers import FAILED_RULE, T0, FakeRunner, corr, ev

ATTACKER = "203.0.113.50"


class Clock:
    def __init__(self):
        self.now = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


def alert(ip=ATTACKER, sev=Severity.HIGH, distinct=None):
    return Alert("ssh_bruteforce", "SSH Brute Force", sev, T0, "correlation", "10 failures", group={"source.ip": ip},
                 context={"distinct_source_ips": distinct if distinct is not None else [ip]})


def mgr(tmp_path, runner=None, enabled=True, apply=False, allow=(), local_ips=(), clock=None, **kw):
    return ResponseManager(tmp_path / "actions.json", enabled=enabled, apply=apply, ttl_seconds=600,
                           allowlist=AllowList(allow, local_ips=list(local_ips)), backend=IptablesBackend(),
                           runner=runner or FakeRunner(), clock=clock or Clock(), **kw)


# ---- two-step opt-in -------------------------------------------------------------------------------
def test_disabled_by_default_does_nothing(tmp_path):
    r = FakeRunner()
    assert mgr(tmp_path, r, enabled=False, apply=True).handle(alert()) is None and r.calls == []


def test_dry_run_never_touches_firewall_and_says_what_it_would_do(tmp_path, caplog):
    r = FakeRunner()
    with caplog.at_level(logging.WARNING):
        act = mgr(tmp_path, r, enabled=True, apply=False).handle(alert())
    assert r.calls == []                                  # the real firewall command was never invoked
    assert act.status == "dry-run" and act.mechanism == "iptables" and act.ip == ATTACKER
    assert f"would block IP {ATTACKER} via iptables" in caplog.text


def test_apply_without_enable_is_still_off(tmp_path):
    r = FakeRunner()
    m = mgr(tmp_path, r, enabled=False, apply=True)
    assert m.apply is False and m.handle(alert()) is None and r.calls == []


def test_apply_executes_time_bounded_rule_and_records_everything(tmp_path):
    r = FakeRunner()
    act = mgr(tmp_path, r, enabled=True, apply=True).handle(alert())
    assert act.status == "applied"
    assert r.calls == [["iptables", "-I", "INPUT", "-s", ATTACKER, "-m", "comment", "--comment",
                        f"mini-siem:{act.id}", "-j", "DROP"]]
    assert act.expires_at and act.ttl_seconds == 600                       # never permanent
    assert act.reverse_cmd[1] == "-D" and act.id in act.how_to_reverse      # how to reverse
    assert act.who == "mini-siem" and act.reason == "10 failures" and act.created and act.rule_id == "ssh_bruteforce"
    stored = mgr(tmp_path).store.load()
    assert stored[0].id == act.id


# ---- allow-list: non-negotiable ----------------------------------------------------------------------
@pytest.mark.parametrize("ip,extra,local", [
    ("127.0.0.1", [], []), ("::1", [], []), ("169.254.9.9", [], []),                 # hard-coded
    ("192.168.1.10", [], ["192.168.1.10"]),                                            # the machine's own IP
    ("192.168.1.1", [], ["192.168.1.1"]),                                              # gateway
    ("203.0.113.77", ["203.0.113.0/24"], []),                                          # configured range
    ("10.1.2.3", ["10.0.0.0/8"], []),
])
def test_allowlisted_target_is_never_blocked_even_when_applying(tmp_path, ip, extra, local):
    r = FakeRunner()
    act = mgr(tmp_path, r, enabled=True, apply=True, allow=extra, local_ips=local).handle(alert(ip, Severity.CRITICAL))
    assert r.calls == []                       # NO rule written
    assert act.status == "skipped" and "allow-list" in act.error


def test_allowlist_enforced_end_to_end_when_alert_matches_own_ip(tmp_path):
    own = "192.168.1.50"
    r = FakeRunner()
    m = mgr(tmp_path, r, enabled=True, apply=True, local_ips=[own])
    rs = load_rules_from_text(FAILED_RULE + corr())
    res = Pipeline(rs, response=m).run([ev(i, ip=own) for i in range(12)])
    assert any(a.kind == "correlation" for a in res.alerts)     # detection DID fire...
    assert r.calls == []                                         # ...but containment refused
    assert all(a.status == "skipped" for a in res.actions)


def test_ioc_critical_alert_against_allowlisted_ip_is_not_blocked(tmp_path):
    r = FakeRunner()
    a = Alert("ioc.ipv4-addr", "IOC", Severity.CRITICAL, T0, "ioc", "m", event=ev(0, ip="127.0.0.1"))
    assert mgr(tmp_path, r, apply=True).handle(a).status == "skipped" and r.calls == []


def test_invalid_allowlist_entry_rejected():
    with pytest.raises(ValueError):
        AllowList(["not-a-cidr"], local_ips=[])


# ---- TTL / undo -----------------------------------------------------------------------------------------
def test_ttl_expiry_removes_the_rule(tmp_path):
    r, clock = FakeRunner(), Clock()
    m = mgr(tmp_path, r, enabled=True, apply=True, clock=clock)
    act = m.handle(alert())
    r.calls.clear()
    clock.now += timedelta(seconds=599)
    assert m.expire_due() == [] and r.calls == []                 # not yet
    clock.now += timedelta(seconds=2)
    done = m.expire_due()
    assert [d.id for d in done] == [act.id] and done[0].status == "expired"
    assert r.calls == [act.reverse_cmd]                           # the delete command ran
    assert m.expire_due() == [] and len(r.calls) == 1             # idempotent


def test_pipeline_run_sweeps_expired_rules(tmp_path):
    r, clock = FakeRunner(), Clock()
    m = mgr(tmp_path, r, enabled=True, apply=True, clock=clock)
    act = m.handle(alert())
    clock.now += timedelta(hours=1)
    res = Pipeline(None, response=m).run([])
    assert [a.status for a in res.actions] == ["expired"] and r.calls[-1] == act.reverse_cmd


def test_expiring_dry_run_runs_no_command(tmp_path):
    r, clock = FakeRunner(), Clock()
    m = mgr(tmp_path, r, apply=False, clock=clock)
    m.handle(alert())
    clock.now += timedelta(hours=1)
    assert m.expire_due()[0].status == "expired" and r.calls == []


def test_undo_reverses_specific_action_only(tmp_path):
    r = FakeRunner()
    m = mgr(tmp_path, r, apply=True)
    a1, a2 = m.handle(alert("203.0.113.1")), m.handle(alert("203.0.113.2"))
    r.calls.clear()
    out = m.undo(a1.id)
    assert out.status == "undone" and r.calls == [a1.reverse_cmd]
    states = {a.id: a.status for a in m.store.load()}
    assert states == {a1.id: "undone", a2.id: "applied"}
    with pytest.raises(ValueError):
        m.undo(a1.id)                                  # already undone
    with pytest.raises(KeyError):
        m.undo("deadbeef")


def test_undo_failure_is_reported_and_status_kept(tmp_path):
    m = mgr(tmp_path, FakeRunner(), apply=True)
    act = m.handle(alert())
    m.runner = FakeRunner(rc=1)
    with pytest.raises(RuntimeError):
        m.undo(act.id)
    assert m.store.load()[0].status == "applied"


def test_undo_dry_run_action_runs_nothing(tmp_path):
    r = FakeRunner()
    m = mgr(tmp_path, r)
    act = m.handle(alert())
    assert m.undo(act.id).status == "undone" and r.calls == []


# ---- judgement / noise control ---------------------------------------------------------------------------------
def test_multiple_source_ips_get_notification_not_block(tmp_path):
    r, sent = FakeRunner(), []
    m = mgr(tmp_path, r, apply=True, notifier=sent.append)
    act = m.handle(alert(distinct=["203.0.113.1", "203.0.113.2", "203.0.113.3"]))
    assert r.calls == [] and act.status == "notified" and act.mechanism == "notify"
    assert "NAT" in sent[0]["why_not_blocked"]


def test_notify_in_dry_run_does_not_send(tmp_path):
    sent = []
    act = mgr(tmp_path, apply=False, notifier=sent.append).handle(alert(distinct=["a", "b"]))
    assert act.status == "would-notify" and sent == []


def test_below_min_severity_ignored_and_duplicates_suppressed(tmp_path):
    r = FakeRunner()
    m = mgr(tmp_path, r, apply=True)
    assert m.handle(alert(sev=Severity.MEDIUM)) is None
    assert m.handle(alert()) is not None and m.handle(alert()) is None and len(r.calls) == 1


def test_runner_failure_recorded_not_raised(tmp_path):
    act = mgr(tmp_path, FakeRunner(rc=1), apply=True).handle(alert())
    assert act.status == "failed"


def test_alert_without_ip_ignored(tmp_path):
    a = Alert("r", "t", Severity.CRITICAL, T0, "single", "m", event={"host": {"name": "x"}})
    assert mgr(tmp_path).handle(a) is None


# ---- backends --------------------------------------------------------------------------------------------------
def test_backend_commands():
    apply, rev = NetshBackend().block("203.0.113.5", "ab12", 60)
    assert apply[:5] == ["netsh", "advfirewall", "firewall", "add", "rule"] and "action=block" in apply
    assert "remoteip=203.0.113.5" in apply and rev[3] == "delete"
    apply, rev = NftBackend().block("203.0.113.5", "x", 90)
    assert "timeout 90s" in apply[-1] and rev[1] == "delete"            # native self-expiry
    assert IptablesBackend().block("2001:db8::1", "x", 1)[0][0] == "ip6tables"
    assert choose_backend("auto", "win32").name == "netsh" and choose_backend("auto", "linux").name == "iptables"
    assert choose_backend("nft").name == "nft"
    with pytest.raises(ValueError):
        choose_backend("pf")
