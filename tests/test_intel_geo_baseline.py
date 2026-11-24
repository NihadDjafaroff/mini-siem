import json
import logging
from datetime import datetime, timezone

import pytest

from mini_siem.baseline import Baseline, hour_ranges
from mini_siem.dedup import Deduper
from mini_siem.ecs import fmt_ts, get_path
from mini_siem.geo import GeoEnricher
from mini_siem.intel import IntelDB, IntelError
from mini_siem.models import Alert, Severity
from mini_siem.pipeline import Pipeline
from mini_siem.rules import load_rules_from_text
from tests.helpers import FAILED_RULE, OK_RULE, T0, corr, ev

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def write_ioc(tmp_path, rows, name="ioc.json"):
    p = tmp_path / name
    p.write_text(json.dumps({"indicators": rows}))
    return p


# ===================== IOC ===========================================================================
def test_ioc_match_escalates_to_critical_and_attaches_threat_name(tmp_path):
    ioc = write_ioc(tmp_path, [{"indicator_type": "ipv4-addr", "value": "203.0.113.50", "threat_name": "EvilBot"}])
    rs = load_rules_from_text(FAILED_RULE.replace("level: low", "level: low"))
    res = Pipeline(rs, IntelDB.load(ioc, NOW)).run([ev(0)])
    kinds = {a.kind: a for a in res.alerts}
    assert kinds["ioc"].severity == Severity.CRITICAL and kinds["ioc"].ioc["threat_name"] == "EvilBot"
    single = kinds["single"]
    assert single.severity == Severity.CRITICAL and single.escalated_from == Severity.LOW
    assert single.ioc["threat_name"] == "EvilBot"


@pytest.mark.parametrize("itype,value,field", [
    ("ipv4-addr", "203.0.113.50", "source.ip"),
    ("ipv4-addr", "198.51.100.1", "destination.ip"),
    ("domain-name", "evil.example", "destination.domain"),
    ("domain-name", "evil.example", "dns.question.name"),
    ("file-hash-sha256", "ab" * 32, "process.hash.sha256"),
    ("file-hash-sha256", "ab" * 32, "file.hash.sha256"),
    ("file-hash-md5", "cd" * 16, "file.hash.md5"),
])
def test_ioc_types_and_fields(tmp_path, itype, value, field):
    db = IntelDB.load(write_ioc(tmp_path, [{"indicator_type": itype, "value": value, "threat_name": "T"}]), NOW)
    e = ev(0, **{field: "sub." + value if itype == "domain-name" else value.upper()})
    assert [i.threat_name for i in db.match(e)] == ["T"]  # also: subdomain + case-insensitive


def test_ioc_no_false_positive():
    db = IntelDB()
    assert db.match(ev(0)) == []


def test_expired_ioc_does_not_fire_but_is_reported_stale(tmp_path, caplog):
    p = write_ioc(tmp_path, [
        {"indicator_type": "ipv4-addr", "value": "203.0.113.50", "threat_name": "Old", "valid_until": "2026-01-01T00:00:00Z"},
        {"indicator_type": "ipv4-addr", "value": "203.0.113.51", "threat_name": "Fresh", "valid_until": "2027-01-01T00:00:00Z"}])
    with caplog.at_level(logging.WARNING):
        db = IntelDB.load(p, NOW)
    assert db.match(ev(0, ip="203.0.113.50")) == []
    assert [i.threat_name for i in db.match(ev(0, ip="203.0.113.51"))] == ["Fresh"]
    assert [s.threat_name for s in db.stale] == ["Old"] and "stale IOC" in caplog.text
    res = Pipeline(None, db).run([ev(0, ip="203.0.113.50")])
    assert res.alerts == [] and res.stale_iocs[0]["threat_name"] == "Old"


def test_missing_ioc_file_degrades_gracefully(tmp_path, caplog):
    with caplog.at_level(logging.WARNING):
        db = IntelDB.load(tmp_path / "nope.json", NOW)
    assert len(db) == 0 and "not found" in caplog.text
    assert Pipeline(load_rules_from_text(FAILED_RULE), db).run([ev(0)]).alerts[0].severity == Severity.LOW


def test_ioc_csv_and_invalid_records(tmp_path, caplog):
    p = tmp_path / "ioc.csv"
    p.write_text("indicator_type,value,threat_name,source,valid_until\n"
                 "ipv4-addr,203.0.113.5,CsvBot,feed,\n"
                 "ipv4-addr,not-an-ip,Bad,feed,\n"
                 "carrier-pigeon,x,Bad,feed,\n")
    with caplog.at_level(logging.WARNING):
        db = IntelDB.load(p, NOW)
    assert len(db) == 1 and len(db.skipped) == 2


def test_corrupt_ioc_file_is_an_error(tmp_path):
    p = tmp_path / "ioc.json"
    p.write_text("{not json")
    with pytest.raises(IntelError):
        IntelDB.load(p, NOW)


# ===================== GeoIP =========================================================================
class FakeReader:
    def __init__(self, table):
        self.table, self.queried = table, []

    def get(self, ip):
        self.queried.append(ip)
        return self.table.get(ip)


def fake_geo(tmp_path):
    (tmp_path / "c.mmdb").write_bytes(b"x")
    (tmp_path / "a.mmdb").write_bytes(b"x")
    readers = {"c.mmdb": FakeReader({"8.8.8.8": {"country": {"iso_code": "US", "names": {"en": "United States"}}}}),
               "a.mmdb": FakeReader({"8.8.8.8": {"autonomous_system_number": 15169,
                                                 "autonomous_system_organization": "GOOGLE"}})}
    g = GeoEnricher(str(tmp_path / "c.mmdb"), str(tmp_path / "a.mmdb"), opener=lambda p: readers[p.split("\\")[-1].split("/")[-1]])
    return g, readers


def test_public_ip_enriched_with_ecs_geo_fields(tmp_path):
    g, _ = fake_geo(tmp_path)
    e = ev(0, ip="8.8.8.8")
    found = g.enrich_event(e)
    assert get_path(e, "source.geo.country_iso_code") == "US" and get_path(e, "source.as.number") == 15169
    assert get_path(e, "source.as.organization.name") == "GOOGLE" and found["source.ip"]["country_iso"] == "US"


@pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.5", "172.16.0.9", "127.0.0.1", "169.254.1.1", "::1", "garbage"])
def test_private_and_invalid_ips_skipped_without_lookup_or_error(tmp_path, ip):
    g, readers = fake_geo(tmp_path)
    e = ev(0, ip=ip)
    assert g.enrich_event(e) == {}
    assert not readers["c.mmdb"].queried and not readers["a.mmdb"].queried


def test_missing_geoip_db_warns_and_continues(tmp_path, caplog):
    with caplog.at_level(logging.WARNING):
        g = GeoEnricher(str(tmp_path / "missing.mmdb"))
    assert not g.available and "not found" in caplog.text
    e = ev(0, ip="8.8.8.8")
    assert g.enrich_event(e) == {}
    Pipeline(load_rules_from_text(FAILED_RULE), geo=g).run([e])  # whole run survives


def test_missing_maxminddb_library_degrades(tmp_path, caplog):
    (tmp_path / "x.mmdb").write_bytes(b"x")
    def boom(_): raise ImportError("no maxminddb")
    with caplog.at_level(logging.WARNING):
        g = GeoEnricher(str(tmp_path / "x.mmdb"), opener=boom)
    assert not g.available and "maxminddb" in caplog.text


def test_alert_carries_enrichment(tmp_path):
    g, _ = fake_geo(tmp_path)
    res = Pipeline(load_rules_from_text(FAILED_RULE), geo=g).run([ev(0, ip="8.8.8.8")])
    assert res.alerts[0].enrichment["source.ip"]["as_org"] == "GOOGLE"


# ===================== Baseline ======================================================================
def login(day, hour, user="alice", cc="US", ip="8.8.8.8", minute=0):
    e = ev(0, ip=ip, outcome="success", user=user, **{"source.geo.country_iso_code": cc})
    e["@timestamp"] = fmt_ts(datetime(2026, 3, day, hour, minute, tzinfo=timezone.utc))
    return e


def trained(min_samples=5):
    b = Baseline(min_samples)
    b.train([login(d, h) for d in range(1, 8) for h in (8, 9, 10, 17)])
    return b


def test_never_seen_hour_is_flagged_with_explanation():
    out = trained().check(login(10, 3, minute=14))
    assert [a.rule_id for a in out] == ["baseline.unusual_hour"]
    r = out[0].reasoning
    assert "alice" in r and "08:00\u201310:59" in r and "17:00\u201317:59" in r and "03:14 UTC" in r
    assert out[0].kind == "anomaly"


def test_never_seen_country_is_flagged_with_explanation():
    out = trained().check(login(10, 9, cc="RU", ip="203.0.113.5"))
    assert [a.rule_id for a in out] == ["baseline.new_country"]
    assert "only logged in from US" in out[0].reasoning and "RU" in out[0].reasoning


def test_login_matching_baseline_not_flagged():
    assert trained().check(login(10, 9)) == []


def test_both_anomalies_at_once():
    assert {a.rule_id for a in trained().check(login(10, 3, cc="CN"))} == {"baseline.unusual_hour", "baseline.new_country"}


def test_cold_start_unknown_user_and_too_few_samples_not_flagged():
    b = trained()
    assert b.check(login(10, 3, user="newbie")) == []
    thin = Baseline(5)
    thin.train([login(1, 9), login(2, 9)])  # only 2 logins < min_samples
    assert thin.check(login(3, 3)) == [] and thin.cold_start_skips == 1
    assert Baseline().check(login(3, 3)) == []  # completely empty baseline


def test_failed_logins_ignored_and_train_until_cutoff():
    b = Baseline(1)
    f = login(1, 9); f["event"]["outcome"] = "failure"
    assert b.train([f]) == 0
    b.train([login(1, 9), login(20, 9)], until=datetime(2026, 3, 10, tzinfo=timezone.utc))
    assert b.subjects["user:alice"]["logins"] == 1


def test_baseline_save_load_roundtrip(tmp_path):
    b = trained(); b.save(tmp_path / "b.json")
    assert Baseline.load(tmp_path / "b.json").subjects == b.subjects


def test_hour_ranges_compaction():
    assert hour_ranges([8, 9, 10, 17]) == "08:00\u201310:59, 17:00\u201317:59"


# ===================== Dedup =========================================================================
def mk_alert(offset, rule="r", ip="1.1.1.1"):
    from datetime import timedelta
    return Alert(rule, "t", Severity.HIGH, T0 + timedelta(seconds=offset), "correlation", "m", group={"source.ip": ip})


def test_dedup_suppresses_within_cooldown_then_realerts():
    d = Deduper(300)
    assert d.allow(mk_alert(0))
    assert not d.allow(mk_alert(10)) and not d.allow(mk_alert(299))
    assert d.allow(mk_alert(300))
    assert d.suppressed == 2


def test_dedup_key_is_rule_plus_group():
    d = Deduper(300)
    assert d.allow(mk_alert(0)) and d.allow(mk_alert(1, ip="2.2.2.2")) and d.allow(mk_alert(2, rule="other"))


def test_sliding_correlation_window_alerts_once_in_pipeline():
    rs = load_rules_from_text(FAILED_RULE + corr())
    res = Pipeline(rs, cooldown=300).run([ev(i) for i in range(40)])  # fires on every event from the 10th
    assert len([a for a in res.alerts if a.kind == "correlation"]) == 1
    assert res.suppressed == 30
    res2 = Pipeline(load_rules_from_text(FAILED_RULE + corr()), cooldown=0).run([ev(i) for i in range(40)])
    assert len(res2.alerts) == 31  # cooldown disabled -> every slide alerts
    res3 = Pipeline(load_rules_from_text(FAILED_RULE + corr()), cooldown=60).run([ev(i * 10) for i in range(40)])
    assert 1 < len(res3.alerts) < 31
