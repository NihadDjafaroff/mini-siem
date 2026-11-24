"""End-to-end CLI tests (same pattern as file-integrity-monitor's test_cli_and_config.py).
Exit codes: 0 clean, 1 alerts, 2 CRITICAL alerts, 3 error."""
import json
from pathlib import Path

import pytest

from mini_siem.cli import main
from mini_siem.config import ConfigError, load_config

ROOT = Path(__file__).resolve().parents[1]
RULES, LOGS, IOC = str(ROOT / "rules"), ROOT / "demo" / "logs", str(ROOT / "demo" / "ioc.json")


def run(capsys, *argv):
    code = main([str(a) for a in argv])
    out = capsys.readouterr()
    return code, out.out, out.err


@pytest.fixture
def dd(tmp_path):
    return str(tmp_path / "data")


# ---- exit codes 0 / 1 / 2 / 3 -----------------------------------------------------------------------
def test_exit_0_normal_traffic_no_alerts(capsys, dd):
    code, out, err = run(capsys, "detect", "--rules", RULES, "--logs", LOGS / "normal_auth.log",
                         "--default-year", 2026, "--data-dir", dd)
    assert code == 0 and "No alerts" in out and "alerts=0" in err


def test_exit_1_non_critical_alert(capsys, dd):
    code, out, _ = run(capsys, "detect", "--rules", RULES, "--logs", LOGS / "web_access.log", "--data-dir", dd)
    assert code == 1 and "web_sqli_probe" in out


def test_exit_2_critical_alert_bruteforce_chain(capsys, dd):
    code, out, err = run(capsys, "detect", "--rules", RULES, "--logs", LOGS / "bruteforce_auth.log",
                         "--default-year", 2026, "--data-dir", dd)
    assert code == 2 and "ssh_bruteforce_then_success" in out and "CRITICAL" in out and "suppressed_duplicates=4" in err


def test_exit_2_ioc_match(capsys, dd):
    code, out, err = run(capsys, "detect", "--rules", RULES, "--logs", LOGS / "web_access.log", "--ioc", IOC,
                         "--as-of", "2026-11-24T00:00:00Z", "--data-dir", dd)
    assert code == 2 and "Demo-C2-Server" in out
    assert "STALE IOC" in err and "Old-Botnet" in err and "stale_iocs=1" in err


@pytest.mark.parametrize("argv", [
    ["detect", "--rules", "/no/such/dir", "--logs", "x"],
    ["detect", "--logs", "x"],                                             # nothing to detect with
    ["detect", "--rules", RULES, "--logs", "/no/such/log"],
    ["detect", "--rules", RULES, "--logs", str(LOGS / "web_access.log"), "--apply"],     # --apply w/o --enable-response
    ["detect", "--rules", RULES, "--logs", str(LOGS / "web_access.log"), "--backend", "pf", "--enable-response"],
    ["detect", "--rules", RULES, "--logs", str(LOGS / "web_access.log"), "--min-severity", "spicy", "--enable-response"],
    ["detect", "--rules", RULES, "--logs", str(LOGS / "web_access.log"), "--allow", "nonsense", "--enable-response"],
    ["detect", "--rules", RULES, "--logs", str(LOGS / "web_access.log"), "--config", "/no/such.yml"],
    ["detect", "--rules", RULES, "--logs", str(LOGS / "web_access.log"), "--format", "klingon"],
    ["response", "undo", "doesnotexist"],
    ["bogus-command"],
    ["ingest", "--source", "file"],                                        # --path missing
])
def test_exit_3_errors(capsys, dd, argv):
    code, _, err = run(capsys, *argv, "--data-dir", dd) if argv[0] in ("detect", "response", "ingest") else run(capsys, *argv)
    assert code == 3


def test_exit_3_on_bad_rule_file(capsys, dd, tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("title: x\ndetection:\n  s: {a: 1}\n  condition: nope\n")
    code, _, err = run(capsys, "detect", "--rules", bad, "--logs", LOGS / "web_access.log", "--data-dir", dd)
    assert code == 3 and "unknown selection" in err


def test_unparseable_records_warned_and_counted_not_fatal(capsys, dd, tmp_path):
    log = tmp_path / "mixed.log"
    log.write_text((LOGS / "web_access.log").read_text() + "this is garbage\n")
    code, _, err = run(capsys, "detect", "--rules", RULES, "--logs", log, "--data-dir", dd)
    assert code == 1 and "rejected_records=1" in err and "PARSE FAILURE" in err and "this is garbage" in err


# ---- output formats -----------------------------------------------------------------------------------
def test_jsonl_output_one_alert_per_line(capsys, dd):
    code, out, _ = run(capsys, "detect", "--rules", RULES, "--logs", LOGS / "bruteforce_auth.log", "--default-year", 2026,
                       "--output", "jsonl", "--data-dir", dd)
    rows = [json.loads(l) for l in out.strip().splitlines()]
    assert [r["severity"] for r in rows] == ["HIGH", "CRITICAL"] and rows[0]["group"] == {"source.ip": "203.0.113.50"}
    assert all("alert_id" in r and "@timestamp" in r for r in rows)


# ---- ingest -> query -> report --------------------------------------------------------------------------
def test_ingest_query_detect_report_pipeline(capsys, dd):
    code, _, err = run(capsys, "ingest", "--source", "file", "--path", LOGS / "bruteforce_auth.log",
                       "--path", LOGS / "normal_auth.log", "--default-year", 2026, "--data-dir", dd)
    assert code == 0 and "ingested=21 rejected=0" in err
    code, out, _ = run(capsys, "query", "--ip", "203.0.113.50", "--event-type", "ssh_login", "--since",
                       "2026-11-21T03:14:30Z", "--data-dir", dd, "--format", "jsonl")
    rows = [json.loads(l) for l in out.splitlines()]
    assert len(rows) == 9 and all(r["source"]["ip"] == "203.0.113.50" for r in rows)
    assert "Failed password" in rows[0]["log"]["original"]
    code, out, _ = run(capsys, "query", "--user", "bob", "--data-dir", dd)
    assert code == 0 and out.count("bob") == 3 and "203.0.113" not in out
    code, out, _ = run(capsys, "query", "--user", "nobody", "--data-dir", dd)
    assert "No matching events" in out
    # detect over the stored normalized events
    code, out, _ = run(capsys, "detect", "--rules", RULES, "--data-dir", dd)
    assert code == 2 and "ssh_bruteforce" in out
    code, out, _ = run(capsys, "report", "--since", "2020-01-01", "--data-dir", dd)
    assert code == 0 and "# mini-siem findings" in out and "| CRITICAL | 1 |" in out and "203.0.113.50" in out
    code, out, _ = run(capsys, "report", "--since", "2020-01-01", "--format", "html", "--data-dir", dd)
    assert code == 0 and out.startswith("<!doctype html>") and "<table>" in out


def test_report_with_no_alerts_and_out_file(capsys, dd, tmp_path):
    target = tmp_path / "r.md"
    code, _, _ = run(capsys, "report", "--out", target, "--data-dir", dd)
    assert code == 0 and "No alerts in this period" in target.read_text()


def test_ingest_rejects_are_loud(capsys, dd, tmp_path):
    bad = tmp_path / "bad.log"
    bad.write_text("garbage one\nMar  1 10:00:00 h sshd[1]: Accepted password for u from 10.0.0.1 port 22 ssh2\n")
    code, _, err = run(capsys, "ingest", "--source", "file", "--path", bad, "--default-year", 2026, "--data-dir", dd)
    assert code == 0 and "rejected=1" in err and "WARNING: 1 record(s) failed parsing" in err
    assert "garbage one" in (Path(dd) / "rejects.jsonl").read_text()


# ---- active response via CLI ------------------------------------------------------------------------------
def test_cli_response_is_dry_run_by_default_and_undoable(capsys, dd):
    args = ["detect", "--rules", RULES, "--logs", LOGS / "bruteforce_auth.log", "--default-year", 2026, "--data-dir", dd,
            "--enable-response", "--backend", "iptables"]
    code, _, err = run(capsys, *args)
    assert code == 2 and "DRY-RUN" in err and "would block IP 203.0.113.50" in err
    actions = json.loads((Path(dd) / "actions.json").read_text())
    assert actions and all(a["status"] == "dry-run" for a in actions)
    code, out, _ = run(capsys, "response", "list", "--data-dir", dd)
    assert "dry-run" in out and "203.0.113.50" in out
    code, out, _ = run(capsys, "response", "undo", actions[0]["id"], "--data-dir", dd)
    assert code == 0 and "unblocked" in out
    assert json.loads((Path(dd) / "actions.json").read_text())[0]["status"] == "undone"


def test_cli_allow_flag_protects_target(capsys, dd):
    run(capsys, "detect", "--rules", RULES, "--logs", LOGS / "bruteforce_auth.log", "--default-year", 2026,
        "--data-dir", dd, "--enable-response", "--allow", "203.0.113.0/24")
    actions = json.loads((Path(dd) / "actions.json").read_text())
    assert actions and all(a["status"] == "skipped" for a in actions)


def test_response_expire_command(capsys, dd):
    code, out, _ = run(capsys, "response", "expire", "--data-dir", dd)
    assert code == 0 and "expired 0" in out


# ---- baseline via CLI ------------------------------------------------------------------------------------
def test_baseline_build_then_detect_flags_unusual_hour(capsys, dd, tmp_path):
    lines = [f"Mar {d:>2} 09:00:00 h sshd[1]: Accepted password for alice from 10.0.0.1 port 22 ssh2" for d in range(1, 8)]
    (tmp_path / "train.log").write_text("\n".join(lines) + "\n")
    (tmp_path / "now.log").write_text("Mar 10 03:14:00 h sshd[1]: Accepted password for alice from 10.0.0.1 port 22 ssh2\n")
    base = tmp_path / "b.json"
    code, _, err = run(capsys, "baseline", "build", "--logs", tmp_path / "train.log", "--default-year", 2026,
                       "--out", base, "--data-dir", dd)
    assert code == 0 and "7 successful logins" in err
    code, out, _ = run(capsys, "detect", "--baseline", base, "--logs", tmp_path / "now.log", "--default-year", 2026,
                       "--data-dir", dd)
    assert code == 1 and "03:14 UTC" in out and "09:00" in out


def test_missing_baseline_file_warns_but_runs(capsys, dd):
    code, _, err = run(capsys, "detect", "--rules", RULES, "--baseline", "/no/baseline.json",
                       "--logs", LOGS / "normal_auth.log", "--default-year", 2026, "--data-dir", dd)
    assert code == 0 and "baseline file" in err


# ---- config validation --------------------------------------------------------------------------------------
def test_config_file_supplies_defaults(capsys, dd, tmp_path):
    cfg = tmp_path / "c.yml"
    cfg.write_text(f"rules: {json.dumps(RULES)}\ncooldown: 1\nresponse: {{enable: false, ttl: 120}}\n")
    code, out, _ = run(capsys, "detect", "--config", cfg, "--logs", LOGS / "web_access.log", "--data-dir", dd)
    assert code == 1 and "web_sqli_probe" in out


@pytest.mark.parametrize("text", [
    "bogus_key: 1", "cooldown: fast", "cooldown: -5", "response: {ttl: 0}", "response: {ttl: soon}",
    "response: {nope: 1}", "- a list", "rules: [unclosed",
])
def test_config_validation_errors(tmp_path, text):
    p = tmp_path / "c.yml"
    p.write_text(text)
    with pytest.raises(ConfigError):
        load_config(str(p))


def test_version_and_help_exit_cleanly(capsys):
    assert main(["--version"]) == 0
    assert main(["detect", "--help"]) == 0
