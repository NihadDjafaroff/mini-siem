import json

import pytest

from mini_siem.ecs import get_path
from mini_siem.models import ParseError
from mini_siem.parsers import available, detect_parser, get_parser, normalize
from mini_siem.store import DataDir, EventSink, read_jsonl


def n(raw, parser, **ctx):
    return normalize(raw, get_parser(parser), ctx)


# ---- one test per supported source format --------------------------------------------------
def test_authlog_failed_password_invalid_user():
    raw = "Mar  1 10:15:02 web01 sshd[812]: Failed password for invalid user bob from 203.0.113.50 port 52144 ssh2"
    e = n(raw, "authlog", default_year=2026)
    assert e["@timestamp"] == "2026-03-01T10:15:02.000Z"
    assert get_path(e, "host.name") == "web01"
    assert get_path(e, "process.name") == "sshd" and get_path(e, "process.pid") == 812
    assert get_path(e, "event.action") == "ssh_login" and get_path(e, "event.outcome") == "failure"
    assert get_path(e, "source.ip") == "203.0.113.50" and get_path(e, "source.port") == 52144
    assert get_path(e, "user.name") == "bob"
    assert get_path(e, "event.category") == ["authentication"]
    assert get_path(e, "log.original") == raw


def test_authlog_accepted_and_sudo_and_iso_timestamp():
    e = n("Mar 11 08:00:00 h sshd[1]: Accepted publickey for alice from 10.0.0.5 port 22 ssh2", "authlog", default_year=2026)
    assert get_path(e, "event.outcome") == "success" and get_path(e, "labels.auth_method") == "publickey"
    s = n("2026-03-01T10:00:00.123456+00:00 h sudo: alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls -l", "authlog")
    assert get_path(s, "event.action") == "sudo" and get_path(s, "user.effective.name") == "root"
    assert get_path(s, "process.command_line") == "/bin/ls -l"
    assert s["@timestamp"] == "2026-03-01T10:00:00.123Z"


RFC5424 = ('<34>1 2026-03-01T10:15:02.003Z fw01 sshd 812 ID47 [exampleSDID@32473 iut="3" eventSource="Application"] '
           "Failed password for root from 198.51.100.9 port 4242 ssh2")


def test_syslog_rfc5424_full_mapping():
    e = n(RFC5424, "syslog", sender="192.0.2.1")
    assert e["@timestamp"] == "2026-03-01T10:15:02.003Z"
    assert get_path(e, "host.name") == "fw01" and get_path(e, "process.name") == "sshd"
    assert get_path(e, "log.syslog.facility.code") == 4 and get_path(e, "log.syslog.severity.code") == 2
    assert get_path(e, "log.syslog.facility.name") == "auth"
    assert get_path(e, "event.code") == "ID47"
    assert get_path(e, "log.syslog.structured_data")["exampleSDID@32473"]["iut"] == "3"
    assert get_path(e, "source.ip") == "198.51.100.9" and get_path(e, "event.outcome") == "failure"
    assert get_path(e, "observer.ip") == "192.0.2.1"


def test_syslog_rfc5424_nil_fields_and_rfc3164_fallback():
    e = n("<13>1 2026-03-01T00:00:00Z - - - - - hello", "syslog")
    assert get_path(e, "host.name") is None and get_path(e, "message") == "hello"
    e = n("<38>Mar  1 10:00:00 gw sshd[9]: Accepted password for u from 10.1.1.1 port 1 ssh2", "syslog", default_year=2026)
    assert get_path(e, "event.outcome") == "success"


def test_web_combined_log():
    raw = '203.0.113.7 - frank [10/Oct/2026:13:55:36 -0700] "GET /a/b?x=1 HTTP/1.1" 404 209 "http://r/" "Mozilla/5.0"'
    e = n(raw, "web")
    assert e["@timestamp"] == "2026-10-10T20:55:36.000Z"  # tz converted to UTC
    assert get_path(e, "source.ip") == "203.0.113.7" and get_path(e, "user.name") == "frank"
    assert get_path(e, "http.request.method") == "GET" and get_path(e, "url.path") == "/a/b"
    assert get_path(e, "url.query") == "x=1" and get_path(e, "http.response.status_code") == 404
    assert get_path(e, "event.outcome") == "failure" and get_path(e, "user_agent.original") == "Mozilla/5.0"
    assert get_path(e, "http.request.referrer") == "http://r/"


def test_web_common_log_without_referrer_and_dash_bytes():
    e = n('198.51.100.1 - - [10/Oct/2026:13:55:36 +0000] "POST /login HTTP/1.0" 200 -', "web")
    assert get_path(e, "user.name") is None and get_path(e, "http.response.body.bytes") is None
    assert get_path(e, "event.outcome") == "success"


SYSMON_FIELDS = {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami", "ProcessId": "100",
                 "ParentImage": "C:\\Windows\\explorer.exe", "User": "CORP\\carol",
                 "Hashes": "SHA256=" + "AB" * 32 + ",MD5=" + "CD" * 16}


@pytest.mark.parametrize("shape", ["evtx", "winlogbeat", "flat"])
def test_sysmon_json_three_shapes_normalize_identically(shape):
    if shape == "evtx":
        doc = {"Event": {"System": {"EventID": 1, "Computer": "WS01", "TimeCreated": {"SystemTime": "2026-03-01T10:00:00.5Z"},
                                    "Channel": "Microsoft-Windows-Sysmon/Operational"}, "EventData": SYSMON_FIELDS}}
    elif shape == "winlogbeat":
        doc = {"@timestamp": "2026-03-01T10:00:00.500Z", "winlog": {"event_id": 1, "computer_name": "WS01",
               "channel": "Microsoft-Windows-Sysmon/Operational", "event_data": SYSMON_FIELDS}}
    else:
        doc = {"EventID": 1, "Computer": "WS01", "UtcTime": "2026-03-01 10:00:00.500", **SYSMON_FIELDS}
    e = n(json.dumps(doc), "sysmon")
    assert e["@timestamp"] == "2026-03-01T10:00:00.500Z"
    assert get_path(e, "host.name") == "WS01"
    assert get_path(e, "process.name") == "cmd.exe" and get_path(e, "process.command_line") == "cmd.exe /c whoami"
    assert get_path(e, "process.parent.name") == "explorer.exe"
    assert get_path(e, "user.name") == "carol" and get_path(e, "user.domain") == "CORP"
    assert get_path(e, "process.hash.sha256") == "ab" * 32 and get_path(e, "process.hash.md5") == "cd" * 16
    assert get_path(e, "event.action") == "process_creation"


def test_sysmon_network_and_windows_security_logon():
    e = n(json.dumps({"EventID": 3, "UtcTime": "2026-03-01 10:00:00.000", "SourceIp": "10.0.0.5", "SourcePort": "5000",
                      "DestinationIp": "203.0.113.9", "DestinationPort": "443", "Protocol": "tcp"}), "winevent")
    assert get_path(e, "destination.port") == 443 and get_path(e, "network.transport") == "tcp"
    e = n(json.dumps({"EventID": 4625, "TimeCreated": "2026-03-01T10:00:00Z", "TargetUserName": "admin",
                      "IpAddress": "203.0.113.5", "LogonType": 3}), "winevent")
    assert get_path(e, "event.outcome") == "failure" and get_path(e, "source.ip") == "203.0.113.5"


# ---- fail loud ---------------------------------------------------------------------------------
@pytest.mark.parametrize("parser,raw", [
    ("authlog", "this is not a log line"),
    ("authlog", "Mar  1 10:00:00 h sshd[1]: Failed password for bob from not.an.ip port 22 ssh2"),
    ("syslog", "<999>1 2026-03-01T00:00:00Z h a - - - x"),
    ("syslog", "garbage"),
    ("web", "203.0.113.7 - - [bad-date] \"GET / HTTP/1.1\" 200 1"),
    ("web", "not an access log"),
    ("sysmon", "{not json"),
    ("sysmon", json.dumps({"hello": "world"})),
    ("sysmon", json.dumps({"EventID": 1})),
    ("ecs", json.dumps({"no": "timestamp"})),
])
def test_malformed_records_raise_parse_error(parser, raw):
    with pytest.raises(ParseError):
        n(raw, parser)


def test_empty_record_raises():
    with pytest.raises(ParseError):
        n("   ", "authlog")


def test_sink_never_silently_drops_malformed(tmp_path, caplog):
    sink = EventSink(DataDir(tmp_path), "authlog", {"default_year": 2026})
    good = "Mar  1 10:00:00 h sshd[1]: Accepted password for u from 10.0.0.1 port 22 ssh2"
    with caplog.at_level("WARNING"):
        assert sink.ingest_line(good, "file:a") is not None
        assert sink.ingest_line("%%% corrupt %%%", "file:a") is None
    assert sink.accepted == 1 and sink.rejected == 1
    assert "PARSE FAILURE" in caplog.text and "file:a" in caplog.text and "%%% corrupt %%%" in caplog.text
    rejects = list(read_jsonl(DataDir(tmp_path).rejects))
    assert rejects[0]["raw"] == "%%% corrupt %%%" and "reason" in rejects[0]
    assert len(list(read_jsonl(DataDir(tmp_path).events))) == 1


def test_log_original_always_preserved_for_every_parser():
    samples = {"authlog": "Mar  1 10:00:00 h sshd[1]: Accepted password for u from 10.0.0.1 port 22 ssh2",
               "syslog": RFC5424, "web": '1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 5',
               "winevent": json.dumps({"EventID": 22, "UtcTime": "2026-03-01 10:00:00.000", "QueryName": "a.example"})}
    for name, raw in samples.items():
        assert get_path(n(raw, name, default_year=2026), "log.original") == raw


def test_auto_detect_picks_right_parser():
    assert detect_parser(RFC5424).name == "syslog"
    assert detect_parser("Mar  1 10:00:00 h sshd[1]: x").name == "authlog"
    assert detect_parser('1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 5').name == "web"
    assert detect_parser(json.dumps({"EventID": 1})).name == "winevent"
    with pytest.raises(ParseError):
        detect_parser("???")


def test_registry_is_pluggable():
    assert {"syslog", "authlog", "web", "winevent", "ecs"} <= set(available())
    with pytest.raises(ValueError):
        get_parser("nope")
    assert get_parser("nginx").name == "web"
