"""mini-siem command line. Exit codes: 0 clean, 1 alerts, 2 CRITICAL alerts, 3 error."""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .baseline import Baseline
from .collectors import FileCollector, SyslogReceiver
from .config import ConfigError, load_config
from .ecs import fmt_ts, parse_since, parse_ts
from .geo import GeoEnricher
from .intel import IntelDB, IntelError
from .models import ParseError, Severity
from .parsers import available, detect_parser, get_parser, normalize
from .pipeline import Pipeline
from .query import filter_events
from .reporting import (alerts_jsonl, alerts_table, events_table, render_html, render_markdown, summarize)
from .response import AllowList, ResponseManager, choose_backend
from .rules import RuleSet, load_rules
from .sigma import RuleError
from .store import DataDir, EventSink, append_jsonl, read_jsonl

log = logging.getLogger("mini_siem")
EXIT_OK, EXIT_ALERTS, EXIT_CRITICAL, EXIT_ERROR = 0, 1, 2, 3


class CliError(Exception):
    pass


def _common(p):
    p.add_argument("--data-dir", default=None, help="where events/alerts/actions live (default ./mini-siem-data)")
    p.add_argument("--config", help="optional YAML config (CLI flags override)")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="mini-siem", description="Mini SIEM: ingest, normalize (ECS), detect (Sigma), respond.")
    ap.add_argument("--version", action="version", version=f"mini-siem {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("ingest", help="collect logs into the normalized event store")
    _common(p)
    p.add_argument("--source", required=True, choices=["syslog", "file"])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5514)
    p.add_argument("--protocol", default="both", choices=["udp", "tcp", "both"])
    p.add_argument("--duration", type=float, help="syslog: stop after N seconds (default: run until Ctrl-C)")
    p.add_argument("--path", action="append", help="file source: file to read (repeatable)")
    p.add_argument("--format", default="auto", help=f"parser: auto or {', '.join(available())}")
    p.add_argument("--follow", action="store_true", help="file source: keep tailing")
    p.add_argument("--default-year", type=int, help="year for syslog timestamps that lack one")

    p = sub.add_parser("detect", help="run Sigma + correlation rules over logs")
    _common(p)
    p.add_argument("--rules", help="directory/file of Sigma rules")
    p.add_argument("--logs", action="extend", nargs="+", help="log file or directory (repeatable); default: stored events")
    p.add_argument("--format", default="auto")
    p.add_argument("--default-year", type=int)
    p.add_argument("--ioc", help="STIX-lite IOC file (.json/.csv)")
    p.add_argument("--geoip-country-db")
    p.add_argument("--geoip-asn-db")
    p.add_argument("--baseline", help="baseline JSON built by `mini-siem baseline build`")
    p.add_argument("--cooldown", type=float, help="dedup cooldown seconds (default 300)")
    p.add_argument("--as-of", help="reference time for IOC expiry (default: now)")
    p.add_argument("--output", choices=["table", "jsonl", "both"], default="table")
    p.add_argument("--no-store", action="store_true", help="do not append alerts to alerts.jsonl")
    p.add_argument("--enable-response", action="store_true", help="ACTIVE RESPONSE (dry-run unless --apply)")
    p.add_argument("--apply", action="store_true", help="actually execute containment (needs --enable-response)")
    p.add_argument("--ttl", type=int, help="block lifetime seconds (default 3600)")
    p.add_argument("--allow", action="append", help="never-block IP/CIDR (repeatable)")
    p.add_argument("--min-severity", help="minimum severity that triggers response (default high)")
    p.add_argument("--webhook", help="URL notified instead of blocking when blocking is too risky")
    p.add_argument("--backend", help="iptables|nft|netsh|auto")

    p = sub.add_parser("query", help="search normalized events")
    _common(p)
    p.add_argument("--user"); p.add_argument("--ip"); p.add_argument("--since"); p.add_argument("--until")
    p.add_argument("--event-type", help="matches event.action / category / type / code")
    p.add_argument("--limit", type=int)
    p.add_argument("--format", choices=["table", "jsonl"], default="table")

    p = sub.add_parser("report", help="one-page findings report from stored alerts")
    _common(p)
    p.add_argument("--since", default="today")
    p.add_argument("--format", choices=["md", "html"], default="md")
    p.add_argument("--out", help="write to file instead of stdout")

    p = sub.add_parser("response", help="manage containment actions")
    rs = p.add_subparsers(dest="rcmd", required=True)
    for name in ("undo", "list", "expire"):
        leaf = rs.add_parser(name)
        _common(leaf)
        leaf.add_argument("--backend")
        if name == "undo":
            leaf.add_argument("action_id")

    p = sub.add_parser("baseline", help="build login baselines")
    bs = p.add_subparsers(dest="bcmd", required=True)
    b = bs.add_parser("build")
    _common(b)
    b.add_argument("--logs", action="extend", nargs="+")
    b.add_argument("--format", default="auto")
    b.add_argument("--until", help="train only on events before this time")
    b.add_argument("--min-samples", type=int, default=5)
    b.add_argument("--geoip-country-db")
    b.add_argument("--geoip-asn-db")
    b.add_argument("--default-year", type=int)
    b.add_argument("--out")
    return ap


def _data(args, cfg) -> DataDir:
    return DataDir(args.data_dir or cfg.get("data_dir") or "mini-siem-data")


def _pick(args, cfg, name, cfgname=None):
    v = getattr(args, name, None)
    return v if v is not None else cfg.get(cfgname or name)


def _log_files(paths: list[str]) -> list[Path]:
    out = []
    for p in paths:
        pp = Path(p)
        if not pp.exists():
            raise CliError(f"log path not found: {p}")
        out += sorted(x for x in pp.rglob("*") if x.is_file()) if pp.is_dir() else [pp]
    return out


def load_events(paths: list[str], fmt: str, ctx: dict) -> tuple[list[dict], int]:
    """Parse raw/ECS log files. Unparseable records are logged loudly and counted, never silently dropped."""
    events, rejected = [], 0
    for f in _log_files(paths):
        with open(f, encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    parser = detect_parser(line) if fmt == "auto" else get_parser(fmt)
                    events.append(normalize(line, parser, ctx))
                except ParseError as exc:
                    rejected += 1
                    log.warning("PARSE FAILURE source=%s:%d reason=%s raw=%r", f.name, n, exc, line.rstrip()[:300])
    return events, rejected


def _geo(args, cfg):
    c, a = _pick(args, cfg, "geoip_country_db"), _pick(args, cfg, "geoip_asn_db")
    return GeoEnricher(c, a) if (c or a) else None


def _make_response(args, cfg, data: DataDir):
    rc = cfg.get("response", {})
    enable = args.enable_response or rc.get("enable", False)
    apply = args.apply or rc.get("apply", False)
    if apply and not enable:
        raise CliError("--apply requires --enable-response")
    if not enable and not data.actions.exists():
        return None
    webhook = args.webhook or rc.get("webhook")

    def notifier(payload):
        if webhook:
            req = urllib.request.Request(webhook, json.dumps(payload).encode(), {"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10).read()
        else:
            data.ensure()
            append_jsonl(data.notifications, payload)
    try:
        sev = Severity.from_level(args.min_severity or rc.get("min_severity") or "high")
        allow = AllowList([*(rc.get("allow") or []), *(args.allow or [])])
        backend = choose_backend(args.backend or rc.get("backend") or "auto")
    except ValueError as exc:
        raise CliError(str(exc))
    return ResponseManager(data.actions, enabled=enable, apply=apply, ttl_seconds=args.ttl or rc.get("ttl") or 3600,
                           allowlist=allow, min_severity=sev, backend=backend, notifier=notifier)


def cmd_ingest(args, cfg) -> int:
    data = _data(args, cfg).ensure()
    ctx = {"default_year": args.default_year} if args.default_year else {}
    if args.source == "file":
        if not args.path:
            raise CliError("--path is required for --source file")
        sink = EventSink(data, args.format, ctx)
        try:
            n = sum(FileCollector(sink, p, follow=args.follow).run() for p in args.path)
        except KeyboardInterrupt:
            n = sink.accepted + sink.rejected
        except FileNotFoundError as exc:
            raise CliError(f"file not found: {exc}")
    else:
        sink = EventSink(data, "syslog", ctx)
        rx = SyslogReceiver(sink, args.host, args.port, args.protocol)
        try:
            rx.start()
        except OSError as exc:
            raise CliError(f"cannot bind {args.host}:{args.port}: {exc}")
        print(f"listening on {args.host}:{args.port} ({args.protocol}); Ctrl-C to stop", file=sys.stderr)
        try:
            time.sleep(args.duration) if args.duration else [time.sleep(1) for _ in iter(int, 1)]
        except KeyboardInterrupt:
            pass
        finally:
            rx.stop()
    print(f"ingested={sink.accepted} rejected={sink.rejected} store={data.events}", file=sys.stderr)
    if sink.rejected:
        print(f"WARNING: {sink.rejected} record(s) failed parsing; see {data.rejects}", file=sys.stderr)
    return EXIT_OK


def cmd_detect(args, cfg) -> int:
    data = _data(args, cfg)
    rules_path = _pick(args, cfg, "rules")
    ruleset: RuleSet | None = load_rules(rules_path) if rules_path else None
    now = parse_ts(args.as_of) if args.as_of else datetime.now(timezone.utc)
    ioc = _pick(args, cfg, "ioc")
    intel = IntelDB.load(ioc, now) if ioc else IntelDB()
    baseline_path = _pick(args, cfg, "baseline")
    baseline = None
    if baseline_path:
        if not Path(baseline_path).exists():
            log.warning("baseline file %s not found: anomaly detection disabled", baseline_path)
        else:
            baseline = Baseline.load(baseline_path)
    if not (ruleset or intel or baseline):
        raise CliError("nothing to detect with: give --rules, --ioc and/or --baseline")
    ctx = {"default_year": args.default_year} if args.default_year else {}
    if args.logs:
        events, rejected = load_events(args.logs, args.format, ctx)
    else:
        events, rejected = list(read_jsonl(data.events)), 0
    cooldown = args.cooldown if args.cooldown is not None else cfg.get("cooldown", 300)
    pipe = Pipeline(ruleset, intel, _geo(args, cfg), baseline, cooldown, _make_response(args, cfg, data))
    res = pipe.run(events)
    alerts = [a.to_dict() for a in res.alerts]
    if alerts and not args.no_store:
        data.ensure()
        for a in alerts:
            append_jsonl(data.alerts, a)
    if args.output in ("table", "both"):
        print(alerts_table(alerts))
    if args.output in ("jsonl", "both") and alerts:
        print(alerts_jsonl(alerts))
    sev = summarize(alerts)["by_severity"]
    print(f"events={res.events} alerts={len(alerts)} critical={sev['CRITICAL']} suppressed_duplicates={res.suppressed} "
          f"rejected_records={rejected} stale_iocs={len(res.stale_iocs)} baseline_cold_start_skips={res.cold_start_skips}",
          file=sys.stderr)
    for s in res.stale_iocs:
        print(f"STALE IOC (expired, not matched): {s['indicator_type']} {s['value']} "
              f"[{s['threat_name']}] valid_until={s['valid_until']}", file=sys.stderr)
    for act in res.actions:
        print(f"RESPONSE {act.id} {act.status.upper()} {act.mechanism} {act.ip} ttl={act.ttl_seconds}s", file=sys.stderr)
    if not alerts:
        return EXIT_OK
    return EXIT_CRITICAL if sev["CRITICAL"] else EXIT_ALERTS


def cmd_query(args, cfg) -> int:
    data = _data(args, cfg)
    now = datetime.now(timezone.utc)
    evs = filter_events(read_jsonl(data.events), args.user, args.ip,
                        parse_since(args.since, now) if args.since else None,
                        parse_since(args.until, now) if args.until else None, args.event_type, args.limit)
    if args.format == "jsonl":
        for e in evs:
            print(json.dumps(e, ensure_ascii=False, separators=(",", ":")))
    else:
        print(events_table(evs))
    return EXIT_OK


def cmd_report(args, cfg) -> int:
    data = _data(args, cfg)
    now = datetime.now(timezone.utc)
    since = parse_since(args.since, now)
    alerts = [a for a in read_jsonl(data.alerts) if parse_ts(a["@timestamp"]) >= since]
    alerts.sort(key=lambda a: (-Severity[a["severity"]], a["@timestamp"]))
    render = render_html if args.format == "html" else render_markdown
    text = render(alerts, fmt_ts(since), fmt_ts(now))
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(text)
    return EXIT_OK


def cmd_response(args, cfg) -> int:
    data = _data(args, cfg)
    mgr = ResponseManager(data.actions, backend=choose_backend(args.backend or "auto"),
                          allowlist=AllowList(local_ips=[]))
    if args.rcmd == "undo":
        try:
            a = mgr.undo(args.action_id)
        except (KeyError, ValueError, RuntimeError) as exc:
            raise CliError(str(exc))
        print(f"action {a.id}: {a.ip} unblocked ({a.mechanism})")
    elif args.rcmd == "expire":
        done = mgr.expire_due()
        print(f"expired {len(done)} action(s)")
    else:
        for a in mgr.store.load():
            print(f"{a.id}  {a.status:<12} {a.mechanism:<9} {a.ip:<18} expires={a.expires_at}  rule={a.rule_id}")
    return EXIT_OK


def cmd_baseline(args, cfg) -> int:
    data = _data(args, cfg)
    paths = args.logs or None
    if paths:
        events, _ = load_events(paths, args.format, {"default_year": args.default_year} if args.default_year else {})
    else:
        events = list(read_jsonl(data.events))
    geo = _geo(args, cfg)
    if geo and geo.available:
        for e in events:
            geo.enrich_event(e)
    b = Baseline(args.min_samples)
    n = b.train(events, parse_ts(args.until) if args.until else None)
    out = Path(args.out or data.baseline)
    out.parent.mkdir(parents=True, exist_ok=True)
    b.save(out)
    print(f"baseline built from {n} successful logins, {len(b.subjects)} subject(s) -> {out}", file=sys.stderr)
    return EXIT_OK


def main(argv=None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s", stream=sys.stderr, force=True)
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:  # argparse: 2 means usage error -> our error code, 0 for --help
        return EXIT_OK if exc.code in (0, None) else EXIT_ERROR
    try:
        cfg = load_config(args.config) if hasattr(args, "config") else {}
        return {"ingest": cmd_ingest, "detect": cmd_detect, "query": cmd_query, "report": cmd_report,
                "response": cmd_response, "baseline": cmd_baseline}[args.cmd](args, cfg)
    except (CliError, ConfigError, RuleError, IntelError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
