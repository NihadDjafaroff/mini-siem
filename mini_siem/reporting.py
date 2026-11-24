"""Output: CLI table, JSON-lines, query rows, and the one-page Markdown/HTML findings report."""
from __future__ import annotations

import html
import json
from collections import Counter

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _trunc(s, n):
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def _grp(a: dict) -> str:
    return ", ".join(f"{v}" for v in a.get("group", {}).values()) or ""


def alerts_table(alerts: list[dict]) -> str:
    if not alerts:
        return "No alerts."
    rows = [("TIME", "SEVERITY", "RULE", "GROUP", "MESSAGE")]
    for a in alerts:
        sev = a["severity"] + (f" (was {a['escalated_from']})" if a.get("escalated_from") else "")
        rows.append((a["@timestamp"], sev, _trunc(a["rule_id"], 28), _trunc(_grp(a), 22), _trunc(a["message"], 70)))
    w = [max(len(r[i]) for r in rows) for i in range(5)]
    fmt = "  ".join(f"{{:<{x}}}" for x in w)
    lines = [fmt.format(*rows[0]), fmt.format(*("-" * x for x in w))] + [fmt.format(*r) for r in rows[1:]]
    for a in alerts:
        if a.get("reasoning"):
            lines.append(f"  [{a['rule_id']}] reasoning: {a['reasoning']}")
        if a.get("enrichment"):
            lines.append(f"  [{a['rule_id']}] enrichment: {json.dumps(a['enrichment'])}")
    return "\n".join(lines)


def alerts_jsonl(alerts: list[dict]) -> str:
    return "\n".join(json.dumps(a, ensure_ascii=False, separators=(",", ":")) for a in alerts)


def events_table(events: list[dict]) -> str:
    if not events:
        return "No matching events."
    from .ecs import get_path
    rows = [("TIME", "HOST", "USER", "SOURCE IP", "ACTION", "OUTCOME")]
    for e in events:
        rows.append((e["@timestamp"], str(get_path(e, "host.name") or "-"), str(get_path(e, "user.name") or "-"),
                     str(get_path(e, "source.ip") or "-"), str(get_path(e, "event.action") or "-"),
                     str(get_path(e, "event.outcome") or "-")))
    w = [max(len(r[i]) for r in rows) for i in range(6)]
    fmt = "  ".join(f"{{:<{x}}}" for x in w)
    return "\n".join([fmt.format(*rows[0]), fmt.format(*("-" * x for x in w))] + [fmt.format(*r) for r in rows[1:]])


def summarize(alerts: list[dict]) -> dict:
    by_sev = Counter(a["severity"] for a in alerts)
    ips = Counter()
    for a in alerts:
        ip = a.get("group", {}).get("source.ip") or (a.get("event") or {}).get("source", {}).get("ip")
        if ip:
            ips[ip] += 1
    return {"total": len(alerts), "by_severity": {s: by_sev.get(s, 0) for s in SEV_ORDER},
            "top_ips": ips.most_common(10)}


def render_markdown(alerts: list[dict], since: str, generated: str) -> str:
    s = summarize(alerts)
    out = [f"# mini-siem findings", "", f"Since: `{since}` · Generated: `{generated}` · Alerts: **{s['total']}**",
           "", "## Alerts by severity", "", "| Severity | Count |", "|---|---|"]
    out += [f"| {k} | {v} |" for k, v in s["by_severity"].items()]
    out += ["", "## Top offending IPs", ""]
    out += ["| IP | Alerts |", "|---|---|"] + [f"| {ip} | {n} |" for ip, n in s["top_ips"]] if s["top_ips"] else ["_none_"]
    out += ["", "## Alerts", ""]
    if not alerts:
        out.append("_No alerts in this period._")
    else:
        out += ["| Time | Severity | Rule | Group | Message |", "|---|---|---|---|---|"]
        for a in alerts:
            m = a["message"].replace("|", "\\|")
            out.append(f"| {a['@timestamp']} | {a['severity']} | {a['rule_id']} | {_grp(a)} | {m} |")
    return "\n".join(out) + "\n"


def render_html(alerts: list[dict], since: str, generated: str) -> str:
    e = html.escape
    s = summarize(alerts)
    rows = "".join(
        f"<tr class='{e(a['severity'].lower())}'><td>{e(a['@timestamp'])}</td><td>{e(a['severity'])}</td>"
        f"<td>{e(a['rule_id'])}</td><td>{e(_grp(a))}</td><td>{e(a['message'])}</td></tr>" for a in alerts)
    sev = "".join(f"<li>{e(k)}: <b>{v}</b></li>" for k, v in s["by_severity"].items())
    ips = "".join(f"<li>{e(str(ip))}: {n}</li>" for ip, n in s["top_ips"]) or "<li>none</li>"
    return (f"<!doctype html><meta charset='utf-8'><title>mini-siem findings</title>"
            "<style>body{font-family:sans-serif;margin:2em}table{border-collapse:collapse}"
            "td,th{border:1px solid #ccc;padding:4px 8px}tr.critical{background:#f8d7da}tr.high{background:#fde2c8}"
            "tr.medium{background:#fff3cd}</style>"
            f"<h1>mini-siem findings</h1><p>Since <code>{e(since)}</code> &middot; generated <code>{e(generated)}"
            f"</code> &middot; {s['total']} alerts</p><h2>By severity</h2><ul>{sev}</ul>"
            f"<h2>Top offending IPs</h2><ul>{ips}</ul><h2>Alerts</h2><table><tr><th>Time</th><th>Severity</th>"
            f"<th>Rule</th><th>Group</th><th>Message</th></tr>{rows}</table>")
