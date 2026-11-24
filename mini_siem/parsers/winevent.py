"""Windows event JSON: Sysmon and Security-log (4624/4625) in three shapes.

  * raw EVTX-JSON   {"Event": {"System": {...}, "EventData": {...}}}
  * Winlogbeat      {"@timestamp":..., "winlog": {"event_id":.., "event_data": {...}}}
  * flat            {"EventID": 1, "UtcTime": ..., "Image": ...}

Modeled after: Winlogbeat / Sysmon module, Wazuh eventchannel collector.
"""
from __future__ import annotations

import json
import ntpath

from ..ecs import build, fmt_ts, parse_ts
from ..models import ParseError
from . import Parser, register


def _extract(doc: dict) -> tuple[int, dict, str | None, str | None, str | None]:
    """-> (event_id, event_data, timestamp, computer, channel) for any of the 3 shapes."""
    if "Event" in doc:
        ev = doc["Event"]
        system, data = ev.get("System", {}), ev.get("EventData", {}) or {}
        tc = system.get("TimeCreated", {})
        ts = tc.get("SystemTime") or tc.get("@SystemTime") if isinstance(tc, dict) else tc
        eid = system.get("EventID")
        if isinstance(eid, dict):
            eid = eid.get("#text")
        return int(eid), data, ts, system.get("Computer"), system.get("Channel")
    if "winlog" in doc:
        w = doc["winlog"]
        data = w.get("event_data", {}) or {}
        return (int(w["event_id"]), data, doc.get("@timestamp") or data.get("UtcTime"),
                w.get("computer_name") or doc.get("host", {}).get("name"), w.get("channel"))
    if "EventID" in doc or "event_id" in doc:
        eid = int(doc.get("EventID", doc.get("event_id")))
        return eid, doc, doc.get("UtcTime") or doc.get("TimeCreated") or doc.get("@timestamp"), \
            doc.get("Computer"), doc.get("Channel")
    raise ParseError("JSON does not look like a Windows event")


def _split_user(u: str | None):
    if not u:
        return None, None
    if "\\" in u:
        d, n = u.split("\\", 1)
        return n, d
    return u, None


def _hashes(prefix: str, s: str | None) -> dict:
    out = {}
    for part in (s or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[f"{prefix}.hash.{k.strip().lower()}"] = v.strip().lower()
    return out


@register
class WinEventParser(Parser):
    name = "winevent"
    dataset = "windows.event"
    description = "Sysmon / Windows Event Log JSON (raw EVTX-JSON, Winlogbeat, flat)"

    def can_parse(self, raw: str) -> bool:
        s = raw.lstrip()
        if not s.startswith("{"):
            return False
        try:
            d = json.loads(s)
        except ValueError:
            return False
        return isinstance(d, dict) and ("Event" in d or "winlog" in d or "EventID" in d or "event_id" in d)

    def parse(self, raw: str, ctx: dict | None = None) -> dict:
        try:
            doc = json.loads(raw)
        except ValueError as exc:
            raise ParseError(f"invalid JSON: {exc}")
        eid, d, ts, computer, channel = _extract(doc)
        if not ts:
            raise ParseError("no timestamp in Windows event")
        f: dict = {"@timestamp": fmt_ts(parse_ts(ts)), "host.name": computer, "event.code": str(eid),
                   "event.provider": "Microsoft-Windows-Sysmon" if channel and "Sysmon" in channel else channel}
        user, dom = _split_user(d.get("User"))
        f["user.name"], f["user.domain"] = user, dom
        if eid == 1:  # Sysmon process create
            f.update({"event.category": ["process"], "event.type": ["start"], "event.action": "process_creation",
                      "process.executable": d.get("Image"), "process.command_line": d.get("CommandLine"),
                      "process.name": ntpath.basename(d["Image"]) if d.get("Image") else None,
                      "process.pid": int(d["ProcessId"]) if str(d.get("ProcessId", "")).isdigit() else None,
                      "process.parent.executable": d.get("ParentImage"),
                      "process.parent.command_line": d.get("ParentCommandLine"),
                      "process.parent.name": ntpath.basename(d["ParentImage"]) if d.get("ParentImage") else None,
                      "process.working_directory": d.get("CurrentDirectory")})
            f.update(_hashes("process", d.get("Hashes")))
        elif eid == 3:  # Sysmon network connection
            f.update({"event.category": ["network"], "event.type": ["connection"], "event.action": "network_connection",
                      "process.executable": d.get("Image"),
                      "process.name": ntpath.basename(d["Image"]) if d.get("Image") else None,
                      "source.ip": d.get("SourceIp"), "source.port": _int(d.get("SourcePort")),
                      "destination.ip": d.get("DestinationIp"), "destination.port": _int(d.get("DestinationPort")),
                      "destination.domain": d.get("DestinationHostname") or None,
                      "network.transport": (d.get("Protocol") or "").lower() or None})
        elif eid == 11:  # file create
            f.update({"event.category": ["file"], "event.type": ["creation"], "event.action": "file_creation",
                      "file.path": d.get("TargetFilename"), "process.executable": d.get("Image")})
        elif eid == 22:  # DNS query
            f.update({"event.category": ["network"], "event.type": ["protocol"], "event.action": "dns_query",
                      "dns.question.name": d.get("QueryName"), "process.executable": d.get("Image")})
        elif eid in (4624, 4625):  # Security logon success / failure
            ok = eid == 4624
            ip = d.get("IpAddress")
            f.update({"event.category": ["authentication"], "event.type": ["start"],
                      "event.action": "logon", "event.outcome": "success" if ok else "failure",
                      "user.name": d.get("TargetUserName"), "user.domain": d.get("TargetDomainName"),
                      "source.ip": ip if ip not in (None, "-", "::1", "") else None,
                      "labels.logon_type": str(d.get("LogonType")) if d.get("LogonType") is not None else None})
        else:
            f["event.action"] = f"windows_event_{eid}"
        if f.get("source.ip"):
            import ipaddress
            try:
                ipaddress.ip_address(f["source.ip"])
            except ValueError:
                raise ParseError(f"invalid source.ip {f['source.ip']!r}")
        return build(f)


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
