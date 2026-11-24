"""STIX-lite threat-intel indicators (JSON or CSV).

Record: indicator_type, value, threat_name, source, valid_until (optional ISO-8601).
Not STIX/TAXII: no bundles, patterns, relationships or confidence scoring.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .ecs import get_path, parse_ts

log = logging.getLogger("mini_siem.intel")

IP_TYPES = {"ipv4-addr", "ipv6-addr"}
HASH_TYPES = {"file-hash-sha256": "sha256", "file-hash-sha1": "sha1", "file-hash-md5": "md5"}
TYPES = IP_TYPES | set(HASH_TYPES) | {"domain-name"}
IP_FIELDS = ("source.ip", "destination.ip")
DOMAIN_FIELDS = ("destination.domain", "source.domain", "url.domain", "dns.question.name")


class IntelError(Exception):
    pass


@dataclass
class IOC:
    indicator_type: str
    value: str
    threat_name: str
    source: str = ""
    valid_until: datetime | None = None

    def to_dict(self) -> dict:
        return {"indicator_type": self.indicator_type, "value": self.value, "threat_name": self.threat_name,
                "source": self.source,
                "valid_until": self.valid_until.isoformat() if self.valid_until else None}


def _norm(t: str, v: str) -> str:
    v = v.strip()
    if t in IP_TYPES:
        return str(ipaddress.ip_address(v))
    return v.lower().rstrip(".") if t == "domain-name" else v.lower()


class IntelDB:
    def __init__(self):
        self.active: dict[tuple, IOC] = {}
        self.stale: list[IOC] = []
        self.skipped: list[str] = []

    def __len__(self):
        return len(self.active)

    @classmethod
    def load(cls, path: str | Path | None, now: datetime | None = None) -> "IntelDB":
        db = cls()
        if not path:
            return db
        p = Path(path)
        if not p.exists():
            log.warning("IOC file %s not found: threat-intel matching disabled for this run", p)
            return db
        now = now or datetime.now(timezone.utc)
        try:
            text = p.read_text(encoding="utf-8")
            if p.suffix.lower() == ".csv":
                rows = list(csv.DictReader(text.splitlines()))
            else:
                data = json.loads(text)
                rows = data.get("indicators", []) if isinstance(data, dict) else data
        except (ValueError, OSError) as exc:
            raise IntelError(f"cannot read IOC file {p}: {exc}")
        if not isinstance(rows, list):
            raise IntelError(f"{p}: expected a list of indicators")
        for i, r in enumerate(rows, 1):
            try:
                t, v = str(r["indicator_type"]).strip().lower(), str(r["value"])
                if t not in TYPES:
                    raise ValueError(f"unsupported indicator_type {t!r}")
                nv = _norm(t, v)
                vu = r.get("valid_until")
                ioc = IOC(t, nv, r.get("threat_name") or "unknown", r.get("source") or "",
                          parse_ts(vu) if vu else None)
            except (KeyError, ValueError) as exc:
                msg = f"{p} record {i}: {exc}"
                log.warning("skipping invalid IOC: %s", msg)
                db.skipped.append(msg)
                continue
            if ioc.valid_until and ioc.valid_until <= now:
                db.stale.append(ioc)
                log.warning("stale IOC ignored (expired %s): %s %s", ioc.valid_until.isoformat(), t, nv)
                continue
            db.active[(t, nv)] = ioc
        return db

    def match(self, ev: dict) -> list[IOC]:
        if not self.active:
            return []
        hits: list[IOC] = []

        def add(ioc):
            if ioc and ioc not in hits:
                hits.append(ioc)
        for f in IP_FIELDS:
            v = get_path(ev, f)
            if v:
                try:
                    n = str(ipaddress.ip_address(str(v)))
                except ValueError:
                    continue
                for t in IP_TYPES:
                    add(self.active.get((t, n)))
        for f in DOMAIN_FIELDS:
            v = get_path(ev, f)
            if v:
                d = str(v).lower().rstrip(".")
                parts = d.split(".")
                for i in range(len(parts) - 1):  # exact + parent domains
                    add(self.active.get(("domain-name", ".".join(parts[i:]))))
        for t, algo in HASH_TYPES.items():
            for prefix in ("file", "process"):
                v = get_path(ev, f"{prefix}.hash.{algo}")
                if v:
                    add(self.active.get((t, str(v).lower())))
        return hits
