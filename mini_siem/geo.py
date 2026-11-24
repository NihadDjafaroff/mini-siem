"""Offline GeoIP / ASN enrichment using local MaxMind GeoLite2 .mmdb files. No network calls, ever."""
from __future__ import annotations

import ipaddress
import logging
from pathlib import Path

from .ecs import get_path, set_path

log = logging.getLogger("mini_siem.geo")


def _default_opener(path):
    import maxminddb  # imported lazily: optional dependency
    return maxminddb.open_database(str(path))


class GeoEnricher:
    def __init__(self, country_db: str | None = None, asn_db: str | None = None, opener=None):
        self.opener = opener or _default_opener
        self.country = self._open(country_db, "country/city")
        self.asn = self._open(asn_db, "ASN")
        self.lookups = 0

    @property
    def available(self) -> bool:
        return self.country is not None or self.asn is not None

    def _open(self, path, label):
        if not path:
            return None
        if not Path(path).exists():
            log.warning("GeoIP %s database %s not found: enrichment disabled (get GeoLite2 from MaxMind, "
                        "see README)", label, path)
            return None
        try:
            return self.opener(path)
        except ImportError:
            log.warning("python package 'maxminddb' not installed: GeoIP %s enrichment disabled", label)
        except Exception as exc:
            log.warning("cannot open GeoIP %s database %s: %s", label, path, exc)
        return None

    @staticmethod
    def is_public(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_global
        except ValueError:
            return False

    def lookup(self, ip: str) -> dict | None:
        """-> {'country_iso','country_name','asn','as_org'} (any subset) or None for private/unknown IPs."""
        if not self.available or not self.is_public(ip):
            return None
        out: dict = {}
        try:
            if self.country:
                rec = self.country.get(ip) or {}
                c = rec.get("country") or rec.get("registered_country") or {}
                if c.get("iso_code"):
                    out["country_iso"] = c["iso_code"]
                    out["country_name"] = (c.get("names") or {}).get("en")
            if self.asn:
                rec = self.asn.get(ip) or {}
                if rec.get("autonomous_system_number"):
                    out["asn"] = rec["autonomous_system_number"]
                    out["as_org"] = rec.get("autonomous_system_organization")
        except Exception as exc:  # a corrupt record must not kill the run
            log.warning("GeoIP lookup failed for %s: %s", ip, exc)
            return None
        self.lookups += 1
        return out or None

    def enrich_event(self, ev: dict) -> dict:
        """Adds ECS source.geo.* / source.as.* (and destination.*). Returns {field: info} of what was enriched."""
        found = {}
        for side in ("source", "destination"):
            ip = get_path(ev, f"{side}.ip")
            if not ip:
                continue
            info = self.lookup(str(ip))
            if not info:
                continue
            found[f"{side}.ip"] = info
            if "country_iso" in info:
                set_path(ev, f"{side}.geo.country_iso_code", info["country_iso"])
                if info.get("country_name"):
                    set_path(ev, f"{side}.geo.country_name", info["country_name"])
            if "asn" in info:
                set_path(ev, f"{side}.as.number", info["asn"])
                if info.get("as_org"):
                    set_path(ev, f"{side}.as.organization.name", info["as_org"])
        return found
