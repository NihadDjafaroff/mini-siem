"""Optional YAML config; CLI flags override it. Unknown keys / wrong types are errors (exit 3)."""
from __future__ import annotations

from pathlib import Path

import yaml

SCHEMA = {"rules": str, "ioc": str, "geoip_country_db": str, "geoip_asn_db": str, "baseline": str,
          "cooldown": (int, float), "data_dir": str, "response": dict}
RESPONSE_SCHEMA = {"enable": bool, "apply": bool, "ttl": int, "allow": list, "min_severity": str,
                   "webhook": str, "backend": str}


class ConfigError(Exception):
    pass


def _check(d: dict, schema: dict, where: str):
    for k, v in d.items():
        if k not in schema:
            raise ConfigError(f"{where}: unknown key '{k}' (valid: {', '.join(sorted(schema))})")
        t = schema[k]
        if not isinstance(v, t) or (t is int and isinstance(v, bool)):
            raise ConfigError(f"{where}: '{k}' has wrong type {type(v).__name__}")


def load_config(path: str | None) -> dict:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"config file not found: {p}")
    try:
        d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{p}: invalid YAML: {exc}")
    if not isinstance(d, dict):
        raise ConfigError(f"{p}: top level must be a map")
    _check(d, SCHEMA, str(p))
    _check(d.get("response", {}), RESPONSE_SCHEMA, f"{p}: response")
    if d.get("cooldown", 0) < 0:
        raise ConfigError(f"{p}: cooldown must be >= 0")
    if "ttl" in d.get("response", {}) and d["response"]["ttl"] <= 0:
        raise ConfigError(f"{p}: response.ttl must be > 0")
    return d
