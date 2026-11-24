"""Pluggable parser registry.

Adding a log format = dropping ONE module in this package that defines a
``Parser`` subclass decorated with ``@register``. Modules are auto-discovered;
the core never needs to change. See README "Adding a parser".
"""
from __future__ import annotations

import importlib
import pkgutil
from datetime import datetime, timezone

from ..ecs import fmt_ts
from ..models import ParseError

_REGISTRY: dict[str, "Parser"] = {}
ALIASES = {"sysmon": "winevent", "auth.log": "authlog", "apache": "web", "nginx": "web",
           "syslog5424": "syslog", "ecs": "ecs"}


class Parser:
    name = ""
    description = ""
    dataset = ""  # ECS event.dataset

    def can_parse(self, raw: str) -> bool:  # used by --format auto
        return False

    def parse(self, raw: str, ctx: dict | None = None) -> dict:
        """Return a nested ECS dict WITHOUT log.original (added by normalize)."""
        raise NotImplementedError


def register(cls):
    inst = cls()
    if not inst.name:
        raise ValueError("parser needs a name")
    _REGISTRY[inst.name] = inst
    return cls


def _discover() -> None:
    for m in pkgutil.iter_modules(__path__):
        importlib.import_module(f"{__name__}.{m.name}")


_discover()


def available() -> list[str]:
    return sorted(_REGISTRY)


def get_parser(name: str) -> Parser:
    name = ALIASES.get(name, name)
    try:
        return _REGISTRY[name]
    except KeyError:
        raise ValueError(f"unknown parser {name!r}; available: {', '.join(available())}")


def detect_parser(raw: str) -> Parser:
    for p in _REGISTRY.values():
        if p.can_parse(raw):
            return p
    raise ParseError("no parser recognizes this record")


def normalize(raw: str, parser: Parser, ctx: dict | None = None) -> dict:
    """Raw record -> ECS event. Raises ParseError (never returns partial junk)."""
    raw = raw.rstrip("\r\n")
    if not raw.strip():
        raise ParseError("empty record")
    try:
        ev = parser.parse(raw, ctx or {})
    except ParseError:
        raise
    except Exception as exc:  # parser bug / unexpected shape -> still fail loud
        raise ParseError(f"{parser.name}: {exc}") from exc
    if "@timestamp" not in ev:
        raise ParseError(f"{parser.name}: no timestamp in record")
    ev.setdefault("event", {})["dataset"] = parser.dataset or parser.name
    ev.setdefault("log", {})["original"] = raw  # forensic traceability: always kept
    return ev
