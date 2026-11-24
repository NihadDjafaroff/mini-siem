"""Already-normalized ECS JSON lines (mini-siem's own store format), for `detect --logs events.jsonl`."""
from __future__ import annotations

import json

from ..ecs import fmt_ts, parse_ts
from ..models import ParseError
from . import Parser, register


@register
class EcsJsonParser(Parser):
    name = "ecs"
    dataset = "ecs"
    description = "ECS JSON lines produced by `mini-siem ingest`"

    def can_parse(self, raw: str) -> bool:
        s = raw.lstrip()
        return s.startswith("{") and '"@timestamp"' in s and '"original"' in s and '"winlog"' not in s

    def parse(self, raw: str, ctx: dict | None = None) -> dict:
        try:
            d = json.loads(raw)
        except ValueError as exc:
            raise ParseError(f"invalid JSON: {exc}")
        if not isinstance(d, dict) or "@timestamp" not in d:
            raise ParseError("ECS record without @timestamp")
        d["@timestamp"] = fmt_ts(parse_ts(d["@timestamp"]))
        return d
