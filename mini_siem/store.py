"""Append-only JSONL storage for normalized events, alerts and rejected records."""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

from .models import ParseError
from .parsers import Parser, detect_parser, get_parser, normalize

log = logging.getLogger("mini_siem.ingest")


class DataDir:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    @property
    def events(self): return self.root / "events.jsonl"
    @property
    def alerts(self): return self.root / "alerts.jsonl"
    @property
    def rejects(self): return self.root / "rejects.jsonl"
    @property
    def actions(self): return self.root / "actions.json"
    @property
    def notifications(self): return self.root / "notifications.jsonl"
    @property
    def baseline(self): return self.root / "baseline.json"

    def ensure(self):
        self.root.mkdir(parents=True, exist_ok=True)
        return self


def append_jsonl(path: Path, obj: dict, lock: threading.Lock | None = None) -> None:
    line = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    if lock:
        with lock, open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    else:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def read_jsonl(path: Path):
    if not Path(path).exists():
        return
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except ValueError:
                    log.warning("%s line %d is not valid JSON, skipped", path, n)


class EventSink:
    """Thread-safe: normalizes raw records, stores good ones, LOUDLY keeps the bad ones."""

    def __init__(self, data: DataDir, parser: str = "auto", ctx: dict | None = None):
        self.data, self.parser_name, self.ctx = data.ensure(), parser, ctx or {}
        self.lock = threading.Lock()
        self.accepted = self.rejected = 0

    def ingest_line(self, raw: str, source: str, ctx: dict | None = None) -> dict | None:
        c = {**self.ctx, **(ctx or {})}
        try:
            parser: Parser = detect_parser(raw) if self.parser_name == "auto" else get_parser(self.parser_name)
            ev = normalize(raw, parser, c)
        except ParseError as exc:
            with self.lock:
                self.rejected += 1
            log.warning("PARSE FAILURE source=%s reason=%s raw=%r", source, exc, raw[:500])
            append_jsonl(self.data.rejects, {"source": source, "reason": str(exc), "raw": raw}, self.lock)
            return None
        ev.setdefault("event", {})["module"] = source.split(":", 1)[0]
        append_jsonl(self.data.events, ev, self.lock)
        with self.lock:
            self.accepted += 1
        return ev
