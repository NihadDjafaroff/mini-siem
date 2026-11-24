"""Shared data models: severity levels and alerts."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum

from .ecs import fmt_ts


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_level(cls, level: str | None) -> "Severity":
        if not level:
            return cls.MEDIUM
        l = str(level).strip().lower()
        if l == "informational":
            return cls.INFO
        try:
            return cls[l.upper()]
        except KeyError:
            raise ValueError(f"unknown severity level {level!r}")


class ParseError(Exception):
    """A raw record could not be normalized. Never swallowed silently."""


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: Severity
    timestamp: datetime
    kind: str  # single | correlation | ioc | anomaly
    message: str
    group: dict = field(default_factory=dict)
    event: dict | None = None
    context: dict = field(default_factory=dict)
    tags: list = field(default_factory=list)
    ioc: dict | None = None
    enrichment: dict = field(default_factory=dict)
    reasoning: str | None = None
    escalated_from: Severity | None = None

    @property
    def alert_id(self) -> str:
        raw = f"{self.rule_id}|{sorted(self.group.items())}|{fmt_ts(self.timestamp)}|{self.kind}"
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    def escalate(self, to: Severity) -> None:
        if to > self.severity:
            self.escalated_from = self.severity
            self.severity = to

    def to_dict(self) -> dict:
        d = {
            "alert_id": self.alert_id,
            "@timestamp": fmt_ts(self.timestamp),
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name,
            "kind": self.kind,
            "message": self.message,
            "group": self.group,
            "tags": self.tags,
            "context": self.context,
        }
        if self.escalated_from is not None:
            d["escalated_from"] = self.escalated_from.name
        if self.ioc:
            d["ioc"] = self.ioc
        if self.enrichment:
            d["enrichment"] = self.enrichment
        if self.reasoning:
            d["reasoning"] = self.reasoning
        if self.event is not None:
            d["event"] = self.event
        return d
