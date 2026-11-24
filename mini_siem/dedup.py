"""Alert suppression on a stable key (rule id + group-by values) within a cooldown, in event time."""
from __future__ import annotations

from datetime import datetime, timedelta

from .models import Alert


class Deduper:
    def __init__(self, cooldown_seconds: float = 300):
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self.last: dict[tuple, datetime] = {}
        self.suppressed = 0

    @staticmethod
    def key(alert: Alert) -> tuple:
        return (alert.rule_id, tuple(sorted((k, str(v)) for k, v in alert.group.items())))

    def allow(self, alert: Alert) -> bool:
        k = self.key(alert)
        prev = self.last.get(k)
        if prev is not None and alert.timestamp - prev < self.cooldown:
            self.suppressed += 1
            return False
        self.last[k] = alert.timestamp
        return True
