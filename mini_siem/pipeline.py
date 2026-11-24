"""Detection pipeline: enrich (GeoIP) -> threat intel -> baseline -> Sigma rules/correlation -> dedup -> response."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .baseline import Baseline
from .dedup import Deduper
from .ecs import event_ts, get_path
from .geo import GeoEnricher
from .intel import IntelDB
from .models import Alert, Severity
from .response import ResponseManager
from .rules import Engine, RuleSet

log = logging.getLogger("mini_siem.pipeline")


@dataclass
class RunResult:
    alerts: list = field(default_factory=list)
    events: int = 0
    suppressed: int = 0
    stale_iocs: list = field(default_factory=list)
    cold_start_skips: int = 0
    actions: list = field(default_factory=list)


class Pipeline:
    def __init__(self, ruleset: RuleSet | None, intel: IntelDB | None = None, geo: GeoEnricher | None = None,
                 baseline: Baseline | None = None, cooldown: float = 300, response: ResponseManager | None = None):
        self.engine = Engine(ruleset) if ruleset else None
        self.intel, self.geo, self.baseline = intel or IntelDB(), geo, baseline
        self.dedup = Deduper(cooldown)
        self.response = response

    def run(self, events) -> RunResult:
        res = RunResult(stale_iocs=[i.to_dict() for i in self.intel.stale])
        if self.response:
            res.actions.extend(self.response.expire_due())
        for ev in sorted(events, key=event_ts):  # correlation requires event-time order
            res.events += 1
            enrich = self.geo.enrich_event(ev) if self.geo and self.geo.available else {}
            ts = event_ts(ev)
            alerts: list[Alert] = []
            hits = self.intel.match(ev)
            if self.engine:
                alerts.extend(self.engine.process(ev))
            if self.baseline:
                alerts.extend(self.baseline.check(ev))
            for ioc in hits:
                alerts.append(Alert(f"ioc.{ioc.indicator_type}", f"Threat intel match: {ioc.threat_name}",
                                    Severity.CRITICAL, ts, "ioc",
                                    f"{ioc.indicator_type} {ioc.value} matches IOC '{ioc.threat_name}' "
                                    f"(source: {ioc.source or 'n/a'})", event=ev,
                                    group={"ioc": ioc.value}, ioc=ioc.to_dict(), tags=["threat-intel"]))
            for a in alerts:
                if a.kind != "ioc" and hits:  # force-escalate whatever the base rule said
                    a.escalate(Severity.CRITICAL)
                    a.ioc = hits[0].to_dict()
                    a.message += f" [IOC: {hits[0].threat_name}]"
                if enrich:
                    a.enrichment = enrich
                # dedup: single-event alerts are distinct events; everything stateful is suppressed
                if a.kind != "single" and not self.dedup.allow(a):
                    continue
                res.alerts.append(a)
                if self.response:
                    act = self.response.handle(a)
                    if act:
                        res.actions.append(act)
        res.suppressed = self.dedup.suppressed
        res.cold_start_skips = self.baseline.cold_start_skips if self.baseline else 0
        return res
