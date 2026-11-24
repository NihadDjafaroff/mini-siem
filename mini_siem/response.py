"""Active response: NIST SP 800-61 *Detect -> Contain* only. Never Eradicate/Recover.

Safety model (two-step opt-in):
  * off unless enable=True
  * dry-run unless apply=True as well (dry-run NEVER invokes the runner)
  * allow-list is checked before anything else and cannot be bypassed by a rule or IOC
  * every block is time-bounded (TTL) and recorded with who/what/when/why + the reverse command
  * ambiguous targets (several distinct source IPs: likely NAT/proxy) get a notification, not a block
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import subprocess
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .ecs import fmt_ts, get_path
from .models import Alert, Severity

log = logging.getLogger("mini_siem.response")

HARDCODED_ALLOW = ["127.0.0.0/8", "::1/128", "0.0.0.0/32", "::/128", "169.254.0.0/16", "fe80::/10",
                   "224.0.0.0/4", "ff00::/8", "255.255.255.255/32"]


# ---- firewall backends ----------------------------------------------------------------------
class Backend:
    name = ""

    def setup(self) -> list[list[str]]:
        return []

    def block(self, ip: str, action_id: str, ttl: int) -> tuple[list[str], list[str]]:
        raise NotImplementedError


class IptablesBackend(Backend):
    name = "iptables"

    def block(self, ip, action_id, ttl):
        tool = "ip6tables" if ":" in ip else "iptables"
        rule = ["-s", ip, "-m", "comment", "--comment", f"mini-siem:{action_id}", "-j", "DROP"]
        return [tool, "-I", "INPUT", *rule], [tool, "-D", "INPUT", *rule]


class NftBackend(Backend):
    """Uses a dedicated table + set with a native element timeout: self-expires even if mini-siem dies."""
    name = "nft"

    def setup(self):
        t = "inet mini_siem"
        return [["nft", "add", "table", *t.split()],
                ["nft", "add", "set", *t.split(), "blocked4", "{ type ipv4_addr; flags timeout; }"],
                ["nft", "add", "set", *t.split(), "blocked6", "{ type ipv6_addr; flags timeout; }"],
                ["nft", "add", "chain", *t.split(), "input", "{ type filter hook input priority -10; }"],
                ["nft", "add", "rule", *t.split(), "input", "ip", "saddr", "@blocked4", "drop"],
                ["nft", "add", "rule", *t.split(), "input", "ip6", "saddr", "@blocked6", "drop"]]

    def block(self, ip, action_id, ttl):
        s = "blocked6" if ":" in ip else "blocked4"
        return (["nft", "add", "element", "inet", "mini_siem", s, f"{{ {ip} timeout {ttl}s }}"],
                ["nft", "delete", "element", "inet", "mini_siem", s, f"{{ {ip} }}"])


class NetshBackend(Backend):
    name = "netsh"

    def block(self, ip, action_id, ttl):
        name = f"name=mini-siem-{action_id}"
        return (["netsh", "advfirewall", "firewall", "add", "rule", name, "dir=in", "action=block", f"remoteip={ip}"],
                ["netsh", "advfirewall", "firewall", "delete", "rule", name])


BACKENDS = {"iptables": IptablesBackend, "nft": NftBackend, "netsh": NetshBackend}


def choose_backend(preference: str = "auto", platform: str | None = None) -> Backend:
    if preference != "auto":
        if preference not in BACKENDS:
            raise ValueError(f"unknown backend {preference!r}; choose from {sorted(BACKENDS)} or auto")
        return BACKENDS[preference]()
    return NetshBackend() if (platform or sys.platform).startswith("win") else IptablesBackend()


# ---- allow-list -----------------------------------------------------------------------------
def local_addresses() -> set[str]:
    """Best-effort own IPs + default gateways. Never raises."""
    ips: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0].split("%")[0])
    except OSError:
        pass
    try:  # UDP connect sends no packet; it only selects the outbound interface
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    ips.update(default_gateways())
    return ips


def default_gateways() -> set[str]:
    gws: set[str] = set()
    try:
        if sys.platform.startswith("win"):
            out = subprocess.run(["route", "print", "-4", "0.0.0.0"], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                p = line.split()
                if len(p) >= 3 and p[0] == "0.0.0.0" and p[1] == "0.0.0.0":
                    gws.add(p[2])
        elif os.path.exists("/proc/net/route"):
            for line in Path("/proc/net/route").read_text().splitlines()[1:]:
                p = line.split()
                if len(p) > 2 and p[1] == "00000000":
                    gws.add(socket.inet_ntoa(bytes.fromhex(p[2])[::-1]))
    except Exception:
        pass
    return {g for g in gws if g not in ("0.0.0.0", "On-link")}


class AllowList:
    def __init__(self, extra=(), local_ips=None):
        nets = []
        for item in [*HARDCODED_ALLOW, *extra, *(local_ips if local_ips is not None else local_addresses())]:
            try:
                nets.append(ipaddress.ip_network(str(item), strict=False))
            except ValueError:
                raise ValueError(f"invalid allow-list entry {item!r}")
        self.nets = nets

    def protects(self, ip: str) -> bool:
        a = ipaddress.ip_address(ip)
        return any(a.version == n.version and a in n for n in self.nets)


# ---- actions --------------------------------------------------------------------------------
@dataclass
class Action:
    id: str
    created: str
    ip: str
    mechanism: str
    status: str            # dry-run | applied | undone | expired | skipped | failed | notified | would-notify
    rule_id: str
    severity: str
    reason: str
    ttl_seconds: int
    expires_at: str | None
    who: str = "mini-siem"
    apply_cmd: list = field(default_factory=list)
    reverse_cmd: list = field(default_factory=list)
    how_to_reverse: str = ""
    error: str | None = None


class ActionStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def load(self) -> list[Action]:
        if not self.path.exists():
            return []
        return [Action(**d) for d in json.loads(self.path.read_text(encoding="utf-8") or "[]")]

    def save(self, actions: list[Action]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps([asdict(a) for a in actions], indent=2), encoding="utf-8")
        tmp.replace(self.path)


def _run(runner, cmd):
    return runner(cmd, capture_output=True, text=True, timeout=30)


class ResponseManager:
    def __init__(self, store_path, enabled=False, apply=False, ttl_seconds=3600, allowlist: AllowList | None = None,
                 min_severity=Severity.HIGH, backend: Backend | None = None, runner=subprocess.run,
                 notifier=None, clock=lambda: datetime.now(timezone.utc)):
        self.store = ActionStore(store_path)
        self.enabled, self.apply = enabled, apply and enabled
        self.ttl = int(ttl_seconds)
        self.allow = allowlist or AllowList()
        self.min_severity = min_severity
        self.backend = backend or choose_backend()
        self.runner, self.notifier, self.clock = runner, notifier, clock
        self._setup_done = False

    # -- helpers
    @staticmethod
    def target_ip(alert: Alert) -> str | None:
        ip = alert.group.get("source.ip") or get_path(alert.event or {}, "source.ip")
        return str(ip) if ip else None

    def _record(self, actions, a: Action) -> Action:
        actions.append(a)
        self.store.save(actions)
        log.warning("RESPONSE %s: %s ip=%s via %s rule=%s reason=%s | reverse: %s", a.id, a.status.upper(), a.ip,
                    a.mechanism, a.rule_id, a.reason, a.how_to_reverse or "n/a")
        return a

    # -- main entry
    def handle(self, alert: Alert) -> Action | None:
        if not self.enabled or alert.severity < self.min_severity:
            return None
        ip = self.target_ip(alert)
        if not ip:
            return None
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None
        now = self.clock()
        actions = self.store.load()
        aid = uuid.uuid4().hex[:8]
        base = dict(id=aid, created=fmt_ts(now), ip=ip, rule_id=alert.rule_id, severity=alert.severity.name,
                    reason=alert.message, ttl_seconds=self.ttl)
        if self.allow.protects(ip):
            return self._record(actions, Action(**base, mechanism="none", status="skipped", expires_at=None,
                                                how_to_reverse="nothing was done",
                                                error="SAFETY: target is on the allow-list (never blocked)"))
        live = [a for a in actions if a.ip == ip and a.status in ("applied", "dry-run")
                and a.expires_at and a.expires_at > fmt_ts(now)]
        if live:
            return None  # already contained/dry-run recorded for this IP within TTL
        expires = fmt_ts(now + timedelta(seconds=self.ttl))
        distinct = alert.context.get("distinct_source_ips") or []
        if len(distinct) > 1:
            return self._notify(actions, alert, base, expires, distinct)
        apply_cmd, reverse_cmd = self.backend.block(ip, aid, self.ttl)
        how = " ".join(reverse_cmd) + f"   (or: mini-siem response undo {aid})"
        act = Action(**base, mechanism=self.backend.name, status="dry-run", expires_at=expires,
                     apply_cmd=apply_cmd, reverse_cmd=reverse_cmd, how_to_reverse=how)
        if not self.apply:
            log.warning("DRY-RUN: would block IP %s via %s for %ss: %s", ip, self.backend.name, self.ttl,
                        " ".join(apply_cmd))
            return self._record(actions, act)
        try:
            if not self._setup_done:
                for c in self.backend.setup():
                    _run(self.runner, c)
                self._setup_done = True
            r = _run(self.runner, apply_cmd)
            if r.returncode != 0:
                act.status, act.error = "failed", (r.stderr or "").strip() or f"exit {r.returncode}"
            else:
                act.status = "applied"
        except Exception as exc:
            act.status, act.error = "failed", str(exc)
        return self._record(actions, act)

    def _notify(self, actions, alert, base, expires, distinct) -> Action:
        payload = {"alert": alert.to_dict(), "why_not_blocked":
                   f"{len(distinct)} distinct source IPs ({', '.join(distinct[:5])}): possible shared NAT/proxy; "
                   "automated block judged too risky"}
        act = Action(**base, mechanism="notify", status="would-notify", expires_at=None,
                     how_to_reverse="nothing to reverse (notification only)")
        if self.apply:
            try:
                (self.notifier or (lambda p: None))(payload)
                act.status = "notified"
            except Exception as exc:
                act.status, act.error = "failed", str(exc)
        return self._record(actions, act)

    # -- lifecycle
    def undo(self, action_id: str) -> Action:
        actions = self.store.load()
        for a in actions:
            if a.id == action_id:
                if a.status == "applied":
                    r = _run(self.runner, a.reverse_cmd)
                    if r.returncode != 0:
                        a.error = (r.stderr or "").strip() or f"exit {r.returncode}"
                        self.store.save(actions)
                        raise RuntimeError(f"undo of {action_id} failed: {a.error}")
                elif a.status not in ("dry-run", "failed"):
                    raise ValueError(f"action {action_id} is '{a.status}' and cannot be undone")
                a.status = "undone"
                self.store.save(actions)
                log.warning("RESPONSE %s: UNDONE (ip %s)", a.id, a.ip)
                return a
        raise KeyError(f"no such action {action_id}")

    def expire_due(self) -> list[Action]:
        """Remove rules whose TTL has passed. Run on every ingest/detect and via `response expire`."""
        now, actions, done = fmt_ts(self.clock()), self.store.load(), []
        for a in actions:
            if a.status in ("applied", "dry-run") and a.expires_at and a.expires_at <= now:
                if a.status == "applied":
                    try:
                        r = _run(self.runner, a.reverse_cmd)
                        if r.returncode != 0:
                            a.error = (r.stderr or "").strip() or f"exit {r.returncode}"
                            continue
                    except Exception as exc:
                        a.error = str(exc)
                        continue
                a.status = "expired"
                done.append(a)
                log.warning("RESPONSE %s: TTL expired, rule for %s removed", a.id, a.ip)
        self.store.save(actions)
        return done
