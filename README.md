# mini-siem

A small, standards-aligned SIEM for lab use: it **collects** logs from several sources, **normalizes** them to
[ECS](https://www.elastic.co/guide/en/ecs/current/index.html), **detects** with Sigma rules (including Sigma
*correlation* rules, so it can reason across many events), enriches with threat intel / offline GeoIP / login
baselines, and can **contain** (opt-in, dry-run first) per NIST SP 800-61.

Part of a cybersecurity portfolio, one step up from its siblings:

| Project | Scope |
|---|---|
| `sigma2wazuh` | compiles Sigma rules to Wazuh XML (static) |
| `sysmon-triage` | evaluates Sigma against single Sysmon events |
| `file-integrity-monitor` | FIM, HMAC baselines, opt-in quarantine |
| **`mini-siem`** | multi-source ingestion + ECS normalization + **cross-event correlation** + response |

> Lab tool. Fully offline (no API calls at alert time), Python 3.10+, runs on Windows and Linux.

## Standards mapping

| Component | Standard it follows |
|---|---|
| Syslog receiver (UDP + TCP) | RFC 5424 (RFC 3164 accepted as a fallback), RFC 5426 (UDP: 1 datagram = 1 message), RFC 6587 (TCP octet-counting and newline framing) |
| Normalized schema | Elastic Common Schema: `@timestamp`, `host.name`, `source.ip`, `destination.ip/port`, `user.name`, `event.action/outcome/category/type/code/dataset`, `process.*`, `file.hash.*`, `url.*`, `http.*`, `source.geo.*`, `source.as.*`, `log.original`, `log.syslog.*`, `observer.ip` (dotted paths become nested dicts) |
| Detection rules | Sigma (single-event) + **Sigma Correlation Rules** (`correlation:` block). Targeted: the SigmaHQ correlation schema with types `event_count`, `value_count`, `temporal`, `temporal_ordered`, keys `rules`, `group-by`, `timespan`, `condition` (`gte`/`gt`/`lte`/`lt`/`eq`, `field`), `generate`. The correlation spec is still evolving; the schema was cross-checked against vendor implementations, so re-verify against the current [sigma-specification](https://github.com/SigmaHQ/sigma-specification) if you depend on edge cases. |
| Threat intel | **STIX-lite** (see below), *not* full STIX 2.1 / TAXII |
| Active response | **NIST SP 800-61 Detect → Contain only** |

### Log collectors and the real tools they imitate

| Input | Modeled after |
|---|---|
| `ingest --source syslog` (UDP/TCP listener) | rsyslog `imudp`/`imtcp`, syslog-ng, Filebeat `syslog` input; what firewalls and `*nix` daemons ship to |
| `ingest --source file --follow` (tail/poll, survives truncation/rotation) | Filebeat `log` input, Wazuh `logcollector` |
| `winevent` parser (Sysmon / Windows Event Log as JSON: raw EVTX-JSON, Winlogbeat, flat) | Winlogbeat, Wazuh `eventchannel` |
| `authlog` parser (Linux `auth.log`/`syslog`) | Filebeat `system` module |
| `web` parser (Apache/Nginx common + combined) | Filebeat `apache`/`nginx` modules |

## Architecture

```
 syslog UDP/TCP ─┐                         ┌─ GeoIP/ASN (offline mmdb) ─┐
 file tail/poll ─┼─► parser registry ─► ECS event ─► STIX-lite IOC match ├─► Sigma rules ─► correlation ─► dedup ─► alerts ─► table / JSONL / report
 (raw record)    │   (1 module/format)   + log.original  baseline check ──┘   (single)       (event_count,         │
                 │                                                                        value_count,        ▼
   parse failure ─┴─► WARNING + rejects.jsonl (never silently dropped)                     temporal[_ordered])  active response (opt-in, dry-run, Detect+Contain)
```

Stores (default `./mini-siem-data/`): `events.jsonl` (normalized), `alerts.jsonl`, `rejects.jsonl`,
`actions.json` (response audit trail), `baseline.json`.

## Features

| # | Feature | Where |
|---|---|---|
| 1 | Multi-source ingestion, pluggable parsers | `collectors.py`, `parsers/` |
| 2 | ECS normalization, `log.original` always kept, fail-loud on bad records | `parsers/__init__.py`, `store.py` |
| 3 | Sigma single-event + correlation detection | `sigma.py`, `correlation.py`, `rules.py` |
| 4 | Threat-intel matching → forced **CRITICAL**, expiry/stale reporting | `intel.py` |
| 5 | Offline GeoIP/ASN enrichment (private ranges skipped, missing DB degrades) | `geo.py` |
| 6 | Explainable baselines (login hour / country), no ML | `baseline.py` |
| 7 | Alert dedup/suppression with cooldown | `dedup.py` |
| 8 | Active response: opt-in, dry-run default, TTL, allow-list, undo | `response.py` |
| 9 | Windows/counts/group-by live in YAML, not Python | `rules/*.yml` |
| 10 | Table + JSON-lines output; one-page Markdown/HTML report | `reporting.py` |
| 11 | `query` over normalized logs, not only alerts | `query.py` |

## Install

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt     # pyyaml, maxminddb (optional, GeoIP only), pytest
pip install -e .                    # optional: gives you the `mini-siem` command (else: python -m mini_siem)
```

## CLI

```
mini-siem ingest   --source <syslog|file> ...
mini-siem detect   --rules <dir> --logs <path...>
mini-siem query    --user X --ip Y --since <time> --event-type Z
mini-siem report   --since <time> --format <md|html>
mini-siem response <undo <id>|list|expire>
mini-siem baseline build --logs <path...>
```

Exit codes (same as FIM): **0** clean · **1** alerts · **2** CRITICAL alerts · **3** error.
Times accept ISO-8601, `2d`/`6h`/`30m` (relative), `today`.
A YAML file (`--config`) can supply defaults (`rules`, `ioc`, `geoip_country_db`, `geoip_asn_db`, `baseline`,
`cooldown`, `response: {enable, apply, ttl, allow, min_severity, webhook, backend}`); unknown keys or wrong types exit 3.

## Demo walkthrough

All demo IPs are RFC 5737 documentation addresses or RFC 1918. Regenerate logs with `python demo/make_demo_logs.py`.

### 1. Normal traffic → no alerts

```powershell
python -m mini_siem detect --rules rules --logs demo/logs/normal_auth.log --default-year 2026
```
```
events=6 alerts=0 critical=0 suppressed_duplicates=0 ...
No alerts.            # exit code 0
```

### 2. Simulated brute force → correlation alert (then escalation)

14 failed SSH logins from `203.0.113.50` in 65 s, then a successful `root` login.

```powershell
python -m mini_siem detect --rules rules --logs demo/logs/bruteforce_auth.log --default-year 2026
```
```
TIME                      SEVERITY  RULE                         GROUP         MESSAGE
2026-11-21T03:14:45.000Z  HIGH      ssh_bruteforce               203.0.113.50  10 matching events (ssh_failed_login) for source.ip=203.0.113.50 within 5m
2026-11-21T03:15:20.000Z  CRITICAL  ssh_bruteforce_then_success  203.0.113.50  sequence (in order) for source.ip=203.0.113.50 within 10m: SSH Brute Force -> SSH Successful Login
events=15 alerts=2 critical=1 suppressed_duplicates=4 ...      # exit code 2
```
The brute-force match fires at the 10th failure; failures 11-14 would re-fire the sliding window but are
deduplicated (`suppressed_duplicates=4`). The `temporal_ordered` rule escalates to CRITICAL only when the success comes
from the **same** `source.ip`, **after** the burst, within 10 minutes.

### 3. Threat-intel match

```powershell
python -m mini_siem detect --rules rules --logs demo/logs/web_access.log demo/logs/sysmon.jsonl --ioc demo/ioc.json --as-of 2026-11-24T00:00:00Z
```
`203.0.113.66` (IOC `Demo-C2-Server`) → CRITICAL. The Sysmon event's SHA-256 matches `Demo-Dropper`, and the encoded-PowerShell
rule that fired on the same event is shown `CRITICAL (was HIGH)`. The fourth IOC has `valid_until: 2020-01-01`, so it does
not fire and is reported separately: `STALE IOC (expired, not matched): ipv4-addr 203.0.113.99 [Old-Botnet]`.

### 4. Active response, dry-run

```powershell
python -m mini_siem detect --rules rules --logs demo/logs/bruteforce_auth.log --default-year 2026 --enable-response --backend iptables
```
```
WARNING DRY-RUN: would block IP 203.0.113.50 via iptables for 3600s: iptables -I INPUT -s 203.0.113.50 -m comment --comment mini-siem:28b9ccc8 -j DROP
WARNING RESPONSE 28b9ccc8: DRY-RUN ip=203.0.113.50 ... | reverse: iptables -D INPUT ... (or: mini-siem response undo 28b9ccc8)
```
Nothing was executed. Add `--apply` to really install the rule (needs admin/root). Then:

```powershell
python -m mini_siem response list
python -m mini_siem response undo 28b9ccc8     # reverse before the TTL
python -m mini_siem response expire            # sweep rules whose TTL passed (run from cron / Task Scheduler / each detect run does it too)
```

### 5. Live syslog

```powershell
python -m mini_siem ingest --source syslog --port 5514 --protocol both        # terminal 1
python -c "import socket;s=socket.socket(2,2);s.sendto(b'<34>1 2026-11-21T03:14:00Z fw01 sshd 1 - - Failed password for root from 203.0.113.50 port 4242 ssh2',('127.0.0.1',5514))"
python -m mini_siem query --ip 203.0.113.50                                    # terminal 2
python -m mini_siem detect --rules rules                                       # runs over events.jsonl
```

## Rules

Single-event rules are ordinary Sigma, evaluated over **ECS fields** (e.g. `process.command_line|contains`, not
Sysmon's `CommandLine`). Supported: wildcards, modifiers `contains startswith endswith all re cidr lt lte gt gte exists`,
keyword selections, `and/or/not`, parentheses, `1 of x*`, `all of them`. Aggregation (`| count()`) is deliberately
rejected; use a correlation rule. *(This is an independent implementation of the same grammar used in `sysmon-triage`,
not shared code.)*

Correlation rules (no code changes needed; this is the shipped brute-force rule):

```yaml
title: SSH Brute Force
name: ssh_bruteforce
level: high
correlation:
  type: event_count          # event_count | value_count | temporal | temporal_ordered
  rules: [ssh_failed_login]  # base rules by name/id, or other correlations (chains)
  group-by: [source.ip]      # any ECS fields; omit to count globally
  timespan: 5m               # s / m / h / d
  condition: {gte: 10}       # gte gt lte lt eq; value_count also needs `field:`
```

Semantics worth knowing:
* A window includes events with `ts >= trigger_ts - timespan` (boundary inclusive); 300 s apart still counts for `5m`.
* Base rules referenced by a correlation do **not** alert on their own unless the correlation sets `generate: true`.
* `temporal_ordered` requires the listed rules in that order; `temporal` accepts any order. Events lacking a `group-by` field are ignored.
* `lte`/`lt` are evaluated on each arriving event (streaming), so use them as the upper bound of a range (`gte: 3, lte: 4`).
* Events are processed in event-time order, so replaying old logs gives the same result as live.

## Threat intel: STIX-lite

JSON (`{"indicators": [...]}` or a bare list) or CSV with header `indicator_type,value,threat_name,source,valid_until`.

| field | meaning |
|---|---|
| `indicator_type` | `ipv4-addr`, `ipv6-addr`, `domain-name`, `file-hash-sha256`, `file-hash-sha1`, `file-hash-md5` (STIX Cyber-observable names) |
| `value` | the observable |
| `threat_name` | attached to the alert |
| `source` | feed name |
| `valid_until` | optional ISO-8601 expiry (STIX `valid_until`) |

Deliberate simplification: no STIX bundles, patterns, relationships, confidence or TAXII transport. IPs are matched on
`source.ip`/`destination.ip`; domains (exact or parent domain) on `destination.domain`/`dns.question.name`/…;
hashes on `file.hash.*`/`process.hash.*`. A match forces every alert from that event to **CRITICAL** (`escalated_from` records
the original) and raises its own `ioc.*` alert. Expired IOCs never fire and are listed as stale (warning + summary); a missing IOC
file only warns. `--as-of` sets the reference time for expiry (default: now).

## GeoIP / ASN (offline)

Download the free **GeoLite2 Country (or City)** and **GeoLite2 ASN** `.mmdb` files from MaxMind (free account + licence
acceptance required) and point at them:

```powershell
python -m mini_siem detect --rules rules --logs ... --geoip-country-db D:\geo\GeoLite2-Country.mmdb --geoip-asn-db D:\geo\GeoLite2-ASN.mmdb
```

The databases are **not in git** (MaxMind licence/size; `*.mmdb` is git-ignored). Lookups are local file reads; no network
at alert time. Public IPs get `source.geo.country_iso_code`, `source.as.number`, … and alerts carry an `enrichment` block.
Private/loopback/link-local/documentation addresses are skipped without a lookup. A missing file or missing `maxminddb`
package logs one clear warning and the run continues unenriched.

## Baseline / anomaly detection

```powershell
python -m mini_siem baseline build --logs train.log --until 2026-03-08 --min-samples 5   # -> mini-siem-data/baseline.json
python -m mini_siem detect --baseline mini-siem-data/baseline.json --rules rules --logs today.log
```
Per user (host if no user) it records successful-login hours (UTC) and source countries. It *flags, never blocks*:
`baseline.unusual_hour` (LOW) and `baseline.new_country` (MEDIUM), each with the reasoning inline, e.g.
`user alice normally logs in 08:00–10:59, 17:00–17:59 UTC (28 logins observed); this login was at 03:14 UTC`.
**Cold start:** a subject with fewer than `--min-samples` training logins (or unknown) is never flagged; skips are counted in the
run summary (`baseline_cold_start_skips`). Country checks need GeoIP enrichment.

## Active response (Detect + Contain only)

Follows NIST SP 800-61's lifecycle: this tool automates **Detect** and **Contain**. It deliberately never does
**Eradicate** or **Recover**; those need human judgement. That is a scope boundary, not a missing feature.

Safety rails (all covered by tests):
1. Off unless `--enable-response`; even then **dry-run** (logs "would block IP X via …") unless `--apply` is also given.
2. **Allow-list always wins**: loopback, link-local, multicast, this machine's own IPs and default gateway, plus anything in
   `--allow CIDR` / config. A match against them is recorded as `skipped` and no command is run, even for CRITICAL IOC hits.
3. Blocks are **time-bounded** (`--ttl`, default 1 h) and recorded with who/what/when/why and the exact reverse command in
   `actions.json`. Expiry sweeps run on each detect and via `response expire`; the nft backend also uses a native element timeout.
4. If an alert involves **several distinct source IPs** (possible shared NAT/proxy) it sends a notification (`--webhook URL`, else
   `notifications.jsonl`) instead of blocking.
5. `mini-siem response undo <action-id>` reverses an action before its TTL.
6. Only alerts of at least `--min-severity` (default `high`) act; one live action per IP.

Backends: `iptables`/`ip6tables` (Linux default), `nft` (dedicated table + timeout set), `netsh advfirewall` (Windows default).

## Adding a parser

Create `mini_siem/parsers/mything.py`; it is auto-discovered, so there is no core change:

```python
from . import Parser, register
from ..ecs import build
from ..models import ParseError

@register
class MyParser(Parser):
    name = "mything"            # --format mything
    dataset = "mything.log"     # ECS event.dataset
    def can_parse(self, raw): return raw.startswith("MYTHING ")   # used by --format auto
    def parse(self, raw, ctx):
        ...                      # raise ParseError on anything you cannot map
        return build({"@timestamp": "...", "source.ip": "...", "event.action": "..."})
```
`log.original` and `event.dataset` are added for you; a record without `@timestamp` is rejected.

## Tests

```powershell
python -m pytest -q
```
205 tests cover: one normalization test per source format (plus three Sysmon JSON shapes) and malformed records raising / being
logged and written to `rejects.jsonl`; Sigma grammar and invalid rules; correlation threshold (N-1 vs N), window edges,
ordering, group isolation, chains, YAML-only configuration; IOC match/expiry/missing file; GeoIP public/private/missing DB;
baseline flag/no-flag/cold start; sliding-window dedup; response dry-run, allow-list, TTL, undo, notification fallback;
live UDP/TCP syslog and file tailing; CLI exit codes 0/1/2/3 end to end and config validation.

## Known limits

* `detect` is a batch pass over a log set / the event store, not a continuously running engine (ingest can run continuously).
* Syslog timestamps without a year assume the current year (`--default-year`) and UTC.
* One `group-by` alias scheme (Sigma `aliases`) and Sigma `fieldref`/`base64` modifiers are not implemented.
* Not a replacement for Wazuh/Elastic: no clustering, auth on the syslog port, or TLS (RFC 5425).

## License

MIT, see [LICENSE](LICENSE).
