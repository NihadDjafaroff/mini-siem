"""Regenerates demo/logs/*. All IPs are RFC 5737 documentation ranges or RFC 1918 (safe, fictional)."""
import json
from datetime import datetime, timedelta
from pathlib import Path

out = Path(__file__).parent / "logs"
out.mkdir(exist_ok=True)


def ts(t):
    return f"{t:%b} {t.day:>2} {t:%H:%M:%S}"


# 1. normal traffic: working-hours logins, one typo'd password, a sudo
L, base = [], datetime(2026, 11, 20, 9, 0, 0)
for i, (u, ip) in enumerate([("alice", "10.0.0.21"), ("bob", "10.0.0.22"), ("alice", "10.0.0.21")]):
    t = base + timedelta(minutes=47 * i)
    L.append(f"{ts(t)} web01 sshd[2{i}01]: Accepted publickey for {u} from {ip} port 5{i}122 ssh2")
t = base + timedelta(hours=1, minutes=3)
L.append(f"{ts(t)} web01 sshd[2311]: Failed password for bob from 10.0.0.22 port 51200 ssh2")
L.append(f"{ts(t + timedelta(seconds=20))} web01 sshd[2312]: Accepted password for bob from 10.0.0.22 port 51201 ssh2")
L.append(f"{ts(t + timedelta(minutes=5))} web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update")
(out / "normal_auth.log").write_text("\n".join(L) + "\n")

# 2. brute force: 14 failures in 65s, then a successful root login from the same IP
L, t = [], datetime(2026, 11, 21, 3, 14, 0)
for i in range(14):
    u = ["root", "admin", "ubuntu", "test"][i % 4]
    inv = "" if u == "root" else "invalid user "
    L.append(f"{ts(t + timedelta(seconds=5 * i))} web01 sshd[4{i:03d}]: Failed password for {inv}{u} from 203.0.113.50 port {40000 + i} ssh2")
L.append(f"{ts(t + timedelta(seconds=80))} web01 sshd[4999]: Accepted password for root from 203.0.113.50 port 40100 ssh2")
(out / "bruteforce_auth.log").write_text("\n".join(L) + "\n")

# 3. web log: one IOC IP, one SQLi probe
W = [
    '198.51.100.7 - - [21/Nov/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 5120 "-" "Mozilla/5.0"',
    '198.51.100.8 - - [21/Nov/2026:10:00:09 +0000] "GET /about HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
    '203.0.113.66 - - [21/Nov/2026:10:01:13 +0000] "GET /wp-login.php HTTP/1.1" 404 196 "-" "curl/8.4.0"',
    '198.51.100.9 - - [21/Nov/2026:10:02:30 +0000] "GET /search?q=1\' OR \'1\'=\'1 HTTP/1.1" 200 812 "-" "sqlmap/1.7"',
]
(out / "web_access.log").write_text("\n".join(W) + "\n")

# 4. Sysmon (raw EVTX-JSON): encoded PowerShell whose hash is in the IOC file
ev = {"Event": {"System": {"EventID": 1, "Computer": "WS01", "Channel": "Microsoft-Windows-Sysmon/Operational",
                           "TimeCreated": {"SystemTime": "2026-11-21T10:05:00.123Z"}},
                "EventData": {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                              "CommandLine": "powershell.exe -enc SQBFAFgA ", "ProcessId": "4412",
                              "ParentImage": "C:\\Windows\\explorer.exe", "User": "CORP\\carol",
                              "Hashes": "SHA256=" + "A" * 64}}}
(out / "sysmon.jsonl").write_text(json.dumps(ev) + "\n")
print("wrote", sorted(p.name for p in out.iterdir()))
