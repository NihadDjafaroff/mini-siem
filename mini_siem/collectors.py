"""Log collection.

  * SyslogReceiver : UDP + TCP listener (RFC 5424; RFC 6587 framing on TCP) ~ rsyslog/syslog-ng imudp/imtcp
  * FileCollector  : agentless tail/poll of local files ~ Filebeat `log` input / Wazuh logcollector
"""
from __future__ import annotations

import logging
import socketserver
import threading
import time
from pathlib import Path

from .store import EventSink

log = logging.getLogger("mini_siem.collect")
MAX_MSG = 64 * 1024


def split_frames(buf: bytes) -> tuple[list[bytes], bytes]:
    """Split a TCP byte stream into syslog messages. Supports RFC 6587 octet-counting and newline framing."""
    msgs: list[bytes] = []
    while buf:
        if buf[:1].isdigit():
            sp = buf.find(b" ")
            if sp == -1:
                if len(buf) > 8:  # no space after >8 digits: not octet counting
                    pass
                else:
                    break
            elif buf[:sp].isdigit():
                n = int(buf[:sp])
                if len(buf) < sp + 1 + n:
                    break
                msgs.append(buf[sp + 1: sp + 1 + n])
                buf = buf[sp + 1 + n:]
                continue
        nl = buf.find(b"\n")
        if nl == -1:
            if len(buf) > MAX_MSG:
                msgs.append(buf)
                buf = b""
            break
        if buf[:nl].strip():
            msgs.append(buf[:nl])
        buf = buf[nl + 1:]
    return msgs, buf


class SyslogReceiver:
    def __init__(self, sink: EventSink, host="127.0.0.1", port=5514, protocol="both"):
        self.sink, self.host, self.port, self.protocol = sink, host, port, protocol
        self._servers: list[socketserver.BaseServer] = []
        self.udp_port = self.tcp_port = None

    def start(self) -> None:
        sink = self.sink
        if self.protocol in ("udp", "both"):
            class UDP(socketserver.BaseRequestHandler):
                def handle(self):
                    data, _ = self.request
                    # one datagram == one message (RFC 5426)
                    sink.ingest_line(data.decode("utf-8", "replace"), f"syslog-udp:{self.client_address[0]}",
                                     {"sender": self.client_address[0]})
            s = socketserver.ThreadingUDPServer((self.host, self.port), UDP)
            self.udp_port = s.server_address[1]
            self._serve(s)
        if self.protocol in ("tcp", "both"):
            class TCP(socketserver.BaseRequestHandler):
                def handle(self):
                    buf, peer = b"", self.client_address[0]
                    while True:
                        chunk = self.request.recv(4096)
                        if not chunk:
                            break
                        msgs, buf = split_frames(buf + chunk)
                        for m in msgs:
                            sink.ingest_line(m.decode("utf-8", "replace"), f"syslog-tcp:{peer}", {"sender": peer})
                    if buf.strip():
                        sink.ingest_line(buf.decode("utf-8", "replace"), f"syslog-tcp:{peer}", {"sender": peer})

            class Srv(socketserver.ThreadingTCPServer):
                allow_reuse_address = True
                daemon_threads = True
            port = self.port if self.protocol == "tcp" or not self.udp_port else self.udp_port
            s = Srv((self.host, port), TCP)
            self.tcp_port = s.server_address[1]
            self._serve(s)
        log.info("syslog receiver listening on %s udp=%s tcp=%s", self.host, self.udp_port, self.tcp_port)

    def _serve(self, srv):
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True, kwargs={"poll_interval": 0.1}).start()
        self._servers.append(srv)

    def stop(self) -> None:
        for s in self._servers:
            s.shutdown()
            s.server_close()
        self._servers.clear()


class FileCollector:
    """Reads a file once, or follows it (poll) surviving truncation/rotation."""

    def __init__(self, sink: EventSink, path: str | Path, follow=False, from_start=True, poll=0.5):
        self.sink, self.path, self.follow, self.from_start, self.poll = sink, Path(path), follow, from_start, poll
        self.stop_event = threading.Event()

    def run(self, max_idle: float | None = None) -> int:
        n, src = 0, f"file:{self.path.name}"
        pos = 0 if self.from_start or not self.follow else (self.path.stat().st_size if self.path.exists() else 0)
        partial, idle_since, ino = "", time.monotonic(), None
        while not self.stop_event.is_set():
            if not self.path.exists():
                if not self.follow:
                    raise FileNotFoundError(self.path)
                time.sleep(self.poll)
                continue
            st = self.path.stat()
            if ino is not None and (st.st_ino != ino or st.st_size < pos):  # rotated / truncated
                pos, partial = 0, ""
            ino = st.st_ino
            if st.st_size > pos:
                with open(self.path, "rb") as f:
                    f.seek(pos)
                    data = f.read()
                    pos = f.tell()
                text = partial + data.decode("utf-8", "replace")
                lines = text.split("\n")
                partial = lines.pop()
                if not self.follow and partial:  # last line without newline
                    lines.append(partial)
                    partial = ""
                for line in lines:
                    if line.strip():
                        self.sink.ingest_line(line, src)
                        n += 1
                idle_since = time.monotonic()
            if not self.follow:
                break
            if max_idle is not None and time.monotonic() - idle_since > max_idle:
                break
            time.sleep(self.poll)
        return n
