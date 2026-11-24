import socket
import threading
import time

from mini_siem.collectors import FileCollector, SyslogReceiver, split_frames
from mini_siem.ecs import get_path
from mini_siem.store import DataDir, EventSink, read_jsonl

MSG = "<34>1 2026-03-01T10:15:02Z fw01 sshd 812 - - Failed password for root from 203.0.113.9 port 4242 ssh2"


def wait_for(cond, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_split_frames_newline_and_octet_counting():
    msgs, rest = split_frames(b"<1>a\n<2>b\n<3>part")
    assert msgs == [b"<1>a", b"<2>b"] and rest == b"<3>part"
    framed = f"{len(MSG)} {MSG}".encode()
    msgs, rest = split_frames(framed + framed[:10])
    assert msgs == [MSG.encode()] and rest == framed[:10]


def test_syslog_udp_and_tcp_end_to_end(tmp_path):
    sink = EventSink(DataDir(tmp_path), "syslog")
    rx = SyslogReceiver(sink, "127.0.0.1", 0, "both")
    rx.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            u.sendto(MSG.encode(), ("127.0.0.1", rx.udp_port))
        with socket.create_connection(("127.0.0.1", rx.tcp_port), timeout=2) as t:
            t.sendall(f"{len(MSG)} {MSG}".encode() + (MSG + "\n").encode() + b"garbage line\n")
        assert wait_for(lambda: sink.accepted == 3 and sink.rejected == 1)
    finally:
        rx.stop()
    evs = list(read_jsonl(DataDir(tmp_path).events))
    assert len(evs) == 3 and all(get_path(e, "source.ip") == "203.0.113.9" for e in evs)
    assert {e["event"]["module"] for e in evs} == {"syslog-udp", "syslog-tcp"}
    assert get_path(evs[0], "observer.ip") == "127.0.0.1"
    rejects = list(read_jsonl(DataDir(tmp_path).rejects))
    assert rejects[0]["raw"] == "garbage line"           # bad frame preserved, not dropped


LINE = "Mar  1 10:00:0{} web01 sshd[1]: Failed password for bob from 203.0.113.5 port 22 ssh2"


def test_file_collector_batch_reads_last_line_without_newline(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text(LINE.format(1) + "\n" + LINE.format(2))
    sink = EventSink(DataDir(tmp_path / "d"), "authlog", {"default_year": 2026})
    assert FileCollector(sink, f).run() == 2 and sink.accepted == 2


def test_file_collector_follow_picks_up_appends_and_truncation(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text(LINE.format(1) + "\n")
    sink = EventSink(DataDir(tmp_path / "d"), "authlog", {"default_year": 2026})
    c = FileCollector(sink, f, follow=True, poll=0.05)
    t = threading.Thread(target=c.run, kwargs={"max_idle": 1.5})
    t.start()
    assert wait_for(lambda: sink.accepted == 1)
    with open(f, "a") as fh:
        fh.write(LINE.format(2) + "\n")
    assert wait_for(lambda: sink.accepted == 2)
    f.write_text(LINE.format(3) + "\n")                    # rotated/truncated, smaller than before
    assert wait_for(lambda: sink.accepted == 3)
    c.stop_event.set()
    t.join(3)
    assert not t.is_alive()


def test_file_collector_missing_file_raises(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError):
        FileCollector(EventSink(DataDir(tmp_path), "authlog"), tmp_path / "nope").run()
