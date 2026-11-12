"""Parsers for OpenSSH auth logs (syslog format) and Apache/Nginx combined access logs."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Iterator

_TS = r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
SSH_FAILED = re.compile(
    _TS + r"\s+\S+\s+sshd\[\d+\]:\s+Failed \S+ for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)
SSH_OK = re.compile(
    _TS + r"\s+\S+\s+sshd\[\d+\]:\s+Accepted \S+ for (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)
ACCESS = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)


@dataclass
class Event:
    ts: datetime
    kind: str            # ssh_fail | ssh_ok | http
    ip: str
    user: str | None = None
    raw: str = ""
    extra: dict = field(default_factory=dict)


def _syslog_ts(text: str, year: int) -> datetime:
    return datetime.strptime(f"{year} {' '.join(text.split())}", "%Y %b %d %H:%M:%S")


def parse_ssh(lines: Iterable[str], year: int) -> Iterator[Event]:
    for line in lines:
        line = line.rstrip("\n")
        m = SSH_FAILED.search(line)
        if m:
            yield Event(_syslog_ts(m["ts"], year), "ssh_fail", m["ip"], m["user"], line)
            continue
        m = SSH_OK.search(line)
        if m:
            yield Event(_syslog_ts(m["ts"], year), "ssh_ok", m["ip"], m["user"], line)


def parse_access(lines: Iterable[str]) -> Iterator[Event]:
    for line in lines:
        line = line.rstrip("\n")
        m = ACCESS.match(line)
        if not m:
            continue
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
        yield Event(
            ts, "http", m["ip"], None, line,
            {"method": m["method"], "path": m["path"],
             "status": int(m["status"]), "ua": m["ua"] or ""},
        )
