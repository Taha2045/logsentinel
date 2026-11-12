"""Detection rules. Each rule returns a list of Finding objects."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import unquote_plus

from .mitre import TECHNIQUES
from .parsers import Event

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Finding:
    rule: str
    severity: str
    src_ip: str
    count: int
    first_seen: datetime
    last_seen: datetime
    description: str
    mitre: list = field(default_factory=list)
    evidence: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "description": self.description,
            "mitre": [{"id": t, "name": TECHNIQUES.get(t, "Unknown")} for t in self.mitre],
            "evidence": self.evidence,
        }


def _densest_window(times: list[datetime], window: timedelta) -> tuple[int, int, int]:
    """Return (count, start_idx, end_idx) of the densest sliding window."""
    best, j = (0, 0, 0), 0
    for i in range(len(times)):
        while times[i] - times[j] > window:
            j += 1
        if i - j + 1 > best[0]:
            best = (i - j + 1, j, i)
    return best


def detect_ssh_bruteforce(events, threshold: int = 5, window_s: int = 300) -> list[Finding]:
    fails: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.kind == "ssh_fail":
            fails[e.ip].append(e)
    out = []
    for ip, evs in fails.items():
        evs.sort(key=lambda e: e.ts)
        count, i, j = _densest_window([e.ts for e in evs], timedelta(seconds=window_s))
        if count < threshold:
            continue
        burst = evs[i:j + 1]
        users = {e.user for e in burst}
        if len(users) >= 5:
            rule, ttp, sev = "ssh_password_spraying", ["T1110.003"], "high"
            desc = f"{count} failed SSH logins against {len(users)} distinct accounts within {window_s}s"
        else:
            rule, ttp = "ssh_bruteforce", ["T1110.001"]
            sev = "high" if count >= 20 else "medium"
            desc = f"{count} failed SSH logins within {window_s}s targeting {len(users)} account(s)"
        out.append(Finding(rule, sev, ip, count, burst[0].ts, burst[-1].ts, desc, ttp,
                           [e.raw for e in burst[:3]]))
    return out


def detect_success_after_failures(events, threshold: int = 5, window_s: int = 300) -> list[Finding]:
    """A successful login right after a burst of failures from the same IP: likely compromise."""
    relevant = sorted((e for e in events if e.kind in ("ssh_fail", "ssh_ok")), key=lambda e: e.ts)
    recent: dict[str, list[Event]] = defaultdict(list)
    window, out = timedelta(seconds=window_s), []
    for e in relevant:
        if e.kind == "ssh_fail":
            recent[e.ip].append(e)
            continue
        fails = [f for f in recent[e.ip] if e.ts - f.ts <= window]
        if len(fails) >= threshold:
            out.append(Finding(
                "ssh_success_after_bruteforce", "critical", e.ip, len(fails) + 1,
                fails[0].ts, e.ts,
                f"Successful login for '{e.user}' after {len(fails)} failures - possible account compromise",
                ["T1110", "T1078"], [fails[-1].raw, e.raw],
            ))
    return out


WEB_RULES = [
    ("web_sqli", "high", ["T1190"], "SQL injection patterns in requests",
     re.compile(r"(union\s+select|\bor\s+1\s*=\s*1|sleep\(\d+\)|information_schema|'\s*or\s*'1'\s*=\s*'1)", re.I), "path"),
    ("web_xss", "medium", ["T1190"], "Cross-site scripting payloads in requests",
     re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=)", re.I), "path"),
    ("web_path_traversal", "high", ["T1190"], "Path traversal / sensitive file access attempts",
     re.compile(r"(\.\./|\.\.\\|/etc/passwd|boot\.ini)", re.I), "path"),
    ("web_scanner_ua", "medium", ["T1595.002"], "Known offensive tool user-agent",
     re.compile(r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|hydra)", re.I), "ua"),
]


def detect_web_attacks(events, enum_threshold: int = 30) -> list[Finding]:
    hits: dict[tuple[str, str], list[Event]] = defaultdict(list)
    not_found: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.kind != "http":
            continue
        target = unquote_plus(e.extra["path"])
        for rule, _s, _t, _d, rx, where in WEB_RULES:
            hay = e.extra["ua"] if where == "ua" else target
            if rx.search(hay):
                hits[(e.ip, rule)].append(e)
        if e.extra["status"] == 404:
            not_found[e.ip].append(e)

    meta = {r[0]: r for r in WEB_RULES}
    out = []
    for (ip, rule), evs in hits.items():
        _, sev, ttp, desc, _, _ = meta[rule]
        evs.sort(key=lambda e: e.ts)
        out.append(Finding(rule, sev, ip, len(evs), evs[0].ts, evs[-1].ts,
                           f"{desc} ({len(evs)} request(s))", ttp, [e.raw for e in evs[:3]]))
    for ip, evs in not_found.items():
        if len(evs) >= enum_threshold:
            evs.sort(key=lambda e: e.ts)
            out.append(Finding("web_enumeration", "medium", ip, len(evs), evs[0].ts, evs[-1].ts,
                               f"{len(evs)} HTTP 404 responses - directory/wordlist scanning",
                               ["T1595.003"], [e.raw for e in evs[:3]]))
    return out


def analyze(events: list[Event], threshold: int = 5, window_s: int = 300) -> list[Finding]:
    findings = (
        detect_ssh_bruteforce(events, threshold, window_s)
        + detect_success_after_failures(events, threshold, window_s)
        + detect_web_attacks(events)
    )
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], -f.count))
