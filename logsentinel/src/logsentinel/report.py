"""Report generators (JSON / Markdown)."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime

from .detectors import Finding


def to_json(findings: list[Finding], total_events: int) -> str:
    return json.dumps({
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "events_analyzed": total_events,
        "findings": [f.to_dict() for f in findings],
    }, indent=2)


def to_markdown(findings: list[Finding], total_events: int) -> str:
    sev = Counter(f.severity for f in findings)
    lines = [
        "# LogSentinel Report", "",
        f"- Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"- Events analyzed: {total_events}",
        f"- Findings: {len(findings)} "
        f"(critical: {sev['critical']}, high: {sev['high']}, medium: {sev['medium']}, low: {sev['low']})",
        "",
    ]
    if not findings:
        return "\n".join(lines + ["No suspicious activity detected."])
    lines += ["## Summary", "", "| Severity | Rule | Source IP | Count | MITRE ATT&CK |", "|---|---|---|---|---|"]
    for f in findings:
        lines.append(f"| {f.severity.upper()} | `{f.rule}` | {f.src_ip} | {f.count} | {', '.join(f.mitre)} |")
    lines += ["", "## Details", ""]
    for n, f in enumerate(findings, 1):
        lines += [f"### {n}. [{f.severity.upper()}] {f.rule} - {f.src_ip}", "",
                  f"{f.description}.", "",
                  f"- First seen: {f.first_seen}", f"- Last seen: {f.last_seen}",
                  "- Evidence:", ""]
        lines += [f"  ```\n  {e}\n  ```" for e in f.evidence]
        lines.append("")
    return "\n".join(lines)
