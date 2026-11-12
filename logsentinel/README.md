# 🛡️ LogSentinel

![CI](https://github.com/Taha2025/logsentinel/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Lightweight **SOC log analyzer** that turns raw SSH and web server logs into prioritized,
**MITRE ATT&CK-mapped** findings. Zero dependencies (Python standard library only).

## Detections

| Rule | Severity | MITRE ATT&CK | Logic |
|---|---|---|---|
| `ssh_bruteforce` | Medium/High | T1110.001 | N failed logins from one IP inside a sliding time window |
| `ssh_password_spraying` | High | T1110.003 | Failures against 5+ distinct accounts from one IP |
| `ssh_success_after_bruteforce` | **Critical** | T1110, T1078 | Successful login following a burst of failures (likely compromise) |
| `web_sqli` | High | T1190 | SQL injection patterns (URL-decoded) |
| `web_xss` | Medium | T1190 | Script / event-handler payloads |
| `web_path_traversal` | High | T1190 | `../`, `/etc/passwd` and similar |
| `web_scanner_ua` | Medium | T1595.002 | sqlmap, nikto, gobuster, ... user-agents |
| `web_enumeration` | Medium | T1595.003 | 30+ HTTP 404s from one IP (wordlist scanning) |

## Install & run

```bash
git clone https://github.com/Taha2025/logsentinel && cd logsentinel
pip install -e .

logsentinel --ssh samples/auth.log --web samples/access.log --year 2026
logsentinel --ssh /var/log/auth.log --format json -o report.json
logsentinel --ssh /var/log/auth.log --threshold 10 --window 600 --fail-on high   # CI / cron friendly
```

`--fail-on` returns exit code `1` when findings at/above that severity exist, so you can plug it
into cron jobs, SOAR playbooks or pipelines.

## Sample output

```
| Severity | Rule                         | Source IP     | Count | MITRE ATT&CK |
|----------|------------------------------|---------------|-------|--------------|
| CRITICAL | ssh_success_after_bruteforce | 203.0.113.50  | 15    | T1110, T1078 |
| HIGH     | ssh_password_spraying        | 198.51.100.7  | 8     | T1110.003    |
| HIGH     | web_sqli                     | 198.51.100.23 | 1     | T1190        |
```

## Project layout

```
src/logsentinel/   parsers.py  detectors.py  mitre.py  report.py  cli.py
tests/             unit tests for every rule (python -m unittest discover -s tests)
samples/           synthetic logs using RFC 5737 documentation IPs
```

## Design notes

- **Sliding-window detection** (not simple totals) so slow, low-noise activity is not falsely flagged.
- **Correlation rule** links failed + successful logins - the event that actually matters to an analyst.
- Payloads are **URL-decoded before matching** to defeat trivial encoding evasion.
- Thresholds are tunable; real deployments should baseline against normal traffic.

## Limitations & roadmap

- Regex-based detection: determined attackers can evade it. Use it alongside a SIEM, not instead of one.
- [ ] Sigma rule export  - [ ] GeoIP / threat-intel enrichment  - [ ] Windows Event Log (4625/4624) support

## License

MIT
