import unittest
from logsentinel.detectors import analyze
from logsentinel.parsers import parse_access, parse_ssh


def ssh(lines):
    return list(parse_ssh(lines, 2026))


class TestSSH(unittest.TestCase):
    def test_bruteforce_detected(self):
        lines = [f"Nov 12 10:00:{i:02d} srv sshd[1]: Failed password for root from 203.0.113.5 port 22" for i in range(10)]
        f = analyze(ssh(lines))
        self.assertEqual(f[0].rule, "ssh_bruteforce")
        self.assertIn("T1110.001", f[0].mitre)

    def test_below_threshold_ignored(self):
        lines = [f"Nov 12 10:00:{i:02d} srv sshd[1]: Failed password for root from 203.0.113.5 port 22" for i in range(3)]
        self.assertEqual(analyze(ssh(lines)), [])

    def test_spraying(self):
        users = ["a", "b", "c", "d", "e", "f"]
        lines = [f"Nov 12 10:00:{i:02d} srv sshd[1]: Failed password for invalid user {u} from 198.51.100.7 port 22" for i, u in enumerate(users)]
        self.assertEqual(analyze(ssh(lines))[0].rule, "ssh_password_spraying")

    def test_success_after_failures_is_critical(self):
        lines = [f"Nov 12 10:00:{i:02d} srv sshd[1]: Failed password for root from 203.0.113.5 port 22" for i in range(6)]
        lines.append("Nov 12 10:01:00 srv sshd[1]: Accepted password for root from 203.0.113.5 port 22")
        f = analyze(ssh(lines))
        self.assertEqual(f[0].severity, "critical")
        self.assertEqual(f[0].rule, "ssh_success_after_bruteforce")

    def test_slow_attempts_not_flagged(self):
        lines = [f"Nov 12 {h:02d}:00:00 srv sshd[1]: Failed password for root from 203.0.113.5 port 22" for h in range(10)]
        self.assertEqual(analyze(ssh(lines)), [])


def web(path="/", status=200, ua="Mozilla/5.0", ip="198.51.100.9"):
    return f'{ip} - - [12/Nov/2026:10:00:00 +0000] "GET {path} HTTP/1.1" {status} 512 "-" "{ua}"'


class TestWeb(unittest.TestCase):
    def test_sqli(self):
        ev = list(parse_access([web("/item?id=1%20UNION%20SELECT%20password%20FROM%20users")]))
        self.assertEqual(analyze(ev)[0].rule, "web_sqli")

    def test_traversal(self):
        ev = list(parse_access([web("/download?f=../../etc/passwd")]))
        self.assertEqual(analyze(ev)[0].rule, "web_path_traversal")

    def test_scanner_ua(self):
        ev = list(parse_access([web("/", ua="sqlmap/1.7")]))
        self.assertEqual(analyze(ev)[0].rule, "web_scanner_ua")

    def test_enumeration(self):
        ev = list(parse_access([web(f"/x{i}", 404) for i in range(35)]))
        self.assertEqual(analyze(ev)[0].rule, "web_enumeration")

    def test_benign_traffic(self):
        ev = list(parse_access([web("/index.html"), web("/about")]))
        self.assertEqual(analyze(ev), [])


if __name__ == "__main__":
    unittest.main()
