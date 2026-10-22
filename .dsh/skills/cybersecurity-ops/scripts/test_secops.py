#!/usr/bin/env python3
"""Unit tests for secops.py (standard library only).

Run from the skill directory:
    python -m unittest discover -s scripts -p "test_*.py" -v
"""

from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import json
import sys
import tempfile
import threading
import unittest
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import secops  # noqa: E402


class TestIOC(unittest.TestCase):
    def test_extracts_common_types(self):
        text = (
            "hxxps://evil[.]example[.]com/a?b=1 203.0.113.7 2001:db8::1 "
            "CVE-2024-1234 user@example.com "
            + "a" * 64
            + " "
            + "b" * 40
            + " "
            + "c" * 32
            + " example.org."
        )
        items = secops.extract_iocs(text, include_emails=True)
        values = {value for _, value in items}
        types = {kind for kind, _ in items}
        self.assertIn("https://evil.example.com/a?b=1", values)
        self.assertIn("evil.example.com", values)
        self.assertIn("203.0.113.7", values)
        self.assertIn("2001:db8::1", values)
        self.assertIn("CVE-2024-1234", values)
        self.assertIn("user@example.com", values)
        self.assertIn("a" * 64, values)
        self.assertIn("b" * 40, values)
        self.assertIn("c" * 32, values)
        self.assertIn("example.org", values)
        self.assertTrue({"url", "domain", "ipv4", "ipv6", "cve", "email", "sha256", "sha1", "md5"} <= types)

    def test_rejects_file_extensions_and_plain_words(self):
        items = secops.extract_iocs("file.py notes.md archive.zip localhost server.local")
        values = {value for _, value in items}
        self.assertNotIn("file.py", values)
        self.assertNotIn("notes.md", values)
        self.assertNotIn("archive.zip", values)
        self.assertNotIn("localhost", values)
        self.assertNotIn("server.local", values)

    def test_defang(self):
        self.assertEqual(secops.defang("https://a.example.com/x", "url"), "hxxps://a[.]example[.]com/x")
        self.assertEqual(secops.defang("a@example.com", "email"), "a[@]example[.]com")
        self.assertEqual(secops.defang("203.0.113.7", "ipv4"), "203[.]0[.]113[.]7")
        self.assertEqual(secops.defang("2001:db8::1", "ipv6"), "2001[:]db8[:][:]1")

    def test_collect_dedupes_and_keeps_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notes.txt"
            path.write_text("evil.example.com\nEVIL.EXAMPLE.COM\n", encoding="utf-8")
            items = secops.collect_iocs([str(path)], include_emails=False)
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["occurrences"], 2)
            self.assertEqual(items[0]["sources"], [str(path)])

    def test_context_is_redacted_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notes.txt"
            path.write_text("password=SuperSecret123 c2 evil.example.com\n", encoding="utf-8")
            items = secops.collect_iocs([str(path)], include_emails=False)
            context = items[0]["context"]
            self.assertIn("[REDACTED:secret]", context)
            self.assertNotIn("SuperSecret123", context)


class TestHash(unittest.TestCase):
    def test_hash_and_magic(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.bin"
            data = b"MZ" + b"\x00" * 30
            path.write_bytes(data)
            item = secops.describe_file(path)
            self.assertEqual(item["size"], 32)
            self.assertEqual(item["magic"], "PE/Windows executable")
            self.assertEqual(item["sha256"], hashlib.sha256(data).hexdigest())
            self.assertGreaterEqual(item["entropy"], 0.0)

    def test_text_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "note.txt"
            path.write_text("hello world\n" * 10, encoding="utf-8")
            self.assertIn("printable", secops.describe_file(path)["magic"])


class TestTriage(unittest.TestCase):
    def _rows(self):
        return [
            {
                "id": "F-001",
                "title": "Unauthenticated RCE in VPN",
                "asset": "vpn.example.com",
                "severity": "critical",
                "cvss": "9.8",
                "epss": "0.73",
                "kev": "yes",
                "internet_exposed": "yes",
                "data_sensitive": "yes",
                "confidence": "0.95",
                "cve": "CVE-2026-0001",
                "source": "nessus",
                "evidence": "E-001",
                "status": "confirmed",
            },
            {
                "id": "F-002",
                "title": "Duplicate VPN RCE",
                "asset": "vpn.example.com",
                "severity": "critical",
                "cvss": "9.8",
                "epss": "0.73",
                "kev": "yes",
                "internet_exposed": "yes",
                "data_sensitive": "yes",
                "confidence": "0.95",
                "cve": "CVE-2026-0001",
                "source": "manual",
                "evidence": "E-002",
                "status": "confirmed",
            },
            {
                "id": "F-003",
                "title": "Outdated TLS library",
                "asset": "internal.example.com",
                "severity": "high",
                "cvss": "7.5",
                "epss": "",
                "kev": "no",
                "internet_exposed": "no",
                "data_sensitive": "no",
                "confidence": "0.8",
                "cve": "",
                "source": "manual",
                "evidence": "E-003",
                "status": "suspected",
            },
        ]

    def test_score_and_priority(self):
        finding = secops.normalize_finding(self._rows()[0], 1, "test.csv")
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["priority"], "P0")
        self.assertGreater(finding["score"], 80)
        self.assertAlmostEqual(finding["epss"], 0.73)

    def test_dedupe_by_asset_and_cve(self):
        findings = [secops.normalize_finding(row, i, "test.csv") for i, row in enumerate(self._rows(), 1)]
        merged = secops.dedupe_findings(findings)
        self.assertEqual(len(merged), 2)
        vpn = [item for item in merged if item["asset"] == "vpn.example.com"][0]
        self.assertEqual(vpn["title"], "Unauthenticated RCE in VPN")
        self.assertIn("nessus", vpn["source"])
        self.assertIn("manual", vpn["source"])

    def test_missing_epss_is_unknown(self):
        finding = secops.normalize_finding(self._rows()[2], 3, "test.csv")
        self.assertIsNone(finding["epss"])
        self.assertIn("epss", finding["missing"])
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["priority"], "P2")

    def test_cvss_vector_without_score_is_unknown(self):
        row = dict(self._rows()[0])
        row["cvss"] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        finding = secops.normalize_finding(row, 1, "test.csv")
        self.assertIsNone(finding["cvss"])
        self.assertIn("cvss", finding["missing"])

    def test_kev_date_is_truthy(self):
        row = dict(self._rows()[0])
        row["kev"] = "2024-01-01"
        finding = secops.normalize_finding(row, 1, "test.csv")
        self.assertTrue(finding["kev"])

    def test_kev_unknown_is_not_truthy(self):
        row = dict(self._rows()[0])
        row["kev"] = "unknown"
        finding = secops.normalize_finding(row, 1, "test.csv")
        self.assertFalse(finding["kev"])

    def test_text_confidence(self):
        self.assertEqual(secops.normalize_confidence("high"), 0.9)
        self.assertEqual(secops.normalize_confidence("low"), 0.4)
        self.assertEqual(secops.normalize_confidence("87%"), 0.87)

    def test_priority_overrides(self):
        self.assertEqual(secops.compute_priority(90, 9.8, "critical", False, False, 0.9), "P0")
        self.assertEqual(secops.compute_priority(50, 9.0, "critical", False, False, 0.8), "P1")
        self.assertEqual(secops.compute_priority(30, 7.5, "high", False, False, 0.8), "P2")
        self.assertEqual(secops.compute_priority(10, 5.3, "medium", False, False, 0.8), "P3")

    def test_triage_markdown_output(self):
        findings = [secops.normalize_finding(row, i, "test.csv") for i, row in enumerate(self._rows(), 1)]
        merged = secops.dedupe_findings(findings)
        rendered = secops.render_triage(merged, date(2026, 10, 22), "md", "test.csv")
        self.assertIn("# Finding triage", rendered)
        self.assertIn("P0", rendered)
        self.assertIn("vpn.example.com", rendered)

    def test_json_input_and_csv_input(self):
        rows = self._rows()
        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "findings.json"
            json_path.write_text(json.dumps({"findings": rows}), encoding="utf-8")
            self.assertEqual(len(secops.load_findings(json_path)), 3)
            csv_path = Path(tmp) / "findings.csv"
            with csv_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)
            self.assertEqual(len(secops.load_findings(csv_path)), 3)


class TestScope(unittest.TestCase):
    def test_scope_matching(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope_path = Path(tmp) / "scope.txt"
            scope_path.write_text(
                "# comment\nexample.com\n*.example.com\n203.0.113.0/24\n127.0.0.1\n",
                encoding="utf-8",
            )
            scope = secops.Scope.from_files([str(scope_path)])
            self.assertTrue(scope.allows_host("example.com"))
            self.assertTrue(scope.allows_host("app.example.com"))
            self.assertFalse(scope.allows_host("a.b.example.com"))
            self.assertFalse(scope.allows_host("example.net"))
            self.assertTrue(scope.allows_host("203.0.113.7"))
            self.assertTrue(scope.allows_ip(secops.ipaddress.ip_address("127.0.0.1")))
            self.assertFalse(scope.allows_host("198.51.100.7"))

    def test_private_ip_rejected_without_explicit_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope_path = Path(tmp) / "scope.txt"
            scope_path.write_text("example.com\n", encoding="utf-8")
            scope = secops.Scope.from_files([str(scope_path)])
            with self.assertRaises(secops.UserError):
                secops.resolve_and_authorize("http://127.0.0.1/", scope)


class TestHTTPHeaders(unittest.TestCase):
    def test_header_findings(self):
        headers = {
            "server": "nginx/1.18.0",
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
            "set-cookie": "sid=abc; Path=/",
        }
        findings = secops.analyze_headers(headers, "http://example.com/", 200, ["sid=abc; Path=/"], None)
        checks = {item["check"]: item for item in findings}
        self.assertEqual(checks["CORS credentials with wildcard"]["severity"], "low")
        self.assertIn("Frame protection", checks)
        self.assertIn("Cookie HttpOnly flag", checks)
        self.assertNotIn("HSTS", checks)  # plain HTTP

    def test_https_hsts_and_cookie(self):
        headers = {
            "strict-transport-security": "max-age=600",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "set-cookie": "sid=abc; Secure; HttpOnly; SameSite=Lax",
        }
        findings = secops.analyze_headers(headers, "https://example.com/", 200, [], None)
        checks = {item["check"] for item in findings}
        self.assertIn("HSTS max-age", checks)
        self.assertNotIn("HSTS", checks)
        self.assertNotIn("Frame protection", checks)
        self.assertNotIn("Cookie Secure flag", checks)

    def test_tls_version_and_expiry(self):
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
        }
        tls = {"version": "TLSv1.1", "notAfter": "Oct 22 08:00:00 2026 GMT"}
        findings = secops.analyze_headers(headers, "https://example.com/", 200, [], tls)
        checks = {item["check"]: item for item in findings}
        self.assertEqual(checks["TLS version"]["severity"], "high")


class TestHTTPIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/final")
                    self.end_headers()
                    return
                body = b"<html><title>Test Page</title><body>ok</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Server", "test-server/1.0")
                self.send_header("X-Powered-By", "test-lang")
                self.send_header("Set-Cookie", "sid=abc; Path=/")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):  # silence test output
                return

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def test_http_command_requires_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = Path(tmp) / "scope.txt"
            scope.write_text("127.0.0.1\n", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                code = secops.main(["http", self.base + "/", "--scope-file", str(scope)])
            self.assertEqual(code, 2)

    def test_http_command_scope_and_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = Path(tmp) / "scope.txt"
            scope.write_text("127.0.0.1\n", encoding="utf-8")
            out = Path(tmp) / "out.json"
            with contextlib.redirect_stderr(io.StringIO()):
                code = secops.main(
                    [
                        "http",
                        self.base + "/redirect",
                        "--method",
                        "GET",
                        "--scope-file",
                        str(scope),
                        "--i-have-authorization",
                        "--format",
                        "json",
                        "--output",
                        str(out),
                        "--delay",
                        "0",
                    ]
                )
            self.assertEqual(code, 0, out.read_text(encoding="utf-8") if out.exists() else "no output")
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], 200)
            self.assertEqual(payload["final_url"], self.base + "/final")
            self.assertEqual(payload["title"], "Test Page")
            self.assertIn("test-server/1.0", payload["headers"]["server"])
            self.assertTrue(any(item["check"] == "CORS credentials with wildcard" for item in payload["findings"]) is False)
            self.assertTrue(any(item["check"] == "Frame protection" for item in payload["findings"]))


class TestRedact(unittest.TestCase):
    def test_secrets(self):
        text = (
            "password=SuperSecret123\n"
            "token: 'abcdef123456'\n"
            "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
        )
        result = secops.redact_text(text)
        self.assertIn("[REDACTED:secret]", result)
        self.assertIn("[REDACTED:github_token]", result)
        self.assertNotIn("SuperSecret123", result)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz0123456789", result)

    def test_pii(self):
        text = "alice@example.com 4111 1111 1111 1111 10.1.2.3 8.8.8.8"
        result = secops.redact_text(text, pii=True)
        self.assertIn("[REDACTED:email]", result)
        self.assertIn("[REDACTED:payment_card]", result)
        self.assertIn("[REDACTED:private_ip]", result)
        self.assertIn("8.8.8.8", result)

    def test_bearer_and_cookie(self):
        text = (
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345\n"
            "Cookie: session=abcdef123456; theme=dark\n"
        )
        result = secops.redact_text(text)
        self.assertIn("[REDACTED:bearer_token]", result)
        self.assertIn("[REDACTED:cookie]", result)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz012345", result)
        self.assertNotIn("session=abcdef123456", result)

    def test_private_key(self):
        text = "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"
        result = secops.redact_text(text)
        self.assertIn("[REDACTED:private_key]", result)
        self.assertNotIn("secret", result)


if __name__ == "__main__":
    unittest.main()
