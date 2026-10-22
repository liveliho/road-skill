"""Security regressions. All network traffic is confined to loopback fixtures."""

import contextlib
import csv
import io
import json
import math
import socket
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import secops


class TestRedactionBoundaries(unittest.TestCase):
    def test_redact_json_keeps_structure(self):
        data = {"note": "Cookie: session=small", "password": {"nested": "secret"},
                "url": "https://example.com/?token=hidden", "count": 2}
        with tempfile.TemporaryDirectory() as tmp:
            path, out = Path(tmp) / "input.json", Path(tmp) / "out.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(secops.main(["redact", str(path), "--output", str(out)]), 0)
            result = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(result["count"], 2)
        self.assertNotIn("small", result["note"])
        self.assertNotIn("hidden", result["url"])
        self.assertIsInstance(result["password"], str)

    def test_structured_short_and_escaped_secrets(self):
        cases = [
            ('{"password": "tiny"}', "tiny"),
            ('{"api_key":"ab\\\"cd"}', 'ab\\\"cd'),
            ("password='two words'", "two words"),
            ("token=x", "=x"),
            ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
            ("Bearer abc", " abc"),
            ("github_pat_" + "A" * 82, "A" * 82),
            ("https://user:tiny@example.com/a?%74oken=hidden", "hidden"),
        ]
        for text, secret in cases:
            with self.subTest(text=text[:32]):
                result = secops.redact_text(text)
                self.assertNotIn(secret, result)
                self.assertIn("[REDACTED:", result)

    def test_private_ipv6(self):
        result = secops.redact_text("fd00::1 fe80::1 ::1 2606:4700:4700::1111", pii=True)
        for value in ("fd00::1", "fe80::1", "::1 "):
            self.assertNotIn(value, result)
        self.assertIn("2606:4700:4700::1111", result)

    def test_ioc_redacts_before_context_truncation_and_extraction(self):
        secret = "b" * 64
        text = ('{"password": "' + secret + '"} evil.example.com\n'
                '-----BEGIN PRIVATE KEY-----\n'
                'https://evil.example.com/?token=hidden\n'
                '-----END PRIVATE KEY-----\n'
                + "x" * 185 + " token=" + "a" * 100 + " evil.example.com\n")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.txt"
            path.write_text(text, encoding="utf-8")
            output = json.dumps(secops.collect_iocs([str(path)], False))
        self.assertNotIn(secret, output)
        self.assertNotIn("hidden", output)
        self.assertNotIn("a" * 8, output)
        self.assertIn("evil.example.com", output)


class TestExportBoundaries(unittest.TestCase):
    def test_fullwidth_formulas_and_control_prefix(self):
        for value in ("＝1+1", "＋1", "－1", "＠SUM(1)", "\ttext", "\ntext"):
            self.assertTrue(secops.csv_safe({"value": value})["value"].startswith("'"))

    def test_uppercase_url_defanging(self):
        self.assertEqual(secops.defang("HTTPS://evil.example.com", "url"), "hxxps://evil[.]example[.]com")

    def test_triage_csv_neutralizes_formulas_in_all_text_columns(self):
        values = ["=1+1", " +SUM(1)", "-1+1", "@SUM(1)", "\t=1", "\r=1", "\n=1"]
        for value in values:
            with self.subTest(value=value):
                item = secops.normalize_finding({"title": value, "asset": value,
                                                "source": value, "evidence": value}, 1, "input")
                rendered = secops.render_triage([item], secops.date(2026, 10, 22), "csv", "input")
                row = next(csv.DictReader(io.StringIO(rendered)))
                for field in ("title", "asset", "source", "evidence"):
                    self.assertTrue(row[field].startswith("'"), field)

    def test_hash_csv_path_formula(self):
        item = {"path": "=1+1", "size": 1, "magic": "text", "entropy": 0,
                "md5": "a", "sha1": "b", "sha256": "c"}
        row = next(csv.DictReader(io.StringIO(secops.render_hashes([item], "csv"))))
        self.assertEqual(row["path"], "'=1+1")

    def test_markdown_cannot_embed_html_links_or_code_fences(self):
        value = '<img src="https://evil.example.com/track"> ![x](https://evil.example.com) ```'
        rendered = secops.md(value)
        self.assertNotIn("<img", rendered)
        self.assertNotIn("![x]", rendered)
        self.assertNotIn("```", rendered)


class TestTriageIntegrity(unittest.TestCase):
    def test_invalid_json_record_is_not_silently_dropped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            path.write_text('[{"asset":"example.com"}, "bad record"]', encoding="utf-8")
            with self.assertRaises(secops.UserError):
                secops.load_findings(path)

    def test_different_chinese_titles_remain_distinct(self):
        items = [secops.normalize_finding({"asset": "example.com", "title": title}, i, "input")
                 for i, title in enumerate(("任意文件读取", "租户权限绕过"), 1)]
        self.assertEqual(len(secops.dedupe_findings(items)), 2)

    def test_url_path_case_remains_distinct(self):
        items = [secops.normalize_finding({"asset": url, "cve": "CVE-2026-0001"}, i, "input")
                 for i, url in enumerate(("https://example.com/Admin", "https://example.com/admin"), 1)]
        self.assertEqual(len(secops.dedupe_findings(items)), 2)

    def test_percentage_and_invalid_numbers(self):
        self.assertAlmostEqual(secops.normalize_epss("0.5%"), 0.005)
        self.assertAlmostEqual(secops.normalize_confidence("0.5%"), 0.005)
        for value in (float("nan"), float("inf"), "score 9.8", "9.8 junk"):
            with self.subTest(value=str(value)):
                self.assertIsNone(secops.normalize_cvss(value))
        self.assertTrue(math.isfinite(secops.normalize_confidence(float("nan"))))
        self.assertFalse(secops.to_kev("2026-99-99"))

    def test_conflicting_statuses_are_reported(self):
        items = [secops.normalize_finding({"asset": "example.com", "cve": "CVE-2026-0001",
                                          "status": status}, i, "input")
                 for i, status in enumerate(("confirmed", "fixed"), 1)]
        merged = secops.dedupe_findings(items)[0]
        self.assertEqual(merged["status"], "unknown")
        self.assertEqual(set(merged["status_conflicts"]), {"confirmed", "fixed"})

    def test_unknown_context_is_visible(self):
        item = secops.normalize_finding({"asset": "example.com"}, 1, "input")
        self.assertEqual(item["severity"], "unknown")
        self.assertTrue({"kev", "exposed", "sensitive", "confidence"} <= set(item["missing"]))


class TestScopeBoundaries(unittest.TestCase):
    def test_head_is_the_default(self):
        args = secops.build_parser().parse_args(["http", "https://example.com/"])
        self.assertEqual(args.method, "HEAD")

    def scope(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.txt"
            path.write_text(text, encoding="utf-8")
            return secops.Scope.from_files([str(path)])

    def test_url_scope_is_not_silently_widened(self):
        with self.assertRaises(secops.UserError):
            self.scope("https://example.com/api\n")

    def test_cidr_host_bits_are_not_silently_widened(self):
        with self.assertRaises(secops.UserError):
            self.scope("203.0.113.7/24\n")

    def test_invalid_and_empty_scope_fail_closed(self):
        for text in ("# empty\n", "*\n", "example.com:8080\n", "*.\n", "example.com/path\n"):
            with self.subTest(text=text):
                with self.assertRaises(secops.UserError):
                    self.scope(text)

    def test_url_rejected_before_dns(self):
        scope = self.scope("example.com\n")
        for url in ("http://example.com:0/", "http://example.com/\nx",
                    "http://example.com/%0d%0aX:y", "http://user:pass@example.com/",
                    "http://example.com\\@127.0.0.1/", "http://example.com/%ZZ"):
            with self.subTest(url=url), mock.patch.object(secops.socket, "getaddrinfo") as dns:
                with self.assertRaises(secops.UserError):
                    secops.resolve_and_authorize(url, scope)
                dns.assert_not_called()

    def test_mapped_ipv6_requires_explicit_ipv4_scope(self):
        scope = self.scope("example.com\n")
        info = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:127.0.0.1", 80, 0, 0))]
        with mock.patch.object(secops.socket, "getaddrinfo", return_value=info):
            with self.assertRaises(secops.UserError):
                secops.resolve_and_authorize("http://example.com/", scope)

    def test_nonfinite_limits_rejected_before_dns(self):
        for option, value in (("--timeout", "nan"), ("--delay", "inf"), ("--max-redirects", "10000")):
            with self.subTest(option=option), mock.patch.object(secops.socket, "getaddrinfo") as dns:
                with contextlib.redirect_stderr(io.StringIO()):
                    result = secops.main(["http", "http://example.com/", option, value,
                                          "--i-have-authorization", "--scope-file", "missing.txt"])
                self.assertEqual(result, 2)
                dns.assert_not_called()


class TestPinnedHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hits = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                cls.hits.append((self.path, self.headers.get("Host")))
                if self.path == "/out":
                    self.send_response(302)
                    self.send_header("Location", "http://outside.example.org/")
                elif self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/final")
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<title>fixture</title>")

            def log_message(self, *args):
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def test_dns_is_not_repeated_by_transport_or_proxy(self):
        url = f"http://allowed.example.com:{self.server.server_port}/"
        scope = secops.Scope(hosts={"allowed.example.com", "127.0.0.1"})
        info = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", self.server.server_port))]
        with mock.patch.object(secops.socket, "getaddrinfo", side_effect=[info]) as dns:
            addresses = secops.resolve_and_authorize(url, scope)
            with mock.patch.dict("os.environ", {"http_proxy": "http://127.0.0.1:1", "no_proxy": ""}):
                result = secops.fetch_once(url, "GET", 2, ssl.create_default_context(), addresses)
            self.assertEqual(result[0], 200)
            self.assertEqual(dns.call_count, 1)
        self.assertEqual(self.hits[-1][1], f"allowed.example.com:{self.server.server_port}")

    def test_redirect_rechecks_scope_and_final_ips(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = Path(tmp) / "scope.txt"
            scope.write_text("127.0.0.1\n", encoding="utf-8")
            out = Path(tmp) / "out.json"
            base = f"http://127.0.0.1:{self.server.server_port}"
            args = ["http", base + "/redirect", "--scope-file", str(scope),
                    "--i-have-authorization", "--method", "GET", "--delay", "0", "--format", "json", "--output", str(out)]
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(secops.main(args), 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["resolved_ips"], ["127.0.0.1"])
            self.assertEqual(payload["final_url"], base + "/final")
            before = len(self.hits)
            args[1] = base + "/out"
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(secops.main(args), 2)
            self.assertEqual(len(self.hits), before + 1)

    def test_https_redirect_to_http_is_blocked_before_second_request(self):
        args = secops.build_parser().parse_args(["http", "https://example.com/", "--scope-file", "scope.txt",
                                                "--i-have-authorization", "--delay", "0"])
        scope = secops.Scope(hosts={"example.com"})
        with mock.patch.object(secops.Scope, "from_files", return_value=scope), \
             mock.patch.object(secops, "resolve_and_authorize", return_value=["8.8.8.8"]), \
             mock.patch.object(secops, "probe_tls", return_value={}, create=True), \
             mock.patch.object(secops, "fetch_once", return_value=(302, {"location": "http://example.com/"}, [], b"")) as fetch:
            with self.assertRaises(secops.UserError):
                secops.cmd_http(args)
            self.assertEqual(fetch.call_count, 1)

    def test_tls_uses_pinned_socket_and_original_sni(self):
        raw, wrapped, context = mock.MagicMock(), mock.MagicMock(), mock.MagicMock()
        context.wrap_socket.return_value = wrapped
        context.verify_mode, context.check_hostname = ssl.CERT_REQUIRED, True
        wrapped.getpeercert.return_value = {"notAfter": "Oct 22 08:00:00 2027 GMT"}
        wrapped.version.return_value = "TLSv1.3"
        wrapped.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        tls = {}
        with mock.patch.object(secops, "connect_pinned", return_value=raw) as connect, \
             mock.patch.object(secops.http.client, "HTTPConnection") as client, \
             mock.patch.object(secops.socket, "getaddrinfo", side_effect=AssertionError("unexpected DNS")):
            connection = client.return_value
            response = connection.getresponse.return_value
            response.status, response.headers, response.read.return_value = 200, {}, b""
            secops.fetch_once("https://allowed.example.com/", "HEAD", 2, context, ["8.8.8.8"], tls)
            connect.assert_called_once_with(["8.8.8.8"], 443, 2)
            context.wrap_socket.assert_called_once_with(raw, server_hostname="allowed.example.com")
            self.assertIs(connection.sock, wrapped)
        self.assertTrue(tls["verified"])
        self.assertEqual(tls["version"], "TLSv1.3")

    def test_certificate_error_is_not_retried_without_verification(self):
        raw, context = mock.MagicMock(), mock.MagicMock()
        context.wrap_socket.side_effect = ssl.SSLCertVerificationError("fixture certificate failure")
        with mock.patch.object(secops, "connect_pinned", return_value=raw), \
             mock.patch.object(secops.http.client, "HTTPConnection") as client:
            with self.assertRaises(ssl.SSLCertVerificationError):
                secops.fetch_once("https://example.com/", "HEAD", 2, context, ["8.8.8.8"])
            context.wrap_socket.assert_called_once()
            client.return_value.request.assert_not_called()
            client.return_value.close.assert_called_once()

    def test_final_report_uses_final_hop_addresses_and_no_stale_tls(self):
        args = secops.build_parser().parse_args(["http", "http://a.example.com/", "--scope-file", "scope.txt",
                                                "--i-have-authorization", "--delay", "0", "--format", "json"])
        scope = secops.Scope(hosts={"a.example.com", "b.example.com"})
        replies = [(302, {"location": "http://b.example.com/"}, [], b""), (200, {}, [], b"<title>Cookie: sid=small</title>")]
        with mock.patch.object(secops.Scope, "from_files", return_value=scope), \
             mock.patch.object(secops, "resolve_and_authorize", side_effect=[["8.8.8.8"], ["1.1.1.1"]]), \
             mock.patch.object(secops, "fetch_once", side_effect=replies), \
             mock.patch.object(secops, "emit") as emit:
            self.assertEqual(secops.cmd_http(args), 0)
        payload = json.loads(emit.call_args[0][0])
        self.assertEqual(payload["resolved_ips"], ["1.1.1.1"])
        self.assertIsNone(payload["tls"])
        self.assertNotIn("small", payload["title"])


class TestHeaderAccuracy(unittest.TestCase):
    def test_browser_controls_not_required_on_json_api(self):
        findings = secops.analyze_headers({"content-type": "application/json"}, "http://example.com/", 200, [], None)
        checks = {finding["check"] for finding in findings}
        self.assertNotIn("Frame protection", checks)
        self.assertNotIn("CSP", checks)
        self.assertIn("X-Content-Type-Options", checks)

    def test_invalid_frame_and_nosniff_values_are_flagged(self):
        headers = {"content-type": "text/html", "x-frame-options": "ALLOWALL", "x-content-type-options": "wrong"}
        checks = {finding["check"] for finding in secops.analyze_headers(headers, "http://example.com/", 200, [], None)}
        self.assertIn("Frame protection", checks)
        self.assertIn("X-Content-Type-Options", checks)


class TestInputLimits(unittest.TestCase):
    def test_oversized_stdin_fails_instead_of_silent_truncation(self):
        with mock.patch.object(secops, "MAX_TEXT_BYTES", 8), mock.patch.object(secops.sys, "stdin", io.StringIO("x" * 9)):
            with self.assertRaises(secops.UserError):
                list(secops._iter_input_files([]))

    def test_missing_file_is_a_clean_cli_error(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(secops.main(["hash", "nonexistent-sample.bin"]), 2)
        self.assertNotIn("Traceback", err.getvalue())


if __name__ == "__main__":
    unittest.main()
