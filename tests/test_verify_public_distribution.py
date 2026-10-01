# SPDX-License-Identifier: GPL-2.0-only
"""Offline regression checks; no public-network or browser acceptance claims."""
import hashlib
from contextlib import ExitStack
import importlib.util
import io
import json
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("public_distribution", ROOT / "tools/verify_public_distribution.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
HOME = b'<html><head><title>Windows 98 Shizuku</title></head><body><h1>Windows 98 Shizuku Second Edition</h1></body></html>'


def iso_fixture():
    data = bytearray(33000)
    data[32768:32775] = b"\x01CD001\x01"
    return bytes(data)


class Response(io.BytesIO):
    def __init__(self, data, url=checker.ORIGIN + "/", headers=None, status=200):
        super().__init__(data)
        self.url, self.headers, self.status = url, headers or {"Content-Type": "text/html"}, status

    def geturl(self):
        return self.url


class URLTests(unittest.TestCase):
    def test_only_certified_https_same_host_paths(self):
        self.assertEqual(checker.public_url("/en/"), "https://m98.nyase.kr/en/")
        for value in ["http://m98.nyase.kr/", "https://evil.test/", "https://m98.nyase.kr.evil.test/", "https://a@m98.nyase.kr/", "https://m98.nyase.kr:444/", "//evil.test/", "/a/../b", "/%2e%2e/b", "/x\r\nHost: evil.test", "/x#fragment"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                checker.public_url(value)

    def test_redirect_cannot_escape_same_hostname(self):
        import urllib.request
        handler = checker.SameHostRedirect()
        request = urllib.request.Request(checker.ORIGIN + "/vnc.html")
        with self.assertRaises(ValueError):
            handler.redirect_request(request, None, 302, "Found", {}, "https://evil.test/")
        self.assertEqual(handler.redirect_request(request, None, 302, "Found", {}, checker.ORIGIN + "/").full_url, checker.ORIGIN + "/")

    def test_only_documented_old_vnc_paths_required(self):
        self.assertEqual(checker.PAGE_PATHS, ("/", "/en/", "/vnc.html", "/vnc_lite.html"))


class HomepageTests(unittest.TestCase):
    def test_real_branding_is_required(self):
        self.assertEqual(checker.validate_homepage(HOME)["title"], "Windows 98 Shizuku")
        for body in [b"<html><title>Hello</title>OK</html>", b"<html><title>Windows 98</title>No project homepage</html>"]:
            with self.assertRaises(ValueError):
                checker.validate_homepage(body)

    def test_cloudflare_and_browser_error_pages_rejected(self):
        for marker in [b"Just a moment...", b"/cdn-cgi/challenge-platform/", b"cf-chl-widget", b"Verify you are human", b"chrome-error://chromewebdata/", b"ERR_CERT_AUTHORITY_INVALID"]:
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                checker.validate_homepage(HOME.replace(b"</body>", marker + b"</body>"))
        with self.assertRaises(ValueError):
            checker.validate_homepage(HOME, {"cf-mitigated": "challenge"})

    def test_legitimate_cloudflare_jsd_injection_does_not_block_homepage(self):
        injection = b"<script>(function(){var a=document.createElement('script');a.src='/cdn-cgi/challenge-platform/scripts/jsd/main.js';document.head.appendChild(a)})();</script>"
        checker.validate_homepage(HOME.replace(b"</body>", injection + b"</body>"))
        checker.validate_homepage(HOME.replace(b"</body>", b"<script>const explanation='verify you are human';</script></body>"))
        with self.assertRaises(ValueError):
            checker.validate_homepage(HOME.replace(b"</body>", injection + b"<h2>Just a moment...</h2></body>"))

    def test_active_novnc_ui_is_rejected_but_plain_explanation_allowed(self):
        checker.validate_homepage(HOME.replace(b"</body>", b"<p>The old noVNC service is retired.</p></body>"))
        for marker in [b'<div id="noVNC_container"></div>', b'<script src="/core/rfb.js"></script>', b'<script src="/app/ui.js"></script>']:
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                checker.validate_homepage(HOME.replace(b"</body>", marker + b"</body>"))

    def test_hidden_branding_does_not_make_error_page_a_homepage(self):
        with self.assertRaises(ValueError):
            checker.validate_homepage(b'<html><title>Error</title><script>"Windows 98 Shizuku"</script></html>')

    def test_http_requires_html_success_and_a_bounded_body(self):
        opener = type("Opener", (), {"open": lambda self, request, timeout: Response(HOME)})()
        self.assertEqual(checker.check_http_page("/", opener, "browser", 2)["status"], "PASS")
        for response in [Response(HOME, status=403), Response(HOME, headers={"Content-Type": "application/octet-stream"}), Response(HOME, url="https://evil.test/")]:
            with patch.object(opener, "open", return_value=response), self.assertRaises(ValueError):
                checker.check_http_page("/", opener, "browser", 2)
        with patch.object(opener, "open", return_value=Response(b"x" * 25)), self.assertRaises(ValueError):
            checker.check_http_page("/", opener, "browser", 2, max_bytes=24)

    def test_http_body_deadline_is_enforced_between_partial_reads(self):
        response = Response(HOME)
        opener = type("Opener", (), {"open": lambda self, request, timeout: response})()
        with patch.object(checker.time, "monotonic", side_effect=[0, 3]), self.assertRaises(TimeoutError):
            checker.check_http_page("/", opener, "browser", 2)


class ISOTests(unittest.TestCase):
    def test_full_stream_exact_bytes_and_hash(self):
        data = iso_fixture()
        row = checker.verify_iso_stream(Response(data), len(data), hashlib.sha256(data).hexdigest(), len(data), 3)
        self.assertEqual(row["checked_bytes"], len(data))
        self.assertEqual(row["status"], "PASS")

    def test_truncated_extra_wrong_hash_or_unbounded_size_rejected(self):
        data = iso_fixture()
        for length, sha, maximum in [(len(data) + 1, hashlib.sha256(data).hexdigest(), 40000), (len(data) - 1, hashlib.sha256(data).hexdigest(), 40000), (len(data), "0" * 64, 40000), (len(data), hashlib.sha256(data).hexdigest(), 2)]:
            with self.subTest(length=length, sha=sha, maximum=maximum), self.assertRaises(ValueError):
                checker.verify_iso_stream(Response(data), length, sha, maximum, 2)

    def test_stream_deadline_is_enforced(self):
        with patch.object(checker.time, "monotonic", side_effect=[0, 3]), self.assertRaises(TimeoutError):
            checker.verify_iso_stream(Response(b"iso"), 3, hashlib.sha256(b"iso").hexdigest(), 3, 2)

    def test_html_and_corrupted_iso_descriptor_rejected_even_with_matching_hash(self):
        corrupt = bytearray(iso_fixture())
        corrupt[32769] = ord("X")
        for data in [HOME, bytes(corrupt)]:
            with self.subTest(bytes=len(data)), self.assertRaises(ValueError):
                checker.verify_iso_stream(Response(data), len(data), hashlib.sha256(data).hexdigest(), 40000, 2)


class BrowserAndEvidenceTests(unittest.TestCase):
    def test_normal_browser_identity_is_bound_to_actual_version(self):
        ua = checker.chrome_user_agent("Google Chrome 140.0.7339.207")
        self.assertIn("Chrome/140.0.7339.207", ua)
        self.assertNotIn("HeadlessChrome", ua)
        with self.assertRaises(ValueError):
            checker.chrome_user_agent("unrecognized product")

    def test_browser_uses_public_url_without_certificate_or_dns_bypass(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            with patch.object(checker, "run_process", return_value={"returncode": 0, "stdout": HOME, "stderr": b""}) as run:
                row = checker.check_browser_page("/", "/usr/bin/google-chrome", "Chrome/140", out, 10)
            self.assertEqual(row["status"], "PASS")
            command = run.call_args.args[0]
            self.assertEqual(command[-1], checker.ORIGIN + "/")
            self.assertTrue(any(x.startswith("--user-agent=") for x in command))
            self.assertFalse(any("ignore-certificate" in x or "host-resolver" in x or "--resolve" in x or "--proxy-server" in x for x in command))

    def test_browser_failure_or_challenge_cannot_pass(self):
        for result in [{"returncode": 1, "stdout": HOME, "stderr": b"failed"}, {"returncode": 0, "stdout": HOME + b"Just a moment...", "stderr": b""}]:
            with tempfile.TemporaryDirectory() as folder:
                with patch.object(checker, "run_process", return_value=result), self.assertRaises(ValueError):
                    checker.check_browser_page("/", "/usr/bin/google-chrome", "Chrome/140", Path(folder), 10)

    def test_outside_host_claim_requires_real_hosted_runner_metadata(self):
        self.assertFalse(checker.external_vantage("local", {"GITHUB_ACTIONS": "true"})["outside_host_verified"])
        with self.assertRaises(ValueError):
            checker.external_vantage("github-hosted", {})
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_RUN_ID": "123", "GITHUB_REPOSITORY": "owner/repo", "GITHUB_SHA": "a" * 40}
        row = checker.external_vantage("github-hosted", env)
        self.assertTrue(row["outside_host_verified"])
        self.assertEqual(row["run_url"], "https://github.com/owner/repo/actions/runs/123")

    def test_https_client_requires_certificate_validation_and_no_proxy_override(self):
        with patch.object(checker.urllib.request, "build_opener", return_value="opener") as build:
            self.assertEqual(checker.https_opener(), "opener")
        handlers = build.call_args.args
        tls = next(x for x in handlers if isinstance(x, checker.urllib.request.HTTPSHandler))
        self.assertEqual(tls._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(tls._context.check_hostname)
        proxy = next(x for x in handlers if isinstance(x, checker.urllib.request.ProxyHandler))
        self.assertEqual(proxy.proxies, {})

    def test_dns_and_hosts_override_cannot_claim_public_resolution(self):
        public = [(2, 1, 6, "", ("1.1.1.1", 443))]
        with patch.object(checker.socket, "getaddrinfo", return_value=public), patch.object(Path, "read_text", return_value="127.0.0.1 localhost\n"):
            self.assertEqual(checker.public_dns()["addresses"], ["1.1.1.1"])
        with patch.object(checker.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]), patch.object(Path, "read_text", return_value=""):
            with self.assertRaises(ValueError):
                checker.public_dns()
        with patch.object(Path, "read_text", return_value="1.1.1.1 m98.nyase.kr # manual override\n"):
            with self.assertRaises(ValueError):
                checker.public_dns()

    def test_failure_receipt_is_retained_and_never_external_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / "fresh"
            with patch.object(checker, "external_vantage", side_effect=ValueError("not a hosted runner")):
                self.assertEqual(checker.main(["--out", str(out), "--vantage", "github-hosted"]), 1)
            row = json.loads((out / "receipt.json").read_text())
            self.assertEqual(row["status"], "FAIL")
            self.assertFalse(row["homepage_external_acceptance_verified"])
            self.assertFalse(row["iso_external_acceptance_verified"])

    def test_browser_still_attempted_when_http_is_blocked_and_local_never_external(self):
        for http_failed in [False, True]:
            with self.subTest(http_failed=http_failed), tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
                out = Path(folder) / "fresh"
                stack.enter_context(patch.object(checker.shutil, "which", return_value="/usr/bin/google-chrome"))
                stack.enter_context(patch.object(checker, "run_process", return_value={"returncode": 0, "stdout": b"Google Chrome 140.0.7339.207", "stderr": b""}))
                stack.enter_context(patch.object(checker, "public_dns", return_value={"addresses": ["1.1.1.1"]}))
                stack.enter_context(patch.object(checker, "https_opener", return_value=object()))
                stack.enter_context(patch.object(checker, "check_http_page", return_value={"status": "PASS"}, side_effect=ValueError("HTTP blocked") if http_failed else None))
                browser = stack.enter_context(patch.object(checker, "check_browser_page", return_value={"status": "PASS"}))
                self.assertEqual(checker.main(["--out", str(out)]), 1 if http_failed else 0)
                self.assertEqual(browser.call_count, 4)
                row = json.loads((out / "receipt.json").read_text())
                self.assertEqual(row["status"], "FAIL" if http_failed else "LOCAL_CHECK_PASS")
                self.assertFalse(row["homepage_external_acceptance_verified"])
                self.assertFalse(row["iso_external_acceptance_verified"])


class ISOHTTPTests(unittest.TestCase):
    def test_wrong_http_encoding_or_content_length_rejected(self):
        data = iso_fixture()
        opener = type("Opener", (), {"open": lambda self, request, timeout: Response(data)})()
        for headers in [{"Content-Encoding": "gzip"}, {"Content-Length": "999"}]:
            with patch.object(opener, "open", return_value=Response(data, headers=headers)), self.assertRaises(ValueError):
                checker.check_iso("/download.iso", opener, "Chrome/140", len(data), hashlib.sha256(data).hexdigest(), 40000, 2)

    def test_exact_http_iso_does_not_write_an_iso_file(self):
        data = iso_fixture()
        opener = type("Opener", (), {"open": lambda self, request, timeout: Response(data, url=checker.ORIGIN + "/download.iso", headers={"Content-Length": str(len(data))})})()
        row = checker.check_iso("/download.iso", opener, "Chrome/140", len(data), hashlib.sha256(data).hexdigest(), 40000, 2)
        self.assertFalse(row["stored_iso"])
        self.assertEqual(row["sha256"], hashlib.sha256(data).hexdigest())

    def test_iso_url_must_end_in_iso(self):
        with self.assertRaises(ValueError):
            checker.check_iso("/error.html", None, "Chrome/140", 33000, "0" * 64, 40000, 2)


if __name__ == "__main__":
    unittest.main()
