#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check the public M98 HTTPS homepage and optional ISO from an identified host.

Uses normal DNS, certificate-verified HTTPS, and installed Chrome. No origin
override, deployment, credentials, browser package download or ISO staging.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

ORIGIN = "https://m98.nyase.kr"
PAGE_PATHS = ("/", "/en/", "/vnc.html", "/vnc_lite.html")
HTML_LIMIT = 2 * 1024**2
PROCESS_LIMIT = 3 * 1024**2


def require(value, reason):
    if not value:
        raise ValueError(reason)


def public_url(value):
    require(isinstance(value, str) and not re.search(r"[\x00-\x20\x7f\\]", value), "unsafe URL characters")
    url = ORIGIN + value if value.startswith("/") and not value.startswith("//") else value
    parts = urllib.parse.urlsplit(url)
    require(parts.scheme == "https" and parts.hostname == "m98.nyase.kr" and parts.netloc == "m98.nyase.kr",
            "only certificate-verified HTTPS on m98.nyase.kr is permitted")
    require(not parts.username and not parts.password and not parts.query and not parts.fragment, "URL credentials, query and fragment forbidden")
    decoded = urllib.parse.unquote(parts.path)
    require(decoded.startswith("/") and not decoded.startswith("//") and "\\" not in decoded and
            not re.search(r"[\x00-\x20\x7f]", decoded) and not any(x in (".", "..") for x in decoded.split("/")),
            "unsafe public URL path")
    require(not re.search(r"%(?![0-9a-fA-F]{2})", parts.path), "invalid URL escape")
    return url


class SameHostRedirect(urllib.request.HTTPRedirectHandler):
    max_repeats = 3
    max_redirections = 5

    def redirect_request(self, request, fp, code, message, headers, newurl):
        public_url(newurl)
        return super().redirect_request(request, fp, code, message, headers, newurl)


def https_opener():
    context = ssl.create_default_context()
    require(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED, "certificate validation required")
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), SameHostRedirect(),
                                      urllib.request.HTTPSHandler(context=context))


def public_dns():
    """Use the normal resolver, refusing a host-file override or private target."""
    for line in Path("/etc/hosts").read_text().splitlines():
        entries = line.split("#", 1)[0].split()
        require(not any(alias.lower().rstrip(".") == "m98.nyase.kr" for alias in entries[1:]), "target hostname has a hosts-file override")
    addresses = sorted({entry[4][0] for entry in socket.getaddrinfo("m98.nyase.kr", 443, type=socket.SOCK_STREAM)})
    require(addresses and all(ipaddress.ip_address(address).is_global for address in addresses), "normal public DNS resolved a non-public address")
    return {"hostname": "m98.nyase.kr", "addresses": addresses, "normal_resolver_used": True, "hosts_override_absent": True}


class HomepageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self.visible, self.in_title, self.hidden, self.vnc = [], [], False, 0, False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "title":
            self.in_title = True
        if tag in ("script", "style", "template"):
            self.hidden += 1
        if attrs.get("id", "").lower().startswith("novnc"):
            self.vnc = True
        src = attrs.get("src", "").lower()
        if tag == "script" and ("novnc" in src or src.split("?")[0].endswith(("/core/rfb.js", "/app/ui.js"))):
            self.vnc = True

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        if tag in ("script", "style", "template") and self.hidden:
            self.hidden -= 1

    def handle_data(self, data):
        if self.in_title:
            self.title.append(data)
        if not self.hidden:
            self.visible.append(data)


def validate_homepage(body, headers=None):
    require(body and len(body) <= HTML_LIMIT, "missing or oversized homepage")
    html = body.decode("utf-8", errors="replace")
    normalized_headers = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    require(normalized_headers.get("cf-mitigated") != "challenge", "Cloudflare challenge response")
    parser = HomepageParser()
    parser.feed(html)
    title = " ".join(" ".join(parser.title).split())
    visible = " ".join(parser.visible)
    text = (title + " " + visible).lower()
    blocked_text = ("just a moment", "cf-chl-", "verify you are human", "checking your browser",
                    "performing security verification", "chrome-error://", "err_cert_",
                    "err_name_not_resolved", "err_connection_", "err_timed_out")
    require(not any(marker in text for marker in blocked_text), "challenge or browser error page returned")
    # Cloudflare legitimately injects this exact JavaScript-detection resource
    # into ordinary HTTP-200 homepages. It is not an interstitial challenge.
    # Other challenge-platform routes retain their rejection semantics.
    other_scripts = html.lower().replace("/cdn-cgi/challenge-platform/scripts/jsd/main.js", "")
    require("challenge-platform" not in other_scripts, "challenge-platform interstitial returned")
    require(not parser.vnc and "novnc" not in title.lower(), "active noVNC interface returned")
    require(title and re.search(r"windows\s*98", visible, re.I) and re.search(r"shizuku", visible, re.I),
            "Windows 98 Shizuku homepage branding absent")
    return {"title": title, "body_bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
            "homepage_branding_verified": True, "challenge_absent": True, "novnc_ui_absent": True}


def check_http_page(path, opener, user_agent, timeout, max_bytes=HTML_LIMIT):
    url = public_url(path)
    request = urllib.request.Request(url, headers={"User-Agent": user_agent, "Accept": "text/html", "Accept-Encoding": "identity"})
    with opener.open(request, timeout=timeout) as response:
        require(response.status == 200, "homepage must return HTTP 200")
        final_url = public_url(response.geturl())
        require("text/html" in response.headers.get("Content-Type", "").lower(), "homepage content type is not HTML")
        deadline, body = time.monotonic() + timeout, bytearray()
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("homepage body exceeded total read budget")
            # read1 returns after one underlying read, allowing deadline checks
            # between partial arrivals instead of filling a large read forever.
            read = getattr(response, "read1", response.read)
            block = read(min(65536, max_bytes - len(body) + 1))
            if not block:
                break
            body.extend(block)
            require(len(body) <= max_bytes, "homepage exceeds read budget")
        body = bytes(body)
        require(len(body) <= max_bytes, "homepage exceeds read budget")
        detail = validate_homepage(body, response.headers)
        return {"status": "PASS", "requested_url": url, "final_url": final_url, "http_status": response.status, **detail}


def verify_iso_stream(response, expected_bytes, expected_sha256, max_bytes, timeout):
    require(0 < expected_bytes <= max_bytes, "expected ISO size exceeds explicit download budget")
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha256), "exact lowercase SHA-256 required")
    started = time.monotonic()
    deadline, total, checksum = started + timeout, 0, hashlib.sha256()
    prefix = bytearray()
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError("ISO stream exceeded total time budget")
        read = getattr(response, "read1", response.read)
        block = read(min(1024**2, expected_bytes - total + 1))
        if not block:
            break
        total += len(block)
        require(total <= expected_bytes and total <= max_bytes, "ISO stream contains extra bytes or exceeds budget")
        if len(prefix) < 32775:
            prefix.extend(block[:32775 - len(prefix)])
        checksum.update(block)
    require(total == expected_bytes, "ISO stream truncated or size mismatch")
    require(checksum.hexdigest() == expected_sha256, "downloaded ISO SHA-256 mismatch")
    require(len(prefix) >= 32775 and prefix[32769:32774] == b"CD001" and prefix[32774] == 1,
            "ISO9660 first volume descriptor signature/version absent; HTML or invalid ISO rejected")
    return {"status": "PASS", "checked_bytes": total, "sha256": checksum.hexdigest(), "full_stream_verified": True,
            "iso9660_descriptor_signature_verified": True, "iso_boot_verified": False,
            "stored_iso": False, "seconds": round(time.monotonic() - started, 3)}


def check_iso(path, opener, user_agent, expected_bytes, expected_sha256, max_bytes, timeout):
    url = public_url(path)
    require(urllib.parse.unquote(urllib.parse.urlsplit(url).path).lower().endswith(".iso"), "download URL must identify an .iso file")
    request = urllib.request.Request(url, headers={"User-Agent": user_agent, "Accept-Encoding": "identity"})
    with opener.open(request, timeout=min(timeout, 15)) as response:
        require(response.status == 200, "ISO must return HTTP 200")
        final_url = public_url(response.geturl())
        require(response.headers.get("Content-Encoding", "identity").lower() == "identity", "encoded ISO response forbidden")
        length = response.headers.get("Content-Length")
        require(length is None or length == str(expected_bytes), "ISO Content-Length differs from expected bytes")
        return {"requested_url": url, "final_url": final_url,
                **verify_iso_stream(response, expected_bytes, expected_sha256, max_bytes, timeout)}


def run_process(command, timeout, max_bytes=PROCESS_LIMIT):
    """Return bounded evidence and limit failures even after child termination."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
        deadline = time.monotonic() + timeout
        error = None
        timed_out = output_limit_exceeded = False
        try:
            while process.poll() is None:
                if os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > max_bytes:
                    output_limit_exceeded = True
                    error = "browser output exceeded budget"
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    error = "browser process exceeded time budget"
                    break
                time.sleep(.05)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)
        observed_bytes = os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size
        if observed_bytes > max_bytes:
            output_limit_exceeded = True
            error = error or "browser output exceeded budget"
        stdout.seek(0)
        stderr.seek(0)
        # Preserve diagnostics first if a flood forces truncation; both streams
        # together must stay within the existing capture limit.
        captured_stderr = stderr.read(max_bytes)
        captured_stdout = stdout.read(max_bytes - len(captured_stderr))
        return {"returncode": process.returncode, "stdout": captured_stdout, "stderr": captured_stderr,
                "timed_out": timed_out, "output_limit_exceeded": output_limit_exceeded,
                "output_truncated": observed_bytes > len(captured_stdout) + len(captured_stderr), "error": error}


def chrome_user_agent(version):
    match = re.fullmatch(r"(?:Google Chrome(?: for Testing)?|Chromium) (\d+\.\d+\.\d+\.\d+)(?:[^\r\n]*)", version.strip())
    require(match, "unrecognized installed Chrome version")
    return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + match[1] + " Safari/537.36"


def check_browser_page(path, chrome, user_agent, out, timeout):
    url = public_url(path)
    slug = hashlib.sha256(path.encode()).hexdigest()[:12]
    with tempfile.TemporaryDirectory(prefix="chrome-profile-", dir=out) as profile:
        command = [chrome, "--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions", "--disable-sync",
                   "--disable-background-networking", "--disk-cache-size=1048576", "--media-cache-size=1048576",
                   "--user-data-dir=" + profile, "--user-agent=" + user_agent, "--virtual-time-budget=8000", "--dump-dom", url]
        result = run_process(command, timeout)
    # Retain actual DOM and diagnostic output even when the DOM is a challenge.
    dom, log = out / ("dom-" + slug + ".html"), out / ("chrome-" + slug + ".log")
    require(not dom.exists() and not log.exists(), "fresh browser evidence paths required")
    dom.write_bytes(result["stdout"])
    log.write_bytes(result["stderr"])
    evidence = {"requested_url": url, "dom": str(dom), "log": str(log), "returncode": result["returncode"],
                "timed_out": result.get("timed_out", False),
                "output_limit_exceeded": result.get("output_limit_exceeded", False),
                "output_truncated": result.get("output_truncated", False)}
    if evidence["timed_out"] or evidence["output_limit_exceeded"]:
        return {"status": "FAIL", **evidence,
                "error": result.get("error") or "browser time or output budget exceeded"}
    require(result["returncode"] == 0, "Chrome failed; inspect retained browser log")
    detail = validate_homepage(result["stdout"])
    return {"status": "PASS", **evidence,
            "normal_chrome_user_agent_explicitly_selected": True,
            "headless_default_user_agent_tested": False, **detail}


def external_vantage(vantage, environment):
    if vantage == "local":
        return {"kind": "local", "outside_host_verified": False}
    require(vantage == "github-hosted" and environment.get("GITHUB_ACTIONS") == "true" and
            environment.get("RUNNER_ENVIRONMENT") == "github-hosted", "outside-host claim requires GitHub hosted runner metadata")
    repository, run_id, sha = (environment.get(k, "") for k in ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_SHA"))
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) and run_id.isdecimal() and
            re.fullmatch(r"[0-9a-f]{40}", sha), "complete GitHub run/revision identity required")
    return {"kind": "github-hosted", "outside_host_verified": True, "repository": repository, "run_id": run_id,
            "revision": sha, "run_url": "https://github.com/" + repository + "/actions/runs/" + run_id,
            "run_attempt": environment.get("GITHUB_RUN_ATTEMPT"), "runner_os": environment.get("RUNNER_OS")}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--chrome", type=Path)
    parser.add_argument("--vantage", choices=("local", "github-hosted"), default="local")
    parser.add_argument("--iso-path")
    parser.add_argument("--iso-sha256")
    parser.add_argument("--iso-bytes", type=int)
    parser.add_argument("--max-iso-bytes", type=int, default=4 * 1024**3)
    parser.add_argument("--iso-timeout", type=int, default=900)
    parser.add_argument("--http-timeout", type=int, default=15)
    parser.add_argument("--browser-timeout", type=int, default=45)
    args = parser.parse_args(argv)
    require(not args.out.exists() and not args.out.is_symlink(), "fresh output directory required")
    args.out.mkdir(parents=True)
    receipt = {"schema": 1, "status": "FAIL", "origin": ORIGIN, "utc": datetime.now(timezone.utc).isoformat(),
               "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               "public_dns_used": False, "certificate_validation_required": True, "origin_override_used": False,
               "homepage_external_acceptance_verified": False, "iso_external_acceptance_verified": False,
               "iso_requested": args.iso_path is not None, "pages": [], "iso": {"status": "NOT_REQUESTED"}}
    try:
        receipt["vantage"] = external_vantage(args.vantage, os.environ)
        require(1 <= args.http_timeout <= 60 and 5 <= args.browser_timeout <= 120 and 1 <= args.iso_timeout <= 1800,
                "explicit bounded timeouts required")
        require(0 < args.max_iso_bytes <= 8 * 1024**3, "ISO limit must be positive and at most 8 GiB")
        require(all(x is not None for x in (args.iso_path, args.iso_sha256, args.iso_bytes)) or
                all(x is None for x in (args.iso_path, args.iso_sha256, args.iso_bytes)), "ISO path, SHA-256 and bytes must be supplied together")
        if args.iso_path:
            public_url(args.iso_path)
            require(urllib.parse.unquote(urllib.parse.urlsplit(public_url(args.iso_path)).path).lower().endswith(".iso"), "download URL must identify an .iso file")
            require(0 < args.iso_bytes <= args.max_iso_bytes and re.fullmatch(r"[0-9a-f]{64}", args.iso_sha256), "invalid expected ISO identity")
            receipt["iso_expected"] = {"url": public_url(args.iso_path), "sha256": args.iso_sha256, "bytes": args.iso_bytes,
                                       "max_bytes": args.max_iso_bytes, "timeout_seconds": args.iso_timeout}
        chrome = str(args.chrome.resolve(strict=True)) if args.chrome else shutil.which("google-chrome")
        require(chrome, "installed Google Chrome required; no browser download is performed")
        version_result = run_process([chrome, "--version"], 10, max_bytes=65536)
        require(not version_result.get("timed_out") and not version_result.get("output_limit_exceeded"),
                version_result.get("error") or "Chrome version time or output budget exceeded")
        require(version_result["returncode"] == 0, "Chrome version command failed")
        version = version_result["stdout"].decode().strip()
        user_agent = chrome_user_agent(version)
        receipt["browser"] = {"path": chrome, "version": version, "user_agent": user_agent,
                              "ua_policy": "Explicit normal installed Chrome identity replaces HeadlessChrome; default headless identity is not tested."}
        receipt["dns"] = public_dns()
        receipt["public_dns_used"] = True
        opener = https_opener()
        for path in PAGE_PATHS:
            row = {"path": path, "status": "FAIL"}
            receipt["pages"].append(row)
            try:
                row["http"] = check_http_page(path, opener, user_agent, args.http_timeout)
            except Exception as error:
                row["http"] = {"status": "FAIL", "error": str(error)}
            try:
                row["browser"] = check_browser_page(path, chrome, user_agent, args.out, args.browser_timeout)
            except Exception as error:
                row["browser"] = {"status": "FAIL", "error": str(error)}
            if row["http"]["status"] == row["browser"]["status"] == "PASS":
                row["status"] = "PASS"
        homepage_ok = all(row["status"] == "PASS" for row in receipt["pages"])
        if args.iso_path:
            try:
                receipt["iso"] = check_iso(args.iso_path, opener, user_agent, args.iso_bytes, args.iso_sha256,
                                           args.max_iso_bytes, args.iso_timeout)
            except Exception as error:
                receipt["iso"] = {"status": "FAIL", "error": str(error)}
        iso_ok = not args.iso_path or receipt["iso"]["status"] == "PASS"
        external = receipt["vantage"]["outside_host_verified"]
        receipt["homepage_external_acceptance_verified"] = external and homepage_ok
        receipt["iso_external_acceptance_verified"] = external and args.iso_path is not None and receipt["iso"]["status"] == "PASS"
        if homepage_ok and iso_ok:
            receipt["status"] = "PASS" if external else "LOCAL_CHECK_PASS"
    except Exception as error:
        receipt["error"] = str(error)
    finally:
        (args.out / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "receipt": str(args.out / "receipt.json"),
                      "homepage_external_acceptance_verified": receipt["homepage_external_acceptance_verified"],
                      "iso_external_acceptance_verified": receipt["iso_external_acceptance_verified"]}))
    return 0 if receipt["status"] in ("PASS", "LOCAL_CHECK_PASS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
