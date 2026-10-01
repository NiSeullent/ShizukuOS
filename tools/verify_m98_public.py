#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check the public m98 hostname and download the complete release ISO.

Uses ordinary DNS, HTTPS certificate validation, and a desktop browser User-Agent.
No origin address override, proxy bypass, cookies, or challenge bypass is used.
"""
import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

BASE = "https://m98.nyase.kr"
USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")


class PageProbe(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.challenge = False
        self.vnc_embed = False

    def handle_starttag(self, tag, attributes):
        values = {key.lower(): (value or "").lower() for key, value in attributes}
        if tag == "form":
            self.challenge |= (values.get("id") in ("challenge-form", "cf-challenge-form")
                               or "/cdn-cgi/challenge" in values.get("action", ""))
        if tag in ("iframe", "frame", "script"):
            src = values.get("src", "")
            self.vnc_embed |= bool(re.search(r"vnc|websockify|legacy-console|/core/rfb\.js", src))


def check_page(body, headers, status, final_url, kind):
    if status != 200:
        raise ValueError(f"HTTP {status}")
    parsed = urlparse(final_url)
    if parsed.scheme != "https" or parsed.hostname != "m98.nyase.kr":
        raise ValueError("Redirect left the official HTTPS hostname")
    if headers.get("cf-mitigated", "").lower() == "challenge":
        raise ValueError("Cloudflare challenge, not the requested page")
    if "text/html" not in headers.get("content-type", "").lower():
        raise ValueError("Expected an HTML page")
    text = body.decode("utf-8", errors="strict")
    title = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if not title or "just a moment" in title.group(1).lower():
        raise ValueError("Missing site title or challenge page")
    probe = PageProbe()
    probe.feed(text)
    if probe.challenge or "_cf_chl_opt" in text:
        raise ValueError("Interactive challenge form, not the requested page")
    if probe.vnc_embed or re.search(r"novnc|websockify|vnc_canvas|new\s+RFB\s*\(", text, re.I):
        raise ValueError("VNC interface is exposed at a public page")
    if kind == "home":
        if "ShizukuOS" not in text:
            raise ValueError("Official homepage markers are missing")
    elif kind == "authorship" and "Authorship" not in text:
        raise ValueError("Authorship page marker is missing")
    elif kind == "handoff" and "CONTINUE_MODERN_APPS.md" not in text:
        raise ValueError("Portable source handoff link is missing")
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
            "title": title.group(1), "vnc_ui": False, "cloudflare_challenge": False}


def open_public(path):
    return urlopen(Request(BASE + path, headers={"User-Agent": USER_AGENT,
                   "Accept": "*/*", "Cache-Control": "no-cache"}), timeout=60)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso-name", default="shizuku-modern-0.9.0-dev.iso")
    parser.add_argument("--iso-sha256", required=True)
    parser.add_argument("--iso-bytes", required=True, type=int)
    parser.add_argument("--vantage", default="current host public internet egress")
    parser.add_argument("--output", type=Path, default=Path("build/public-site-result.json"))
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.iso", args.iso_name):
        parser.error("ISO name must be a plain .iso filename")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", args.iso_sha256):
        parser.error("ISO SHA256 must contain 64 hexadecimal digits")
    if not 32774 <= args.iso_bytes <= 2 * 1024 ** 3:
        parser.error("ISO size must be between 32774 bytes and 2 GiB")
    report = {"schema": "win98modern.public-distribution-verification.v1",
              "observed_utc": datetime.now(timezone.utc).isoformat(),
              "base_url": BASE, "vantage": args.vantage,
              "transport": "ordinary DNS and validated public HTTPS",
              "user_agent": USER_AGENT, "origin_override": False,
              "browser_rendering_verified": False, "routes": [], "status": "FAIL"}
    try:
        routes = [("/", "home"), ("/en/", "home"),
                  ("/vnc.html", "home"), ("/vnc_lite.html", "home"),
                  ("/authorship/", "authorship"),
                  ("/authorship/handoff.html", "handoff")]
        for path, kind in routes:
            row = {"path": path}
            report["routes"].append(row)
            with open_public(path) as response:
                row.update(status=response.status, final_url=response.url)
                body = response.read(2 * 1024 ** 2 + 1)
                if len(body) > 2 * 1024 ** 2:
                    raise ValueError("HTML response exceeds 2 MiB")
                headers = {k.lower(): v for k, v in response.headers.items()}
                row.update(check_page(body, headers, response.status, response.url, kind))
            if path in ("/vnc.html", "/vnc_lite.html"):
                if urlparse(row["final_url"]).path != "/":
                    raise ValueError("Legacy VNC URL did not redirect to the homepage")
        digest = hashlib.sha256()
        size = 0
        prefix = bytearray()
        path = "/downloads/" + args.iso_name
        report["iso"] = {"path": path, "expected_bytes": args.iso_bytes,
                         "expected_sha256": args.iso_sha256.lower()}
        with open_public(path) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            if response.status != 200 or headers.get("cf-mitigated") == "challenge":
                raise ValueError("ISO request did not return an ordinary HTTP 200 download")
            parsed = urlparse(response.url)
            if parsed.scheme != "https" or parsed.hostname != "m98.nyase.kr":
                raise ValueError("ISO redirect left the official HTTPS hostname")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > args.iso_bytes:
                    raise ValueError("ISO download exceeds expected size")
                digest.update(chunk)
                prefix.extend(chunk[:max(0, 32774 - len(prefix))])
        report["iso"].update(bytes=size, sha256=digest.hexdigest())
        if size != args.iso_bytes or digest.hexdigest() != args.iso_sha256.lower():
            raise ValueError("Complete downloaded ISO does not match release bytes/hash")
        if prefix[32769:32774] != b"CD001":
            raise ValueError("Downloaded file lacks the ISO9660 volume descriptor")
        report["iso"]["complete_download_verified"] = True
        report["status"] = "PASS"
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "report": str(args.output),
                      "error": report.get("error")}, ensure_ascii=False))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
