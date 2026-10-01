#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Probe the current publisher Steam desktop client in standalone Kernel64.

The actual package tree is supplied with --tree. Uses the same package-content
identity and isolated disk checks as the productivity runner. A successful
client login, usable library or game launch must be measured separately; this
offline startup probe never reports a full Steam functionality pass.
"""
import sys
import run_k64_productivity as runner

runner.PRODUCTS["steam"] = {
    "version": "Valve stable manifest 1788652215", "candidates": ("steam.exe",), "dir": "steam",
    "args": "-console --no-sandbox -no-cef-sandbox", "expect": None, "scenario": "publisher-desktop-client-startup",
    "publisher": "https://client-update.akamai.steamstatic.com/steam_client_win64",
}

if __name__ == "__main__":
    sys.exit(runner.main())
