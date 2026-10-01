"""Read-only source-port assessment consuming the existing app_preflight schema.

No downloads, application execution, source patching or output files. Static
eligibility and source availability never become browser acceptance.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
SCHEMA = "win98modern.browser-source-port-assessment.v1"
PREFLIGHT_SCHEMA = "win98modern.app-preflight.v1"
MAX_METADATA_BYTES = 4 * 1024 * 1024


def load_json(path: Path) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(MAX_METADATA_BYTES + 1)
    if len(raw) > MAX_METADATA_BYTES:
        raise ValueError("Metadata exceeds the bounded source assessment size")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Require a JSON object")
    return value


def assess(profile: dict, preflight: dict | None = None) -> dict:
    if (profile.get("schema") != "win98modern.browser-source-port-profile.v1"
            or profile.get("app") not in ("chromium", "legcord")
            or profile.get("guest_target") != {"os": "win98se", "os_version": "4.10.2222", "arch": "x86"}
            or not re.fullmatch(r"[0-9a-f]{40}", profile.get("source_commit", ""))):
        raise ValueError("Require the exact pinned x86 Win98 source profile")
    blockers = ["Upstream Windows10+ runtime requires a genuine Win98 source port."]
    pe = None
    unresolved = []
    active_input_matches_profile = None
    if preflight is not None:
        if preflight.get("schema") != PREFLIGHT_SCHEMA:
            raise ValueError("Consume tools/app_preflight.py output; do not substitute an unbound inventory")
        pe = preflight["pe"]
        if not isinstance(pe, dict):
            raise ValueError("Malformed preflight PE record")
        if pe.get("machine") != 0x14C or pe.get("format") != "PE32":
            blockers.append("The native 32-bit Win98 process requires x86 PE32; x64 UEFI does not change that ABI.")
        if pe.get("subsystem") not in (2, 3):
            blockers.append("Unsupported guest GUI/console subsystem.")
        version = pe.get("subsystem_version")
        if (not isinstance(version, list) or len(version) != 2
                or any(type(item) is not int or item < 0 for item in version)):
            raise ValueError("Malformed PE subsystem version")
        if tuple(version) > (4, 10):
            blockers.append("PE subsystem version exceeds real Win98; a header edit does not implement missing APIs.")
        if pe.get("clr_present") is not False:
            blockers.append("CLR requires a separate native runtime port.")
        if preflight.get("import_inventory_complete") is not True:
            blockers.append("Load/delay import inventory is incomplete.")
        unresolved = preflight.get("unresolved_by_ntw32", [])
        if not isinstance(unresolved, list):
            raise ValueError("Malformed preflight unresolved-import inventory")
        if preflight.get("api_set_dlls"):
            blockers.append("API-set routes require explicit native or bundled implementations.")
        selected = profile.get("existing_preflights", [])
        if selected:
            active_input_matches_profile = preflight.get("input", {}).get("sha256") in {
                row["input_sha256"] for row in selected
            }
            if not active_input_matches_profile:
                blockers.append("Preflight input SHA-256 is outside the active publisher snapshot bindings.")
    return {
        "schema": SCHEMA,
        "app": profile["app"],
        "status": "SOURCE_PORT_REQUIRED",
        "upstream_pin": {key: profile[key] for key in ("version", "source_commit", "source_url", "as_of")},
        "target": profile["guest_target"],
        "preflight_input": preflight.get("input") if preflight else None,
        "active_input_matches_profile": active_input_matches_profile,
        "pe": pe,
        "blockers": blockers,
        "prerequisites": profile["prerequisites"],
        "ntw32_unresolved_count": len(unresolved),
        "ntw32_unresolved_is_native_missing_proof": False,
        "note": "Reuse canonical app_preflight output. Native/bundled exports and source semantics need separate validation.",
        "acceptance": profile["acceptance"],
        "guest_executed": False,
        "runtime_compatibility": "unverified",
        "browser_pass": False,
        "download_performed": False,
        "execution_performed": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", choices=("chromium", "legcord"), default="chromium")
    parser.add_argument("--preflight", type=Path, help="Existing canonical preflight JSON; '-' reads bounded stdin")
    args = parser.parse_args(argv)
    try:
        profile = load_json(HERE / (args.app + "_port_profile.json"))
        preflight = None
        if args.preflight is not None:
            if str(args.preflight) == "-":
                raw = sys.stdin.buffer.read(MAX_METADATA_BYTES + 1)
                if len(raw) > MAX_METADATA_BYTES:
                    raise ValueError("Preflight exceeds bounded size")
                preflight = json.loads(raw)
                if not isinstance(preflight, dict):
                    raise ValueError("Require preflight object")
            else:
                preflight = load_json(args.preflight)
        report = assess(profile, preflight)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("browser-source-profile: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0  # Successful assessment generation, never browser PASS.


if __name__ == "__main__":
    raise SystemExit(main())
