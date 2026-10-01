#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze three verified CSS native inputs in canonical boot build; launch nothing."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from build_css_mshtml_fixture import SOURCES as FIXTURE_SOURCES, CORE_EXPORTS
from build_css_mshtml_runner import SOURCES as OBSERVER_SOURCES
from verify_trident_automation_native import read, receipt, build_logs, sources, artifact

ROOT = Path(__file__).resolve().parents[1]
BOOT_BUILD = Path("/root/Win98-Modern-boot/build")
PROFILE = dict(self="C:\\GOPLAB\\M98CSR.EXE", supervisor_log="C:\\GOPLAB\\CSRUN.LOG",
    child_stdout="C:\\GOPLAB\\CSOUT.LOG", child="C:\\GOPLAB\\CSS13PR.EXE",
    child_log="C:\\GOPLAB\\CSS13.LOG", child_timeout_ms=60000, reap_timeout_ms=5000)
STAGE_TOOLS = ["tools/stage_css_mshtml_native.py", "tools/verify_trident_automation_native.py"]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(read(path, 16 * 1024 * 1024)).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("core", "fixture", "observer"):
        parser.add_argument("--" + label + "-receipt", required=True, type=Path)
        parser.add_argument("--" + label + "-sha256", required=True)
    parser.add_argument("--stage", required=True, type=Path)
    args = parser.parse_args()
    stage = args.stage.absolute()
    require(stage.resolve() == stage and stage.parent == BOOT_BUILD and not stage.exists(),
            "fresh canonical direct boot build stage required")
    builds, paths, copies, merged = {}, {}, {}, {}
    for role in ("core", "fixture", "observer"):
        path = getattr(args, role + "_receipt").absolute()
        require(path.resolve() == path and path.parent.parent == ROOT / "build",
                "canonical owned direct build receipt required")
        approved = getattr(args, role + "_sha256")
        build = receipt(path, approved, 16 * 1024 * 1024)
        require(type(build.get("schema")) is int and build["schema"] == 1 and
                build.get("passed") is True and build.get("native_execution") is False and
                build.get("vm_operations") is False, "approved build-only profile required")
        expected = set(FIXTURE_SOURCES) if role == "fixture" else (
            set(OBSERVER_SOURCES) if role == "observer" else set(build["source_sha256"]))
        require(1 <= len(expected) <= 128, "bounded source closure required")
        sources(build, expected, path.parent / "source", merged)
        build_logs(build, path.parent)
        for name, sha in build["source_sha256"].items():
            source = path.parent / "source" / name
            require(digest(ROOT / name) == sha, "current source drift: " + name)
            copies["source/" + name] = (source, sha)
        for step in build["steps"]:
            log = Path(step["log"])
            require(log.parent == path.parent, "log escapes approved direct build")
            copies["build-logs/" + role + "/" + log.name] = (log, step["sha256"])
        for filename, item in build["artifacts"].items():
            require(Path(filename).name == filename, "canonical build artifact required")
            source = path.parent / filename
            size = source.stat().st_size
            require(type(item.get("size", item.get("bytes"))) is int and
                    size == item.get("size", item.get("bytes")) and
                    0 < size <= 1024 * 1024 and digest(source) == item["sha256"],
                    "original build artifact differs")
            copies["build-artifacts/" + role + "/" + filename] = (source, item["sha256"])
        copies[role + "-build.json"] = (path, approved)
        builds[role], paths[role] = build, path
    core, fixture, observer = (builds[n] for n in ("core", "fixture", "observer"))
    require(core.get("kind") == "current-css-token-and-variable-core-build" and
            core.get("profile") == "current-css-variables-active-fallback-core-v1" and
            all(core.get(k) is False for k in ("foreign_script_execution", "mshtml_style_integration",
                "native_paint", "browser_wpt_pass", "full_modern_css", "full_browser", "wasm",
                "webgpu", "webgl", "modern_apps")), "approved pure current CSS core required")
    require(fixture.get("kind") == "genuine-mshtml-css-variable-consumer-build" and
            fixture.get("core_receipt_sha256") == args.core_sha256 and
            fixture.get("core_source_sha256") == core["source_sha256"] and
            all(fixture.get(k) is False for k in ("native_mshtml_styles", "native_geometry",
                "native_paint", "actual_child_exit", "full_css", "browser_wpt", "full_browser",
                "wasm", "webgpu", "webgl", "modern_apps")), "genuine CSS consumer scope/closure required")
    require(digest(paths["fixture"].parent / "core-build.json") == args.core_sha256,
            "fixture's original core receipt differs")
    require(observer.get("kind") == "win98-css-owned-child-observer-build" and
            isinstance(observer.get("nonce"), str) and
            re.fullmatch(r"[A-Za-z0-9_-]{1,64}", observer["nonce"]), "exact CSS observer required")
    require(all(observer.get(k) is False for k in ("native_mshtml_styles", "native_geometry",
                "native_paint", "actual_child_exit", "full_css", "browser_wpt", "webgpu",
                "webgl", "full_web_standards")), "observer must retain component-only scope")
    profile = observer.get("profiles", {}).get("css", {})
    require(all(profile.get(k) == v for k, v in PROFILE.items()) and
            profile.get("host") == profile.get("sanitizer") and
            "across 18 injected scenarios" in profile.get("host", ""), "CSS observer lifecycle profile")
    for name, sha in core["generated_sha256"].items():
        require(Path(name).name == name, "canonical generated core member")
        source = paths["core"].parent / name
        require(digest(source) == sha, "generated core pin differs")
        copies["core-generated/" + name] = (source, sha)
    for role, filename, commit in (("core", "M98CSS.DLL", 524288),
                                   ("fixture", "CSS13PR.EXE", 524288),
                                   ("observer", "M98CSR.EXE", 65536)):
        source = paths[role].parent / filename
        item = builds[role]["artifacts"][filename]
        size = source.stat().st_size
        require(0 < size <= 1024 * 1024 and digest(source) == item["sha256"], "actual PE input changed")
        artifact(builds[role], filename, dict(bytes=size, sha256=item["sha256"]), commit)
        gate = (fixture if role == "core" else builds[role])["artifacts"][filename]
        machine = gate.get("i486_instructions", {})
        require(gate.get("sha256") == item["sha256"] and
                machine.get("artifact_sha256") == item["sha256"] and
                machine.get("parser") == "horizontal-lines-explicit-i486-x87-allowlist-v1" and
                type(machine.get("instructions_decoded")) is int and
                machine["instructions_decoded"] > 100 and
                machine.get("post_i486_families") == "absent" and
                machine.get("executable_sections") and all(
                    type(s.get("bytes")) is int and s["bytes"] > 0 and
                    s.get("decoded_bytes") == s["bytes"]
                    for s in machine["executable_sections"].values()), "corrected complete i486 proof required")
        copies[filename] = (source, item["sha256"])
    require(core["artifacts"]["M98CSS.DLL"].get("imports") == {} and
            core["artifacts"]["M98CSS.DLL"].get("exports") == CORE_EXPORTS,
            "exact pure core ABI required")
    for name in STAGE_TOOLS:
        source = ROOT / name
        copies["stage-tools/" + name] = (source, digest(source))
    # Every approval/source/log/gate check above is read-only. One fresh private
    # canonical stage is created only after the complete closure agrees.
    stage.mkdir()
    for name, (source, sha) in copies.items():
        data = read(source, 16 * 1024 * 1024)
        require(hashlib.sha256(data).hexdigest() == sha, "source drift before staging")
        destination = stage / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        require(digest(destination) == sha, "staged readback differs")
    inputs = [dict(source=str(stage / name), guest="C:\\GOPLAB\\" + name,
                   bytes=(stage / name).stat().st_size, sha256=copies[name][1])
              for name in ("M98CSS.DLL", "CSS13PR.EXE", "M98CSR.EXE")]
    manifest = dict(schema=1, kind="isolated-guest-file-inputs", inputs=inputs,
        outputs=["C:\\GOPLAB\\" + n for n in ("CSS13.LOG", "CSRUN.LOG", "CSOUT.LOG")],
        command=PROFILE["self"], nonce=observer["nonce"], network_required=False,
        source_receipts=[dict(path=str(stage / (role + "-build.json")),
                             sha256=getattr(args, role + "_sha256"))
                         for role in ("core", "fixture", "observer")])
    output = stage / "guest-files.json"
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    provenance = dict(schema=1, kind="genuine-mshtml-css-frozen-native-stage",
        manifest_sha256=digest(output), source_sha256=merged,
        stage_sha256={n: sha for n, (_, sha) in copies.items()}, native_execution=False,
        native_styles=False, native_geometry=False, native_paint=False, actual_child_exit=False,
        full_modern_css=False, browser_wpt=False, webgpu=False, webgl=False,
        modern_apps=False, vm_operations=False)
    (stage / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(json.dumps(dict(manifest=str(output), sha256=digest(output), native_execution=False)))


if __name__ == "__main__":
    main()
