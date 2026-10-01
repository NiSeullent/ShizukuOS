#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze three runtime-only native inputs; no VM, installation or network."""
import argparse
import json
from pathlib import Path
import verify_trident_script_native as V

ROOT = Path(__file__).resolve().parents[1]
BOOT_BUILD = Path('/root/Win98-Modern-boot/build')


def freeze(runtime_path, runtime_sha, observer_path, observer_sha, stage):
    """Validate every original byte before creating one fresh owned stage."""
    H = V.H
    stage = Path(stage).absolute()
    owned = ROOT / "build"
    H.need(stage.parent == BOOT_BUILD and stage == stage.resolve()
           and BOOT_BUILD == BOOT_BUILD.resolve()
           and not stage.exists() and not stage.is_symlink(),
           "select a fresh direct child of the canonical boot build receipt scope")
    builds, copies, merged = {}, {}, {}

    def plan(name, source, expected, limit=8 << 20):
        H.need(name not in copies or copies[name][1] == expected, "conflicting staged source generations")
        data = H.read(source, limit)
        H.need(H.sha(data) == H.pin(expected, name), "frozen input changed: " + name)
        copies[name] = (data, expected)

    for role, original, digest in (("runtime", runtime_path, runtime_sha), ("observer", observer_path, observer_sha)):
        original = Path(original).absolute()
        H.need(original.parent.parent == owned, "receipt outside direct owned build checkpoint")
        build = H.receipt(original, digest)
        H.need(build.get("passed") is True, "build did not pass")
        expected = H.RUNTIME_SOURCES if role == "runtime" else H.OBSERVER_SOURCES
        H.sources(build, expected, original.parent / "source", merged)
        H.build_logs(build, original.parent)
        for name, sha in build["source_sha256"].items():
            H.need(H.sha(H.read(ROOT / name, 8 << 20)) == sha, "current source drift: " + name)
            plan("source/" + name, original.parent / "source" / name, sha)
        for step in build["steps"]:
            log = Path(step["log"])
            H.need(log.parent == original.parent, "build log outside owned checkpoint")
            plan("build-logs/" + role + "/" + log.name, log, step["sha256"])
        plan(role + "-build.json", original, digest, 1 << 20)
        builds[role] = (build, original.parent)

    runtime, runtime_dir = builds["runtime"]
    observer, observer_dir = builds["observer"]
    for name, sha in H.prepared_sources(runtime, runtime_dir / "prepared").items():
        plan("runtime-prepared/" + name, runtime_dir / "prepared" / name, sha)
    # Reuse the verifier's bounded path and licence validation at the original
    # checkpoint, then copy only approved members, never archive extraction.
    V.original_sources(runtime, runtime_dir, "original")
    for role, key in (("quickjs", "quickjs_original_sha256"), ("math", "musl_original_sha256")):
        for name, sha in runtime["dependency"][key].items():
            plan("runtime-original/" + role + "/" + name, runtime_dir / "original" / role / name, sha)
    plan("runtime-selected.h", runtime_dir / "selected.h", runtime["embedded_fixture_header_sha256"], 65536)
    inputs = []
    for directory, build, name in ((runtime_dir, runtime, "M98QJS.DLL"),
                                  (runtime_dir, runtime, "QJS13PR.EXE"),
                                  (observer_dir, observer, "M98JSRUN.EXE")):
        item = build["artifacts"][name]
        plan(name, directory / name, item["sha256"], 1048576)
        size = len(copies[name][0])
        row = dict(source=str(stage / name), guest=V.PREFIX + name, bytes=size, sha256=item["sha256"])
        H.artifact(build, name, row, 65536 if name == "M98JSRUN.EXE" else 524288)
        inputs.append(row)
    H.need(sum(len(data) for data, _ in copies.values()) <= 64 << 20, "stage exceeds bounded host copy budget")
    manifest = dict(schema=1, kind="isolated-guest-file-inputs", nonce=runtime.get("nonce"),
        command=V.PREFIX + "M98JSRUN.EXE", network_required=False, inputs=inputs,
        outputs=[V.PREFIX + n for n in ("QJS13.LOG", "JSRUN.LOG", "JSOUT.LOG")],
        source_receipts=[dict(path=str(stage / (role + "-build.json")), sha256=sha)
                         for role, sha in (("runtime", runtime_sha), ("observer", observer_sha))])
    # Check all semantics before mutation, using a temporary in-memory view of
    # the final stage. No caller path or peer verifier is changed.
    pins = {"runtime-build.json": runtime_sha, "observer-build.json": observer_sha}
    import tempfile
    with tempfile.TemporaryDirectory(prefix="trident-script-stage-validation-") as temporary:
        preview = Path(temporary) / "stage"
        preview.mkdir()
        for name, (data, _) in copies.items():
            path = preview / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        preview_manifest = json.loads(json.dumps(manifest))
        for row in preview_manifest["inputs"]:
            row["source"] = str(preview / Path(row["source"]).name)
        for row in preview_manifest["source_receipts"]:
            row["path"] = str(preview / Path(row["path"]).name)
        path = preview / "guest-files.json"
        path.write_text(json.dumps(preview_manifest, indent=2) + "\n")
        V.approved_stage(path, H.sha(H.read(path)), pins)
    stage.mkdir()
    for name, (data, sha) in copies.items():
        path = stage / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as output:
            output.write(data)
        H.need(H.sha(H.read(path, 8 << 20)) == sha, "staged readback differs: " + name)
    manifest_path = stage / "guest-files.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    manifest_sha = H.sha(H.read(manifest_path))
    V.approved_stage(manifest_path, manifest_sha, pins)
    provenance = dict(schema=1, kind="runtime-only-native-frozen-stage", manifest_sha256=manifest_sha,
        source_sha256=merged, stage_sha256={name: sha for name, (_, sha) in copies.items()},
        verifier_helper_sha256=V.HELPER_SHA256, native_execution=False, native_mshtml_dom=False,
        full_javascript=False, modern_css=False, wasm=False, webgpu=False, webgl=False,
        applications=False, vm_operations=False, global_registration=False)
    (stage / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    return dict(manifest=str(manifest_path), sha256=manifest_sha, native_execution=False,
                guest_input_count=3, guest_output_count=3, source_receipt_count=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ("runtime", "observer"):
        parser.add_argument("--" + role + "-receipt", type=Path, required=True)
        parser.add_argument("--" + role + "-sha256", required=True)
    parser.add_argument("--stage", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = freeze(args.runtime_receipt, args.runtime_sha256, args.observer_receipt, args.observer_sha256, args.stage)
    except (V.EvidenceError, OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print(json.dumps(dict(passed=False, native_execution=False, error=str(error))))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
