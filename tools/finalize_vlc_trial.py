#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze a new VLCLAB assets-only native trial; never modify or boot a guest."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(path):
    path = path.resolve(strict=True)
    if not path.is_relative_to(ROOT / "build"):
        raise ValueError("private repository build input required")
    return {"path": str(path), "sha256": sha(path), "bytes": path.stat().st_size}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--prepared", type=Path, required=True)
    p.add_argument("--prepared-sha", required=True)
    p.add_argument("--installer", type=Path, required=True)
    p.add_argument("--modes", type=Path, required=True)
    p.add_argument("--watch", type=Path, required=True)
    p.add_argument("--core", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        p.error("new private build output required")
    if sha(args.prepared) != args.prepared_sha:
        p.error("original prepared manifest changed")
    spec = importlib.util.spec_from_file_location("vlc_asset_guard", ROOT / "shizukudos/csm/app_staging.py")
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    # Validate the actual production confinement/count/path/pin contract,
    # rather than maintaining a second approximate stager parser.
    guard.validate(args.prepared, args.prepared_sha, ROOT)
    base = json.loads(args.prepared.read_text())
    if (base.get("staging_prefix") != "VLCLAB" or base.get("outputs") != [] or
            base.get("application_success") is not False):
        p.error("fresh VLCLAB assets-only source manifest required")
    inputs, sources = [], [record(args.prepared)]
    for item in base["inputs"]:
        path = Path(item["source"])
        if (sha(path) != item["sha256"] or path.stat().st_size != item["bytes"] or
                not item["guest"].startswith("C:\\VLCLAB\\") or ".." in item["guest"]):
            p.error("prepared exact source/path changed")
        inputs.append(dict(item))
    if len(inputs) != 40:
        p.error("exact preceding40-input closure required")
    expected_schemas = {"VLCINST.EXE": (args.installer, "win98modern.vlc-prerequisite-installer-build.v1"),
                        "VLCMODE.EXE": (args.modes, "win98modern.vlc-app-modes-build.v1"),
                        "VLCWATCH.EXE": (args.watch, "win98modern.vlc-native-observer-build.v1")}
    additions = []
    for name, (path, schema) in expected_schemas.items():
        document = json.loads(path.read_text())
        if (document.get("schema") != schema or document.get("status") != "PASS" or
                document.get("native_execution") is not False):
            p.error("source-bound native compile-only helper receipt required")
        for source, pin in document["sources"].items():
            if sha(ROOT / source) != pin or sha(path.parent / "frozen" / source) != pin:
                p.error("helper current/frozen source changed")
        artifact = document["artifact"]
        original = Path(artifact["path"])
        if (original.name != name or original.resolve() != path.parent.resolve() / name or
                sha(original) != artifact["sha256"] or original.stat().st_size != artifact["bytes"] or
                artifact.get("native_import_gate") != "PASS"):
            p.error("actual helper artifact changed")
        if name == "VLCMODE.EXE":
            official = {item["guest"].upper() for item in inputs
                        if item["guest"].upper().startswith("C:\\VLCLAB\\VLC\\") and
                        item["guest"].lower().endswith((".dll", ".exe"))}
            if official != set(document["exact_guest_paths"]) or len(official) != 21:
                p.error("mode guard must cover exact official21-image closure")
        if name == "VLCINST.EXE":
            core_pin = next(item for item in document["inputs"] if Path(item["path"]) == args.core.resolve())
            if sha(args.core) != core_pin["sha256"]:
                p.error("guarded installer CORE pin changed")
        sources.append(record(path)); sources.append(record(original))
        additions.append((original, name))
    core_receipt = args.core.with_name(args.core.name + ".receipt.json")
    d = json.loads(core_receipt.read_text())
    if d.get("status") != "PASS" or sha(args.core) != d["output_sha256"]:
        p.error("guarded Core receipt changed")
    sources += [record(args.core), record(core_receipt)]
    additions.append((args.core, "CORE.NEW"))
    for name in ("DWMAPI.DLL", "DBGHELP.DLL", "BCRYPT.DLL"):
        item = next(i for i in inputs if i["guest"].upper() == "C:\\VLCLAB\\PROVIDE\\" + name)
        additions.append((Path(item["source"]), "VLC/" + name))
    out.mkdir(parents=True)
    # Every original and additional input must live beneath this NEW
    # manifest's parent; references into earlier payload folders are refused
    # by the unchanged production stager.
    for item in inputs:
        path = Path(item["source"])
        name = item["guest"][len("C:\\VLCLAB\\"):].replace("\\", "/")
        dest = out / "inputs" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)
        if sha(dest) != item["sha256"] or dest.stat().st_size != item["bytes"]:
            raise ValueError("original payload changed while freezing")
        item["source"] = str(dest)
    for path, name in additions:
        dest = out / "inputs" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)
        if sha(path) != sha(dest):
            raise ValueError("input changed while freezing")
        inputs.append({"source": str(dest), "guest": "C:\\VLCLAB\\" + name.replace("/", "\\"),
                       "bytes": dest.stat().st_size, "sha256": sha(dest)})
    paths = [i["guest"].upper() for i in inputs]
    if (len(paths) != len(set(paths)) or len(paths) > 512 or
            sum(i["bytes"] for i in inputs) > 128 * 1024**2):
        raise ValueError("stager count/case/size guard violated")
    own_source = out / "frozen/tools/finalize_vlc_trial.py"
    own_source.parent.mkdir(parents=True)
    own_source.write_bytes(Path(__file__).read_bytes())
    sources.append({"path": str(own_source), "sha256": sha(own_source), "bytes": own_source.stat().st_size})
    for item in sources:
        if sha(Path(item["path"])) != item["sha256"]:
            raise ValueError("frozen receipt changed during finalization")
    manifest = dict(base)
    manifest.update({"inputs": inputs, "outputs": [], "staging_prefix": "VLCLAB",
                     "source_receipts": base["source_receipts"] + sources,
                     "expected_manual_outputs": [{"guest": "C:\\VLCLAB\\" + name, "max_bytes": limit}
                                                 for name, limit in (("INSTALLA.LOG", 65536), ("INSTALLV.LOG", 65536),
                                                                    ("MODEI.LOG", 65536), ("MODEA.LOG", 65536),
                                                                    ("MODEV.LOG", 65536), ("VIDWATCH.LOG", 65536),
                                                                    ("AUDWATCH.LOG", 65536), ("VIDEO.LOG", 1048576),
                                                                    ("AUDIO.LOG", 1048576))],
                     "trial_commands": ["C:\\VLCLAB\\VLCINST.EXE apply", "C:\\VLCLAB\\VLCINST.EXE verify",
                                        "C:\\VLCLAB\\VLCMODE.EXE inspect", "C:\\VLCLAB\\VLCMODE.EXE apply",
                                        "C:\\VLCLAB\\VLCMODE.EXE verify", "COLD_OWNED_REBOOT_REQUIRED",
                                        "C:\\VLCLAB\\VLCWATCH.EXE video", "C:\\VLCLAB\\VLCWATCH.EXE audio"],
                     "limitations": ["Every existing NPP path/configuration is preserved; original source disk stays immutable.",
                                     "Setup requires independent post-run old Core backup/new Core/3providers/21registry modes readbacks.",
                                     "No automatic app WM_CLOSE;600-second observer deadline termination is failure.",
                                     "Audio hardware absent in held VM: do not claim audible playback.",
                                     "VLC GUI/video/normal-exit acceptance requires actual original guest evidence."]})
    target = out / "manifest.json"
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    validated = guard.validate(target, sha(target), ROOT)
    if validated["staging_prefix"] != "VLCLAB" or validated["outputs"]:
        raise ValueError("final actual assets-only guard contract violated")
    receipt = {"schema": "win98modern.final-vlc-trial-assets.v1", "status": "FROZEN-INPUTS-NOT-APPLICATION-PASS",
               "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "native_execution": False,
               "application_success": False, "manifest": record(target), "source_inputs": sources,
               "input_files": len(inputs), "input_bytes": sum(i["bytes"] for i in inputs),
               "production_asset_guard": "PASS",
               "asset_guard_source_sha256": sha(ROOT / "shizukudos/csm/app_staging.py")}
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "manifest": str(target), "sha256": sha(target),
                      "files": len(inputs), "bytes": receipt["input_bytes"]}))


if __name__ == "__main__":
    main()
