#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Rebuild native Win64 code while carrying a recorded, unchanged Wine build.

The ordinary win64/build.py must first finish its Wine-port build. This helper
reuses those exact DLLs, fonts and selected tests, records their content hashes,
and otherwise runs the ordinary builder. It does not run a VM or install tools.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main():
    if len(sys.argv) != 1:
        raise SystemExit("usage: python3 tools/rebuild_modern_runtime.py")
    receipt = ROOT / "build/shizukudos/win64/wineport/wineport-result.json"
    metadata = json.loads(receipt.read_text())
    carried = []
    info = {}
    for name, module in sorted(metadata["modules"].items()):
        carried.append((f"\\SHZ\\SYS64\\{name}.dll", Path(module["dll"])))
        info[name] = {"exports": module["exports"], "counts": module["counts"]}
    carried.extend((name, Path(path)) for name, path in sorted(metadata["image_files"].items()))
    for test in metadata["tests"].values():
        if test["in_plain_image"]:
            path = Path(test["exe"])
            carried.append((f"\\SHZ\\TESTS\\{path.name.upper()}", path))
    records = []
    files = []
    for guest, path in carried:
        if not path.resolve().is_relative_to(ROOT / "build"):
            raise SystemExit(f"cached input is outside this worktree's build directory: {path}")
        payload = path.read_bytes()
        files.append((guest, payload))
        records.append({"guest": guest, "path": str(path), "bytes": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest()})
    recipe = ROOT / "shizukudos/win64/wineport"
    recipe_hashes = {str(p.relative_to(ROOT)): digest(p) for p in sorted(recipe.rglob("*"))
                     if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"}
    manifest = ROOT / "shizukudos/upstream/manifest.json"
    before = {"wineport_receipt_sha256": digest(receipt), "manifest_sha256": digest(manifest),
              "recipe_hashes": recipe_hashes, "carried_inputs": records,
              "mode": "native-rebuild-with-frozen-wineport-artifacts"}
    out = ROOT / "build/modern-apps"
    out.mkdir(parents=True, exist_ok=True)
    proof = out / "cached-wineport-rebuild.json"
    proof.write_text(json.dumps({**before, "status": "RUNNING"}, indent=2) + "\n")
    spec = importlib.util.spec_from_file_location("modern_win64_build", ROOT / "shizukudos/win64/build.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    builder.build_wineport = lambda: (files, info)
    try:
        builder.main()
    except BaseException as error:
        proof.write_text(json.dumps({**before, "status": "FAIL",
                                     "build_error": str(error)}, indent=2) + "\n")
        raise
    changed = [r["path"] for r in records if digest(Path(r["path"])) != r["sha256"]]
    changed += [path for path, sha in recipe_hashes.items() if digest(ROOT / path) != sha]
    if digest(receipt) != before["wineport_receipt_sha256"] or digest(manifest) != before["manifest_sha256"]:
        changed.append("Wine build receipt or manifest")
    status = "FAIL" if changed else "PASS"
    proof.write_text(json.dumps({**before, "status": status, "changed_during_build": changed}, indent=2) + "\n")
    if changed:
        raise SystemExit("cached inputs changed during native rebuild; resulting runtime is unverified")


if __name__ == "__main__":
    main()
