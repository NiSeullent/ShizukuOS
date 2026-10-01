#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Apply exact public patches to pinned Wine blobs, execute actual transfer bodies."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

PIN = "db11d0fe6a169c457e23d007e20404643d067aa8"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--patch-stage", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    repo, stage, out = args.repo.resolve(), args.patch_stage.resolve(), args.out.resolve()
    if out.exists(): raise ValueError("new owned output required")
    out.mkdir(parents=True)
    prepared = repo / "build/upstream/wine"
    actual = subprocess.check_output(["git", "-C", str(prepared), "rev-parse", "HEAD"], text=True).strip()
    if actual != PIN: raise ValueError("prepared Wine revision differs")
    shadow = out / "source/dlls/oleacc"
    shadow.mkdir(parents=True)
    for name in ("main.c", "oleacc_classes.idl"):
        data = subprocess.check_output(["git", "-C", str(prepared), "show", PIN + ":dlls/oleacc/" + name])
        (shadow / name).write_bytes(data)
    patches = [repo / "shizukudos/win64/wineport/patches/wine/0007-oleacc-local-standard-objects.patch",
               stage / "shizukudos/win64/wineport/patches/wine/0008-oleacc-local-interface-transfer.patch"]
    pins = {str(path): sha(path) for path in patches}
    for patch in patches:
        subprocess.run(["patch", "--batch", "-p1", "-i", str(patch)], cwd=out / "source", check=True,
                       capture_output=True, timeout=30)
    main_c = (shadow / "main.c").read_text()
    start, end = main_c.index("#define SHZ_LRESULT_TAG"), main_c.index("static void variant_init_i4")
    fixture = Path(__file__).with_name("oleacc_transfer_host.c")
    generated = out / "actual_transfer_host.c"
    generated.write_text(fixture.read_text().replace("/* ACTUAL_PATCHED_WINE_TRANSFER_BODIES */", main_c[start:end]))
    rows = []
    for compiler, extra in (("gcc", []), ("clang", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
        command = [compiler, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", *extra,
                   str(generated), "-pthread", "-o", str(out / compiler)]
        build = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (out / (compiler + "-build.log")).write_text(build.stdout + build.stderr)
        row = {"compiler": compiler, "command": command, "build_exit_code": build.returncode}
        if not build.returncode:
            run = subprocess.run([str(out / compiler)], capture_output=True, text=True, timeout=60)
            (out / (compiler + "-run.log")).write_text(run.stdout + run.stderr)
            row.update(run_exit_code=run.returncode, stdout=run.stdout, stderr=run.stderr)
        rows.append(row)
    result = {"schema": "shizuku-oleacc-transfer-host/1", "wine_commit": PIN, "patches_sha256": pins,
              "actual_patched_main_sha256": sha(shadow / "main.c"), "fixture_sha256": sha(fixture),
              "runner_sha256": sha(Path(__file__)), "results": rows,
              "source_before_after_match": pins == {str(path): sha(path) for path in patches},
              "VM_executed": False, "cross_process_RPC_supported": False}
    passed = result["source_before_after_match"] and all(row.get("run_exit_code", -1) == 0 and not row["stderr"] for row in rows)
    result["status"] = "PASS_ACTUAL_OLEACC_TRANSFER_HOST" if passed else "FAIL_ACTUAL_OLEACC_TRANSFER_HOST"
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    for row in rows: print(json.dumps({k: v for k, v in row.items() if k != "command"}))
    print(result["status"])
    return 0 if passed else 1


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main())
