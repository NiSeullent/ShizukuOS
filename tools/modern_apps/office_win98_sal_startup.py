#!/usr/bin/env python3
"""Verify and apply the LibreOffice 26.8.0.3 SAL Win98 startup/process/module/file patch.

Checks the pinned sha256 of the four preserved upstream files and of the patch,
applies it with `patch -p1` into a private tree seeded from those files (or a
caller-supplied checkout via --tree, whose files must match the pins), and
verifies the patched hashes. No build, network or VM. SPDX-License-Identifier: GPL-2.0-only
"""
import argparse, hashlib, json, pathlib, shutil, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent


def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tree", help="LibreOffice checkout at the pinned commit; default is a temp tree of preserved files")
    ap.add_argument("--apply", action="store_true", help="modify --tree in place (default: dry-run on a copy)")
    ap.add_argument("--pin", default="office_win98_sal_startup_pin.json", help="pin file in this directory (e.g. office_win98_sal_w32api_pin.json)")
    a = ap.parse_args()
    PIN = json.loads((HERE / a.pin).read_text())
    patch = HERE / PIN["patch"]["file"]
    if sha(patch) != PIN["patch"]["sha256"]:
        sys.exit("patch hash mismatch")
    work = pathlib.Path(tempfile.mkdtemp(prefix="office-win98-sal-"))
    for rel, info in PIN["files"].items():
        src = HERE / info["original"]["file"]
        if sha(src) != info["original"]["sha256"]:
            sys.exit(f"preserved upstream {src.name} hash mismatch")
        dst = work / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if a.tree:
            live = pathlib.Path(a.tree) / rel
            if sha(live) != info["original"]["sha256"]:
                sys.exit(f"{rel}: checkout differs from pinned upstream")
            shutil.copy2(live, dst)
        else:
            shutil.copy2(src, dst)
    r = subprocess.run(["patch", "-p1", "-d", str(work), "-i", str(patch)], capture_output=True, text=True)
    if r.returncode:
        sys.exit(r.stdout + r.stderr)
    for rel, info in PIN["files"].items():
        if sha(work / rel) != info["modified_sha256"]:
            sys.exit(f"{rel}: patched hash mismatch")
    if PIN["new_file"]["path"] and sha(work / PIN["new_file"]["path"]) != PIN["new_file"]["sha256"]:
        sys.exit("new header hash mismatch")
    if a.tree and a.apply:
        for rel in [*PIN["files"], PIN["new_file"]["path"]]:
            shutil.copy2(work / rel, pathlib.Path(a.tree) / rel)
    print("OK patch applies cleanly; pins match", "(applied in place)" if a.tree and a.apply else "")
    shutil.rmtree(work)


if __name__ == "__main__":
    main()
