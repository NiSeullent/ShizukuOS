#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Fetch the NT driver corpus upstreams (ReactOS, virtio-win, Microsoft WDF) at the commits pinned in
shizukudos/upstream/manifest.json into build/upstream/<name> (ignored by git).

The trees are fetched shallow (depth 1 at the pinned commit): ReactOS with history is over a gigabyte and none of
it is needed to compile drivers. Nothing in the fetched trees is modified; corpus patches, if any, live under
shizukudos/ntdrv/corpus/patches/ and are applied to copies under build/ by build.py.

Usage: fetch.py [name ...]      (default: every upstream whose manifest entry has "corpus": true)
"""
import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from shzlib import UPSTREAM_DIR, load_manifest  # noqa: E402


def git(dest, *args, check=True, capture=False, timeout=1800):
    r = subprocess.run(["git", "-C", str(dest), *args], check=False, timeout=timeout, text=True,
                       stdout=subprocess.PIPE if capture else None, stderr=subprocess.STDOUT if capture else None)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed ({r.returncode}) in {dest}\n{r.stdout or ''}")
    return r


def head(dest):
    r = git(dest, "rev-parse", "HEAD", check=False, capture=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def ensure_shallow(name, spec):
    """Shallow checkout of spec["commit"] in build/upstream/<name>; returns the path. Verifies the commit afterwards."""
    dest = UPSTREAM_DIR / name
    UPSTREAM_DIR.mkdir(parents=True, exist_ok=True)
    if head(dest) == spec["commit"]:
        return dest
    if not (dest / ".git").exists():
        dest.mkdir(parents=True, exist_ok=True)
        git(dest, "init", "-q")
        git(dest, "remote", "add", "origin", spec["repository"])
    git(dest, "fetch", "-q", "--depth", "1", "origin", spec["commit"])
    git(dest, "checkout", "-q", "--detach", "FETCH_HEAD")
    got = head(dest)
    if got != spec["commit"]:
        raise RuntimeError(f"{name}: pinned {spec['commit']} but checked out {got}")
    for lic in spec.get("license_files", []):
        if not list(dest.glob(lic)):
            raise RuntimeError(f"{name}: licence file {lic} missing from the fetched tree")
    return dest


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("names", nargs="*")
    args = ap.parse_args()
    ups = load_manifest()["upstreams"]
    names = args.names or [n for n, s in ups.items() if s.get("corpus")]
    for n in names:
        if n not in ups:
            raise SystemExit(f"unknown upstream {n}; known: {', '.join(ups)}")
        path = ensure_shallow(n, ups[n])
        print(f"{n}: {ups[n]['commit']} at {path}")


if __name__ == "__main__":
    main()
