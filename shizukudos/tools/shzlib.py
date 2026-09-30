# SPDX-License-Identifier: GPL-2.0-only
"""Shared helpers for the ShizukuDOS 10.0 build, test and evidence tooling.

Everything here is host-side. Nothing installs software or touches the host
boot configuration; downloads go to the ignored build/ directory only.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SHZ = REPO / "shizukudos"
BUILD = REPO / "build" / "shizukudos"
UPSTREAM_DIR = REPO / "build" / "upstream"
TOOLS_DIR = REPO / "build" / "tools"
MANIFEST = SHZ / "upstream" / "manifest.json"

RESULTS = ("PASS", "FAIL", "SKIP", "BLOCKED")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def run(command, cwd=None, env=None, timeout=300, capture=False, check=True):
    """Run one command, recording the whole command line for evidence."""
    command = [str(x) for x in command]
    result = subprocess.run(command, cwd=cwd, env=env, timeout=timeout, check=False,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.STDOUT if capture else None, text=capture)
    if check and result.returncode != 0:
        tail = (result.stdout or "")[-2000:] if capture else ""
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{tail}")
    return result


def load_manifest():
    return json.loads(MANIFEST.read_text())


def git_state():
    """Git revision and dirty state of this repository for evidence records."""
    def git(*args):
        r = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else ""
    status = git("status", "--porcelain")
    return {
        "revision": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "dirty": bool(status),
        "dirty_paths": len(status.splitlines()) if status else 0,
        # Hash of the tracked diff plus untracked names: a source manifest when dirty.
        "worktree_fingerprint": sha256_bytes((git("diff", "HEAD") + "\n" + git(
            "ls-files", "--others", "--exclude-standard")).encode()),
    }


def tool_version(name, args=("--version",)):
    path = shutil.which(name)
    if not path:
        return None
    r = subprocess.run([path, *args], capture_output=True, text=True, timeout=20)
    first = (r.stdout or r.stderr).strip().splitlines()
    return {"path": path, "version": first[0] if first else ""}


def ensure_upstream(name):
    """Fetch (never modify) the pinned upstream tree into build/upstream/<name>."""
    spec = load_manifest()["upstreams"][name]
    dest = UPSTREAM_DIR / name
    UPSTREAM_DIR.mkdir(parents=True, exist_ok=True)
    if not (dest / ".git").exists():
        run(["git", "clone", "-q", spec["repository"], dest], timeout=600)
    head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True,
                          text=True).stdout.strip()
    if head != spec["commit"]:
        run(["git", "-C", dest, "fetch", "-q", "--tags", "origin"], timeout=600)
        run(["git", "-C", dest, "checkout", "-q", spec["commit"]])
    if spec.get("submodules"):
        # The superproject commit already records each submodule commit (gitlink) and URL;
        # check both against the manifest before fetching so a re-pin cannot drift silently.
        for sub, info in spec["submodules"].items():
            link = subprocess.run(["git", "-C", str(dest), "ls-tree", "HEAD", sub], capture_output=True,
                                  text=True).stdout.split()
            if len(link) < 3 or link[1] != "commit" or link[2] != info["commit"]:
                raise RuntimeError(f"{name}/{sub}: manifest pins {info['commit']} but the superproject "
                                   f"records {link[2] if len(link) > 2 else 'nothing'}")
            url = subprocess.run(["git", "-C", str(dest), "config", "-f", ".gitmodules", "--get",
                                  f"submodule.{sub}.url"], capture_output=True, text=True).stdout.strip()
            if url.removesuffix(".git") != info["repository"].removesuffix(".git"):
                raise RuntimeError(f"{name}/{sub}: manifest repository {info['repository']} but .gitmodules has {url}")
        run(["git", "-C", dest, "submodule", "update", "--init", "--recursive", "-q"], timeout=600)
        for sub, info in spec["submodules"].items():
            got = subprocess.run(["git", "-C", str(dest / sub), "rev-parse", "HEAD"],
                                 capture_output=True, text=True).stdout.strip()
            if got != info["commit"]:
                raise RuntimeError(f"{name}/{sub}: pinned {info['commit']} but found {got}")
    head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True,
                          text=True).stdout.strip()
    if head != spec["commit"]:
        raise RuntimeError(f"{name}: pinned {spec['commit']} but found {head}")
    return dest


def _fetch_pinned(url, dest, sha256):
    """Download `url` to `dest` unless a file with the pinned sha256 is already there."""
    if dest.exists() and sha256_file(dest) == sha256:
        return dest
    partial = dest.with_name(dest.name + ".partial")
    urllib.request.urlretrieve(url, partial)
    digest = sha256_file(partial)
    if digest != sha256:
        partial.unlink()
        raise RuntimeError(f"{url}: sha256 {digest}, manifest pins {sha256}; refusing a different file")
    partial.replace(dest)
    return dest


def ensure_deb_upstream(name):
    """Fetch and unpack a `kind: debian-binary-packages` upstream (never modified).

    Layout under build/upstream/<name>/: downloads/ (the pinned .deb and Debian source files, each
    checked against its manifest sha256), root/ (every .deb unpacked with dpkg-deb -x). Every file the
    manifest lists under "files" is checked in root/. Returns {"root", "downloads", "spec"}."""
    spec = load_manifest()["upstreams"][name]
    if spec.get("kind") != "debian-binary-packages":
        raise RuntimeError(f"{name} is not a debian-binary-packages upstream")
    base = UPSTREAM_DIR / name
    downloads, root = base / "downloads", base / "root"
    downloads.mkdir(parents=True, exist_ok=True)
    for group in ("packages", "source"):
        for item in spec[group].values():
            _fetch_pinned(item["url"], downloads / item["file"], item["sha256"])
    stamp = root / ".unpacked-from"
    want = "\n".join(sorted(p["sha256"] for p in spec["packages"].values()))
    if not (stamp.exists() and stamp.read_text() == want):
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True)
        for item in spec["packages"].values():
            run(["dpkg-deb", "-x", downloads / item["file"], root])
        stamp.write_text(want)
    for relative, digest in spec["files"].items():
        path = root / relative
        if not path.is_file() or sha256_file(path) != digest:
            raise RuntimeError(f"{name}: {relative} missing or not the pinned file (sha256 {digest})")
    return {"root": root, "downloads": downloads, "spec": spec}


def ensure_open_watcom():
    """Return the Open Watcom root, extracting the snapshot if needed.

    The manifest's URL is Open Watcom v2's rolling `Last-CI-build` release: upstream replaces the archive with every CI
    build (it changed twice within hours on 2026-09-29/30), so a fixed sha256 cannot be a hard gate. The manifest keeps
    the hash of the last snapshot a full verification ran with; the archive actually used is recorded next to the tree
    (`ow/.snapshot-sha256`) and by the host suite, which rebuilds DOS16 twice and compares, so reproducibility is always
    checked within a run. A snapshot that differs from the pin is used with a warning, never silently."""
    spec = load_manifest()["tools"]["open-watcom-v2"]
    root = TOOLS_DIR / "ow"
    stamp = root / ".snapshot-sha256"               # the archive this tree was extracted from
    archive = TOOLS_DIR / "ow-snapshot.tar.xz"
    if (root / "binl64" / "wcc").exists() and stamp.exists():
        return root
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        urllib.request.urlretrieve(spec["url"], archive)
    digest = sha256_file(archive)
    if digest != spec["sha256"]:
        print(f"WARNING: Open Watcom snapshot {digest[:16]} differs from the pinned {spec['sha256'][:16]} "
              f"(rolling {spec['url']}); using it", file=sys.stderr)
    if root.exists():                                # an unrecorded or older tree: replace it by this archive
        shutil.rmtree(root)
    root.mkdir()
    with tarfile.open(archive) as tar:
        tar.extractall(root)
    stamp.write_text(digest + "\n")
    return root


def open_watcom_snapshot():
    """(sha256 of the snapshot the extracted tree came from or None, pinned sha256)"""
    spec = load_manifest()["tools"]["open-watcom-v2"]
    stamp = TOOLS_DIR / "ow" / ".snapshot-sha256"
    return (stamp.read_text().strip() if stamp.exists() else None), spec["sha256"]


def ow_env():
    root = ensure_open_watcom()
    env = dict(os.environ)
    env["WATCOM"] = str(root)
    env["PATH"] = f"{root / 'binl64'}:{env['PATH']}"
    env["INCLUDE"] = str(root / "h")
    return env


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n")


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def result_record(name, status, **details):
    assert status in RESULTS, status
    return {"test": name, "status": status, **details}


def print_json(value):
    json.dump(value, sys.stdout, indent=2)
    sys.stdout.write("\n")
