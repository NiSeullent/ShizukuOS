# SPDX-License-Identifier: GPL-2.0-only
"""Shared helpers for the ShizukuDOS 10.0 build, test and evidence tooling.

Everything here is host-side. Nothing installs software or touches the host
boot configuration; downloads go to the ignored build/ directory only.
"""
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path, PurePosixPath, PureWindowsPath

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
    # A loaded build host may spend most of its wall time waiting for memory
    # or I/O. Opt in per invocation; explicitly bounded test timeouts stay intact.
    if timeout == 300 and os.environ.get("SHZ_COMMAND_TIMEOUT_SECONDS"):
        timeout = int(os.environ["SHZ_COMMAND_TIMEOUT_SECONDS"])
        if not 1 <= timeout <= 3600:
            raise ValueError("SHZ_COMMAND_TIMEOUT_SECONDS must be in 1..3600")
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


def _deb_data_member(package):
    """Read Debian's simple ar container, rejecting truncation and ambiguity."""
    members = {}
    with Path(package).open("rb") as stream:
        if stream.read(8) != b"!<arch>\n":
            raise RuntimeError(f"{package}: not an ar Debian package")
        end = Path(package).stat().st_size
        while stream.tell() < end:
            header = stream.read(60)
            if len(header) != 60 or header[58:] != b"`\n":
                raise RuntimeError(f"{package}: invalid or truncated ar header")
            try:
                name = header[:16].decode("ascii").strip().removesuffix("/")
                size_text = header[48:58].decode("ascii").strip()
            except UnicodeDecodeError as exc:
                raise RuntimeError(f"{package}: non-ASCII ar header") from exc
            if not name or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-" for c in name):
                raise RuntimeError(f"{package}: unsupported ar member name {name!r}")
            if not size_text or not size_text.isdecimal() or name in members:
                raise RuntimeError(f"{package}: invalid size or duplicate ar member {name!r}")
            size = int(size_text)
            if size > end - stream.tell():
                raise RuntimeError(f"{package}: truncated ar member {name!r}")
            members[name] = (stream.tell(), size)
            stream.seek(size, 1)
            if size & 1 and stream.read(1) != b"\n":
                raise RuntimeError(f"{package}: invalid ar alignment padding")
        names = list(members)
        if not names or names[0] != "debian-binary" or members[names[0]][1] != 4:
            raise RuntimeError(f"{package}: missing Debian package version")
        stream.seek(members["debian-binary"][0])
        if stream.read(4) != b"2.0\n":
            raise RuntimeError(f"{package}: unsupported Debian package version")
        controls = [n for n in names if n == "control.tar" or n.startswith("control.tar.")]
        data = [n for n in names if n == "data.tar" or n.startswith("data.tar.")]
        if len(controls) != 1 or len(data) != 1 or names.index(controls[0]) > names.index(data[0]):
            raise RuntimeError(f"{package}: needs one control archive followed by one data archive")
        name = data[0]
        stream.seek(members[name][0])
        return name, stream.read(members[name][1])


def _deb_tar_filter(member, destination):
    """Keep package paths portable and let tarfile enforce link containment."""
    path = PurePosixPath(member.name)
    if (not member.name or "\x00" in member.name or "\\" in member.name or PureWindowsPath(member.name).drive
            or path.is_absolute() or ".." in path.parts or (path == PurePosixPath(".") and not member.isdir())):
        raise RuntimeError(f"unsafe Debian archive path: {member.name!r}")
    if member.issym() or member.islnk():
        target = member.linkname
        if not target or "\x00" in target or "\\" in target or PureWindowsPath(target).drive or PurePosixPath(target).is_absolute():
            raise RuntimeError(f"unsafe Debian archive link: {member.name!r} -> {target!r}")
    return tarfile.data_filter(member, destination)


def _extract_deb_payload(package, root):
    """Build-local fallback for hosts without dpkg-deb; never runs maintainer scripts."""
    if not hasattr(tarfile, "data_filter"):
        raise RuntimeError("Debian fallback requires Python tarfile.data_filter (Python 3.12 or a security-backported version)")
    root = Path(root)
    if root.is_symlink():
        raise RuntimeError(f"Debian extraction root is a symlink: {root}")
    name, payload = _deb_data_member(package)
    if name == "data.tar.zst":
        zstd = shutil.which("zstd")
        if not zstd:
            raise RuntimeError(f"{package}: data.tar.zst requires dpkg-deb or the zstd decompressor")
        result = subprocess.run([zstd, "-d", "-q", "-c"], input=payload, capture_output=True, timeout=300)
        if result.returncode:
            raise RuntimeError(f"{package}: zstd decompression failed: {result.stderr.decode(errors='replace')[-400:]}")
        payload = result.stdout
    elif name not in ("data.tar", "data.tar.gz", "data.tar.xz", "data.tar.bz2"):
        raise RuntimeError(f"{package}: unsupported Debian data compression: {name}")
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
            members = archive.getmembers()  # Validate all headers before writing any package files.
            seen = set()
            for member in members:
                normalized = str(PurePosixPath(member.name))
                if normalized in seen:
                    raise RuntimeError(f"{package}: duplicate tar path {member.name!r}")
                seen.add(normalized)
                _deb_tar_filter(member, str(root))
            root.mkdir(parents=True, exist_ok=True)
            # Revalidate at each write too: earlier members may have created links.
            archive.extractall(root, members=members, filter=_deb_tar_filter)
    except (tarfile.TarError, EOFError) as exc:
        raise RuntimeError(f"{package}: invalid or unsafe Debian data archive: {exc}") from exc


def ensure_deb_upstream(name):
    """Fetch and unpack a `kind: debian-binary-packages` upstream (never modified).

    Layout under build/upstream/<name>/: downloads/ (the pinned .deb and Debian source files, each
    checked against its manifest sha256), root/ (dpkg-deb -x, or a checked ar/tar fallback). Every file the
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
    unpack = not (stamp.exists() and stamp.read_text() == want)
    if unpack:
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True)
        dpkg_deb = shutil.which("dpkg-deb")
        for item in spec["packages"].values():
            package = downloads / item["file"]
            if dpkg_deb:
                run([dpkg_deb, "-x", package, root])
            else:
                _extract_deb_payload(package, root)
    for relative, digest in spec["files"].items():
        path = root / relative
        if not path.is_file() or sha256_file(path) != digest:
            raise RuntimeError(f"{name}: {relative} missing or not the pinned file (sha256 {digest})")
    if unpack:
        stamp.write_text(want)
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
