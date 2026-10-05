#!/usr/bin/env python3
"""Explicit pinned public source/license capsule for the candidate installer ISO.

The capsule is assembled from named inputs only, never from a blind tree copy:
  * project GPL source: an allowlist of roots, read from git blobs of ONE pinned
    commit (not the working tree), each file passing the path/name/content guards;
  * upstream source trees: the names in the builder's MEDIA_UPSTREAMS (plus the
    Wine port set when asked), each verified at the commit that
    shizukudos/upstream/manifest.json pins, with the builder's own helpers;
  * patches: exactly the patches the producer receipts list, hash-checked;
  * licence files: from the pinned trees / project LICENSE.

Nothing here claims GPL/LGPL source closure.  Every provenance field that cannot
be established stays false and the exact requirement is recorded under
"requirements".  "compliance_claim" (GPL corresponding-source closure) is only true when no source requirement
remains.  It is deliberately independent of OS boot qualification: the historical installed-guest FAIL is kept as a
separate field and "os_boot_qualification_claim" is always false here.

Read-only contract: nothing in this module downloads, builds, unpacks or calls the builder's ensure_* helpers, in
--check or --out.  The Syslinux (Debian binary package) upstream is read ONLY from an explicit existing cache given as
--syslinux-cache (a directory holding root/ and downloads/, or the API tuple (root, downloads)).  Every pinned file,
package, source file and legal file is re-hashed against shizukudos/upstream/manifest.json (legal files additionally
against the bytes inside the pinned .deb).  An absent or failing cache leaves the upstream false with the exact
requirement and mutates nothing.

Consumed receipts: explicit producer receipts (kernels, guest successor, setup, DOS) are named by path, hashed and
their recorded source SHA-256 maps are compared with the current files and with the bytes that really enter the
capsule.  Stale/missing entries are reported as stale/missing and never bound as current.  The consumed receipt always
carries release_claim=false and the preserved installed-UEFI-guest FAIL; it is evidence of binding, not acceptance.

API:  build_capsule(...) -> (members: dict[str, bytes], manifest: dict)
CLI:  --check validates and writes nothing; otherwise --out must be absent/empty.
"""
from __future__ import annotations

import argparse
import fnmatch
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "shizuku-source-capsule/1"
DEFAULT_PREFIX = "ShizukuDOS10"
BUILDER_RECEIPT_DIR = "build/shizukudos"
RECEIPTS = ("dos16/build-result.json", "csm/build-result.json", "kernels-build-result.json",
            "supervisor/build-result.json", "win64/build-result.json")
FIXED_EPOCH = 1785283200

# Allowlist of project roots (files at top level are named explicitly).
DEFAULT_PROJECT_ROOTS = ("shizukudos", "shizukufs", "tools", "platform", "ntwrapper", "ntwin32", "ntwddm",
                         "integration", "docs", "apps", "drivers", "patches", "licenses", "LICENSE", "THIRD_PARTY.md",
                         "AGENTS.md", "README.md", ".gitmodules")
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 768 * 1024 * 1024
MAX_FILES = 60000

# --- guards -----------------------------------------------------------------
PRIVATE_DIRS = {"private", "secrets", "secret", "keys", "build", "out", "dist", "obj", "node_modules",
                "__pycache__", ".git", ".claude", "credentials", "win98-media", "msmedia"}
BAD_SUFFIX = {".img", ".iso", ".vhd", ".vhdx", ".vmdk", ".qcow2", ".raw", ".wim", ".cab", ".dmp", ".exe", ".dll",
              ".vxd", ".drv", ".efi", ".bin", ".obj", ".o", ".a", ".pdb", ".pyc", ".gz", ".zip",
              ".7z", ".tar", ".xz", ".pem", ".key", ".pfx", ".p12", ".pvk", ".snk", ".jks", ".kdbx", ".ppk"}
MS_NAMES = {"io.sys", "msdos.sys", "command.com", "win.com", "system.dat", "user.dat", "win.ini", "system.ini",
            "setupx.dll", "mkcompat.exe", "win98.cab", "precopy1.cab"}
SECRET_NAMES = ("id_rsa*", "id_ed25519*", "id_ecdsa*", ".env", ".env.*", "*.secret", "*secret*.json",
                "*credential*", ".netrc", ".npmrc", ".pypirc", "*token*.txt", "*password*", "*.pcap*")
KEY_RE = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")
CDKEY_RE = re.compile(rb"\b[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}\b")


class CapsuleError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def guard_path(rel: str, strict: bool = True) -> str | None:
    """Reason a path must not enter the capsule, or None.  strict adds the binary-suffix rule (project source);
    upstream trees keep their legitimate fixtures and get only the private/Microsoft/secret rules."""
    parts = PurePosixPath(rel).parts
    name = parts[-1].lower()
    if any(p.startswith("..") or p == "." for p in parts) or rel.startswith("/") or "\\" in rel:
        return "unsafe-path"
    if strict and any(p.lower() in PRIVATE_DIRS or p.lower().endswith("-private") for p in parts[:-1]):
        return "private-or-output-directory"
    if name in MS_NAMES:
        return "microsoft-media-name"
    if any(fnmatch.fnmatch(name, pat) for pat in SECRET_NAMES):
        return "secret-name"
    suffix = PurePosixPath(name).suffix
    if suffix in {".pem", ".key", ".pfx", ".p12", ".pvk", ".snk", ".jks", ".kdbx", ".ppk"}:
        return "key-file"
    if suffix in {".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".qcow2", ".wim", ".cab"}:
        return "disk-or-media-image"
    if strict and suffix in BAD_SUFFIX:
        return "binary-or-build-output"
    return None


def guard_content(data: bytes) -> str | None:
    if KEY_RE.search(data):
        return "private-key-content"
    if CDKEY_RE.search(data[:1 << 20]) and b"\0" not in data[:4096]:
        return "product-key-shaped-content"
    return None


# --- git / builder access ----------------------------------------------------
def git(root: Path, *args: str, check: bool = True) -> bytes:
    r = subprocess.run(["git", "--no-optional-locks", "-C", str(root), *args], capture_output=True)
    if check and r.returncode:
        raise CapsuleError(f"git {' '.join(args)} failed in {root}: {r.stderr.decode(errors='replace').strip()}")
    return r.stdout


def load_builder(root: Path):
    path = root / "tools" / "build_shizuku_se_iso.py"
    if not path.is_file():
        raise CapsuleError(f"{path} missing; the reused producer helpers are required")
    spec = importlib.util.spec_from_file_location("_shz_iso_builder", path)
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(root / "tools"))
    saved_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True  # importing must not write __pycache__
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = saved_bytecode
        sys.path.pop(0)
    if Path(mod.ROOT).resolve() != root.resolve():
        raise CapsuleError("builder ROOT differs from capsule ROOT; refusing mixed trees")
    _forbid_mutating_helpers(mod)
    def readonly_git_output(*args, cwd=root):
        result = subprocess.run(["git", "--no-optional-locks", "-C", str(cwd), *args], capture_output=True, text=True)
        return result.stdout.strip() if result.returncode == 0 else ""
    mod.git_output = readonly_git_output
    return mod


FORBIDDEN_CALLS: list[str] = []


def _forbid_mutating_helpers(mod) -> None:
    """Replace the builder's ensure/download/payload helpers (in memory only) with raisers.  The capsule never needs
    them; a call would mean a download or unpack, which --check and --out must not do.  Calls are recorded."""
    def make(label):
        def forbidden(*_a, **_k):
            FORBIDDEN_CALLS.append(label)
            raise CapsuleError(f"{label} is forbidden in source_capsule (read-only; use --syslinux-cache)")
        return forbidden
    holders = [("se_media", getattr(mod, "se_media", None)), ("shzlib", getattr(mod, "shzlib", None)),
               ("se_media.shzlib", getattr(getattr(mod, "se_media", None), "shzlib", None))]
    for hname, holder in holders:
        if holder is None:
            continue
        for fn in ("syslinux_payload", "syslinux", "ensure_deb_upstream", "_fetch_pinned", "ensure_open_watcom",
                   "ensure_upstream", "ensure_git_upstream"):
            if hasattr(holder, fn):
                setattr(holder, fn, make(f"{hname}.{fn}"))


def project_entries(root: Path, commit: str, roots: tuple[str, ...], req: list, rejected: list):
    """(path, mode, blob_sha1, data) for allowlisted tracked files of `commit`."""
    listing = git(root, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0")
    wanted, skipped_links = [], []
    for item in listing:
        if not item:
            continue
        meta, path = item.split(b"\t", 1)
        mode, kind, blob = meta.decode().split()
        rel = path.decode("utf-8")
        if not any(rel == r or rel.startswith(r.rstrip("/") + "/") for r in roots):
            continue
        if kind != "blob" or mode == "120000":
            skipped_links.append({"path": rel, "mode": mode, "reason": "gitlink-or-symlink-not-shipped"})
            continue
        reason = guard_path(rel)
        if reason:
            rejected.append({"path": rel, "reason": reason})
            continue
        wanted.append((rel, mode, blob))
    if len(wanted) > MAX_FILES:
        raise CapsuleError(f"project source has {len(wanted)} files (> {MAX_FILES})")
    proc = subprocess.run(["git", "-C", str(root), "cat-file", "--batch"], input="".join(b + "\n" for _, _, b in wanted).encode(),
                          capture_output=True, check=True)
    out, buf, pos = [], proc.stdout, 0
    for rel, mode, blob in wanted:
        end = buf.index(b"\n", pos)
        _sha, _type, size = buf[pos:end].decode().split()
        data = buf[end + 1:end + 1 + int(size)]
        pos = end + 1 + int(size) + 1
        if hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest() != blob:
            raise CapsuleError(f"blob hash mismatch for {rel}")
        reason = "file-too-large" if len(data) > MAX_FILE else guard_content(data)
        if not reason and PurePosixPath(rel.lower()).suffix in {".sys", ".lib"} and b"\0" in data:
            reason = "binary-or-build-output"
        if reason:
            rejected.append({"path": rel, "reason": reason})
            continue
        out.append((rel, mode, blob, data))
    if skipped_links:
        req.append(f"{len(skipped_links)} gitlink/symlink entries are not shipped in the project tarball "
                   "(submodule trees must be shipped as pinned upstream trees)")
    return out, skipped_links


def project_tar(entries, top: str) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, compresslevel=9, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tar:
            for rel, mode, _blob, data in sorted(entries):
                info = tarfile.TarInfo(f"{top}/{rel}")
                info.size, info.mtime, info.mode = len(data), FIXED_EPOCH, 0o755 if mode == "100755" else 0o644
                tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def read_receipt(root: Path, rel: str, req: list) -> dict | None:
    path = root / BUILDER_RECEIPT_DIR / rel
    if not path.is_file():
        req.append(f"producer receipt {BUILDER_RECEIPT_DIR}/{rel} is absent; build it (or point --receipt-root at "
                   "the producer output) so patches, toolchain and git revision can be bound")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        req.append(f"producer receipt {rel} unreadable: {exc}")
        return None


# --- consumed producer receipts ----------------------------------------------
CONSUMED_ROLES = ("kernels", "guest-result", "guest-readback", "setup-build", "setup-result", "dos")
SETUP_RESULT_DEFAULT = "build/installer-link-boot05/setup/stage-setup-result.json"
SOURCE_MAP_POINTERS = ("sources_sha256", "pins_before/sources", "sources", "source_sha256", "inputs_sha256",
                       "source_before", "before")
HEX64 = re.compile(r"[0-9a-f]{64}")
MAX_RECEIPT = 16 * 1024 * 1024
INSTALLED_GUEST_FAIL = (
    "Historical actual installed UEFI guest FAIL, preserved as evidence and not repaired or reinterpreted: the loader "
    "attests generation 1, AHCI 8086:2922 recognizes 512 MiB and 3 GPT partitions, then boot stops after "
    "'K64 disk: ahci0: 3 partition(s)' (120 s timeout).  Reported by the installed-runtime owner; this tool did not "
    "launch, control or poll any VM and has not re-verified it.  It is OS boot qualification data and is not a "
    "prerequisite or gate of the GPL corresponding-source flags.")
MAX_STALE_LISTED = 1000


class _DupKey(ValueError):
    pass


def _no_dups(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise _DupKey(f"duplicate JSON key {k!r}")
        seen[k] = v
    return seen


def _reject_const(name):
    raise ValueError(f"non-standard JSON constant {name}")


def strict_json(raw: bytes):
    """json.loads that refuses duplicate keys and NaN/Infinity; deep nesting is a ValueError too."""
    try:
        return json.loads(raw, object_pairs_hook=_no_dups, parse_constant=_reject_const)
    except RecursionError as exc:
        raise ValueError("JSON nesting too deep") from exc


def _dig(obj, pointer: str):
    for part in pointer.split("/"):
        if not isinstance(obj, dict) or part not in obj:
            return None
        obj = obj[part]
    return obj


def _present(obj, pointer: str) -> bool:
    for part in pointer.split("/"):
        if not isinstance(obj, dict) or part not in obj:
            return False
        obj = obj[part]
    return True


def _source_map(doc) -> tuple[str | None, dict, str | None]:
    """(pointer, map, problem).  The FIRST pointer that is present decides: it must be a non-empty
    {relative path: 64-lowercase-hex} map, otherwise problem is set (a later pointer never rescues a malformed
    earlier one, and a non-dict document never yields a map)."""
    if not isinstance(doc, dict):
        return None, {}, "receipt document is not a JSON object"
    for pointer in SOURCE_MAP_POINTERS:
        if not _present(doc, pointer):
            continue
        found = _dig(doc, pointer)
        if not isinstance(found, dict) or not found:
            return pointer, {}, f"{pointer} is not a non-empty object"
        if not all(isinstance(k, str) and k and isinstance(v, str) and HEX64.fullmatch(v) for k, v in found.items()):
            return pointer, {}, f"{pointer} is not a map of path -> 64 lowercase hex SHA-256"
        return pointer, found, None
    return None, {}, None


def _named_source_ok(rel: str) -> str | None:
    """Reason a receipt-named path may not be read as capsule source, or None.  Only normalised, relative,
    allowlisted project-source paths that pass the strict guards are ever opened."""
    pp = PurePosixPath(rel)
    if pp.as_posix() != rel or rel.endswith("/") or rel.startswith("build/") or "//" in rel:
        return "not-normalised"
    if guard_path(rel, strict=True):
        return "guarded"
    if not any(rel == r or rel.startswith(r.rstrip("/") + "/") for r in DEFAULT_PROJECT_ROOTS):
        return "outside-project-roots"
    return None


def read_named_source(root: Path, rel: str) -> tuple[bytes | None, str | None]:
    """Read ONE named source file exactly once without following symlinks; stat before and after the read must agree.
    Returns (bytes, None) or (None, reason in missing/symlink/not-regular/too-large/changed-during-read)."""
    cur = root
    for part in PurePosixPath(rel).parts:
        cur = cur / part
        if cur.is_symlink():
            return None, "symlink"
    try:
        fd = os.open(cur, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except (FileNotFoundError, NotADirectoryError):
        return None, "missing"
    except OSError:
        return None, "symlink"
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            return None, "not-regular"
        if before.st_size > MAX_FILE:
            return None, "too-large"
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read(MAX_FILE + 1)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    key = lambda st: (st.st_size, st.st_mtime_ns, st.st_ino, st.st_dev)  # noqa: E731
    if key(before) != key(after) or len(data) != before.st_size:
        return None, "changed-during-read"
    return data, None


def _read_receipt_file(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise OSError("not a regular file")
        data = fh.read(MAX_RECEIPT + 1)
    if len(data) > MAX_RECEIPT:
        raise OSError(f"larger than {MAX_RECEIPT} bytes")
    return data


def _snapshot_digest(pairs) -> str:
    return sha256("".join(f"{rel} {digest}\n" for rel, digest in sorted(pairs)).encode())


def consume_receipts(root: Path, inputs: dict[str, Path], capsule_files: dict[str, bytes] | None = None,
                     commit: str | None = None) -> dict:
    """Build the consumed receipt for explicitly named producer receipts.

    inputs maps a role in CONSUMED_ROLES to a receipt path.  Each receipt is read once (its hash and parse use the
    same bytes).  Each source path it records is opened at most once, only if it is a normalised allowlisted project
    source path; the single read supplies the current hash and the bytes compared with the capsule.  An entry is
    "bound" only when recorded == read == shipped capsule bytes; stale entries are listed, never bound.  Compiled
    outputs are never read or bound: this records source hashes only.  all_roles_consumed_and_current needs every role
    named, a JSON-object receipt with a valid non-empty source map, no stale/missing/refused entry, and the
    shipped-capsule comparison (capsule_files) to have been made."""
    root = Path(root).resolve()
    unknown = sorted(set(inputs) - set(CONSUMED_ROLES))
    if unknown:
        raise CapsuleError(f"unknown consumed receipt role(s) {unknown}; allowed {list(CONSUMED_ROLES)}")
    out, req = {}, []
    role_ok = {}
    for role in CONSUMED_ROLES:
        role_ok[role] = False
        if role not in inputs:
            req.append(f"consumed receipt role {role} was not named; pass the frozen producer receipt explicitly")
            continue
        path = Path(inputs[role])
        rec = {"path": str(path), "status": "consumed"}
        out[role] = rec
        try:
            raw = _read_receipt_file(path)
        except OSError as exc:
            rec.update(status="unreadable", error=str(exc))
            req.append(f"{role}: receipt {path} unreadable ({exc}); run with read access to exactly this file")
            continue
        rec.update(sha256=sha256(raw), bytes=len(raw))
        if guard_content(raw) is not None:
            rec.update(status="refused", error="content guard")
            req.append(f"{role}: receipt content matched a secret guard and is not consumed")
            continue
        try:
            doc = strict_json(raw)
        except ValueError as exc:
            rec.update(status="not-json", error=str(exc))
            req.append(f"{role}: receipt {path} is not strict JSON ({exc})")
            continue
        if not isinstance(doc, dict) or not doc:
            rec.update(status="not-a-receipt", error="top-level JSON is not a non-empty object")
            req.append(f"{role}: receipt {path} top level is not a non-empty JSON object")
            continue
        if "$schema" in doc or "$id" in doc or (isinstance(doc.get("properties"), dict) and "type" in doc):
            rec.update(status="not-a-receipt", error="document looks like a JSON Schema")
            req.append(f"{role}: {path} is a JSON Schema style document, not a producer receipt")
            continue
        g = doc.get("git")
        if isinstance(g, dict):
            rec["git"] = {"revision": g.get("revision"), "dirty": g.get("dirty")}
            if commit and g.get("revision") not in (None, commit):
                req.append(f"{role}: receipt git revision {g.get('revision')} differs from capsule commit {commit}")
        pointer, smap, problem = _source_map(doc)
        rec["source_map_pointer"] = pointer
        if not smap:
            rec["sources"] = None
            rec["status"] = "no-source-map"
            req.append(f"{role}: receipt has no usable recorded source SHA-256 map "
                       f"({problem or 'looked at ' + str(list(SOURCE_MAP_POINTERS))}); its inputs cannot be bound to "
                       "source bytes")
            continue
        current, stale, missing, unsafe, bound, readpairs = 0, [], [], [], 0, []
        for rel, want in sorted(smap.items()):
            why = _named_source_ok(rel)
            if why:
                unsafe.append(f"{rel} ({why})")
                continue
            data, why = read_named_source(root, rel)
            if why == "missing":
                missing.append(rel)
                continue
            if why:
                unsafe.append(f"{rel} ({why})")
                continue
            have = sha256(data)
            readpairs.append((rel, have))
            if have != want:
                stale.append({"path": rel, "recorded_sha256": want, "current_sha256": have})
                continue
            current += 1
            if capsule_files is not None and rel in capsule_files and capsule_files[rel] == data:
                bound += 1
        rec["sources"] = {"recorded": len(smap), "current": current, "stale": len(stale), "missing": len(missing),
                          "unsafe": len(unsafe), "bound_to_capsule_bytes": bound if capsule_files is not None else None,
                          "recorded_snapshot_sha256": _snapshot_digest(smap.items()),
                          "read_snapshot_sha256": _snapshot_digest(readpairs),
                          "stale_entries": stale[:MAX_STALE_LISTED], "missing_entries": missing[:MAX_STALE_LISTED],
                          "unsafe_entries": unsafe[:MAX_STALE_LISTED]}
        if stale:
            req.append(f"{role}: {len(stale)} recorded source hash(es) are stale (e.g. {stale[0]['path']}); the "
                       "binary was built from bytes that are not the current files; rebuild that producer, do not bind")
        if missing or unsafe:
            req.append(f"{role}: {len(missing)} missing and {len(unsafe)} refused source path(s) recorded")
        if capsule_files is None:
            req.append(f"{role}: shipped capsule bytes were not compared (consumed-only mode)")
        elif bound != current:
            req.append(f"{role}: {current - bound} current source file(s) are not in the capsule tarball bytes "
                       "(uncommitted or guard-refused); commit/publish them")
        role_ok[role] = (not stale and not missing and not unsafe and current == len(smap)
                         and capsule_files is not None and bound == current)
    bound_all = (set(out) == set(CONSUMED_ROLES) and all(role_ok.values())
                 and all(r["status"] == "consumed" for r in out.values()))
    return {
        "schema": "shizuku-consumed-source-receipt/1",
        "release_claim": False,
        "acceptance_claim": False,
        "os_boot_qualification_claim": False,
        "compiled_binary_binding_claim": False,
        "compiled_binary_binding_note": "Only source-file SHA-256 values recorded by producers are compared with source "
                                        "bytes.  No compiled output is read, hashed or bound here.",
        "installed_guest_result": "FAIL (historical, preserved)",
        "historical_installed_guest": {"result": "FAIL", "scope": "historical evidence, not re-verified by this tool",
                                       "note": INSTALLED_GUEST_FAIL, "gates_source_license_flags": False},
        "installed_guest_note": INSTALLED_GUEST_FAIL,
        "note": "Records which producer receipts were consumed and the truthful source delta.  Stale entries are "
                "reported as stale and are not bound as current.  Not a release, acceptance, boot-qualification or "
                "GPL-closure claim.",
        "receipts": out,
        "all_roles_consumed_and_current": bound_all,
        "requirements": sorted(set(req)),
    }


# --- Syslinux (Debian binary packages): explicit read-only cache --------------
SYSLINUX_MODULES = ("ldlinux.c32", "libcom32.c32", "libutil.c32", "menu.c32", "mboot.c32")
MAX_CACHE_FILE = 96 * 1024 * 1024


def _cache_read(base: Path, rel: str, limit: int = MAX_CACHE_FILE) -> tuple[bytes | None, str | None]:
    """One non-following read of base/rel (no mutation).  Returns (bytes, None) or (None, reason)."""
    cur = base
    for part in PurePosixPath(rel).parts:
        cur = cur / part
        if cur.is_symlink():
            return None, "symlink in path"
    try:
        fd = os.open(cur, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        return None, "missing" if isinstance(exc, (FileNotFoundError, NotADirectoryError)) else f"unreadable ({exc.strerror})"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, "not a regular file"
        if st.st_size > limit:
            return None, "too large"
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read(limit + 1)
    finally:
        os.close(fd)
    if len(data) != st.st_size:
        return None, "changed during read"
    return data, None


def _deb_member(deb: bytes, wanted: str) -> bytes | None:
    """Bytes of a regular file inside a Debian package (pure read; zstd via the local decompressor if needed)."""
    if deb[:8] != b"!<arch>\n":
        return None
    pos, data_name, data = 8, None, None
    while pos + 60 <= len(deb):
        hdr = deb[pos:pos + 60]
        name = hdr[:16].decode("ascii", "replace").strip().removesuffix("/")
        try:
            size = int(hdr[48:58].decode("ascii").strip())
        except ValueError:
            return None
        body = deb[pos + 60:pos + 60 + size]
        if len(body) != size:
            return None
        if name == "data.tar" or name.startswith("data.tar."):
            data_name, data = name, body
        pos += 60 + size + (size & 1)
    if data is None:
        return None
    if data_name.endswith(".zst"):
        r = subprocess.run(["zstd", "-d", "-q", "-c"], input=data, capture_output=True, timeout=30)
        if r.returncode:
            return None
        data = r.stdout
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
            for member in tar.getmembers():
                if PurePosixPath(member.name.removeprefix("./")).as_posix() == wanted:
                    seen = 0
                    while member.issym() and seen < 4:
                        base = PurePosixPath(wanted).parent
                        wanted = os.path.normpath(str(base / member.linkname)).lstrip("/")
                        member = next((m for m in tar.getmembers()
                                       if PurePosixPath(m.name.removeprefix("./")).as_posix() == wanted), None)
                        if member is None:
                            return None
                        seen += 1
                    if not member.isreg() or member.size > MAX_FILE:
                        return None
                    return tar.extractfile(member).read()
    except (tarfile.TarError, EOFError, OSError):
        return None
    return None


def syslinux_payload_from_cache(prefix: str, spec: dict, cache) -> tuple[dict[str, bytes] | None, list[str]]:
    """Read-only replacement for builder.se_media.syslinux_payload.  `cache` is a directory holding root/ and
    downloads/, or a (root, downloads) pair; it must already exist.  Nothing is created, fetched, unpacked or
    repaired.  Returns (payload or None, exact problems).  payload is None if ANY check fails."""
    problems: list[str] = []
    if cache is None:
        return None, ["syslinux: no --syslinux-cache given; the Debian source package and legal files cannot be "
                      "verified (this tool never downloads or unpacks; supply an existing validated cache holding "
                      "root/ and downloads/)"]
    if isinstance(cache, (tuple, list)) and len(cache) == 2:
        root, downloads = Path(cache[0]), Path(cache[1])
    else:
        root, downloads = Path(cache) / "root", Path(cache) / "downloads"
    for label, d in (("root", root), ("downloads", downloads)):
        if d.is_symlink() or not d.is_dir():
            problems.append(f"syslinux cache {label} directory {d} is absent, a symlink or not a directory")
    if problems:
        return None, problems
    # Pinned binaries.
    files: dict[str, bytes] = {}
    for rel, digest in sorted(spec.get("files", {}).items()):
        data, why = _cache_read(root, rel)
        if why:
            problems.append(f"syslinux cache: {rel} {why}")
        elif sha256(data) != digest:
            problems.append(f"syslinux cache: {rel} sha256 {sha256(data)} != pinned {digest}")
        else:
            files[rel] = data
    # Pinned packages (needed to verify the legal files) and Debian source files.
    debs: dict[str, bytes] = {}
    for group in ("packages", "source"):
        for pname, item in sorted(spec.get(group, {}).items()):
            data, why = _cache_read(downloads, item["file"])
            if why:
                problems.append(f"syslinux cache: downloads/{item['file']} {why}")
            elif sha256(data) != item["sha256"]:
                problems.append(f"syslinux cache: downloads/{item['file']} sha256 {sha256(data)} != pinned {item['sha256']}")
            elif group == "packages":
                debs[pname] = data
            else:
                files["source:" + item["file"]] = data
    # Legal files: present in root, and byte-identical to the file inside the pinned package.
    payload: dict[str, bytes] = {}
    for relative in spec.get("license_files", []):
        package = relative.split("/")[3] if relative.count("/") >= 4 else ""
        data, why = _cache_read(root, relative, MAX_FILE)
        if why or not data:
            problems.append(f"syslinux legal file {relative}: {why or 'empty'}")
            continue
        if guard_content(data):
            problems.append(f"syslinux legal file {relative}: refused by content guard")
            continue
        if package not in debs:
            problems.append(f"syslinux legal file {relative}: pinned package {package or '?'} not verified in downloads")
            continue
        packed = _deb_member(debs[package], relative)
        if packed is None or packed != data:
            problems.append(f"syslinux legal file {relative} differs from, or is not found in, the pinned {package} package")
            continue
        payload[f"{prefix}/LICENSES/syslinux-{package}-copyright.txt"] = data
    if problems:
        return None, problems
    for item in spec["source"].values():
        payload[f"{prefix}/SOURCE/syslinux/{item['file']}"] = files["source:" + item["file"]]
    located = {"isolinux.bin": "usr/lib/ISOLINUX/isolinux.bin", "isohdpfx.bin": "usr/lib/ISOLINUX/isohdpfx.bin",
               "memdisk": "usr/lib/syslinux/memdisk", "mbr.bin": "usr/lib/syslinux/mbr/mbr.bin",
               **{m: f"usr/lib/syslinux/modules/bios/{m}" for m in SYSLINUX_MODULES}}
    used = {}
    for name, rel in located.items():
        if rel not in files:
            return None, [f"syslinux cache: manifest files list lacks {rel}"]
        used[name] = sha256(files[rel])
    payload[f"{prefix}/SOURCE/syslinux/README.TXT"] = (
        "Syslinux 6.04 (third-party boot loaders) - licence and source\r\n"
        "==============================================================\r\n"
        f"Binaries  Ubuntu 24.04 packages {spec['distribution'].split()[-1]}\r\n"
        "          (isolinux, syslinux-common; the syslinux FAT installer is only a\r\n"
        "          build tool for the raw disk image), unmodified.\r\n"
        f"Upstream  {spec['repository']} snapshot {spec['commit']}\r\n"
        f"Licence   {spec['license']}; see LICENSES\\syslinux-*-copyright.txt for the\r\n"
        "          per-file terms (most com32 modules are MIT/Expat).\r\n"
        "Source    the Debian source package in this directory (.dsc, .orig.tar.xz,\r\n"
        "          .debian.tar.xz) is the corresponding source of every binary used:\r\n"
        + "".join(f"            {name:14} sha256 {digest}\r\n" for name, digest in used.items())
    ).encode("ascii")
    return payload, []


def build_capsule(root: Path = ROOT, *, prefix: str = DEFAULT_PREFIX, commit: str | None = None,
                  project_roots: tuple[str, ...] = DEFAULT_PROJECT_ROOTS, wineport: bool = False,
                  receipt_root: Path | None = None, max_total: int = MAX_TOTAL,
                  consumed: dict[str, Path] | None = None, syslinux_cache=None) -> tuple[dict[str, bytes], dict]:
    """Return (members, manifest).  members maps ISO-relative paths to bytes; the manifest lists every member with
    SHA-256 and provenance.  Never raises for missing optional provenance; it records the requirement instead.
    syslinux_cache: existing directory (root/ + downloads/) or (root, downloads); read-only, never created or repaired.
    Raises CapsuleError for guard violations in upstream trees, size overflow and unpinned/modified trees."""
    root = Path(root).resolve()
    receipt_root = Path(receipt_root).resolve() if receipt_root else root
    req: list[str] = []
    rejected: list[dict] = []
    members: dict[str, bytes] = {}
    index: dict[str, dict] = {}

    def add(path: str, data: bytes, role: str, **prov):
        if path in members:
            raise CapsuleError(f"duplicate capsule member {path}")
        if guard_path(path.split("/", 1)[1] if "/" in path else path, strict=False):
            raise CapsuleError(f"guard rejects capsule member {path}")
        members[path] = data
        index[path] = {"sha256": sha256(data), "bytes": len(data), "role": role, **prov}
        if sum(len(v) for v in members.values()) > max_total:
            raise CapsuleError(f"capsule exceeds {max_total} bytes")

    builder = load_builder(root)
    manifest_path = root / "shizukudos" / "upstream" / "manifest.json"
    upstream_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    head = git(root, "rev-parse", "HEAD").decode().strip()
    commit = commit or head
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise CapsuleError("--commit must be a full 40-hex commit id")
    git(root, "cat-file", "-e", commit + "^{commit}")
    dirty = bool(git(root, "status", "--porcelain", "--untracked-files=no").strip())

    # Project source (GPL-2.0-only) from the pinned commit's blobs.
    entries, _links = project_entries(root, commit, tuple(project_roots), req, rejected)
    if not any(e[0] == "LICENSE" for e in entries):
        raise CapsuleError("project LICENSE is not part of the allowlisted source")
    license_blob = next(e[3] for e in entries if e[0] == "LICENSE")
    top = "win98-modern-shizukudos10-source"
    add(f"{prefix}/SOURCE/shizukudos-source.tar.gz", project_tar(entries, top), "project-source",
        license="GPL-2.0-only", git_commit=commit, files=len(entries),
        file_list_sha256=sha256("".join(f"{e[0]} {e[2]}\n" for e in sorted(entries)).encode()),
        selection="allowlisted roots from git blobs of the pinned commit", roots=list(project_roots))
    add(f"{prefix}/LICENSES/Shizuku-LICENSE-GPL-2.0.txt", license_blob, "license", license="GPL-2.0-only",
        git_commit=commit)
    if rejected:
        req.append(f"{len(rejected)} tracked project paths were refused by the path/name/content guards "
                   "(listed under rejected); the tarball is therefore not the complete tracked tree")
    if commit != head:
        req.append(f"capsule commit {commit} is not HEAD {head}; the receipts were produced for a different tree "
                   "unless they record this commit")
    if dirty:
        req.append("working tree has uncommitted tracked changes; binaries built from it are not reproduced by the "
                   "pinned commit; commit/publish the exact source and rebuild")

    # Upstream trees, patches, licences.
    names = tuple(builder.MEDIA_UPSTREAMS) + (tuple(builder.WINEPORT_UPSTREAMS) if wineport else ())
    ups: dict[str, dict] = {}
    for name in names:
        spec = upstream_manifest["upstreams"].get(name)
        if spec is None:
            req.append(f"upstream/manifest.json lacks {name}")
            continue
        rec = {"repository": spec.get("repository"), "ref": spec.get("ref"), "commit": spec.get("commit"),
               "license": spec.get("license"), "source_present": False}
        rec["submodules"] = {k: {"commit": v["commit"], "repository": v.get("repository"),
                                 "license": v.get("license")} for k, v in spec.get("submodules", {}).items()}
        ups[name] = rec
        try:
            if spec.get("kind") == "debian-binary-packages":
                if name != "syslinux":
                    raise CapsuleError(f"no source staging for debian-binary-packages upstream {name}")
                sl_payload, sl_problems = syslinux_payload_from_cache(prefix, spec, syslinux_cache)
                rec["cache_validated"] = sl_payload is not None
                if sl_payload is None:
                    req.extend(sl_problems)
                    req.append("upstream syslinux: source/legal files not verified from an existing cache; "
                               "source closure for syslinux stays false")
                    continue
                for path, data in sl_payload.items():
                    add(path, data, "upstream-source" if "/SOURCE/" in path else "license", upstream=name,
                        license=spec.get("license"))
                rec["source_present"] = True
                rec["source_kind"] = "Debian source package (.dsc, .orig.tar.xz, .debian.tar.xz) read from a hash-verified cache"
                continue
            stem = f"{name}-{spec['commit'][:12]}"
            if name in builder.WINEPORT_UPSTREAMS:
                licences, tarball = builder.pristine_upstream(name, spec)
                lic_items = [(p, d) for p, d in licences.items()]
                data_tar = tarball
            else:
                tree = builder.pinned_upstream_tree(name, spec)
                tracked = builder.tracked_entries(tree, stem)
                bad = [(a, guard_path(a.split("/", 1)[1], strict=False)) for a, _ in tracked]
                bad = [(a, r) for a, r in bad if r]
                if bad:
                    raise CapsuleError(f"upstream {name} contains guarded paths: {bad[:5]}")
                lic_items = [(p.relative_to(tree).as_posix(), p.read_bytes()) for p in builder.license_files(tree, spec)]
                data_tar = builder.deterministic_tar_gz(tracked)
            for path, data in lic_items:
                add(f"{prefix}/LICENSES/{name}-{path.replace('/', '-')}.txt", data, "license", upstream=name,
                    license=spec.get("license"), source_path=path)
            if data_tar is None:
                rec["source_kind"] = "licence texts only (unmodified OFL fonts)"
                rec["source_present"] = True
            else:
                add(f"{prefix}/SOURCE/{stem}.tar.gz", data_tar, "upstream-source", upstream=name,
                    commit=spec["commit"], repository=spec.get("repository"), license=spec.get("license"))
                rec["source_present"] = True
                rec["source_kind"] = ("pinned-commit git objects (checked-out files + font sources)"
                                      if name in builder.WINEPORT_UPSTREAMS else "pinned clean tree, tracked files")
        except (RuntimeError, OSError, subprocess.CalledProcessError, KeyError) as exc:
            if isinstance(exc, CapsuleError) and "guarded" in str(exc):
                raise
            req.append(f"upstream {name}: source tree at commit {spec.get('commit')} not usable ({exc}); fetch "
                       f"{spec.get('repository')} at exactly that commit (submodules at manifest pins), unmodified, "
                       "under build/upstream/" + name)
    add(f"{prefix}/SOURCE/upstream-manifest.json", manifest_path.read_bytes(), "provenance")

    # Patches exactly as the producer receipts list them.
    receipts: dict[str, dict] = {}
    patch_rec: dict[str, list] = {"freedos": [], "csmwrap": []}
    for rel in RECEIPTS:
        path = receipt_root / BUILDER_RECEIPT_DIR / rel
        rcpt = read_receipt(receipt_root, rel, req) if rel in ("dos16/build-result.json", "csm/build-result.json") \
            else (json.loads(path.read_text()) if path.is_file() else None)
        if rcpt is None:
            continue
        receipts[rel] = {"file_sha256": sha256(path.read_bytes()), "git": rcpt.get("git")}
        g = rcpt.get("git") or {}
        if g.get("revision") != commit:
            req.append(f"receipt {rel} records git revision {g.get('revision') or 'none'}, capsule commit is {commit}")
        if g.get("dirty"):
            req.append(f"receipt {rel} was produced from a dirty tree; its inputs are not named by a commit")
    for rel, key, sub in (("dos16/build-result.json", "freedos", "dos16/patches"),
                          ("csm/build-result.json", "csmwrap", "csm/patches")):
        rcpt = json.loads((receipt_root / BUILDER_RECEIPT_DIR / rel).read_text()) if rel in receipts else None
        if rcpt is None:
            continue
        for applied in rcpt.get("patches", []):
            p = PurePosixPath(applied["patch"])
            if not str(p).startswith(f"shizukudos/{sub}/") or ".." in p.parts:
                raise CapsuleError(f"receipt patch path outside shizukudos/{sub}: {p}")
            blob = git(root, "show", f"{commit}:{p}", check=False)
            if not blob or sha256(blob) != applied["sha256"]:
                req.append(f"patch {p} at {commit} does not match receipt sha256 {applied['sha256']}")
                continue
            folder = "patches" if key == "freedos" else "csm-patches"
            add(f"{prefix}/SOURCE/{folder}/{p.name}", blob, "patch", upstream=key, receipt=rel,
                receipt_sha256=applied["sha256"])
            patch_rec[key].append({"name": p.name, "sha256": applied["sha256"]})
        if not patch_rec[key]:
            req.append(f"receipt {rel} lists no verified {key} patches")
    dos = json.loads((receipt_root / BUILDER_RECEIPT_DIR / "dos16/build-result.json").read_text()) \
        if "dos16/build-result.json" in receipts else {}
    snap = ((dos.get("toolchain") or {}).get("open-watcom") or {}).get("snapshot_sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", snap or ""):
        req.append("DOS receipt lacks a valid actual Open Watcom snapshot SHA-256")
    # Build/runtime upstream pins in the DOS receipt must equal the capsule's manifest pins (stems stay exact).
    for name, rec in ups.items():
        got = (dos.get("upstream") or {}).get(name)
        if dos and (not got or got.get("commit") != rec["commit"]):
            req.append(f"DOS receipt upstream pin for {name} differs from manifest commit {rec['commit']}")
    consumed_doc = None
    if consumed:
        consumed_doc = consume_receipts(root, consumed, {e[0]: e[3] for e in entries}, commit)
        add(f"{prefix}/SOURCE/CONSUMED-RECEIPT.json", json.dumps(consumed_doc, indent=2, sort_keys=True).encode() + b"\n",
            "consumed-receipt", release_claim=False)
        req.extend(f"consumed receipt: {r}" for r in consumed_doc["requirements"])
    else:
        req.append("no consumed-source receipt was named (--consume ROLE=PATH); binaries are not bound to these "
                   "source bytes (tracked paths and a Git URL alone do not close source)")
    req.append("build toolchain (Open Watcom, NASM, gcc, mtools) is not redistributed; its pinned version/source "
               "offer is recorded only by hash/name in receipts")

    for rel in sorted(receipts):
        text = json.loads((receipt_root / BUILDER_RECEIPT_DIR / rel).read_text())
        add(f"{prefix}/SOURCE/receipts/{rel.replace('/', '-')}",
            json.dumps(_strip(text), indent=2, sort_keys=True).encode() + b"\n", "receipt-copy",
            source_file_sha256=receipts[rel]["file_sha256"])

    missing = sorted(n for n, r in ups.items() if not r["source_present"])
    manifest = {
        "schema": SCHEMA,
        "project": {"commit": commit, "head": head, "working_tree_dirty_tracked": dirty, "license": "GPL-2.0-only",
                    "roots": list(project_roots), "rejected": rejected},
        "upstreams": ups,
        "patches": patch_rec,
        "receipts": receipts,
        "consumed_receipt": None if consumed_doc is None else {
            "member": f"{prefix}/SOURCE/CONSUMED-RECEIPT.json", "release_claim": False,
            "all_roles_consumed_and_current": consumed_doc["all_roles_consumed_and_current"]},
        "release_claim": False,
        "os_boot_qualification": {
            "claim": False,
            "historical_installed_guest_result": "FAIL" if consumed_doc else None,
            "note": "Separate from source/license data: the historical installed-guest FAIL is kept as evidence in "
                    "the consumed receipt and is neither cleared nor used as a source-closure requirement here."},
        "toolchain_open_watcom_snapshot_sha256": snap if re.fullmatch(r"[0-9a-f]{64}", snap or "") else None,
        "flags": {
            "project_source_pinned_to_commit": True,
            "project_source_complete_tracked_tree": not rejected,
            "upstream_sources_all_present": not missing and bool(ups),
            "patches_verified_against_receipts": all(patch_rec.values()),
            "receipts_bind_commit": bool(receipts) and not any("records git revision" in r or "dirty tree" in r
                                                                for r in req),
            "consumed_source_receipt_bound": bool(consumed_doc and consumed_doc["all_roles_consumed_and_current"]),
            "toolchain_source_offered": False,
        },
        "requirements": sorted(set(req)),
        "compliance_claim": False,
        "note": "Informational capsule; not a statement of GPL/LGPL source closure while requirements remain. "
                "Not an OS boot qualification.",
        "members": dict(sorted(index.items())),
    }
    # GPL corresponding-source flag: derived only from source/provenance requirements, never from boot results.
    manifest["compliance_claim"] = not manifest["requirements"] and all(manifest["flags"].values())
    body = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
    if guard_content(body) is not None:
        raise CapsuleError("manifest itself matched a content guard")
    members[f"{prefix}/SOURCE/CAPSULE-MANIFEST.json"] = body
    return dict(sorted(members.items())), manifest


def _strip(receipt: dict) -> dict:
    """Receipt copy without build time (reproducible), as the builder's shipped_receipt does."""
    receipt = dict(receipt)
    if receipt.pop("built_utc", None) is not None:
        receipt["built_utc_note"] = "removed for reproducibility"
    return receipt


def write_capsule(members: dict[str, bytes], out: Path) -> None:
    out = Path(out)
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise CapsuleError(f"{out} exists and is not an empty directory; refusing to overwrite")
    out.mkdir(parents=True, exist_ok=True)
    for rel, data in members.items():
        path = out / rel
        if not path.resolve().is_relative_to(out.resolve()):
            raise CapsuleError(f"member escapes output: {rel}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def _self_test() -> int:
    """Offline fixtures in temporary directories only.  Network and the builder's ensure/download helpers are
    poisoned; every case asserts they were never called and the cache/tree was not mutated."""
    import contextlib
    import socket
    import tempfile
    import unittest
    import urllib.request

    def tar_bytes(files):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            for name, data in files.items():
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
        return buf.getvalue()

    def deb(files):
        out = b"!<arch>\n"
        for name, body in (("debian-binary", b"2.0\n"), ("control.tar", tar_bytes({})), ("data.tar", tar_bytes(files))):
            out += f"{name + '/':<16}0           0     0     100644  {len(body):<10}`\n".encode() + body
            out += b"\n" if len(body) & 1 else b""
        return out

    def tree_state(base):
        state = {}
        for dp, dn, fn in os.walk(base):
            dn[:] = sorted(d for d in dn if d != ".git")
            for n in sorted(fn):
                f = Path(dp) / n
                st = f.lstat()
                state[str(f.relative_to(base))] = (st.st_size, st.st_mtime_ns, sha256(f.read_bytes()) if f.is_file() else "")
            for d in dn:
                state[str((Path(dp) / d).relative_to(base)) + "/"] = ()
        return state

    BIN = {"usr/lib/ISOLINUX/isolinux.bin": b"iso", "usr/lib/ISOLINUX/isohdpfx.bin": b"hdp",
           "usr/lib/syslinux/modules/bios/ldlinux.c32": b"ld", "usr/lib/syslinux/modules/bios/libcom32.c32": b"lc",
           "usr/lib/syslinux/modules/bios/libutil.c32": b"lu", "usr/lib/syslinux/modules/bios/menu.c32": b"me",
           "usr/lib/syslinux/modules/bios/mboot.c32": b"mb", "usr/lib/syslinux/memdisk": b"md",
           "usr/lib/syslinux/mbr/mbr.bin": b"mbr", "usr/bin/syslinux": b"tool"}
    LEGAL = {"usr/share/doc/syslinux-common/copyright": b"GPL common\n", "usr/share/doc/isolinux/copyright": b"GPL iso\n",
             "usr/share/doc/syslinux/copyright": b"GPL sys\n"}
    SRC = {"dsc": b"dsc-bytes", "orig": b"orig-bytes", "debian": b"debian-bytes"}

    def make_spec_and_cache(base):
        debs = {"isolinux": deb({"./usr/share/doc/isolinux/copyright": LEGAL["usr/share/doc/isolinux/copyright"]}),
                "syslinux-common": deb({"./usr/share/doc/syslinux-common/copyright": LEGAL["usr/share/doc/syslinux-common/copyright"]}),
                "syslinux": deb({"./usr/share/doc/syslinux/copyright": LEGAL["usr/share/doc/syslinux/copyright"]})}
        spec = {"kind": "debian-binary-packages", "repository": "https://example.invalid/syslinux", "ref": "x",
                "commit": "bf6db5b4", "distribution": "Ubuntu 24.04 (noble) package version 6.04-test",
                "license": "GPL-2.0-or-later", "license_files": list(LEGAL),
                "packages": {k: {"url": "https://example.invalid/" + k, "file": k + ".deb", "sha256": sha256(v)} for k, v in debs.items()},
                "source": {k: {"url": "https://example.invalid/" + k, "file": "s." + k, "sha256": sha256(v)} for k, v in SRC.items()},
                "files": {k: sha256(v) for k, v in BIN.items()}}
        cache = base / "cache"
        for rel, data in {**BIN, **LEGAL}.items():
            (cache / "root" / rel).parent.mkdir(parents=True, exist_ok=True)
            (cache / "root" / rel).write_bytes(data)
        (cache / "downloads").mkdir(parents=True, exist_ok=True)
        for k, v in debs.items():
            (cache / "downloads" / (k + ".deb")).write_bytes(v)
        for k, v in SRC.items():
            (cache / "downloads" / ("s." + k)).write_bytes(v)
        return spec, cache

    FAKE_BUILDER = (
        "from pathlib import Path\nimport types\nROOT = Path(__file__).resolve().parents[1]\n"
        "MEDIA_UPSTREAMS = ('syslinux',)\nWINEPORT_UPSTREAMS = ()\n"
        "def _t(*a, **k):\n    raise RuntimeError('tripwire')\n"
        "shzlib = types.SimpleNamespace(ensure_deb_upstream=_t, _fetch_pinned=_t)\n"
        "se_media = types.SimpleNamespace(syslinux_payload=_t, syslinux=_t, shzlib=shzlib)\n")

    def make_repo(base, spec):
        repo = base / "repo"
        (repo / "tools").mkdir(parents=True)
        (repo / "shizukudos/upstream").mkdir(parents=True)
        (repo / "tools/build_shizuku_se_iso.py").write_text(FAKE_BUILDER)
        (repo / "shizukudos/upstream/manifest.json").write_text(json.dumps({"upstreams": {"syslinux": spec}}))
        (repo / "LICENSE").write_text("GPL-2.0-only fixture\n")
        g = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-C", str(repo)]
        subprocess.run([*g[:5], "-C", str(repo), "init", "-q"], check=True)
        subprocess.run([*g, "add", "-A"], check=True)
        subprocess.run([*g, "commit", "-q", "-m", "fixture"], check=True)
        return repo

    class Fixtures(unittest.TestCase):
        def setUp(self):
            del FORBIDDEN_CALLS[:]
            self.tmp = tempfile.TemporaryDirectory()
            self.base = Path(self.tmp.name)
            self.spec, self.cache = make_spec_and_cache(self.base)
            self.repo = make_repo(self.base, self.spec)
            def net(*_a, **_k):
                raise AssertionError("network used")
            self._saved = (urllib.request.urlretrieve, urllib.request.urlopen, socket.create_connection)
            urllib.request.urlretrieve = urllib.request.urlopen = socket.create_connection = net

        def tearDown(self):
            urllib.request.urlretrieve, urllib.request.urlopen, socket.create_connection = self._saved
            self.assertEqual(FORBIDDEN_CALLS, [])
            self.tmp.cleanup()

        def check(self, cache):
            before_c, before_r = tree_state(self.cache) if self.cache.exists() else None, tree_state(self.repo)
            members, manifest = build_capsule(self.repo, syslinux_cache=cache)
            self.assertEqual(tree_state(self.repo), before_r)
            if before_c is not None:
                self.assertEqual(tree_state(self.cache), before_c)
            return members, manifest

        def test_valid_cache_read_only(self):
            members, m = self.check(self.cache)
            self.assertTrue(m["upstreams"]["syslinux"]["source_present"])
            self.assertTrue(m["flags"]["upstream_sources_all_present"])
            self.assertIn("ShizukuDOS10/SOURCE/syslinux/s.orig", members)
            self.assertFalse(m["compliance_claim"])
            self.assertFalse(m["os_boot_qualification"]["claim"])
            self.assertFalse(any("installed UEFI guest FAIL" in r for r in m["requirements"]))
            m2 = self.check((self.cache / "root", self.cache / "downloads"))[1]
            self.assertTrue(m2["flags"]["upstream_sources_all_present"])

        def test_absent_cache_exact_false_no_mutation(self):
            for cache in (None, self.base / "no-such-cache"):
                _, m = self.check(cache)
                self.assertFalse(m["upstreams"]["syslinux"]["source_present"])
                self.assertFalse(m["flags"]["upstream_sources_all_present"])
                self.assertTrue(any("syslinux" in r for r in m["requirements"]))
            self.assertFalse((self.base / "no-such-cache").exists())
            self.assertFalse((self.repo / "build").exists())

        def corrupt(self, rel, data=b"X"):
            f = self.cache / rel
            f.write_bytes(data)
            _, m = self.check(self.cache)
            self.assertFalse(m["upstreams"]["syslinux"]["source_present"])
            self.assertFalse(m["flags"]["upstream_sources_all_present"])
            self.assertEqual((self.cache / rel).read_bytes(), data)  # not repaired
            return m

        def test_bad_source_hash(self):
            m = self.corrupt("downloads/s.orig")
            self.assertTrue(any("s.orig sha256" in r for r in m["requirements"]))

        def test_bad_binary_hash(self):
            self.corrupt("root/usr/lib/syslinux/memdisk")

        def test_bad_package_hash(self):
            self.corrupt("downloads/isolinux.deb", b"junk")

        def test_legal_file_differs_from_pinned_package(self):
            m = self.corrupt("root/usr/share/doc/isolinux/copyright", b"tampered license\n")
            self.assertTrue(any("legal file" in r for r in m["requirements"]))

        def test_missing_file_and_symlink(self):
            (self.cache / "downloads/s.dsc").unlink()
            self.assertFalse(self.check(self.cache)[1]["flags"]["upstream_sources_all_present"])
            (self.cache / "downloads/s.dsc").symlink_to(self.cache / "downloads/s.orig")
            self.assertFalse(self.check(self.cache)[1]["flags"]["upstream_sources_all_present"])

        def test_cli_check_and_cli_without_cache(self):
            for extra in ([], ["--syslinux-cache", str(self.cache)]):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = main(["--root", str(self.repo), "--check", *extra])
                self.assertEqual(rc, 0)
                self.assertFalse(json.loads(buf.getvalue())["compliance_claim"])
            self.assertFalse((self.repo / "build").exists())

        def test_historical_fail_not_a_source_requirement(self):
            files = {"shizukudos/a.c": b"x"}
            rec = {r: self.receipt(r, {"shizukudos/a.c": sha256(b"x")}) for r in CONSUMED_ROLES}
            doc = consume_receipts(self.repo, rec, files)
            self.assertIn("FAIL", doc["installed_guest_result"])
            self.assertFalse(doc["os_boot_qualification_claim"])
            self.assertFalse(doc["compiled_binary_binding_claim"])
            self.assertFalse(any("installed" in r for r in doc["requirements"]))

        # consume parser
        def receipt(self, name, content):
            path = self.base / f"{name}.json"
            path.write_bytes(content if isinstance(content, bytes) else json.dumps(content).encode())
            return path

        def src(self, rel="shizukudos/a.c", data=b"x"):
            f = self.base / "srcroot" / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
            return self.base / "srcroot", {rel: data}

        def all_roles(self, content):
            return {r: self.receipt(r, content) for r in CONSUMED_ROLES}

        def test_consume_good_then_oddities_never_all_true(self):
            root, files = self.src()
            good = {"sources_sha256": {"shizukudos/a.c": sha256(b"x")}}
            doc = consume_receipts(root, self.all_roles(good), files)
            self.assertTrue(doc["all_roles_consumed_and_current"], doc["requirements"])
            self.assertFalse(consume_receipts(root, self.all_roles(good), None)["all_roles_consumed_and_current"])
            partial = self.all_roles(good)
            partial["guest-readback"] = self.receipt("gr", {"note": "no map"})
            self.assertFalse(consume_receipts(root, partial, files)["all_roles_consumed_and_current"])
            self.assertFalse(consume_receipts(root, {}, files)["all_roles_consumed_and_current"])
            odd = [[], "x", 3, None, True, {}, {"sources_sha256": {}}, {"sources_sha256": []}, {"sources_sha256": "ab" * 32},
                   {"sources_sha256": {"shizukudos/a.c": "A" * 64}}, {"sources_sha256": {"": sha256(b"x")}},
                   {"$schema": "http://json-schema.org/draft-07/schema#", "sources_sha256": good["sources_sha256"]},
                   {"type": "object", "properties": {"sources_sha256": {"type": "object"}}},
                   {"sources_sha256": {}, "sources": good["sources_sha256"]},
                   {"sources_sha256": {"shizukudos/a.c": sha256(b"y")}},
                   {"sources_sha256": {"../a.c": sha256(b"x")}}, {"sources_sha256": {"/etc/passwd": sha256(b"x")}},
                   {"sources_sha256": {"shizukudos/./a.c": sha256(b"x")}},
                   {"sources_sha256": {"build/x.c": sha256(b"x")}}, {"sources_sha256": {"shizukudos/a.exe": sha256(b"x")}},
                   {"sources_sha256": {"unlisted/a.c": sha256(b"x")}},
                   b'{"sources_sha256": {"shizukudos/a.c": "%s"}, "sources_sha256": {}}' % sha256(b"x").encode(),
                   b'{"x": NaN}', b"", b"\xff\xfe", b"[", b"{" * 100000]
            for content in odd:
                d = consume_receipts(root, self.all_roles(content), files)
                self.assertFalse(d["all_roles_consumed_and_current"], content)
                self.assertTrue(d["requirements"], content)
            # one bad role among good ones
            mixed = self.all_roles(good)
            mixed["dos"] = self.receipt("bad", [])
            self.assertFalse(consume_receipts(root, mixed, files)["all_roles_consumed_and_current"])

        def test_consume_reads_only_named_safe_sources(self):
            root, files = self.src()
            (root / "shizukudos/link.c").symlink_to(root / "shizukudos/a.c")
            (root / "secret.txt").write_bytes(b"s")
            m = {"shizukudos/link.c": sha256(b"x"), "shizukudos/a.c": sha256(b"x")}
            doc = consume_receipts(root, {"kernels": self.receipt("k", {"sources_sha256": m})}, files)
            src = doc["receipts"]["kernels"]["sources"]
            self.assertEqual((src["current"], src["unsafe"]), (1, 1))
            self.assertEqual(src["bound_to_capsule_bytes"], 1)
            self.assertFalse(doc["all_roles_consumed_and_current"])

        def test_stale_source_not_bound(self):
            root, files = self.src()
            doc = consume_receipts(root, {"kernels": self.receipt("k", {"sources_sha256": {"shizukudos/a.c": sha256(b"old")}})}, files)
            src = doc["receipts"]["kernels"]["sources"]
            self.assertEqual((src["current"], src["stale"], src["bound_to_capsule_bytes"]), (0, 1, 0))

        def test_drivers_root_and_k64s_map_shapes(self):
            root, files = self.src("drivers/ahci_native/ahci.c")
            for ptr in ("source_before", "before"):
                doc = consume_receipts(root, {"kernels": self.receipt("k", {ptr: {"drivers/ahci_native/ahci.c": sha256(b"x")}})}, files)
                src = doc["receipts"]["kernels"]["sources"]
                self.assertEqual((src["current"], src["bound_to_capsule_bytes"]), (1, 1), ptr)
            self.assertIsNone(_named_source_ok("drivers/ahci_native/ahci.c"))
            self.assertIsNone(_named_source_ok("drivers/shz_laptop/x.h"))
            for bad in ("drivers/a.bin", "drivers/private/a.c", "drivers/secret.json"):
                self.assertTrue(_named_source_ok(bad), bad)
            self.assertEqual(_source_map({"sources_sha256": {"a": "0" * 64}, "before": {}})[0], "sources_sha256")
            for bad in ({"source_before": {"shizukudos/a.c": "A" * 64}}, {"before": []}, {"source_before": {}, "before": {"shizukudos/a.c": sha256(b"x")}}):
                d = consume_receipts(root, {"kernels": self.receipt("k", bad)}, files)
                self.assertFalse(d["all_roles_consumed_and_current"])
                self.assertFalse((d["receipts"]["kernels"].get("sources") or {}).get("bound_to_capsule_bytes"))
            d = consume_receipts(root, {"kernels": self.receipt("k", {"source_before": {"drivers/ahci_native/ahci.c": sha256(b"y")}})}, files)
            self.assertEqual(d["receipts"]["kernels"]["sources"]["current"], 0)
            self.assertFalse(d["all_roles_consumed_and_current"])

        def test_setup_result_flag(self):
            with self.assertRaises(SystemExit):
                with contextlib.redirect_stderr(io.StringIO()):
                    main(["--check", "--setup-result", "build/installer-link-boot05/setup/result.json"])

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Fixtures)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, default=ROOT, help="repository root (default: derived from this file)")
    ap.add_argument("--commit", help="pinned 40-hex project commit (default HEAD)")
    ap.add_argument("--prefix", default=DEFAULT_PREFIX, help="ISO directory prefix")
    ap.add_argument("--project-root", action="append", dest="roots", help="allowlisted project root (repeatable)")
    ap.add_argument("--wineport", action="store_true", help="include Wine/FreeType/Noto upstreams")
    ap.add_argument("--receipt-root", type=Path, help="tree holding build/shizukudos receipts (default --root)")
    ap.add_argument("--max-total-mib", type=int, default=MAX_TOTAL >> 20)
    ap.add_argument("--consume", action="append", metavar="ROLE=PATH",
                    help="explicit producer receipt consumed; ROLE in " + "/".join(CONSUMED_ROLES) + " (repeatable)")
    ap.add_argument("--consumed-only", type=Path, metavar="OUT.json",
                    help="only write the consumed receipt (no git/builder/upstream work; shipped-byte binding unknown)")
    ap.add_argument("--syslinux-cache", type=Path, metavar="DIR",
                    help="EXISTING syslinux cache holding root/ and downloads/ (e.g. build/upstream/syslinux); "
                         "validated read-only against the manifest hashes; never created, downloaded or repaired")
    ap.add_argument("--setup-result", type=Path, metavar="PATH",
                    help="shorthand for --consume setup-result=PATH; normally " + SETUP_RESULT_DEFAULT)
    ap.add_argument("--self-test", action="store_true", help="run the offline fixtures (tmp dirs only) and exit")
    ap.add_argument("--check", action="store_true", help="validate and print summary; write nothing (read-only)")
    ap.add_argument("--out", type=Path, help="fresh/empty output directory")
    ap.add_argument("--strict", action="store_true", help="exit 2 while any requirement remains")
    args = ap.parse_args(argv)
    if sum(bool(x) for x in (args.check, args.out, args.consumed_only, args.self_test)) != 1:
        ap.error("choose exactly one of --check, --out, --consumed-only or --self-test")
    if args.self_test:
        return _self_test()
    consumed = {}
    if args.setup_result:
        if args.setup_result.name == "result.json":
            ap.error(f"--setup-result must name the existing {SETUP_RESULT_DEFAULT}, not setup/result.json")
        consumed["setup-result"] = args.setup_result
    for item in args.consume or []:
        role, sep, path = item.partition("=")
        if not sep or role not in CONSUMED_ROLES or not path or role in consumed:
            ap.error(f"--consume wants unique ROLE=PATH with ROLE in {CONSUMED_ROLES}: {item!r}")
        consumed[role] = Path(path)
    if args.consumed_only:
        try:
            doc = consume_receipts(args.root, consumed, None, args.commit)
            if args.consumed_only.exists():
                raise CapsuleError(f"{args.consumed_only} exists; refusing to overwrite")
            args.consumed_only.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except (CapsuleError, OSError) as exc:
            print(f"source_capsule: FAIL: {exc}", file=sys.stderr)
            return 1
        print(json.dumps({"written": str(args.consumed_only), "release_claim": False,
                          "all_roles_consumed_and_current": doc["all_roles_consumed_and_current"],
                          "requirements": doc["requirements"]}, indent=2))
        return 2 if args.strict and doc["requirements"] else 0
    if not args.check and not args.out:
        ap.error("give --check, --out DIR or --consumed-only FILE")
    try:
        members, manifest = build_capsule(args.root, prefix=args.prefix, commit=args.commit,
                                          project_roots=tuple(args.roots or DEFAULT_PROJECT_ROOTS),
                                          wineport=args.wineport, receipt_root=args.receipt_root,
                                          max_total=args.max_total_mib << 20, consumed=consumed or None,
                                          syslinux_cache=args.syslinux_cache)
        if not args.check:
            write_capsule(members, args.out)
    except (CapsuleError, subprocess.CalledProcessError, OSError, ValueError) as exc:
        print(f"source_capsule: FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"members": len(members), "bytes": sum(map(len, members.values())),
                      "compliance_claim": manifest["compliance_claim"], "flags": manifest["flags"],
                      "requirements": manifest["requirements"],
                      "rejected": len(manifest["project"]["rejected"]),
                      "written": None if args.check else str(args.out)}, indent=2))
    return 2 if args.strict and manifest["requirements"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
