#!/usr/bin/env python3
"""Compose ONE pinned public git-commit project tree with an externally pinned consumed_overlay snapshot.

Baseline  = sc.project_entries(root, FULL_COMMIT, public allowlist)  (existing guarded git-blob API, unchanged).
Overlay   = consumed_overlay TAR + manifest, each pinned by an EXTERNAL lowercase SHA-256 (digests written inside the
            manifest are only cross-checked, never trusted).  Overlay paths replace the same baseline path or are added.
Output    = deterministic plain GNU tar SOURCE/project/<rel> + a manifest with truthful provenance.

This is NOT a full source capsule, upstream/GPL/licence closure, release, reproducible binary, compiled-binary binding
or OS/DOS/EFI/install/Win98 proof; every such claim is literally false.  The result is not a git commit.  Baseline
gitlink/symlink/guard skips are disclosed and never counted as closure.  Nothing is written to Git, the network or the
inputs.

CLI (exactly one mode):
  --root REPO --commit FULL_HEX --overlay-tar P --overlay-tar-sha256 H --overlay-manifest P
      --overlay-manifest-sha256 H  (--check | --out DIR)
  --self-test            offline, no git
"""
from __future__ import annotations

import sys

sys.dont_write_bytecode = True  # global guard BEFORE importing sibling modules: --check must not create __pycache__

import argparse  # noqa: E402
import hashlib  # noqa: E402
import importlib.util  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import stat  # noqa: E402
import tarfile  # noqa: E402
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

_HERE = Path(__file__).resolve().parent


def _load_overlay():
    spec = importlib.util.spec_from_file_location("_merge_consumed_overlay", _HERE / "consumed_overlay.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


co = _load_overlay()
sc = co.sc  # existing source_capsule, unchanged

SCHEMA = "shizuku-project-source-merge/1"
ARCHIVE_NAME = "project-source-merge.tar"
MANIFEST_NAME = "project-source-merge-manifest.json"
TOP = co.TOP
EPOCH = sc.FIXED_EPOCH
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_FILES = 20000
MAX_METADATA = 8 * 1024 * 1024
MAX_ARCHIVE = MAX_TOTAL + MAX_FILES * 1024 + (1 << 20)
MAX_LISTED = 1000
HEX64 = re.compile(r"[0-9a-f]{64}")
GIT_HEAD_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")  # overlay manifest's declared (untrusted) git head
COMMIT_RE = re.compile(r"[0-9a-f]{40}")  # pinned baseline commit: SHA-1 repositories only
GIT_REDIRECT_ENV = ("GIT_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_REPLACE_REF_BASE",
                    "GIT_WORK_TREE", "GIT_COMMON_DIR")
CLAIMS = ("full_source_claim", "license_closure_claim", "gpl_corresponding_source_claim", "upstream_closure_claim",
          "compliance_claim", "release_claim", "reproducible_binary_claim", "compiled_binary_binding_claim",
          "os_qualification_claim", "efi_dos_install_win98_proof_claim")
OVERLAY_KEYS = {"schema", "kind", "snapshot_is_commit", "archive", "tool_source_capsule_sha256", "limits",
                "tool_consumed_overlay_sha256", "receipts", "receipt_note", "files", "totals", "git",
                "limitation", *CLAIMS}
RECEIPT_KEYS = {"receipt_sha256", "receipt_bytes", "source_map_pointer", "producer_status", "source_map_entries",
                "source_map_snapshot_sha256"}
MODES = {"100644": 0o644, "100755": 0o755}


class MergeError(RuntimeError):
    pass


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _int(x) -> bool:
    return type(x) is int and x >= 0  # bool is refused


def read_bounded(path, limit: int) -> bytes:
    """One bounded read of a regular file; final component never followed; stat before/after must agree."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise MergeError(f"input unreadable or symlink ({exc.__class__.__name__})") from None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise MergeError("input is not a regular file")
        if before.st_size > limit:
            raise MergeError(f"input larger than {limit} bytes")
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read(limit + 1)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    key = lambda st: (st.st_size, st.st_mtime_ns, st.st_ino, st.st_dev)  # noqa: E731
    if len(data) > limit or len(data) != before.st_size or key(before) != key(after):
        raise MergeError("input changed during read or exceeds bound")
    return data


def check_pin(name: str, pin, data: bytes) -> None:
    if not isinstance(pin, str) or not HEX64.fullmatch(pin):
        raise MergeError(f"{name}: external pin missing or not 64 lowercase hex SHA-256")
    if sha256(data) != pin:
        raise MergeError(f"{name}: bytes do not match the external pin")


def _path_ok(rel) -> None:
    if not isinstance(rel, str) or not rel:
        raise MergeError("path is not a non-empty string")
    try:
        co.check_path_text(rel)
        rel.encode("utf-8")
    except (co.OverlayError, UnicodeError) as exc:
        raise MergeError(str(exc)) from None
    why = sc._named_source_ok(rel)
    if why:
        raise MergeError(f"{ascii(rel)}: refused path ({why})")


def _tree_conflicts(paths) -> None:
    ps = set(paths)
    for p in ps:
        parts = p.split("/")
        for i in range(1, len(parts)):
            if "/".join(parts[:i]) in ps:
                raise MergeError(f"{ascii(p)}: a file path is also a directory prefix")


# --- overlay validation --------------------------------------------------------
def validate_overlay(tar_bytes: bytes, tar_pin, mfst_bytes: bytes, mfst_pin, *, max_total=MAX_TOTAL,
                     max_files=MAX_FILES) -> tuple[dict, dict[str, bytes]]:
    """Returns (manifest, {rel: exact bytes}); the tar is parsed in memory, never extracted."""
    if len(mfst_bytes) > MAX_METADATA:
        raise MergeError("overlay manifest exceeds metadata bound")
    if len(tar_bytes) > MAX_ARCHIVE:
        raise MergeError("overlay archive exceeds archive bound")
    check_pin("overlay manifest", mfst_pin, mfst_bytes)
    check_pin("overlay archive", tar_pin, tar_bytes)
    try:
        m = sc.strict_json(mfst_bytes)
    except ValueError as exc:
        raise MergeError(f"overlay manifest is not strict JSON ({exc})") from None
    if not isinstance(m, dict) or set(m) != OVERLAY_KEYS:
        raise MergeError("overlay manifest keys are not exactly the consumed_overlay schema")
    if m["schema"] != co.SCHEMA or m["kind"] != "source-only-snapshot":
        raise MergeError("overlay manifest schema/kind mismatch")
    if m["snapshot_is_commit"] is not False:
        raise MergeError("overlay snapshot_is_commit is not false")
    for k in CLAIMS:
        if m[k] is not False:
            raise MergeError(f"overlay claim {k} is not literal false")
    for k in ("tool_source_capsule_sha256", "tool_consumed_overlay_sha256"):
        if not isinstance(m[k], str) or not HEX64.fullmatch(m[k]):
            raise MergeError(f"overlay {k} malformed")
    for k in ("receipt_note", "limitation"):
        if not isinstance(m[k], str) or len(m[k]) > 4000:
            raise MergeError(f"overlay {k} malformed")
    g = m["git"]
    if not (isinstance(g, dict) and set(g) == {"head", "note"} and isinstance(g["note"], str)
            and (g["head"] is None or (isinstance(g["head"], str) and GIT_HEAD_RE.fullmatch(g["head"])))):
        raise MergeError("overlay git block malformed")
    lim = m["limits"]
    if not (isinstance(lim, dict) and set(lim) == {"max_file", "max_total", "max_files", "max_receipts"}
            and all(_int(v) for v in lim.values())):
        raise MergeError("overlay limits malformed")
    a = m["archive"]
    want_a = {"name": co.ARCHIVE_NAME, "layout": TOP + "/<path>", "format": "plain GNU tar, uncompressed",
              "mtime": EPOCH, "uid": 0, "gid": 0, "mode": "0644"}
    if not (isinstance(a, dict) and set(a) == set(want_a) | {"sha256", "bytes"}):
        raise MergeError("overlay archive block keys malformed")
    for k, v in want_a.items():
        if type(a[k]) is not type(v) or a[k] != v:
            raise MergeError(f"overlay archive.{k} mismatch")
    if not _int(a["bytes"]) or a["bytes"] != len(tar_bytes):
        raise MergeError("overlay archive.bytes mismatch")
    if not isinstance(a["sha256"], str) or a["sha256"] != tar_pin:
        raise MergeError("overlay archive.sha256 differs from the external archive pin")
    # receipts
    rec = m["receipts"]
    if not isinstance(rec, dict) or not 1 <= len(rec) <= co.MAX_RECEIPTS:
        raise MergeError("overlay receipts count out of bounds")
    for name, r in rec.items():
        if not isinstance(name, str) or not co.ROLE_RE.fullmatch(name):
            raise MergeError("overlay receipt name malformed")
        if not (isinstance(r, dict) and set(r) == RECEIPT_KEYS):
            raise MergeError(f"overlay receipt {name} keys malformed")
        for k in ("receipt_sha256", "source_map_snapshot_sha256"):
            if not isinstance(r[k], str) or not HEX64.fullmatch(r[k]):
                raise MergeError(f"overlay receipt {name}.{k} malformed digest")
        if not _int(r["receipt_bytes"]) or not _int(r["source_map_entries"]) or r["source_map_entries"] < 1:
            raise MergeError(f"overlay receipt {name} counts malformed")
        ptrs = r["source_map_pointer"]
        if not (isinstance(ptrs, str) and ptrs and all(p in sc.SOURCE_MAP_POINTERS for p in ptrs.split("+"))):
            raise MergeError(f"overlay receipt {name} pointer malformed")
        ps = r["producer_status"]
        if ps is not None and not (isinstance(ps, str) and ps.strip().lower() in co.SNAPSHOT_STATUS):
            raise MergeError(f"overlay receipt {name} producer_status not a completed build")
    # files
    fl = m["files"]
    if not isinstance(fl, list) or not fl or len(fl) > min(max_files, MAX_FILES):
        raise MergeError("overlay file count out of bounds")
    paths, total = [], 0
    by_role: dict[str, list] = {n: [] for n in rec}
    for e in fl:
        if not (isinstance(e, dict) and set(e) == {"path", "sha256", "bytes", "consumed_by"}):
            raise MergeError("overlay file entry keys malformed")
        _path_ok(e["path"])
        if not isinstance(e["sha256"], str) or not HEX64.fullmatch(e["sha256"]):
            raise MergeError(f"{ascii(e['path'])}: malformed digest")
        if not _int(e["bytes"]) or e["bytes"] > MAX_FILE:
            raise MergeError(f"{ascii(e['path'])}: size not a bounded non-bool integer")
        cb = e["consumed_by"]
        if not (isinstance(cb, list) and cb and all(isinstance(x, str) and x in rec for x in cb)
                and cb == sorted(set(cb))):
            raise MergeError(f"{ascii(e['path'])}: consumed_by malformed")
        total += e["bytes"]
        if total > min(max_total, MAX_TOTAL):
            raise MergeError("overlay total bytes exceed bound")
        paths.append(e["path"])
        for x in cb:
            by_role[x].append((e["path"], e["sha256"]))
    if paths != sorted(paths) or len(set(paths)) != len(paths):
        raise MergeError("overlay file list is duplicated or not sorted")
    _tree_conflicts(paths)
    t = m["totals"]
    if not (isinstance(t, dict) and set(t) == {"files", "bytes"} and _int(t["files"]) and _int(t["bytes"])
            and t["files"] == len(fl) and t["bytes"] == total):
        raise MergeError("overlay totals mismatch")
    for name, r in rec.items():
        pairs = by_role[name]
        if len(pairs) != r["source_map_entries"] or sc._snapshot_digest(pairs) != r["source_map_snapshot_sha256"]:
            raise MergeError(f"overlay receipt {name} source-map count/digest does not match file list")
    # tar members: plain GNU tar, regular members only, exact layout; parsed in memory
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tf:
            for e in fl:
                mem = tf.next()
                if mem is None:
                    raise MergeError("overlay archive is missing a member")
                rel = e["path"]
                if mem.name != f"{TOP}/{rel}":
                    raise MergeError(f"overlay archive member order/name mismatch at {ascii(rel)}")
                if mem.type != tarfile.REGTYPE or not mem.isreg() or mem.issym() or mem.islnk():
                    raise MergeError(f"{ascii(rel)}: member is not a plain regular file")
                if (mem.mtime, mem.uid, mem.gid, mem.mode, mem.uname, mem.gname, mem.linkname) != (EPOCH, 0, 0, 0o644, "", "", ""):
                    raise MergeError(f"{ascii(rel)}: member metadata is not the fixed layout")
                if mem.pax_headers:
                    raise MergeError(f"{ascii(rel)}: pax headers present")
                if mem.size != e["bytes"]:
                    raise MergeError(f"{ascii(rel)}: member size differs from manifest")
                data = tf.extractfile(mem).read(MAX_FILE + 1)
                if len(data) != e["bytes"] or sha256(data) != e["sha256"]:
                    raise MergeError(f"{ascii(rel)}: member bytes differ from manifest sha256")
                why = co.content_refusal(data)
                if why:
                    raise MergeError(f"{ascii(rel)}: content refused ({why})")
                files[rel] = data
            if tf.next() is not None:
                raise MergeError("overlay archive has an extra member")
    except MergeError:
        raise
    except (tarfile.TarError, EOFError, ValueError, OSError, UnicodeError) as exc:
        raise MergeError(f"overlay archive is not a valid plain tar ({exc.__class__.__name__})") from None
    if co.deterministic_archive(files) != tar_bytes:
        raise MergeError("overlay archive bytes are not the exact deterministic plain GNU tar layout")
    return m, files


# --- baseline ------------------------------------------------------------------
def verify_commit(root: Path, commit: str) -> str:
    """Read the raw commit object, require sha1("commit N\\0"+body) == the pinned name, return its tree id.
    Call only under _git_env() so replace objects cannot substitute the commit or its tree."""
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise MergeError("--commit must be a full 40 lowercase hex SHA-1 commit name")
    try:
        body = sc.git(root, "cat-file", "commit", commit, check=False)
    except OSError:
        body = b""
    if not isinstance(body, bytes) or not body:
        raise MergeError("commit object is unreadable or absent")
    if hashlib.sha1(b"commit %d\0" % len(body) + body).hexdigest() != commit:
        raise MergeError("commit object does not hash to the pinned name")
    first = body.split(b"\n", 1)[0]
    m = re.fullmatch(rb"tree ([0-9a-f]{40})", first)
    if not m:
        raise MergeError("commit object has no tree header")
    return m.group(1).decode()


class _git_env:
    """Refuse inherited git redirection variables and force GIT_NO_REPLACE_OBJECTS=1 (inherited by the git
    subprocesses of source_capsule); the previous environment is restored on exit."""

    def __enter__(self):
        bad = [k for k in GIT_REDIRECT_ENV if k in os.environ]
        if bad:
            raise MergeError("refusing inherited git redirection environment: " + ",".join(bad))
        self.old = os.environ.get("GIT_NO_REPLACE_OBJECTS")
        os.environ["GIT_NO_REPLACE_OBJECTS"] = "1"
        return self

    def __exit__(self, *exc):
        if self.old is None:
            os.environ.pop("GIT_NO_REPLACE_OBJECTS", None)
        else:
            os.environ["GIT_NO_REPLACE_OBJECTS"] = self.old


def revalidate_baseline(entries, max_total=MAX_TOTAL, max_files=MAX_FILES):
    """Stronger re-check of sc.project_entries output.  Returns ({rel: (mode, data, blob)}, [newly rejected])."""
    out: dict[str, tuple] = {}
    extra: list[dict] = []
    total = 0
    for ent in entries:
        if not (isinstance(ent, (tuple, list)) and len(ent) == 4):
            raise MergeError("baseline entry malformed")
        rel, mode, blob, data = ent
        _path_ok(rel)
        if rel in out:
            raise MergeError(f"{ascii(rel)}: duplicate baseline path")
        if mode not in MODES:
            raise MergeError(f"{ascii(rel)}: baseline mode {ascii(mode)} not a regular git mode")
        if not isinstance(data, bytes) or not isinstance(blob, str) or not re.fullmatch(r"[0-9a-f]{40}", blob):
            raise MergeError(f"{ascii(rel)}: baseline data/blob malformed")
        if hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest() != blob:
            raise MergeError(f"{ascii(rel)}: baseline blob hash mismatch")
        if len(data) > MAX_FILE:
            raise MergeError(f"{ascii(rel)}: baseline file too large")
        why = co.content_refusal(data)
        if why:
            extra.append({"path": rel, "reason": "overlay-guard-" + why})
            continue
        total += len(data)
        if total > max_total:
            raise MergeError("baseline total bytes exceed bound")
        out[rel] = (mode, data, blob)
        if len(out) > max_files:
            raise MergeError("baseline file count exceeds bound")
    _tree_conflicts(out)
    return out, extra


def _pairs_digest(pairs) -> str:
    return sc._snapshot_digest(pairs)


def tool_digests() -> dict:
    return {"project_source_merge_sha256": sha256(Path(__file__).read_bytes()),
            "source_capsule_sha256": sha256((_HERE / "source_capsule.py").read_bytes()),
            "consumed_overlay_sha256": sha256((_HERE / "consumed_overlay.py").read_bytes())}


def merged_archive(files: dict[str, tuple[bytes, int]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for rel in sorted(files):
            data, mode = files[rel]
            ti = tarfile.TarInfo(f"{TOP}/{rel}")
            ti.size, ti.mtime, ti.mode, ti.uid, ti.gid = len(data), EPOCH, mode, 0, 0
            ti.uname = ti.gname = ""
            ti.type = tarfile.REGTYPE
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def compose(root, commit, tar_bytes, tar_pin, mfst_bytes, mfst_pin, *, roots=sc.DEFAULT_PROJECT_ROOTS,
            baseline_fn=None, check_commit=True, max_total=MAX_TOTAL, max_files=MAX_FILES,
            max_metadata=MAX_METADATA, max_archive=MAX_ARCHIVE):
    """Returns (archive bytes, manifest dict, {rel: bytes}).  Every bound is enforced before anything is written."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise MergeError("root is not a real directory")
    roots = tuple(roots)
    if not roots or any(r not in sc.DEFAULT_PROJECT_ROOTS for r in roots):
        raise MergeError("baseline roots must be a non-empty subset of the public allowlist")
    tree = None
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise MergeError("--commit must be a full 40 lowercase hex SHA-1 commit name")
    om, ofiles = validate_overlay(tar_bytes, tar_pin, mfst_bytes, mfst_pin, max_total=max_total, max_files=max_files)
    narrowed = roots != sc.DEFAULT_PROJECT_ROOTS
    if narrowed:
        outside = [r for r in ofiles if not any(r == x or r.startswith(x.rstrip("/") + "/") for x in roots)]
        if outside:
            raise MergeError(f"{ascii(outside[0])}: overlay path outside the selected --project-root set "
                             f"({len(outside)} such paths)")
    req: list = []
    rejected: list = []
    try:
        with _git_env():
            if check_commit:
                tree = verify_commit(root, commit)
            entries, skipped = (baseline_fn or sc.project_entries)(root, commit, roots, req, rejected)
    except (sc.CapsuleError, OSError, ValueError, KeyError, subprocess_error()) as exc:
        raise MergeError(f"baseline read failed ({exc.__class__.__name__})") from None
    base, extra_rej = revalidate_baseline(entries, max_total, max_files)
    rejected = [dict(r) for r in rejected] + extra_rej
    skipped = [dict(s) for s in skipped]
    blocked = {x["path"] for x in rejected} | {x["path"] for x in skipped}
    for rel in ofiles:
        if rel in blocked:
            raise MergeError(f"{ascii(rel)}: overlay path collides with a baseline path that was skipped/rejected")
    result: dict[str, tuple[bytes, int]] = {}
    kind: dict[str, str] = {}
    for rel, (mode, data, _b) in base.items():
        result[rel] = (data, MODES[mode])
        kind[rel] = "baseline"
    adds, repl, ident = [], [], []
    for rel, data in ofiles.items():
        if rel in base:
            bmode, bdata, _ = base[rel]
            if bdata == data:
                ident.append(rel)
                kind[rel] = "overlay-identical"
            else:
                repl.append(rel)
                kind[rel] = "overlay-replacement"
            result[rel] = (data, MODES[bmode])  # replacement keeps the baseline git mode; overlay carries none
        else:
            adds.append(rel)
            kind[rel] = "overlay-addition"
            result[rel] = (data, 0o644)
    if len(result) > max_files:
        raise MergeError("result file count exceeds bound")
    total = sum(len(d) for d, _ in result.values())
    if total > max_total:
        raise MergeError("result total bytes exceed bound")
    _tree_conflicts(result)
    unchanged = [r for r in base if r not in ofiles]
    archive = merged_archive(result)
    if len(archive) > max_archive:
        raise MergeError("result archive exceeds bound")
    sha = {rel: sha256(result[rel][0]) for rel in result}

    def cat(paths):
        ps = sorted(paths)
        return {"count": len(ps), "paths_sha256": sha256("".join(p + "\n" for p in ps).encode()),
                "path_content_sha256": _pairs_digest((p, sha[p]) for p in ps)}

    def listed(items):
        return {"count": len(items), "listed": sorted(items, key=lambda x: x["path"])[:MAX_LISTED],
                "list_truncated": len(items) > MAX_LISTED,
                "list_sha256": sha256(json.dumps(sorted(items, key=lambda x: x["path"]), sort_keys=True).encode())}

    manifest = {
        "schema": SCHEMA,
        "kind": "project-tree-with-consumed-overlay",
        "snapshot_is_commit": False,
        "archive": {"name": ARCHIVE_NAME, "sha256": sha256(archive), "bytes": len(archive), "layout": TOP + "/<path>",
                    "format": "plain GNU tar, uncompressed", "mtime": EPOCH, "uid": 0, "gid": 0,
                    "modes": "0755 for baseline git mode 100755, otherwise 0644"},
        "baseline": {"commit": commit, "tree": tree, "replace_objects_disabled": True, "api": "source_capsule.project_entries (git blobs, guarded)",
                     "roots": list(roots), "roots_are_default_public_allowlist": roots == sc.DEFAULT_PROJECT_ROOTS,
                     "files": len(base), "path_content_sha256": _pairs_digest((r, sha256(base[r][1])) for r in base),
                     "guard_rejected": listed(rejected),
                     "gitlink_or_symlink_skipped": listed(skipped),
                     "skips_disclosed_closure_not_claimed": True,
                     "capsule_requirements": sorted(set(str(x) for x in req))[:50]},
        "overlay": {"archive_sha256_external_pin": tar_pin, "archive_bytes": len(tar_bytes),
                    "manifest_sha256_external_pin": mfst_pin, "manifest_bytes": len(mfst_bytes),
                    "schema": om["schema"], "files": len(ofiles),
                    "declared_tool_digests_unverified": {"source_capsule_sha256": om["tool_source_capsule_sha256"],
                                                         "consumed_overlay_sha256": om["tool_consumed_overlay_sha256"]},
                    "receipts": {n: {k: om["receipts"][n][k] for k in sorted(RECEIPT_KEYS)} for n in sorted(om["receipts"])},
                    "receipt_note": "Only digests and original producer_status values are recorded; no raw receipts "
                                    "or absolute input paths are shipped."},
        "tool": tool_digests(),
        "counts": {"baseline": len(base), "additions": len(adds), "replacements": len(repl),
                   "overlay_identical_to_baseline": len(ident), "unchanged_baseline": len(unchanged),
                   "result": len(result)},
        "path_hashes": {"additions": cat(adds), "replacements": cat(repl), "overlay_identical": cat(ident),
                        "unchanged_baseline": cat(unchanged), "result": cat(result)},
        "files": [{"path": rel, "sha256": sha[rel], "bytes": len(result[rel][0]), "mode": "%04o" % result[rel][1],
                   "source": kind[rel]} for rel in sorted(result)],
        "totals": {"files": len(result), "bytes": total},
        **{k: False for k in CLAIMS},
        "limitation": "Pinned-commit public project tree with a pinned working-tree overlay applied; skipped/rejected "
                      "baseline entries are listed and not shipped.  Not a commit, not a source closure, and not "
                      "evidence of GPL/upstream/licence compliance, a reproducible or bound binary, a release, or "
                      "OS/DOS/EFI/install/Win98 behaviour.",
    }
    mb = manifest_bytes(manifest)
    if len(mb) > max_metadata:
        raise MergeError("result manifest exceeds metadata bound")
    verify_result(archive, manifest, result)
    return archive, manifest, {r: d for r, (d, _m) in result.items()}


def subprocess_error():
    import subprocess
    return subprocess.CalledProcessError


def verify_result(archive: bytes, manifest: dict, result: dict) -> None:
    """Re-read the produced tar in memory and compare with the manifest (internal consistency control)."""
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tf:
        ms = tf.getmembers()
        if [m.name for m in ms] != [f"{TOP}/{e['path']}" for e in manifest["files"]]:
            raise MergeError("internal: result member list differs from manifest")
        for m, e in zip(ms, manifest["files"]):
            if not m.isreg() or "%04o" % m.mode != e["mode"] or m.mtime != EPOCH or (m.uid, m.gid) != (0, 0):
                raise MergeError("internal: result member metadata differs")
            if sha256(tf.extractfile(m).read()) != e["sha256"]:
                raise MergeError("internal: result member bytes differ")
    if manifest["archive"]["sha256"] != sha256(archive) or manifest["archive"]["bytes"] != len(archive):
        raise MergeError("internal: archive digest differs")


def manifest_bytes(manifest: dict) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()


def write_out(out, archive: bytes, manifest: dict) -> None:
    out = Path(out)
    if out.is_symlink():
        raise MergeError("--out is a symlink")
    parent = out.parent
    if parent.is_symlink() or not parent.is_dir():
        raise MergeError("--out parent is not a real directory")
    if out.exists():
        if not out.is_dir() or any(out.iterdir()):
            raise MergeError("--out exists and is not an empty directory (no overwrite)")
    tmp = Path(tempfile.mkdtemp(prefix=".merge-tmp-", dir=parent))
    try:
        for name, data in ((ARCHIVE_NAME, archive), (MANIFEST_NAME, manifest_bytes(manifest))):
            fd = os.open(tmp / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        os.chmod(tmp, 0o755)
        os.rename(tmp, out)  # atomic; onto an empty directory it replaces it, on failure out is untouched
        try:
            dfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)  # only the temp directory this call created
        raise


# --- self test -----------------------------------------------------------------
def _self_test() -> int:
    import contextlib
    import copy
    import time
    t0 = time.time()
    fails: list[str] = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    def refuses(msg, fn, needle=None):
        try:
            fn()
        except MergeError as exc:
            check(needle is None or needle in str(exc), f"{msg}: wrong reason {exc}")
            return
        except Exception as exc:  # noqa: BLE001
            fails.append(f"{msg}: wrong exception {exc!r}")
            return
        fails.append(f"{msg}: not refused")

    COMMIT = "a" * 40

    def blob(data):
        return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()

    base_files = {"README.md": (b"readme\n", "100644"), "shizukudos/kernel64/main.c": (b"int old;\n", "100644"),
                  "tools/pin.py": (b"print('x')\n", "100644"), "tools/run.sh": (b"#!/bin/sh\n", "100755"),
                  "docs/keep.md": (b"keep\n", "100644")}

    def baseline(files=base_files, rejected=(), skipped=()):
        def fn(root, commit, roots, req, rej):
            rej.extend(rejected)
            if skipped:
                req.append(f"{len(skipped)} gitlink/symlink entries are not shipped")
            return [(r, m, blob(d), d) for r, (d, m) in sorted(files.items())], list(skipped)
        return fn

    with tempfile.TemporaryDirectory(prefix="merge-st-") as td:
        td = Path(td)
        proj = td / "proj"
        (proj / "shizukudos/kernel64").mkdir(parents=True)
        (proj / "tools").mkdir()
        new = {"shizukudos/kernel64/main.c": b"int new;\n", "shizukudos/kernel64/added.c": b"/* add */\n",
               "tools/pin.py": b"print('x')\n"}
        for r, d in new.items():
            (proj / r).write_bytes(d)
        rd = td / "rc"
        rd.mkdir()
        rp = []
        for i, doc in enumerate(({"status": "PASS", "source_before": {r: sha256(d) for r, d in new.items()}},
                                 {"sources": {"tools/pin.py": sha256(new["tools/pin.py"])}})):
            (rd / f"{i}.json").write_text(json.dumps(doc))
            rp.append(str(rd / f"{i}.json"))
        oa, om, _ = co.build_overlay(proj, {"k64s": rp[0], "pins": rp[1]})
        omb = co.manifest_bytes(om)
        TP, MP = sha256(oa), sha256(omb)
        assert len(oa) < 8 << 20

        def run(tar=oa, mf=omb, tp=None, mp=None, **kw):
            kw.setdefault("baseline_fn", baseline())
            kw.setdefault("check_commit", False)
            return compose(proj, COMMIT, tar, TP if tp is None else tp, mf, MP if mp is None else mp, **kw)

        a1, m1, f1 = run()
        a2, m2, _ = run()
        check(a1 == a2 and m1 == m2 and manifest_bytes(m1) == manifest_bytes(m2), "not deterministic")
        c = m1["counts"]
        check(c == {"baseline": 5, "additions": 1, "replacements": 1, "overlay_identical_to_baseline": 1,
                    "unchanged_baseline": 3, "result": 6}, f"counts {c}")
        src = {e["path"]: e["source"] for e in m1["files"]}
        check(src["shizukudos/kernel64/main.c"] == "overlay-replacement" and src["shizukudos/kernel64/added.c"] == "overlay-addition"
              and src["tools/pin.py"] == "overlay-identical" and src["README.md"] == "baseline", "sources")
        check(f1["shizukudos/kernel64/main.c"] == b"int new;\n" and f1["README.md"] == b"readme\n", "bytes")
        with tarfile.open(fileobj=io.BytesIO(a1), mode="r:") as tf:
            ms = tf.getmembers()
            check([m.name for m in ms] == sorted(f"{TOP}/{p}" for p in f1), "tar names/order")
            check(all(m.mtime == EPOCH and m.uid == m.gid == 0 and not m.uname and m.isreg() for m in ms), "tar meta")
            check({m.name[len(TOP) + 1:]: m.mode for m in ms}["tools/run.sh"] == 0o755, "explicit exec mode")
        check(a1[:2] != b"\x1f\x8b" and a1[257:262] == b"ustar", "plain tar")
        check(m1["baseline"]["commit"] == COMMIT and m1["overlay"]["archive_sha256_external_pin"] == TP
              and m1["overlay"]["manifest_sha256_external_pin"] == MP, "provenance pins")
        check(m1["overlay"]["receipts"]["k64s"]["producer_status"] == "PASS"
              and m1["overlay"]["receipts"]["pins"]["producer_status"] is None, "producer_status")
        check(m1["tool"]["source_capsule_sha256"] == sha256((_HERE / "source_capsule.py").read_bytes()), "tool digest")
        check(all(m1[k] is False for k in CLAIMS) and m1["snapshot_is_commit"] is False, "claims")
        check(m1["baseline"]["skips_disclosed_closure_not_claimed"] is True, "skip flag")
        mb = manifest_bytes(m1)
        check(str(td).encode() not in mb and b"/tmp" not in mb, "absolute path leaked")
        # disclosure of skips
        _, ms2, _ = run(baseline_fn=baseline(skipped=[{"path": "docs/sub", "mode": "160000", "reason": "gitlink-or-symlink-not-shipped"}],
                                           rejected=[{"path": "tools/x.exe", "reason": "binary-or-build-output"}]))
        check(ms2["baseline"]["gitlink_or_symlink_skipped"]["count"] == 1 and ms2["baseline"]["guard_rejected"]["count"] == 1
              and ms2["baseline"]["capsule_requirements"], "skips not disclosed")
        refuses("overlay onto skipped", lambda: run(baseline_fn=baseline(skipped=[{"path": "tools/pin.py", "mode": "120000", "reason": "x"}])), "collides")

        # pins
        refuses("wrong tar pin", lambda: run(tp="0" * 64), "pin")
        refuses("wrong mfst pin", lambda: run(mp="0" * 64), "pin")
        refuses("upper pin", lambda: run(tp=TP.upper()), "pin")
        refuses("missing pin", lambda: compose(proj, COMMIT, oa, None, omb, MP, baseline_fn=baseline(), check_commit=False), "pin")
        refuses("missing pin2", lambda: compose(proj, COMMIT, oa, TP, omb, "", baseline_fn=baseline(), check_commit=False), "pin")
        refuses("self-described digest", lambda: run(tp=om["archive"]["sha256"][:63] + ("0" if om["archive"]["sha256"][-1] != "0" else "1")), "pin")
        refuses("bad commit", lambda: compose(proj, "main", oa, TP, omb, MP, baseline_fn=baseline(), check_commit=False), "commit")
        refuses("short commit", lambda: compose(proj, "abc123", oa, TP, omb, MP, baseline_fn=baseline(), check_commit=False), "commit")

        # manifest mutations, re-pinned so only content is wrong
        def mut(fn, needle=None, label=None):
            m = copy.deepcopy(om)
            fn(m)
            b = (json.dumps(m, indent=2, sort_keys=True) + "\n").encode()
            refuses(label or fn.__name__, lambda: run(mf=b, mp=sha256(b)), needle)

        def raw_manifest(b, label, needle=None):
            refuses(label, lambda: run(mf=b, mp=sha256(b)), needle)

        mut(lambda m: m["files"][0].update(bytes=True), "size", "bool_size")
        mut(lambda m: m["totals"].update(files=True), "totals", "bool_count")
        mut(lambda m: m["receipts"]["k64s"].update(source_map_entries=True), "counts", "bool_receipt_count")
        mut(lambda m: m["archive"].update(bytes=True), "bytes", "bool_archive_bytes")
        mut(lambda m: m["files"].append(dict(m["files"][-1])), "duplicated", "dup_entry")
        mut(lambda m: m["files"][0].update(sha256=m["files"][0]["sha256"].upper()), "digest", "upper_digest")
        mut(lambda m: m["files"][0].update(sha256="zz"), "digest", "short_digest")
        mut(lambda m: m["files"][0].update(path="a\x00b.c"), "control", "nul_path")
        mut(lambda m: m["files"][0].update(path="shizukudos/\n.c"), "control", "ctl_path")
        mut(lambda m: m["files"][0].update(path="shizukudos/../x.c"), "refused path", "dotdot_path")
        mut(lambda m: m["files"][0].update(path="zzz/x.c"), "refused path", "outside_allowlist")
        mut(lambda m: m["files"][0].update(path="shizukudos//x.c"), "refused path", "non_normalised")
        mut(lambda m: m["files"][0].update(path="private/x.c"), "refused path", "private_path")
        mut(lambda m: m["files"][0].update(sha256="1" * 64), "does not match", "hash_mismatch")
        mut(lambda m: m["files"][0].update(bytes=m["files"][0]["bytes"] + 1), "", "size_mismatch")
        mut(lambda m: m["totals"].update(bytes=m["totals"]["bytes"] + 1), "totals", "totals_bytes")
        mut(lambda m: m["files"].pop(), "totals", "missing_file")
        mut(lambda m: m["files"][0].update(consumed_by=[]), "consumed_by", "empty_role")
        mut(lambda m: m["files"][0].update(consumed_by=["nope"]), "consumed_by", "unknown_role")
        mut(lambda m: m["files"][0].update(consumed_by=[{}]), "consumed_by", "role_dict")
        mut(lambda m: m["files"][0].update(consumed_by=[m["files"][0]["consumed_by"][0], 1]), "consumed_by", "role_mixed")
        mut(lambda m: m["files"][0].update(consumed_by=[[]]), "consumed_by", "role_list")
        mut(lambda m: m["files"][0].update(consumed_by="k64s"), "consumed_by", "role_string")
        mut(lambda m: m["files"][0].update(extra=1), "keys", "extra_file_key")
        mut(lambda m: m.update(extra=1), "keys", "extra_top_key")
        mut(lambda m: m.pop("limits"), "keys", "missing_top_key")
        mut(lambda m: m.update(full_source_claim=True), "claim", "claim_true")
        mut(lambda m: m.update(release_claim=1), "claim", "claim_truthy_int")
        mut(lambda m: m.update(compliance_claim=0), "claim", "claim_zero_int")
        mut(lambda m: m.update(snapshot_is_commit=True), "snapshot", "snapshot_true")
        mut(lambda m: m.update(schema="x"), "schema", "schema")
        mut(lambda m: m["archive"].update(name="other.tar"), "archive.name", "archive_name")
        mut(lambda m: m["archive"].update(format="tar.gz"), "archive.format", "archive_format")
        mut(lambda m: m["archive"].update(layout="x/<path>"), "archive.layout", "archive_layout")
        mut(lambda m: m["archive"].update(sha256="2" * 64), "pin", "archive_sha_mismatch")
        mut(lambda m: m["archive"].update(bytes=1), "archive.bytes", "archive_bytes")
        mut(lambda m: m["receipts"]["k64s"].update(producer_status="FAIL"), "producer_status", "status_fail")
        mut(lambda m: m["receipts"]["k64s"].update(receipt_sha256="x"), "digest", "receipt_digest")
        mut(lambda m: m["receipts"]["k64s"].update(source_map_entries=9), "does not match", "receipt_entries")
        mut(lambda m: m["receipts"]["k64s"].update(source_map_pointer="evil"), "pointer", "receipt_pointer")
        mut(lambda m: m["receipts"].update(**{"Bad Name": m["receipts"]["pins"]}), "name", "receipt_name")
        mut(lambda m: m["limits"].update(max_files=True), "limits", "bool_limit")
        mut(lambda m: m["git"].update(head="nothex"), "git", "git_head")
        mut(lambda m: m.update(tool_consumed_overlay_sha256="q"), "malformed", "tool_digest")
        raw_manifest(b'{"schema": 1,"schema": 2}', "dup json key", "JSON")
        raw_manifest(b"[1]", "not object")
        raw_manifest(b'{"a": NaN}', "nan json", "JSON")
        raw_manifest(b"\xff\xfe", "bad utf8", "JSON")
        raw_manifest(omb.replace(b'"tools/pin.py"', b'"tools/\\ud800.py"', 1), "surrogate path", "control")
        refuses("oversize result metadata", lambda: run(max_metadata=100), "metadata")

        # tar mutations: manifest archive block repinned to match the bad tar
        def with_tar(label, tar, needle=None, fix_manifest=True):
            m = copy.deepcopy(om)
            if fix_manifest:
                m["archive"]["sha256"], m["archive"]["bytes"] = sha256(tar), len(tar)
            b = (json.dumps(m, indent=2, sort_keys=True) + "\n").encode()
            refuses(label, lambda: run(tar=tar, tp=sha256(tar), mf=b, mp=sha256(b)), needle)

        def mktar(members, fmt=tarfile.GNU_FORMAT):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:
                for name, data, typ, extra in members:
                    ti = tarfile.TarInfo(name)
                    ti.size = len(data) if typ == tarfile.REGTYPE else 0
                    ti.mtime, ti.mode, ti.type = EPOCH, 0o644, typ
                    for k, v in extra.items():
                        setattr(ti, k, v)
                    tf.addfile(ti, io.BytesIO(data) if typ == tarfile.REGTYPE else None)
            return buf.getvalue()

        ofl = co.build_overlay(proj, {"k64s": rp[0], "pins": rp[1]})[2]
        good = [(f"{TOP}/{p}", ofl[p], tarfile.REGTYPE, {}) for p in sorted(ofl)]
        check(mktar(good) == oa, "test tar builder differs from overlay API")
        with_tar("symlink member", mktar([(good[0][0], b"", tarfile.SYMTYPE, {"linkname": "x"})] + good[1:]), "regular")
        with_tar("hardlink member", mktar([(good[0][0], b"", tarfile.LNKTYPE, {"linkname": "x"})] + good[1:]), "regular")
        with_tar("fifo member", mktar([(good[0][0], b"", tarfile.FIFOTYPE, {})] + good[1:]), "regular")
        with_tar("chr member", mktar([(good[0][0], b"", tarfile.CHRTYPE, {})] + good[1:]), "regular")
        with_tar("dir member", mktar([(good[0][0], b"", tarfile.DIRTYPE, {})] + good[1:]), "regular")
        with_tar("extra member", mktar(good + [(f"{TOP}/tools/zzz.py", b"x", tarfile.REGTYPE, {})]), "extra")
        with_tar("missing member", mktar(good[:-1]), "missing")
        with_tar("duplicate member", mktar([good[0]] + good), "name")
        with_tar("wrong name", mktar([("SOURCE/other/" + good[0][0].split("/", 2)[2], good[0][1], tarfile.REGTYPE, {})] + good[1:]), "name")
        with_tar("wrong order", mktar(list(reversed(good))), "name")
        with_tar("wrong mode", mktar([(good[0][0], good[0][1], tarfile.REGTYPE, {"mode": 0o755})] + good[1:]), "metadata")
        with_tar("wrong uid", mktar([(good[0][0], good[0][1], tarfile.REGTYPE, {"uid": 5})] + good[1:]), "metadata")
        with_tar("wrong mtime", mktar([(good[0][0], good[0][1], tarfile.REGTYPE, {"mtime": 1})] + good[1:]), "metadata")
        with_tar("pax format", mktar([(good[0][0], good[0][1], tarfile.REGTYPE, {"pax_headers": {"k": "v"}})] + good[1:], tarfile.PAX_FORMAT), None)
        with_tar("changed bytes", mktar([(good[0][0], b"tampered\n", tarfile.REGTYPE, {})] + good[1:]), "differ")
        with_tar("trailing garbage", oa + b"garbage" * 100, None)
        with_tar("gzip", __import__("gzip").compress(oa, mtime=0), None)
        with_tar("empty tar", b"", None)
        with_tar("not a tar", b"x" * 2048, None)
        with_tar("truncated", oa[:len(oa) // 2], None)
        with_tar("tar/manifest bytes mismatch only", oa + b"\0" * 512, None, fix_manifest=False)
        # content refusal inside a consistently forged overlay
        def forged(path, data, label, needle="content refused", expect_ok=False):
            files2 = dict(ofl)
            files2[path] = data
            tar2 = co.deterministic_archive(files2)
            m = copy.deepcopy(om)
            m["files"] = [{"path": p, "sha256": sha256(files2[p]), "bytes": len(files2[p]),
                           "consumed_by": ["pins"] if p == path else next(e["consumed_by"] for e in om["files"] if e["path"] == p)}
                          for p in sorted(files2)]
            m["totals"] = {"files": len(files2), "bytes": sum(len(v) for v in files2.values())}
            for n in m["receipts"]:
                pairs = [(e["path"], e["sha256"]) for e in m["files"] if n in e["consumed_by"]]
                m["receipts"][n].update(source_map_entries=len(pairs), source_map_snapshot_sha256=sc._snapshot_digest(pairs))
            m["archive"]["sha256"], m["archive"]["bytes"] = sha256(tar2), len(tar2)
            b = (json.dumps(m, indent=2, sort_keys=True) + "\n").encode()
            if expect_ok:
                try:
                    _, mo, _ = run(tar=tar2, tp=sha256(tar2), mf=b, mp=sha256(b))
                    check(mo["counts"]["additions"] == 2, label)
                except MergeError as exc:
                    fails.append(f"{label}: control refused: {exc}")
                return
            refuses(label, lambda: run(tar=tar2, tp=sha256(tar2), mf=b, mp=sha256(b)), needle)

        forged("tools/ok.py", b"print(1)\n", "forge control must validate", expect_ok=True)
        forged("tools/priv.py", b"-----BEGIN RSA PRIVATE KEY-----\n", "private key")
        forged("tools/pk.py", b"ABCDE-12345-ABCDE-12345-ABCDE\n", "product key")
        forged("tools/bin.py", b"a\0b", "binary nul")
        forged("tools/mz.py", b"MZ\x90\x00 x", "MZ magic")
        forged("tools/tok.py", b"ghp_" + b"A" * 36, "token")
        forged("tools/id_rsa", b"x\n", "secret name", "refused path")
        forged("tools/a.exe", b"x\n", "binary suffix", "refused path")
        forged("shizukudos/kernel64/main.c/sub.c", b"x\n", "file/dir prefix conflict", "prefix")

        # baseline refusals
        def bl(label, entries, needle=None, rejected=()):
            def fn(root, commit, roots, req, rej):
                return entries, []
            refuses(label, lambda: run(baseline_fn=fn), needle)
        d = b"x\n"
        bl("baseline dup", [("tools/a.py", "100644", blob(d), d)] * 2, "duplicate")
        bl("baseline ctl path", [("tools/a\nb.py", "100644", blob(d), d)], "control")
        bl("baseline nul path", [("tools/a\x00.py", "100644", blob(d), d)], "control")
        bl("baseline outside", [("zzz/a.py", "100644", blob(d), d)], "refused path")
        bl("baseline bad blob", [("tools/a.py", "100644", "0" * 40, d)], "blob hash")
        bl("baseline bad mode", [("tools/a.py", "120000", blob(d), d)], "mode")
        bl("baseline malformed", [("tools/a.py",)], "malformed")
        bl("baseline too large", [("tools/a.py", "100644", blob(b"x" * (MAX_FILE + 1)), b"x" * (MAX_FILE + 1))], "too large")
        bl("baseline prefix", [("tools/a", "100644", blob(d), d), ("tools/a/b", "100644", blob(d), d)], "prefix")
        # stronger content guard: baseline file is disclosed, not shipped, and cannot be overridden
        mzd = b"MZ\x90\x00 text"
        def mz_fn(root, commit, roots, req, rej):
            return [("tools/mz.py", "100644", blob(mzd), mzd), ("README.md", "100644", blob(b"r"), b"r")], []
        _, mmz, fmz = run(baseline_fn=mz_fn)
        check("tools/mz.py" not in fmz and mmz["baseline"]["guard_rejected"]["listed"][0]["reason"].startswith("overlay-guard-"),
              "stronger baseline guard not disclosed")
        def boom_fn(root, commit, roots, req, rej):
            raise sc.CapsuleError("x")
        refuses("baseline read failure", lambda: run(baseline_fn=boom_fn), "baseline read")
        # bounds before output
        refuses("max files", lambda: run(max_files=3), "count")
        refuses("max total", lambda: run(max_total=20), "total")
        refuses("max archive", lambda: run(max_archive=1000), "archive")
        refuses("bad roots", lambda: run(roots=("nope",)), "roots")
        os.symlink(proj, td / "projlink")
        refuses("root symlink", lambda: compose(td / "projlink", COMMIT, oa, TP, omb, MP, baseline_fn=baseline(), check_commit=False), "root")
        refuses("root missing", lambda: compose(td / "nolink", COMMIT, oa, TP, omb, MP, baseline_fn=baseline(), check_commit=False), "root")
        refuses("sha256 commit name", lambda: compose(proj, "a" * 64, oa, TP, omb, MP, baseline_fn=baseline(), check_commit=False), "commit")

        # commit binding (faked sc.git, no git): raw commit object must hash to the pinned name; tree is recorded
        tree_id = "b" * 40
        cbody = b"tree " + tree_id.encode() + b"\nauthor x <x> 1 +0000\ncommitter x <x> 1 +0000\n\nmsg\n"
        creal = hashlib.sha1(b"commit %d\0" % len(cbody) + cbody).hexdigest()
        real_git, seen_env = sc.git, []
        real_env_before = os.environ.get("GIT_NO_REPLACE_OBJECTS")

        def fake(result):
            def g(root, *a, check=True):
                seen_env.append((a, os.environ.get("GIT_NO_REPLACE_OBJECTS")))
                if isinstance(result, BaseException):
                    raise result
                return result
            return g

        def with_git(result, **kw):
            sc.git = fake(result)
            try:
                return compose(proj, kw.pop("commit", creal), oa, TP, omb, MP, baseline_fn=baseline(), **kw)
            finally:
                sc.git = real_git
        _, mc, _ = with_git(cbody)
        check(mc["baseline"]["tree"] == tree_id and mc["baseline"]["commit"] == creal, "tree not recorded")
        check(seen_env and seen_env[0][0][:2] == ("cat-file", "commit") and seen_env[0][1] == "1", "no-replace env not set")
        check(os.environ.get("GIT_NO_REPLACE_OBJECTS") == real_env_before, "env not restored")
        refuses("commit hash mismatch (replaced/peeled object)", lambda: with_git(cbody.replace(tree_id.encode(), b"c" * 40)), "hash")
        refuses("commit empty output", lambda: with_git(b""), "unreadable")
        refuses("commit OSError", lambda: with_git(OSError("x")), "unreadable")
        nt = b"parent " + tree_id.encode() + b"\n\nmsg\n"
        refuses("commit without tree", lambda: with_git(nt, commit=hashlib.sha1(b"commit %d\0" % len(nt) + nt).hexdigest()), "tree header")
        check(sc.git is real_git, "sc.git not restored")
        for var in GIT_REDIRECT_ENV:
            os.environ[var] = "/nonexistent"
            try:
                refuses("env " + var, lambda: with_git(cbody), "redirection")
            finally:
                del os.environ[var]
        # narrowed roots: overlay path outside the selected roots is refused, not counted as an addition
        refuses("outside narrowed roots", lambda: run(roots=("docs",)), "outside the selected")

        # read_bounded
        (td / "reg").write_bytes(b"abc")
        check(read_bounded(td / "reg", 10) == b"abc", "read_bounded")
        os.symlink(td / "reg", td / "lnk")
        refuses("read symlink", lambda: read_bounded(td / "lnk", 10), "symlink")
        refuses("read too big", lambda: read_bounded(td / "reg", 2), "larger")
        refuses("read dir", lambda: read_bounded(td, 10), "regular")
        os.mkfifo(td / "ff")
        refuses("read fifo", lambda: read_bounded(td / "ff", 10), "regular")
        refuses("read missing", lambda: read_bounded(td / "nope", 10), "unreadable")

        # CLI --check read-only, --out atomic
        ot, om_p = td / "ov.tar", td / "ov.json"
        ot.write_bytes(oa)
        om_p.write_bytes(omb)
        args = ["--root", str(proj), "--commit", COMMIT, "--overlay-tar", str(ot), "--overlay-tar-sha256", TP,
                "--overlay-manifest", str(om_p), "--overlay-manifest-sha256", MP]

        def snap(p):
            return sorted((str(x.relative_to(p)), x.lstat().st_mtime_ns, x.lstat().st_size) for x in p.rglob("*"))
        hook = dict(_baseline=baseline(), _check_commit=False)
        before = snap(td)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(args + ["--check"], **hook)
        o = json.loads(buf.getvalue())
        check(rc == 0 and o["ok"] is True and o["manifest"] == json.loads(manifest_bytes(m1)), "check output")
        check(snap(td) == before, "--check wrote something")
        mal = copy.deepcopy(om)
        mal["files"][0]["consumed_by"] = [{}]
        malb = (json.dumps(mal, indent=2, sort_keys=True) + "\n").encode()
        om_bad = td / "bad.json"
        om_bad.write_bytes(malb)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(args[:-3] + [str(om_bad), "--overlay-manifest-sha256", sha256(malb), "--check"], **hook)
        o = json.loads(buf.getvalue())
        check(rc == 1 and o["ok"] is False and "consumed_by" in o["error"], "malformed role CLI refusal not structured")
        check(sys.dont_write_bytecode is True and not list(_HERE.glob("__pycache__")), "bytecode guard / pycache")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(args[:-1] + ["0" * 64, "--check"], **hook)
        check(rc == 1 and json.loads(buf.getvalue())["ok"] is False, "check failure rc")
        dest = td / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(args + ["--out", str(dest)], **hook)
        check(rc == 0 and sorted(p.name for p in dest.iterdir()) == sorted([ARCHIVE_NAME, MANIFEST_NAME]), "out contents")
        check((dest / ARCHIVE_NAME).read_bytes() == a1 and (dest / MANIFEST_NAME).read_bytes() == mb, "out bytes")
        check(ot.read_bytes() == oa and om_p.read_bytes() == omb, "input modified")
        check(not [p for p in td.iterdir() if p.name.startswith(".merge-tmp")], "temp left")
        refuses("nonempty out", lambda: write_out(dest, a1, m1), "no overwrite")
        (td / "file_out").write_bytes(b"x")
        refuses("out is file", lambda: write_out(td / "file_out", a1, m1), "no overwrite")
        check((td / "file_out").read_bytes() == b"x", "colliding file touched")
        os.symlink(dest, td / "outlink")
        refuses("out symlink", lambda: write_out(td / "outlink", a1, m1), "symlink")
        refuses("out parent missing", lambda: write_out(td / "nodir" / "o", a1, m1), "parent")
        empty = td / "empty"
        empty.mkdir()
        write_out(empty, a1, m1)
        check((empty / MANIFEST_NAME).is_file(), "empty out dir unused")
        # failed compose via CLI leaves no output
        bad_dest = td / "bad_out"
        with contextlib.redirect_stderr(io.StringIO()):
            rc = main(args[:-1] + ["1" * 64, "--out", str(bad_dest)], **hook)
        check(rc == 1 and not bad_dest.exists(), "failed CLI left output")
        # atomic failure: injected rename failure
        real_rename = os.rename

        def boom(a, b):
            raise OSError("injected")
        for label, target, pre in (("fresh", td / "failout", False), ("existing empty", td / "keepdir", True)):
            if pre:
                target.mkdir()
            os.rename = boom
            try:
                write_out(target, a1, m1)
                fails.append(f"injected rename failure not raised ({label})")
            except OSError:
                pass
            finally:
                os.rename = real_rename
            check(target.exists() == pre and (not pre or not list(target.iterdir())), f"{label}: output state wrong")
            check(not [p for p in td.iterdir() if p.name.startswith(".merge-tmp")], f"{label}: temp left")
        check(ot.read_bytes() == oa, "input not preserved after failure")
    elapsed = time.time() - t0
    check(elapsed <= 60, f"self-test took {elapsed:.1f}s")
    if fails:
        for f in fails:
            print("FAIL:", f, file=sys.stderr)
        print(f"project_source_merge self-test: FAIL ({len(fails)})")
        return 1
    print(f"project_source_merge self-test: PASS ({elapsed:.1f}s)")
    return 0


def main(argv: list[str] | None = None, *, _baseline=None, _check_commit=True) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root")
    ap.add_argument("--commit", help="full 40/64 lowercase hex commit object name")
    ap.add_argument("--overlay-tar")
    ap.add_argument("--overlay-tar-sha256")
    ap.add_argument("--overlay-manifest")
    ap.add_argument("--overlay-manifest-sha256")
    ap.add_argument("--project-root", action="append", default=None, metavar="ALLOWLISTED",
                    help="narrow the baseline to a subset of the public allowlist (recorded in the manifest)")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--out", metavar="DIR")
    mode.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    try:
        for opt in ("root", "commit", "overlay_tar", "overlay_tar_sha256", "overlay_manifest", "overlay_manifest_sha256"):
            if not getattr(a, opt):
                raise MergeError(f"--{opt.replace('_', '-')} is required")
        mfst = read_bounded(a.overlay_manifest, MAX_METADATA)
        tar = read_bounded(a.overlay_tar, MAX_ARCHIVE)
        archive, manifest, _ = compose(a.root, a.commit, tar, a.overlay_tar_sha256, mfst, a.overlay_manifest_sha256,
                                       roots=tuple(a.project_root) if a.project_root else sc.DEFAULT_PROJECT_ROOTS,
                                       baseline_fn=_baseline, check_commit=_check_commit)
        if a.check:
            print(json.dumps({"ok": True, "manifest": manifest}, indent=2, sort_keys=True))
            return 0
        write_out(a.out, archive, manifest)
        print(json.dumps({"ok": True, "out": a.out, "archive_sha256": manifest["archive"]["sha256"],
                          "files": manifest["totals"]["files"]}, sort_keys=True))
        return 0
    except (MergeError, co.OverlayError, OSError, ValueError, sc.CapsuleError) as exc:
        if a.check:
            print(json.dumps({"ok": False, "error": ascii(str(exc))[1:-1]}, sort_keys=True))
        else:
            print(f"project_source_merge: refused: {ascii(str(exc))[1:-1]}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
