#!/usr/bin/env python3
"""Source-only snapshot of the exact bytes named by producer source maps.

Producer receipts (for example the K64S result with source_before/before, or an installer pins file with sources)
record {relative path: sha256}.  This tool reads ONLY those named paths (union, de-duplicated), once each, requires
every byte string to equal its recorded SHA-256, and snapshots them -- dirty and untracked files included -- into a
deterministic plain tar (no compression, so bytes do not depend on the host zlib) plus a manifest.  Nothing is traversed, searched, cached, downloaded or written to Git.

This is NOT a full source capsule, GPL/LGPL/upstream corresponding-source closure, licence closure, release claim,
reproducible-binary claim or OS/DOS/EFI/install/Win98 proof.  All of those manifest claims are false.  A snapshot is
not a commit; the optional Git HEAD is only a reference to the checkout it was taken from.

Reuses source_capsule guards, _source_map, strict_json and read_named_source (same directory, imported unchanged).

CLI (exactly one mode):
  --root PROJECT --receipt NAME=PATH [--receipt ...] --check            read-only, JSON on stdout
  --root PROJECT --receipt NAME=PATH [--receipt ...] --out DIR          DIR absent or empty; created atomically
  --self-test
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True  # never write __pycache__ for source_capsule.py (read-only --check)


def _load_capsule():
    spec = importlib.util.spec_from_file_location("_overlay_source_capsule", _HERE / "source_capsule.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


sc = _load_capsule()

SCHEMA = "shizuku-consumed-overlay/1"
ARCHIVE_NAME = "overlay-source.tar"
MANIFEST_NAME = "overlay-manifest.json"
TOP = "SOURCE/project"
EPOCH = sc.FIXED_EPOCH
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILES = 10000
MAX_RECEIPTS = 16
MAX_METADATA = 8 * 1024 * 1024
MAX_ARCHIVE = MAX_TOTAL + MAX_FILES * 1024 + (1 << 20)
ROLE_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
EXTRA_SECRET_RE = re.compile(rb"(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|xox[abprs]-[A-Za-z0-9-]{10,})")
MAGICS = (  # (offset, magic, reason)
    (0, b"MZ", "pe-or-dos-executable"), (0, b"\x7fELF", "elf"), (0, b"PK\x03\x04", "zip"),
    (0, b"\x1f\x8b", "gzip"), (0, b"MSCF", "cab"), (0, b"conectix", "vhd"), (0, b"KDMV", "vmdk"),
    (0, b"QFI\xfb", "qcow2"), (0, b"vhdxfile", "vhdx"), (0, b"\x03\xd9\xa2\x9a", "kdbx-key-database"),
    (0, b"PuTTY-User-Key-File", "putty-key"), (0, b"-----BEGIN", "pem-block"),
    (0, b"\x4d\x53\x57\x49\x4d", "wim"), (0x8001, b"CD001", "iso9660"),
    (0, b"\xfd7zXZ", "xz"),
    (0, b"7z\xbc\xaf", "7z"), (0, b"EFI PART", "gpt-header"), (512, b"EFI PART", "gpt-disk"),
)


class OverlayError(RuntimeError):
    pass


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def content_refusal(data: bytes) -> str | None:
    why = sc.guard_content(data)
    if why:
        return why
    if EXTRA_SECRET_RE.search(data):
        return "token-shaped-content"
    for off, magic, reason in MAGICS:
        if data[off:off + len(magic)] == magic:
            return "binary-magic-" + reason
    if len(data) >= 512 and data[510:512] == b"\x55\xaa" and b"\0" in data[:512]:
        return "binary-magic-boot-sector"
    if b"\0" in data[:8192]:
        return "binary-content"
    return None


SNAPSHOT_STATUS = {"pass", "passed", "ok", "success", "succeeded", "verified",
                   "built_pending_guest_validation"}
# A completed build can name source bytes before its guest qualification. Preserve
# that status in the snapshot; accepting it never establishes runtime acceptance.


def check_path_text(rel: str) -> None:
    """Refuse NUL, control characters/newlines and lone surrogates before the path is used anywhere."""
    for ch in rel:
        o = ord(ch)
        if o < 32 or o == 127 or 0xD800 <= o <= 0xDFFF:
            raise OverlayError(f"source path {ascii(rel)} contains a control character or invalid code point")


def parse_receipt_args(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    if not items:
        raise OverlayError("at least one --receipt NAME=PATH is required")
    if len(items) > MAX_RECEIPTS:
        raise OverlayError(f"more than {MAX_RECEIPTS} receipts")
    for item in items:
        name, eq, path = item.partition("=")
        if not eq or not path:
            raise OverlayError("receipt must be NAME=PATH")
        if not ROLE_RE.fullmatch(name):
            raise OverlayError("receipt name must be normalised ASCII [a-z0-9][a-z0-9_-]{0,31}")
        if name in out:
            raise OverlayError(f"duplicate receipt name {name}")
        out[name] = path
    return out


def read_receipt(name: str, path: str) -> tuple[bytes, dict, str, dict]:
    try:
        raw = sc._read_receipt_file(Path(path))
    except OSError as exc:
        raise OverlayError(f"{name}: receipt unreadable ({exc.__class__.__name__})") from None
    why = content_refusal(raw)
    if why:
        raise OverlayError(f"{name}: receipt refused ({why})")
    try:
        doc = sc.strict_json(raw)
    except ValueError as exc:
        raise OverlayError(f"{name}: receipt is not strict JSON ({exc})") from None
    if not isinstance(doc, dict) or not doc:
        raise OverlayError(f"{name}: receipt is not a non-empty JSON object")
    if "$schema" in doc or "$id" in doc or (isinstance(doc.get("properties"), dict) and "type" in doc):
        raise OverlayError(f"{name}: JSON Schema style document, not a producer receipt")
    st = doc.get("status")
    if "status" in doc and not (isinstance(st, str) and st.strip().lower() in SNAPSHOT_STATUS):
        raise OverlayError(f"{name}: receipt status does not name a completed build ({ascii(st)[:40]})")
    if "inputs_unchanged" in doc and doc["inputs_unchanged"] is not True:
        raise OverlayError(f"{name}: receipt inputs_unchanged is not true")
    pointers, smap = [], {}
    for pointer in sc.SOURCE_MAP_POINTERS:
        if not sc._present(doc, pointer):
            continue
        found = sc._dig(doc, pointer)
        if not isinstance(found, dict) or not found:
            raise OverlayError(f"{name}: {pointer} is not a non-empty object")
        if not all(isinstance(k, str) and k and isinstance(v, str) and sc.HEX64.fullmatch(v) for k, v in found.items()):
            raise OverlayError(f"{name}: {pointer} is not a map of path -> 64 lowercase hex SHA-256")
        for rel, want in found.items():
            check_path_text(rel)
            if rel in smap and smap[rel] != want:
                raise OverlayError(f"{name}: hash conflict for {ascii(rel)} between source maps in one receipt")
            smap[rel] = want
        pointers.append(pointer)
    if not smap:
        raise OverlayError(f"{name}: no usable source map (none of {list(sc.SOURCE_MAP_POINTERS)})")
    if "source_after" in doc:
        after = doc["source_after"]
        if not isinstance(after, dict) or after != smap:
            raise OverlayError(f"{name}: source_after does not equal the recorded source maps")
    return raw, doc, "+".join(pointers), smap


def git_head(root: Path) -> dict:
    info = {"head": None, "note": "Git HEAD is a reference to the checkout this snapshot was taken from; the snapshot "
            "itself is the named working-tree bytes (possibly dirty/untracked) and is not that commit."}
    try:
        out = sc.git(root, "rev-parse", "--verify", "HEAD", check=False).decode().strip()
    except OSError:
        return info
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", out):
        info["head"] = out
    return info


def build_overlay(root, receipts: dict[str, str], *, with_git: bool = False, max_total: int = MAX_TOTAL,
                  max_files: int = MAX_FILES) -> tuple[bytes, dict, dict[str, bytes]]:
    """Returns (archive bytes, manifest dict, {path: exact bytes}).  Raises OverlayError on any refused input."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise OverlayError("root is not a real directory")
    root = root.resolve()
    if not receipts or len(receipts) > MAX_RECEIPTS:
        raise OverlayError("receipt count out of bounds")
    for name in receipts:
        if not ROLE_RE.fullmatch(name):
            raise OverlayError("receipt name not normalised ASCII")
    rec_meta: dict[str, dict] = {}
    wanted: dict[str, str] = {}
    roles: dict[str, set] = {}
    seen_raw: dict[str, str] = {}
    seen_real: dict[str, str] = {}
    meta_bytes = 0
    for name in sorted(receipts):
        real = os.path.realpath(receipts[name])
        if real in seen_real:
            raise OverlayError(f"{name}: same receipt file as {seen_real[real]}")
        seen_real[real] = name
        raw, _doc, pointer, smap = read_receipt(name, receipts[name])
        meta_bytes += len(raw)
        if meta_bytes > MAX_METADATA:
            raise OverlayError("receipt metadata budget exceeded")
        digest = sha256(raw)
        if digest in seen_raw:
            raise OverlayError(f"{name}: receipt bytes duplicate {seen_raw[digest]}")
        seen_raw[digest] = name
        for rel, want in smap.items():
            if rel in wanted and wanted[rel] != want:
                raise OverlayError(f"hash conflict for {ascii(rel)}: receipts disagree")
            wanted[rel] = want
            roles.setdefault(rel, set()).add(name)
        rec_meta[name] = {"receipt_sha256": digest, "receipt_bytes": len(raw), "source_map_pointer": pointer,
                          "producer_status": _doc.get("status"),
                          "source_map_entries": len(smap),
                          "source_map_snapshot_sha256": sc._snapshot_digest(smap.items())}
    if len(wanted) > max_files:
        raise OverlayError(f"{len(wanted)} unique source files exceeds limit {max_files}")
    for rel in wanted:
        why = sc._named_source_ok(rel)
        if why:
            raise OverlayError(f"{ascii(rel)}: refused path ({why})")
    files: dict[str, bytes] = {}
    total = 0
    for rel in sorted(wanted):
        data, why = sc.read_named_source(root, rel)
        if why:
            raise OverlayError(f"{ascii(rel)}: {why}")
        total += len(data)
        if total > max_total:
            raise OverlayError(f"total source bytes exceed {max_total}")
        why = content_refusal(data)
        if why:
            raise OverlayError(f"{ascii(rel)}: content refused ({why})")
        if sha256(data) != wanted[rel]:
            raise OverlayError(f"{ascii(rel)}: stale, current bytes differ from recorded sha256")
        files[rel] = data
    archive = deterministic_archive(files)
    if len(archive) > MAX_ARCHIVE:
        raise OverlayError("archive budget exceeded")
    manifest = {
        "schema": SCHEMA,
        "kind": "source-only-snapshot",
        "snapshot_is_commit": False,
        "archive": {"name": ARCHIVE_NAME, "sha256": sha256(archive), "bytes": len(archive),
                    "layout": TOP + "/<path>", "format": "plain GNU tar, uncompressed", "mtime": EPOCH, "uid": 0, "gid": 0, "mode": "0644"},
        "tool_source_capsule_sha256": sha256((_HERE / "source_capsule.py").read_bytes()),
        "limits": {"max_file": MAX_FILE, "max_total": max_total, "max_files": max_files,
                   "max_receipts": MAX_RECEIPTS},
        "tool_consumed_overlay_sha256": sha256(Path(__file__).read_bytes()),
        "receipts": rec_meta,
        "receipt_note": "Only receipt SHA-256 digests and source-map digests are recorded; raw receipts and their "
                        "paths are not shipped.",
        "files": [{"path": rel, "sha256": sha256(files[rel]), "bytes": len(files[rel]),
                   "consumed_by": sorted(roles[rel])} for rel in sorted(files)],
        "totals": {"files": len(files), "bytes": total},
        "git": git_head(root) if with_git else {"head": None, "note": "not requested"},
        "full_source_claim": False,
        "license_closure_claim": False,
        "gpl_corresponding_source_claim": False,
        "upstream_closure_claim": False,
        "compliance_claim": False,
        "release_claim": False,
        "reproducible_binary_claim": False,
        "compiled_binary_binding_claim": False,
        "os_qualification_claim": False,
        "efi_dos_install_win98_proof_claim": False,
        "limitation": "Source-only snapshot of exactly the files named by the given source maps.  It does not by itself "
                      "establish GPL/upstream/EFI/DOS/install/Win98 proof, a reproducible binary, or licence closure.",
    }
    if len(json.dumps(manifest)) > MAX_METADATA:
        raise OverlayError("manifest metadata budget exceeded")
    return archive, manifest, files


def deterministic_archive(files: dict[str, bytes]) -> bytes:
    tbuf = io.BytesIO()
    with tarfile.open(fileobj=tbuf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for rel in sorted(files):
            ti = tarfile.TarInfo(f"{TOP}/{rel}")
            ti.size = len(files[rel])
            ti.mtime = EPOCH
            ti.mode = 0o644
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            ti.type = tarfile.REGTYPE
            tf.addfile(ti, io.BytesIO(files[rel]))
    return tbuf.getvalue()


def manifest_bytes(manifest: dict) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()


def write_out(out, archive: bytes, manifest: dict) -> None:
    out = Path(out)
    if out.is_symlink():
        raise OverlayError("--out is a symlink")
    parent = out.parent
    if parent.is_symlink() or not parent.is_dir():
        raise OverlayError("--out parent is not a real directory")
    if out.exists():
        if not out.is_dir() or any(out.iterdir()):
            raise OverlayError("--out exists and is not an empty directory (no overwrite)")
    tmp = Path(tempfile.mkdtemp(prefix=".overlay-tmp-", dir=parent))
    try:
        for name, data in ((ARCHIVE_NAME, archive), (MANIFEST_NAME, manifest_bytes(manifest))):
            fd = os.open(tmp / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        os.chmod(tmp, 0o755)
        os.rename(tmp, out)  # onto an empty directory this replaces it atomically; on failure out is untouched
        try:
            dfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


# --- self test -----------------------------------------------------------------
def _self_test() -> int:
    import contextlib
    import time
    t0 = time.time()
    fails: list[str] = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    def refuses(msg, fn, needle=None):
        try:
            fn()
        except OverlayError as exc:
            check(needle is None or needle in str(exc), f"{msg}: wrong reason {exc}")
            return
        fails.append(f"{msg}: not refused")

    with tempfile.TemporaryDirectory(prefix="overlay-st-") as td:
        td = Path(td)
        root = td / "proj"
        (root / "shizukudos/kernel64").mkdir(parents=True)
        (root / "tools").mkdir()
        files = {"shizukudos/kernel64/main.c": b"int main(void){return 0;}\n",  # "dirty"
                 "shizukudos/kernel64/new_untracked.c": b"/* untracked */\n",
                 "tools/pin.py": b"print('x')\n"}
        for rel, data in files.items():
            (root / rel).write_bytes(data)
        h = {rel: sha256(d) for rel, d in files.items()}
        rd = td / "rcpt"
        rd.mkdir()

        def rcpt(name, doc=None, raw=None):
            p = rd / name
            p.write_bytes(raw if raw is not None else json.dumps(doc).encode())
            return str(p)

        k64 = rcpt("k64.json", {"source_before": {"shizukudos/kernel64/main.c": h["shizukudos/kernel64/main.c"],
                                                   "shizukudos/kernel64/new_untracked.c": h["shizukudos/kernel64/new_untracked.c"]}})
        pins = rcpt("pins.json", {"sources": {"shizukudos/kernel64/main.c": h["shizukudos/kernel64/main.c"],
                                               "tools/pin.py": h["tools/pin.py"]}, "note": "SECRET-PATH-" + str(rd)})
        good = {"k64s": k64, "installer": pins}
        a1, m1, f1 = build_overlay(root, good)
        a2, m2, _ = build_overlay(root, good)
        check(a1 == a2 and m1 == m2, "archive/manifest not deterministic")
        check(f1 == files, "exact dirty/untracked bytes not retained")
        check([f["path"] for f in m1["files"]] == sorted(files), "union/dedupe wrong")
        main_entry = [f for f in m1["files"] if f["path"].endswith("main.c")][0]
        check(main_entry["consumed_by"] == ["installer", "k64s"], "overlap roles wrong")
        with tarfile.open(fileobj=io.BytesIO(a1), mode="r:") as tf:
            ms = tf.getmembers()
            check([m.name for m in ms] == [f"{TOP}/{p}" for p in sorted(files)], "tar names/order")
            check(all(m.mtime == EPOCH and m.uid == 0 and m.gid == 0 and m.mode == 0o644 and not m.uname for m in ms),
                  "tar metadata not fixed")
            check(tf.extractfile(ms[0]).read() == files[ms[0].name[len(TOP) + 1:]], "tar content")
        mb = manifest_bytes(m1)
        check(str(td).encode() not in mb and b"SECRET-PATH" not in mb, "paths/raw receipt leaked in manifest")
        claims = [k for k in m1 if k.endswith("_claim")]
        check(len(claims) >= 8 and not any(m1[k] for k in claims) and m1["snapshot_is_commit"] is False, "claims")
        # source map digest independent of absolute root
        root2 = td / "other-root-name"
        shutil.copytree(root, root2)
        _, m3, _ = build_overlay(root2, good)
        check(m3 == m1, "manifest depends on root path")

        # refusals
        refuses("dup name", lambda: parse_receipt_args(["a=x", "a=y"]), "duplicate")
        refuses("bad name", lambda: parse_receipt_args(["Bad Name=x"]), "normalised")
        refuses("same receipt twice", lambda: build_overlay(root, {"a": k64, "b": k64}), "same receipt")
        refuses("dup json key", lambda: build_overlay(root, {"a": rcpt("d.json", raw=b'{"sources":{},"sources":{}}')}), "JSON")
        refuses("schema doc", lambda: build_overlay(root, {"a": rcpt("s.json", {"$schema": "x", "sources": {"tools/pin.py": h["tools/pin.py"]}})}), "Schema")
        refuses("no source map", lambda: build_overlay(root, {"a": rcpt("n.json", {"x": 1})}), "no usable")
        refuses("malformed digest", lambda: build_overlay(root, {"a": rcpt("m.json", {"sources": {"tools/pin.py": h["tools/pin.py"].upper()}})}), "64 lowercase")
        refuses("bad path", lambda: build_overlay(root, {"a": rcpt("p.json", {"sources": {"../x": "0" * 64}})}), "refused path")
        refuses("conflict", lambda: build_overlay(root, {"a": pins, "b": rcpt("c.json", {"sources": {"tools/pin.py": "1" * 64}})}), "hash conflict")
        refuses("stale", lambda: build_overlay(root, {"a": rcpt("st.json", {"sources": {"tools/pin.py": "2" * 64}})}), "stale")
        refuses("missing", lambda: build_overlay(root, {"a": rcpt("mi.json", {"sources": {"tools/gone.py": "3" * 64}})}), "missing")
        refuses("missing receipt", lambda: build_overlay(root, {"a": str(rd / "nope.json")}), "unreadable")
        refuses("too many files", lambda: build_overlay(root, good, max_files=2), "exceeds")
        refuses("total budget", lambda: build_overlay(root, good, max_total=10), "total")
        # bad content
        bad = {"wrong.c": b"x", "tools/priv.py": b"-----BEGIN RSA PRIVATE KEY-----\n",
               "tools/key.txt": b"ABCDE-12345-ABCDE-12345-ABCDE\n", "tools/mz.txt": b"MZ\x90\x00 text",
               "tools/elf.c": b"\x7fELF\x02\x01", "tools/nul.c": b"a\0b", "tools/tok.c": b"AKIA" + b"A" * 16}
        for rel, data in bad.items():
            if rel == "wrong.c":
                continue
            (root / rel).write_bytes(data)
            refuses("content " + rel, lambda rel=rel, data=data: build_overlay(
                root, {"a": rcpt("b.json", {"sources": {rel: sha256(data)}})}), "content refused")
        # wrong hash on otherwise good file handled by stale above; symlink and FIFO
        os.symlink(root / "tools/pin.py", root / "tools/link.py")
        refuses("symlink", lambda: build_overlay(root, {"a": rcpt("l.json", {"sources": {"tools/link.py": h["tools/pin.py"]}})}), "symlink")
        os.mkfifo(root / "tools/fifo.py")
        refuses("fifo", lambda: build_overlay(root, {"a": rcpt("f.json", {"sources": {"tools/fifo.py": "4" * 64}})}), "not-regular")
        (root / "private").mkdir()
        (root / "private/s.c").write_bytes(b"x")
        refuses("private dir", lambda: build_overlay(root, {"a": rcpt("pd.json", {"sources": {"private/s.c": sha256(b"x")}})}), "refused path")
        refuses("outside roots", lambda: build_overlay(root, {"a": rcpt("o.json", {"sources": {"zzz/s.c": sha256(b"x")}})}), "refused path")

        # receipt status / inputs_unchanged / source_after
        sm = {"tools/pin.py": h["tools/pin.py"]}
        refuses("status FAIL", lambda: build_overlay(root, {"a": rcpt("sf.json", {"status": "FAIL", "sources": sm})}), "status")
        refuses("status non-string", lambda: build_overlay(root, {"a": rcpt("sn.json", {"status": 1, "sources": sm})}), "status")
        refuses("inputs changed", lambda: build_overlay(root, {"a": rcpt("ic.json", {"inputs_unchanged": False, "sources": sm})}), "inputs_unchanged")
        refuses("source_after mismatch", lambda: build_overlay(root, {"a": rcpt("sa.json", {"source_before": sm, "source_after": {"tools/pin.py": "5" * 64}})}), "source_after")
        ok_doc = {"status": "PASS", "inputs_unchanged": True, "source_before": sm, "source_after": sm}
        build_overlay(root, {"a": rcpt("okp.json", ok_doc)})
        # several source maps: union, never drop one; conflicts refused
        two = rcpt("two.json", {"sources": sm, "source_before": {"tools/pin.py": h["tools/pin.py"],
                                "shizukudos/kernel64/main.c": h["shizukudos/kernel64/main.c"]}})
        _, m4, f4 = build_overlay(root, {"a": two})
        check(sorted(f4) == ["shizukudos/kernel64/main.c", "tools/pin.py"] and
              m4["receipts"]["a"]["source_map_pointer"] == "sources+source_before", "multi-map union")
        refuses("multi-map conflict", lambda: build_overlay(root, {"a": rcpt("mc.json", {"sources": sm, "before": {"tools/pin.py": "6" * 64}})}), "hash conflict")
        refuses("multi-map malformed later", lambda: build_overlay(root, {"a": rcpt("mm.json", {"sources": sm, "before": {"tools/pin.py": "zz"}})}), "64 lowercase")
        # control characters / NUL / lone surrogate in paths: OverlayError, no traceback, --check still JSON
        for i, key in enumerate(("tools/a\nb.py", "tools/a\x00b.py", "tools/a\x1fb.py", "tools/a\x7fb.py")):
            refuses("ctl path %d" % i, lambda key=key: build_overlay(root, {"a": rcpt("cp.json", {"sources": {key: "7" * 64}})}), "control character")
        sur = rcpt("sur.json", raw=b'{"sources": {"tools/\\ud800.py": "' + b"7" * 64 + b'"}}')
        refuses("surrogate path", lambda: build_overlay(root, {"a": sur}), "control character")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--root", str(root), "--receipt", "a=" + sur, "--check"])
        check(rc == 1 and json.loads(buf.getvalue())["ok"] is False, "surrogate check JSON")
        # archive is plain tar and independent of zlib
        check(a1[:2] != b"\x1f\x8b" and a1[257:262] == b"ustar", "archive not plain tar")
        check(m1["tool_consumed_overlay_sha256"] == sha256(Path(__file__).read_bytes()), "own sha not recorded")

        # --check is read only, JSON on stdout
        def snap(p):
            return sorted((str(x.relative_to(p)), x.lstat().st_mtime_ns, x.lstat().st_size) for x in p.rglob("*"))
        before = snap(td)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--root", str(root), "--receipt", f"k64s={k64}", "--receipt", f"installer={pins}", "--check"])
        out = json.loads(buf.getvalue())
        check(rc == 0 and out["ok"] is True and out["manifest"] == json.loads(mb), "check output")
        check(snap(td) == before, "--check wrote something")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--root", str(root), "--receipt", "a=" + str(rd / "n.json"), "--check"])
        check(rc == 1 and json.loads(buf.getvalue())["ok"] is False, "check failure rc")

        # --out
        dest = td / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(["--root", str(root), "--receipt", f"k64s={k64}", "--receipt", f"installer={pins}", "--out", str(dest)])
        check(rc == 0 and sorted(p.name for p in dest.iterdir()) == [MANIFEST_NAME, ARCHIVE_NAME], "out contents")
        check((dest / ARCHIVE_NAME).read_bytes() == a1 and (dest / MANIFEST_NAME).read_bytes() == mb, "out bytes")
        check(not [p for p in td.iterdir() if p.name.startswith(".overlay-tmp")], "temp left")
        refuses("existing nonempty out", lambda: write_out(dest, a1, m1), "no overwrite")
        empty = td / "empty"
        empty.mkdir()
        write_out(empty, a1, m1)
        check((empty / MANIFEST_NAME).is_file(), "empty out dir not used")
        os.symlink(dest, td / "outlink")
        refuses("out symlink", lambda: write_out(td / "outlink", a1, m1), "symlink")
        refuses("out parent missing", lambda: write_out(td / "nodir" / "o", a1, m1), "parent")
        # write failure leaves nothing
        real_rename, fail_dest = os.rename, td / "failout"

        def boom(a, b):
            raise OSError("injected")
        os.rename = boom
        try:
            write_out(fail_dest, a1, m1)
            fails.append("injected rename failure not raised")
        except OSError:
            pass
        finally:
            os.rename = real_rename
        check(not fail_dest.exists() and not [p for p in td.iterdir() if p.name.startswith(".overlay-tmp")],
              "failed write left output/PASS state")
        # failed rename onto the user's existing empty directory leaves it intact (no rmdir first)
        keepdir = td / "keepdir"
        keepdir.mkdir()
        os.rename = boom
        try:
            write_out(keepdir, a1, m1)
            fails.append("injected rename failure not raised (existing dir)")
        except OSError:
            pass
        finally:
            os.rename = real_rename
        check(keepdir.is_dir() and not list(keepdir.iterdir()), "user's empty directory not intact")
        check(not [p for p in td.iterdir() if p.name.startswith(".overlay-tmp")], "temp left (existing dir)")
        # git provenance absent for non-repo, never claims commit
        check(git_head(td)["head"] is None, "git head for non-repo")
    elapsed = time.time() - t0
    check(elapsed <= 60, f"self-test took {elapsed:.1f}s")
    if fails:
        for f in fails:
            print("FAIL:", f, file=sys.stderr)
        print(f"consumed_overlay self-test: FAIL ({len(fails)})")
        return 1
    print(f"consumed_overlay self-test: PASS ({elapsed:.1f}s)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", help="project root")
    ap.add_argument("--receipt", action="append", default=[], metavar="NAME=PATH")
    ap.add_argument("--git-head", action="store_true", help="record read-only git HEAD reference")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--out", metavar="DIR")
    mode.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    try:
        if not a.root:
            raise OverlayError("--root is required")
        receipts = parse_receipt_args(a.receipt)
        archive, manifest, _ = build_overlay(a.root, receipts, with_git=a.git_head)
        if a.check:
            print(json.dumps({"ok": True, "manifest": manifest}, indent=2, sort_keys=True))
            return 0
        write_out(a.out, archive, manifest)
        print(json.dumps({"ok": True, "out": a.out, "archive_sha256": manifest["archive"]["sha256"],
                          "files": manifest["totals"]["files"]}, sort_keys=True))
        return 0
    except (OverlayError, OSError, ValueError, sc.CapsuleError) as exc:  # UnicodeError is a ValueError
        if a.check:
            print(json.dumps({"ok": False, "error": ascii(str(exc))[1:-1]}, sort_keys=True))
        else:
            print(f"consumed_overlay: refused: {ascii(str(exc))[1:-1]}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
