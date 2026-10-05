#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded UNRELEASED BIOS+UEFI ShizukuOS installer ISO candidate builder.

Packages the existing SHZSETUP installer from frozen, hash-pinned compiled inputs
using the production helpers (tools/build_shizuku_se_iso.py, tools/shizuku_se_media.py).
It builds nothing else: no kernel/source/Win64 build, no VM, no publication, no git.

Every location is explicit (no hidden defaults) and the output directory must not
exist.  The production setup_payload() public guard stays in force: the payload must
be a fresh production-answer payload; the QA/unattended answer is rejected.
The receipt is an UNRELEASED candidate record; every unmet gate is an explicit false.
Schema-only or PASS-claiming receipts are rejected by --check-receipt.

  candidate_iso.py --tools T --syslinux S --input-root I --input-pins P \\
      --payload-root D --out-dir NEWDIR [--dry-run]
  candidate_iso.py --check-receipt NEWDIR/candidate-receipt.json
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if not (HERE.name == "installer-media" and HERE.parent.name == "integration"
        and (ROOT / "AGENTS.md").is_file() and (ROOT / "tools" / "shizuku_se_media.py").is_file()):
    raise SystemExit("candidate_iso.py must live at <source root>/integration/installer-media/")

SCHEMA = "shizukuos.installer-iso-candidate.v1"
PINS_SCHEMA = "shizukuos.installer-candidate-pins.v1"
STATUS = "unreleased-candidate"
GIB = 1 << 30
MAX_ISO = 1 * GIB
RESERVE_FREE = 17 * GIB
CMD_TIMEOUT = 180
LOG_TAIL = 4000
DEFAULT_MAX_PAYLOAD_AGE_H = 24
ISO_NAME = "shizukuos-installer-candidate.iso"
TOOL_FILES = ("build_shizuku_se_iso.py", "shizuku_se_media.py", "shizuku_image_io.py", "shizuku_se_drivers.py")
SUPPORTED_CONDITIONS = [
    "unreleased candidate; not a release, not published (distribution is only https://m98.nyase.kr)",
    "BIOS: isolinux direct installer entry (mboot.c32, no menu); UEFI: BOOT.INI mode=install menu_timeout=0",
    "both boot Kernel64 with SHZ/SETUP/INSTALL.IMG and shz.setup=interactive shz.noapps",
    "interactive SHZSETUP only; no unattended/QA erase; target is chosen and confirmed in the installer",
    "UEFI needs Secure Boot off; CSM fallback needs 2+ logical CPUs",
    "host-side structural ISO verification only (El Torito BIOS+UEFI, isohybrid MBR/GPT, EFI FAT readback)",
]
FALSE_GATES = (
    "windows98_acceptance", "private_windows_assets_included", "microsoft_media_included",
    "vm_boot_verified", "installer_executed", "install_target_written", "installed_disk_boot_verified",
    "desktop_claim", "private_native_claim", "native_apps_verified", "released", "published", "pass_claimed",
    "source_license_closure", "public_compliance_verified",
)


class CandidateError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def regular(path: Path, what: str) -> Path:
    """Existing regular non-symlink file; frozen inputs are only ever read."""
    if path.is_symlink() or not path.is_file():
        raise CandidateError(f"{what}: {path} is not an existing regular file (symlinks refused)")
    return path


def need_dir(value: str, what: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise CandidateError(f"{what} must be an absolute path (no hidden defaults)")
    path = path.resolve()
    if not path.is_dir():
        raise CandidateError(f"{what}: {path} is not a directory")
    return path


# ------------------------------------------------------------------ isolated helper copies

class BoundedSubprocess:
    """Adapter for the isolated helper copies: every subprocess call is bounded to CMD_TIMEOUT."""

    def __getattr__(self, name):
        return getattr(subprocess, name)

    @staticmethod
    def run(*args, **kwargs):
        kwargs.setdefault("timeout", CMD_TIMEOUT)
        return subprocess.run(*args, **kwargs)

    @staticmethod
    def check_output(*args, **kwargs):
        kwargs.setdefault("timeout", CMD_TIMEOUT)
        return subprocess.check_output(*args, **kwargs)


def bounded_run(command, cwd=None, env=None):
    result = subprocess.run([str(c) for c in command], cwd=cwd or ROOT, env=env, capture_output=True,
                            timeout=CMD_TIMEOUT)
    if result.returncode != 0:
        tail = (result.stdout + result.stderr)[-LOG_TAIL:].decode("utf-8", "replace")
        raise CandidateError(f"{command[0]} failed ({result.returncode}); log tail:\n{tail}")


def load_copy(alias: str, path: Path):
    """Execute a private copy of a production helper module; sys.modules gets only the unique alias."""
    spec = importlib.util.spec_from_file_location(alias, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module


def load_helpers(tools: Path):
    if tools != (ROOT / "tools").resolve():
        raise CandidateError(f"--tools must be this source root's tools directory {ROOT / 'tools'}")
    for name in TOOL_FILES:
        regular(tools / name, "production helper")
    for extra in (str(ROOT / "shizukudos" / "tools"), str(tools)):
        if extra not in sys.path:
            sys.path.insert(0, extra)
    media = load_copy("_candidate_se_media", tools / "shizuku_se_media.py")
    iso = load_copy("_candidate_build_se_iso", tools / "build_shizuku_se_iso.py")
    iso.se_media = media            # the iso helper copy must use the media helper copy, not the global one
    media.subprocess = BoundedSubprocess()
    iso.subprocess = BoundedSubprocess()
    iso.run = bounded_run
    return media, iso


# ------------------------------------------------------------------ inputs

def load_pins(path: Path) -> dict[str, str]:
    data = json.loads(regular(path, "--input-pins").read_text(encoding="utf-8"))
    if data.get("schema") != PINS_SCHEMA or not isinstance(data.get("files"), dict) or not data["files"]:
        raise CandidateError(f"--input-pins must be {{schema: {PINS_SCHEMA}, files: {{relpath: sha256}}}}")
    return data["files"]


def rebind_inputs(media, input_root: Path, pins: dict[str, str]):
    """Point the media helper copy at the frozen input root, verifying every used file against its pin."""
    base = media.SHZ_BUILD
    def moved(path: Path) -> Path:
        return input_root / path.relative_to(base)
    media.DEFAULT_LOADER = moved(media.DEFAULT_LOADER)
    media.DEFAULT_CSMWRAP = moved(media.DEFAULT_CSMWRAP)
    media.CSMWRAP_RECEIPT = moved(media.CSMWRAP_RECEIPT)
    media.K64_FILES = {k: moved(v) for k, v in media.K64_FILES.items()}
    media.SHZDOS_FILES = {k: moved(v) for k, v in media.SHZDOS_FILES.items()}
    used = {media.DEFAULT_LOADER, media.DEFAULT_CSMWRAP, media.CSMWRAP_RECEIPT,
            *media.K64_FILES.values(), *media.SHZDOS_FILES.values()}
    wanted = {p.relative_to(input_root).as_posix(): p for p in used}
    if set(pins) != set(wanted):
        raise CandidateError(f"--input-pins must cover exactly: {sorted(wanted)}")
    observed, retained = {}, {}
    for name, path in sorted(wanted.items()):
        regular(path, "frozen input")
        if path.resolve().parent != path.parent.resolve() or not path.resolve().is_relative_to(input_root):
            raise CandidateError(f"frozen input escapes the input root: {name}")
        data = path.read_bytes()
        observed[name] = sha256_bytes(data)
        if observed[name] != pins[name]:
            raise CandidateError(f"frozen input {name} sha256 {observed[name]} differs from its pin {pins[name]}")
        retained[path] = data
    # Input.data normally reopens its pathname. All actual packaged component
    # reads in this isolated helper copy must consume the verified bytes above.
    def retained_data(item):
        try:
            return retained[item.path]
        except KeyError as exc:
            raise CandidateError(f"unretained component input: {item.path}") from exc
    media.Input.data = property(retained_data)
    media._candidate_retained_inputs = retained
    return observed


def syslinux_from_root(media, base: Path) -> tuple[dict, dict]:
    """The pinned Ubuntu syslinux tree/downloads (layout of build/upstream/syslinux), each file checked."""
    spec = media.syslinux_spec()
    root, downloads = base / "root", base / "downloads"
    if not root.is_dir() or not downloads.is_dir():
        raise CandidateError("--syslinux must contain root/ and downloads/ (build/upstream/syslinux layout)")
    for relative, digest in spec["files"].items():
        path = regular(root / relative, "pinned syslinux file")
        if sha256_file(path) != digest:
            raise CandidateError(f"syslinux {relative} is not the pinned file")
    for item in spec["source"].values():
        if sha256_file(regular(downloads / item["file"], "pinned syslinux source")) != item["sha256"]:
            raise CandidateError(f"syslinux source {item['file']} is not the pinned file")
    files = {name: root / "usr/lib/syslinux/modules/bios" / name for name in media.SYSLINUX_MODULES}
    files.update({"isolinux.bin": root / "usr/lib/ISOLINUX/isolinux.bin",
                  "isohdpfx.bin": root / "usr/lib/ISOLINUX/isohdpfx.bin",
                  "memdisk": root / "usr/lib/syslinux/memdisk",
                  "mbr.bin": root / "usr/lib/syslinux/mbr/mbr.bin",
                  "installer": root / "usr/bin/syslinux", "_root": root, "_downloads": downloads})
    for name, path in files.items():
        if not name.startswith("_"):
            regular(path, f"syslinux {name}")
    media.syslinux = lambda: files   # syslinux_payload() reads this helper-copy global; no download/unpack
    return files, {name: sha256_file(p) for name, p in files.items() if not name.startswith("_")}


def check_payload(media, payload_root: Path, max_age_h: float):
    """Fresh production-answer payload; the production public guard runs inside setup_payload and is not bypassed."""
    image = regular(payload_root / media.SETUP_MAIN, "installer payload")
    age = (time.time() - image.stat().st_mtime) / 3600
    if age > max_age_h or age < -0.1:
        raise CandidateError(f"payload {image} is not fresh (age {age:.1f} h, limit {max_age_h} h); rerun install/mkpayload.py")
    product = regular(ROOT / "shizukudos" / "install" / "shzsetup.ini", "product answer").read_bytes()
    if regular(payload_root / "shzsetup.ini", "payload answer").read_bytes() != product:
        raise CandidateError("payload answer is not the production answer install/shzsetup.ini (QA answer refused)")
    files, info = media.setup_payload(payload_root)      # public guard, receipt hash and answer equality
    if not files:
        raise CandidateError(info.get("note", "no installer payload"))
    guard_spec = importlib.util.spec_from_file_location(
        "_candidate_public_guard", ROOT / "shizukudos/install/native_payload_ingest.py")
    guard = importlib.util.module_from_spec(guard_spec)
    guard_spec.loader.exec_module(guard)
    answers = {n: d for n, d in guard.archive_entries(image.read_bytes()).items() if n.upper().endswith("SHZSETUP.INI")}
    if not answers or any(d != product for d in answers.values()):
        raise CandidateError("INSTALL.IMG does not embed exactly the production answer (QA/other answer refused)")
    return files, info


# ------------------------------------------------------------------ build

def plan(args) -> dict:
    tools = need_dir(args.tools, "--tools")
    syslinux_base = need_dir(args.syslinux, "--syslinux")
    input_root = need_dir(args.input_root, "--input-root")
    payload_root = need_dir(args.payload_root, "--payload-root")
    out = Path(args.out_dir)
    if not out.is_absolute():
        raise CandidateError("--out-dir must be an absolute path")
    if os.path.lexists(out):
        raise CandidateError(f"--out-dir {out} exists; candidates never overwrite")
    parent = out.parent.resolve()
    if not parent.is_dir():
        raise CandidateError(f"parent of --out-dir does not exist: {parent}")
    out = parent / out.name
    for other in (tools, syslinux_base, input_root, payload_root):
        if out.is_relative_to(other) or other.is_relative_to(out):
            raise CandidateError(f"--out-dir overlaps a read-only input: {other}")
    media, iso = load_helpers(tools)
    pins = load_pins(Path(args.input_pins))
    input_hashes = rebind_inputs(media, input_root, pins)
    syslinux, syslinux_hashes = syslinux_from_root(media, syslinux_base)
    setup_files, setup_info = check_payload(media, payload_root, args.max_payload_age_hours)
    mode, menu_timeout, direct = iso.iso_boot_policy(False, True, "install")
    if (mode, menu_timeout, direct) != ("install", 0, True):
        raise CandidateError("production boot policy is not the direct interactive installer")
    loader, csm = media.loader_input(), media.csmwrap_input()
    if loader.data[:2] != b"MZ" or not all(media.loader_features(loader.data).values()):
        raise CandidateError("retained UEFI loader lacks the production installer features")
    csm_receipt = json.loads(media._candidate_retained_inputs[media.CSMWRAP_RECEIPT])
    if csm_receipt["artifacts"]["CSMWRAP.EFI"]["sha256"] != sha256_bytes(csm.data):
        raise CandidateError("retained CSMWrap differs from its retained build receipt")
    k64, shzdos = media.k64_inputs(), media.shzdos_inputs()
    efi_members = media.efi_members(loader, csm, shzdos, mode, setup_files, menu_timeout=menu_timeout)
    boot = iso.boot_payload(syslinux, k64, True, False, direct_install=True)
    cfg = boot[f"{iso.ISOLINUX_DIR}/isolinux.cfg"].decode("ascii")
    for needle in ("DEFAULT setup", "shz.setup=interactive shz.noapps", "/SHZ/SETUP/INSTALL.IMG"):
        if needle not in cfg or "shz.setup=auto" in cfg:
            raise CandidateError(f"BIOS direct install menu lacks {needle!r}")
    if b"mode = install" not in efi_members["EFI/SHIZUKU/BOOT.INI"] or b"menu_timeout = 0" not in efi_members["EFI/SHIZUKU/BOOT.INI"]:
        raise CandidateError("UEFI BOOT.INI is not mode=install menu_timeout=0")
    estimate = 2 * sum(len(d) for d in efi_members.values()) + sum(len(d) for d in setup_files.values()) \
        + sum(len(d) for d in boot.values()) + 8 * (1 << 20)
    # efi members appear in the ISO inside efiboot.img and the SHZ/K64 copies; the estimate is deliberately generous
    if estimate > MAX_ISO:
        raise CandidateError(f"estimated candidate size {estimate} exceeds the {MAX_ISO} byte cap")
    free = shutil.disk_usage(parent).free
    if free - 3 * estimate < RESERVE_FREE:
        raise CandidateError(f"free space {free} leaves less than the 17 GiB reserve after {3 * estimate} bytes of work")
    return dict(media=media, iso=iso, out=out, loader=loader, csm=csm, k64=k64, shzdos=shzdos, syslinux=syslinux,
                setup_files=setup_files, setup_info=setup_info, efi_members=efi_members, boot=boot,
                estimate=estimate, free=free, input_hashes=input_hashes, syslinux_hashes=syslinux_hashes,
                tools=tools, input_root=input_root, payload_root=payload_root)


def candidate_payload(p: dict, work: Path) -> dict[str, bytes]:
    media, iso = p["media"], p["iso"]
    payload: dict[str, bytes] = {}
    payload.update(p["boot"])
    payload.update(p["setup_files"])
    payload.update(media.syslinux_payload(iso.SHZ10_DIR))
    efi = iso.build_efi_image(work, p["efi_members"])
    payload[iso.EFI_IMAGE] = efi
    payload[f"{iso.SHZ10_DIR}/EFIBOOT.TXT"] = (
        f"EFI boot image, FAT16 SHZESP, {len(efi)} bytes sha256 {sha256_bytes(efi)}\r\n"
        + "".join(f"  {m}  {len(d)} bytes  sha256 {sha256_bytes(d)}\r\n" for m, d in sorted(p["efi_members"].items()))
    ).encode("ascii")
    payload[f"{iso.SHZ10_DIR}/LICENSES/Shizuku-LICENSE-GPL-2.0.txt"] = (ROOT / "LICENSE").read_bytes()
    payload["CANDIDATE.TXT"] = (
        "ShizukuOS installer ISO CANDIDATE - UNRELEASED, not published, not Windows98-accepted.\r\n"
        "Boots the interactive SHZSETUP installer (BIOS isolinux and UEFI BOOT.INI mode=install).\r\n"
        "Contains no Microsoft media, keys or private disks. VM boot and installation are NOT verified here.\r\n"
        "Upstream licences and provenance: ShizukuDOS10/LICENSES and ShizukuDOS10/SOURCE (syslinux).\r\n"
    ).encode("ascii")
    payload["VMPROFIL.TXT"] = media.vm_profiles_text(direct_install=True).encode("ascii")
    lines = ["sha256  bytes  path\r\n"] + [f"{sha256_bytes(d)}  {len(d)}  {n}\r\n" for n, d in sorted(payload.items())]
    payload["HASHES.TXT"] = "".join(lines).encode("ascii")
    return payload


def build(p: dict) -> dict:
    iso, out = p["iso"], p["out"]
    out.mkdir(mode=0o750)          # fails if it appeared meanwhile: never overwrite
    stage, work, evidence = out / "stage", out / "work", out / "evidence"
    for d in (stage, work, evidence):
        d.mkdir()
    iso_path = out / ISO_NAME
    try:
        payload = candidate_payload(p, work)
        for name, data in payload.items():
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        optimization = iso.write_iso(stage, iso_path, p["syslinux"]["isohdpfx.bin"], payload)
        if iso_path.stat().st_size > MAX_ISO:
            raise CandidateError("candidate ISO exceeds the 1 GiB cap")
        report = iso.verify_iso(iso_path, payload, p["efi_members"], p["syslinux"], evidence)
    except BaseException:
        iso_path.unlink(missing_ok=True)
        raise
    finally:
        iso.rmtree_force(stage)
        iso.rmtree_force(work)
    return {"payload": payload, "optimization": optimization, "report": report, "iso": iso_path}


def make_receipt(p: dict, built: dict, pins_path: Path) -> dict:
    iso_path, payload = built["iso"], built["payload"]
    sources = [ROOT / "tools" / n for n in TOOL_FILES] + [
        Path(__file__).resolve(), ROOT / "shizukudos/install/shzsetup.ini",
        ROOT / "shizukudos/install/native_payload_ingest.py", ROOT / "LICENSE"]
    return {
        "schema": SCHEMA, "status": STATUS, "released": False,
        "distribution_origin": "https://m98.nyase.kr (publication is a separate owner; nothing was published)",
        "supported_conditions": SUPPORTED_CONDITIONS,
        "gates": {name: False for name in FALSE_GATES},
        "gate_note": "false means not established by this builder; none may be flipped without real evidence elsewhere",
        "missing_source_license_closure": [
            "project corresponding source capsule is not embedded",
            "consumed GPL DOS sources, patches, licenses and producer closure are not embedded",
            "consumed CSMWrap/SeaBIOS sources, patches, licenses and producer closure are not embedded",
            "only the pinned Syslinux source/license payload is included; public compliance is not established",
        ],
        "not_run": ["VM boot (BIOS/UEFI)", "installer execution", "installed-disk boot", "Windows98 acceptance",
                    "source/kernel/Win64 rebuild", "publication"],
        "iso": {"name": iso_path.name, "bytes": iso_path.stat().st_size, "sha256": sha256_file(iso_path),
                "volume_id": p["iso"].VOLUME_ID, "cap_bytes": MAX_ISO},
        "boot": {"bios": "isolinux direct install (DEFAULT setup, PROMPT 0, NOESCAPE 1)",
                 "uefi": {"mode": "install", "menu_timeout": 0},
                 "kernel_cmdline": "shz.setup=interactive shz.noapps", "installer": "SHZ/SETUP/INSTALL.IMG"},
        "source": {rel(s): sha256_file(s) for s in sources},
        "tools_dir": rel(p["tools"]),
        "input_pins_file_sha256": sha256_file(pins_path),
        "frozen_inputs": p["input_hashes"],
        "syslinux_files": p["syslinux_hashes"],
        "setup": {"boot_profile": p["setup_info"].get("boot_profile"),
                  "install_img_sha256": p["setup_info"]["install_img_sha256"],
                  "files": p["setup_info"]["files"], "public_guard": "setup_payload+require_public_payload passed",
                  "answer": "production install/shzsetup.ini"},
        "efi_members": {n: {"bytes": len(d), "sha256": sha256_bytes(d)} for n, d in sorted(p["efi_members"].items())},
        "payload_files": {n: {"bytes": len(d), "sha256": sha256_bytes(d)} for n, d in sorted(payload.items())},
        "disk_optimization": built["optimization"],
        "verification": {"scope": "host structural (xorriso/mtools/fsck.vfat) only",
                         "log_tail": built["report"][-LOG_TAIL:]},
    }


def rel(path: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def check_receipt(path: Path) -> list[str]:
    """Reject schema-only, PASS-claiming or gate-flipped receipts; bind artifacts to the actual ISO."""
    errors = []
    data = json.loads(regular(path, "receipt").read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA:
        errors.append("wrong schema")
    if data.get("status") != STATUS or data.get("released") is not False:
        errors.append("status must be unreleased-candidate and released false (no PASS/release claim)")
    gates = data.get("gates")
    if not isinstance(gates, dict) or set(gates) != set(FALSE_GATES) or any(v is not False for v in gates.values()):
        errors.append("every gate must be present and exactly false")
    if any(k in data for k in ("pass", "PASS", "result")):
        errors.append("PASS/result fields are refused")
    iso = data.get("iso", {})
    actual = path.parent / str(iso.get("name", ""))
    if not actual.is_file() or actual.is_symlink():
        errors.append("schema-only receipt: ISO named by the receipt is not beside it")
    elif sha256_file(actual) != iso.get("sha256") or actual.stat().st_size != iso.get("bytes"):
        errors.append("ISO bytes/sha256 differ from the receipt")
    for key in ("source", "frozen_inputs", "syslinux_files", "payload_files", "efi_members", "setup"):
        if not data.get(key):
            errors.append(f"missing hash binding: {key}")
    for name, digest in data.get("source", {}).items():
        file = ROOT / name
        if file.is_file() and sha256_file(file) != digest:
            errors.append(f"source changed since the receipt: {name}")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tools", help="absolute path of this source root's tools/ (production helpers)")
    ap.add_argument("--syslinux", help="absolute path of the pinned syslinux dir (root/ + downloads/)")
    ap.add_argument("--input-root", help="absolute path of frozen compiled inputs (build/shizukudos layout), read only")
    ap.add_argument("--input-pins", help="JSON {schema, files:{relpath:sha256}} for exactly the input-root files used")
    ap.add_argument("--payload-root", help="absolute path of a FRESH install/mkpayload.py --out payload (production answer)")
    ap.add_argument("--out-dir", help="absolute path of a NEW candidate directory (must not exist)")
    ap.add_argument("--max-payload-age-hours", type=float, default=DEFAULT_MAX_PAYLOAD_AGE_H,
                    help=f"payload freshness limit (default {DEFAULT_MAX_PAYLOAD_AGE_H})")
    ap.add_argument("--dry-run", "--check", action="store_true", dest="dry_run",
                    help="validate every input and the plan; build and write nothing")
    ap.add_argument("--check-receipt", type=Path, metavar="RECEIPT", help="validate a candidate receipt and exit")
    args = ap.parse_args()
    try:
        if args.check_receipt:
            errors = check_receipt(args.check_receipt)
            print(json.dumps({"receipt": str(args.check_receipt), "valid": not errors, "errors": errors}, indent=2))
            return 0 if not errors else 2
        for flag in ("tools", "syslinux", "input_root", "input_pins", "payload_root", "out_dir"):
            if not getattr(args, flag):
                ap.error(f"--{flag.replace('_', '-')} is required (no hidden defaults)")
        if not 0 < args.max_payload_age_hours <= 24 * 30:
            ap.error("--max-payload-age-hours must be in (0, 720]")
        p = plan(args)
        summary = {"status": STATUS, "out_dir": str(p["out"]), "estimated_bytes": p["estimate"],
                   "free_bytes": p["free"], "inputs": p["input_hashes"], "setup_files": len(p["setup_files"])}
        if args.dry_run:
            print(json.dumps({"dry_run": True, "valid": True, **summary}, indent=2))
            return 0
        built = build(p)
        receipt = make_receipt(p, built, Path(args.input_pins))
        receipt_path = p["out"] / "candidate-receipt.json"
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        errors = check_receipt(receipt_path)
        if errors:
            raise CandidateError("own receipt rejected: " + "; ".join(errors))
        print(json.dumps({**summary, "iso": receipt["iso"], "receipt": str(receipt_path)}, indent=2))
        return 0
    except (CandidateError, RuntimeError, ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
