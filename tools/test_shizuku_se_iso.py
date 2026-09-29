#!/usr/bin/env python3
"""Boot-test the integrated Windows 98 Shizuku Second Edition ISO in QEMU.

Groups (select with --only, default all):
  layout   El Torito catalog (parsed independently and through xorriso), boot
           image extraction and byte comparison, UEFI image content.
  bios     SeaBIOS (-machine pc): CD boot -> ShizukuDOS prompt on COM1, DIR
           lists the embedded NTW32/NTWRAP9X/NTWGPROB files, PNG evidence.
  uefi     OVMF (-machine q35, ISO as ATA CD-ROM on AHCI): the El Torito EFI
           image is loaded and BOOTX64.EFI (Shizuku Supervisor loader) starts.
           Without Intel VMX in the guest the loader must report the VMX
           backend unusable and return to firmware; that path is verified and
           the multikernel domains are reported BLOCKED. With /dev/kvm and
           nested VMX the full supervisor run of
           shizukudos/supervisor/test_qemu.py is attempted against the ISO.
  install  Windows 98 installation. No Microsoft media ships in this tree, so
           without --win98-iso the result is one BLOCKED record. With
           --win98-iso only the media's boot/setup screen is captured (PARTIAL
           evidence). A full unattended install check is NOT implemented.

Result semantics follow shizukudos/tools/shzlib.py: PASS, FAIL, SKIP, BLOCKED.
A missing prerequisite or a feature that cannot be verified is BLOCKED or SKIP,
never PASS. The verdict is VERIFIED only when nothing is FAIL/SKIP/BLOCKED,
FAILED when any FAIL exists, otherwise INCOMPLETE. Exit code 0 means no FAIL
(exit code 2: the ISO to test does not exist). QEMU under TCG or KVM is a
development tool; nothing here is a claim about real hardware.

The ISO is never modified. OVMF variable stores are per-run copies.
"""
from __future__ import annotations

import argparse
import atexit
import hashlib
import os
import re
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shizukudos" / "tools"))
import qemu as qemu_tools  # noqa: E402
import shzlib  # noqa: E402

DEFAULT_ISO = "build/windows98-shizuku-second-edition.iso"
DEFAULT_EVIDENCE = "build/shizuku-se-iso-tests"
GROUPS = ("layout", "bios", "uefi", "install")
SECTOR = 2048
BIOS_IMAGE_PATH = "/ShizukuDOS/shizukudos.img"
BIOS_IMAGE_SIZE = 1474560
PROMPT = "A:\\>"
DIR_EXPECTED = ("NTW32.DLL", "NTWRAP9X.VXD", "NTWGPROB.EXE")
LOADER_BANNER = re.compile(r"ShizukuDOS [^\n]*Supervisor loader \(UEFI x64\)")
VMX_REASON = "needs Intel VMX in L1 (/dev/kvm + nested)"
MISSING_MEDIA = ("vm/Win98-SE-ko-OEM.iso", "build/win98-lab/win98se-ko-oem.iso",
                 "build/win98-lab (installed-checkpoint directory)")
ANSI = re.compile(rb"\x1b\[[0-9;?=]*[A-Za-z]|\x1b[()][A-Z0-9]")

PLATFORMS = {0x00: "BIOS", 0x01: "PPC", 0x02: "Mac", 0xEF: "UEFI"}
MEDIA_XORRISO = {0: "none", 1: "fd1.2", 2: "fd1.4", 3: "fd2.8", 4: "hd"}
MEDIA_TEXT = {0: "no emulation", 1: "1.2MB floppy", 2: "1.44MB floppy", 3: "2.88MB floppy", 4: "hard disk"}

_LIVE: list[subprocess.Popen] = []


def _cleanup() -> None:
    for proc in _LIVE:
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass


atexit.register(_cleanup)


def _on_signal(signum, _frame):
    raise SystemExit(128 + signum)


class Tee:
    """Mirror console output into evidence/report.txt."""

    def __init__(self, stream, path: Path) -> None:
        self.stream = stream
        self.file = path.open("w", encoding="utf-8")

    def write(self, text: str) -> int:
        self.file.write(text)
        return self.stream.write(text)

    def flush(self) -> None:
        self.file.flush()
        self.stream.flush()

    def close(self) -> None:
        self.file.close()


class Context:
    """Everything the test groups share."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.iso: Path = args.iso
        self.evidence: Path = args.evidence_dir
        self.timeout: int = args.timeout
        self.results: list[dict] = []
        self.kvm_device = os.access("/dev/kvm", os.R_OK | os.W_OK)
        self.nested_vmx = self._nested_vmx()
        if args.accel == "auto":
            self.accel = "kvm" if self.kvm_device else "tcg"
        else:
            self.accel = args.accel
        self.accel_problem = ""
        if self.accel == "kvm" and not self.kvm_device:
            self.accel_problem = "--accel kvm requested but /dev/kvm is not accessible"
        self.qemu = self._find_qemu(args.qemu)
        self.ovmf_code = Path(args.ovmf_code) if args.ovmf_code else Path(qemu_tools.DEFAULT_OVMF_CODE)
        self.ovmf_vars = Path(args.ovmf_vars) if args.ovmf_vars else Path(qemu_tools.DEFAULT_OVMF_VARS)
        self.iso_sha256 = ""
        self.layout: dict | None = None

    @staticmethod
    def _nested_vmx() -> bool:
        try:
            value = Path("/sys/module/kvm_intel/parameters/nested").read_text().strip()
        except OSError:
            return False
        return value in ("Y", "y", "1")

    @staticmethod
    def _find_qemu(explicit: str | None) -> str | None:
        candidates = [explicit, os.environ.get("QEMU"), shutil.which("qemu-system-x86_64"),
                      qemu_tools.DEFAULT_QEMU]
        for candidate in candidates:
            if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        return None

    @property
    def full_supervisor_possible(self) -> bool:
        return self.accel == "kvm" and self.kvm_device and self.nested_vmx

    def record(self, group: str, name: str, status: str, detail: str = "", **extra) -> dict:
        rec = shzlib.result_record(name, status, group=group, detail=detail, **extra)
        self.results.append(rec)
        text = " ".join(detail.split())
        if len(text) > 260:
            text = text[:257] + "..."
        print(f"[{status:7}] {group}: {name}" + (f"  -- {text}" if text else ""), flush=True)
        return rec

    def qemu_unavailable(self, group: str, names: list[str]) -> bool:
        """Record BLOCKED for a group when QEMU or the accelerator is missing."""
        reason = ""
        if self.qemu is None:
            reason = "no qemu-system-x86_64 found (looked at --qemu, $QEMU, PATH, /usr/libexec/qemu-kvm)"
        elif self.accel_problem:
            reason = self.accel_problem
        if not reason:
            return False
        for name in names:
            self.record(group, name, "BLOCKED", reason)
        return True

    def group_dir(self, group: str) -> Path:
        path = self.evidence / group
        shutil.rmtree(path, ignore_errors=True)
        path.mkdir(parents=True)
        return path


# --------------------------------------------------------------------- utils
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def read_clean(path: Path, flat: bool = False) -> str:
    """Serial capture with terminal escape sequences removed."""
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    text = ANSI.sub(b"", raw).replace(b"\r", b"").decode("ascii", "replace")
    return re.sub(r"\s+", " ", text) if flat else text


def iso_read(iso: Path, lba: int, length: int) -> bytes:
    with iso.open("rb") as fh:
        fh.seek(lba * SECTOR)
        return fh.read(length)


def run_tool(command: list, timeout: int = 120, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([str(c) for c in command], capture_output=True, text=True, timeout=timeout, env=env)


# --------------------------------------------------------------- El Torito
def parse_el_torito_raw(iso: Path) -> dict:
    """Read the boot catalog straight from the ISO bytes, independent of xorriso."""
    with iso.open("rb") as fh:
        catalog_lba = None
        for sector in range(16, 48):
            fh.seek(sector * SECTOR)
            desc = fh.read(SECTOR)
            if len(desc) < SECTOR or desc[1:6] != b"CD001" or desc[0] == 255:
                break
            if desc[0] == 0 and desc[7:30] == b"EL TORITO SPECIFICATION":
                catalog_lba = u32(desc, 0x47)
                break
        if catalog_lba is None:
            raise ValueError("no El Torito boot record among the ISO volume descriptors")
        fh.seek(catalog_lba * SECTOR)
        cat = fh.read(SECTOR)
    words = struct.unpack_from("<16H", cat, 0)
    validation = {
        "header_id": cat[0], "platform": cat[1], "key55aa": cat[30:32] == b"\x55\xaa",
        "checksum_ok": sum(words) & 0xFFFF == 0,
    }
    entries: list[dict] = []

    def entry_at(pos: int, platform: int, section: int) -> None:
        media = cat[pos + 1] & 0x0F
        entries.append({
            "index": len(entries) + 1, "section": section, "platform": platform,
            "platform_name": PLATFORMS.get(platform, f"0x{platform:02x}"),
            "bootable": cat[pos] == 0x88, "media": media,
            "media_xorriso": MEDIA_XORRISO.get(media, str(media)),
            "media_text": MEDIA_TEXT.get(media, f"type {media}"),
            "load_segment": u16(cat, pos + 2), "system_type": cat[pos + 4],
            "sector_count": u16(cat, pos + 6), "lba": u32(cat, pos + 8),
        })

    if cat[0] == 1 and validation["key55aa"] and cat[32] in (0x88, 0x00):
        entry_at(32, cat[1], 0)
    pos = 64
    while pos + 32 <= len(cat) and cat[pos] in (0x90, 0x91):
        final = cat[pos] == 0x91
        platform = cat[pos + 1]
        count = u16(cat, pos + 2)
        pos += 32
        for _ in range(count):
            if pos + 32 > len(cat):
                break
            entry_at(pos, platform, 1)
            pos += 32
            while pos + 32 <= len(cat) and cat[pos] == 0x44:  # selection-criteria extension
                pos += 32
        if final:
            break
    return {"catalog_lba": catalog_lba, "validation": validation, "entries": entries}


XORRISO_IMG = re.compile(
    r"^El Torito boot img :\s+(\d+)\s+(\S+)\s+(\S)\s+(\S+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(\d+)\s+(\d+)\s*$")
XORRISO_PATH = re.compile(r"^El Torito img path :\s+(\d+)\s+(\S.*?)\s*$")


def parse_xorriso_report(text: str) -> list[dict]:
    images: dict[int, dict] = {}
    for line in text.splitlines():
        m = XORRISO_IMG.match(line)
        if m:
            images[int(m.group(1))] = {
                "index": int(m.group(1)), "platform_name": m.group(2), "bootable": m.group(3) == "y",
                "media_xorriso": m.group(4), "load_segment": int(m.group(5), 16),
                "load_size": int(m.group(7)), "lba": int(m.group(8)), "path": None}
            continue
        m = XORRISO_PATH.match(line)
        if m and int(m.group(1)) in images:
            images[int(m.group(1))]["path"] = m.group(2)
    return [images[k] for k in sorted(images)]


def pe_summary(data: bytes) -> dict | None:
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    off = u32(data, 0x3C)
    if data[off:off + 4] != b"PE\0\0" or len(data) < off + 24 + 70:
        return None
    opt = off + 24
    return {"machine": u16(data, off + 4), "optional_magic": u16(data, opt), "subsystem": u16(data, opt + 68)}


def mtools_env() -> dict:
    env = dict(os.environ)
    env["MTOOLS_SKIP_CHECK"] = "1"
    return env


def gather_layout(ctx: Context, work: Path | None) -> dict:
    """Parse and extract everything about the ISO's boot entries. Used by the layout group
    (with a work directory for evidence) and, quietly, by the other groups."""
    info: dict = {"errors": [], "entries": [], "xorriso": [], "raw": None}
    try:
        info["raw"] = parse_el_torito_raw(ctx.iso)
        info["entries"] = info["raw"]["entries"]
    except (OSError, ValueError, struct.error) as exc:
        info["errors"].append(f"independent El Torito parse failed: {exc}")
    if shutil.which("xorriso") is None:
        info["errors"].append("xorriso not installed")
        return info
    proc = run_tool(["xorriso", "-indev", ctx.iso, "-report_el_torito", "plain"], env=dict(os.environ, LC_ALL="C"))
    report = proc.stdout + proc.stderr
    info["xorriso_text"] = report
    info["xorriso"] = parse_xorriso_report(report)
    if work is not None:
        (work / "el_torito.txt").write_text(report, encoding="utf-8")
    extract_dir = Path(tempfile.mkdtemp(prefix="shz-se-x-"))
    try:
        for img in info["xorriso"]:
            img["extracted_sha256"] = None
            if not img["path"]:
                continue
            out = extract_dir / f"entry{img['index']}.bin"
            proc = run_tool(["xorriso", "-osirrox", "on", "-indev", ctx.iso, "-extract", img["path"], out])
            if out.is_file():
                data = out.read_bytes()
                img["extracted_size"] = len(data)
                img["extracted_sha256"] = sha256_bytes(data)
                img["at_lba_equal"] = iso_read(ctx.iso, img["lba"], len(data)) == data
                img["data"] = data
                if work is not None:
                    (work / f"entry{img['index']}-{Path(img['path']).name}").write_bytes(data)
            else:
                img["extract_error"] = (proc.stderr or proc.stdout)[-300:]
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)
    return info


def find_entry(info: dict, platform: str) -> dict | None:
    for entry in info.get("entries", []):
        if entry["platform_name"] == platform:
            return entry
    return None


def xorriso_for(info: dict, index: int) -> dict | None:
    for img in info.get("xorriso", []):
        if img["index"] == index:
            return img
    return None


# --------------------------------------------------------------- layout group
def test_layout(ctx: Context) -> None:
    group = "layout"
    work = ctx.group_dir(group)
    info = gather_layout(ctx, work)
    ctx.layout = info
    ev = [rel(work / "el_torito.txt")]
    if shutil.which("xorriso") is None:
        ctx.record(group, "xorriso available", "BLOCKED", "xorriso is not installed; El Torito listing/extraction not verified")
        return

    raw = info.get("raw")
    if raw and raw["validation"]["checksum_ok"] and raw["validation"]["key55aa"] and raw["entries"]:
        desc = "; ".join(f"#{e['index']} {e['platform_name']}(0x{e['platform']:02x}) {e['media_text']} LBA {e['lba']} "
                         f"sectors {e['sector_count']} {'bootable' if e['bootable'] else 'NOT bootable'}"
                         for e in raw["entries"])
        ctx.record(group, "El Torito catalog valid (independent parse of ISO bytes)", "PASS",
                   f"catalog LBA {raw['catalog_lba']}, validation checksum ok, key 55AA; {desc}", evidence=ev)
    else:
        why = "; ".join(info["errors"]) or f"validation={raw['validation'] if raw else None}, entries={len(raw['entries']) if raw else 0}"
        ctx.record(group, "El Torito catalog valid (independent parse of ISO bytes)", "FAIL", why, evidence=ev)

    mismatches = []
    if raw and info["xorriso"]:
        if len(raw["entries"]) != len(info["xorriso"]):
            mismatches.append(f"entry count raw={len(raw['entries'])} xorriso={len(info['xorriso'])}")
        for e, x in zip(raw["entries"], info["xorriso"]):
            if (e["platform_name"], e["media_xorriso"], e["lba"]) != (x["platform_name"], x["media_xorriso"], x["lba"]):
                mismatches.append(f"#{e['index']} raw=({e['platform_name']},{e['media_xorriso']},{e['lba']}) "
                                  f"xorriso=({x['platform_name']},{x['media_xorriso']},{x['lba']})")
    elif not info["xorriso"]:
        mismatches.append("xorriso -report_el_torito plain listed no boot images")
    ctx.record(group, "xorriso -report_el_torito agrees with the independent parse (platform/emulation/LBA)",
               "FAIL" if mismatches else "PASS", "; ".join(mismatches) or f"{len(info['xorriso'])} image(s) agree", evidence=ev)

    # Default BIOS entry.
    bios = find_entry(info, "BIOS")
    bx = xorriso_for(info, bios["index"]) if bios else None
    if bios and bios["index"] == 1 and bios["bootable"] and bios["media"] == 2 and bx and bx["path"] == BIOS_IMAGE_PATH:
        ctx.record(group, f"default BIOS entry: floppy emulation, {BIOS_IMAGE_PATH[1:]}", "PASS",
                   f"entry #1 platform BIOS, media fd1.4, LBA {bios['lba']}, path {bx['path']}", evidence=ev)
    else:
        ctx.record(group, f"default BIOS entry: floppy emulation, {BIOS_IMAGE_PATH[1:]}", "FAIL",
                   f"entry={bios}, xorriso={ {k: v for k, v in (bx or {}).items() if k != 'data'} }", evidence=ev)

    # BIOS image bytes.
    if bx and bx.get("extracted_sha256"):
        data = bx["data"]
        problems = []
        if not bx["at_lba_equal"]:
            problems.append("extracted file differs from the bytes at the catalog LBA")
        if len(data) != BIOS_IMAGE_SIZE:
            problems.append(f"size {len(data)} != {BIOS_IMAGE_SIZE}")
        if data[510:512] != b"\x55\xaa":
            problems.append("boot signature 55AA missing")
        if data[3:11] != b"SHIZUKU ":
            problems.append(f"OEM name {data[3:11]!r} is not b'SHIZUKU '")
        ctx.record(group, "BIOS boot image: extracted bytes == bytes at El Torito LBA, 1.44 MiB, SHIZUKU boot sector",
                   "FAIL" if problems else "PASS",
                   "; ".join(problems) or f"{len(data)} bytes, sha256 {bx['extracted_sha256']}", evidence=ev)
    else:
        ctx.record(group, "BIOS boot image: extracted bytes == bytes at El Torito LBA, 1.44 MiB, SHIZUKU boot sector",
                   "FAIL", f"BIOS boot image could not be extracted: {(bx or {}).get('extract_error', 'no image listed')}",
                   evidence=ev)

    # UEFI entry.
    uefi = find_entry(info, "UEFI")
    ux = xorriso_for(info, uefi["index"]) if uefi else None
    name = "UEFI El Torito entry present (platform 0xEF, no emulation)"
    if uefi is None:
        ctx.record(group, name, "FAIL",
                   "the ISO has no UEFI El Torito entry (platform 0xEF, no-emulation); it is required in the final "
                   "ISO. BIOS tests are unaffected.", evidence=ev)
    elif uefi["media"] != 0 or not uefi["bootable"] or uefi["platform"] != 0xEF:
        ctx.record(group, name, "FAIL", f"UEFI entry has wrong shape: {uefi}", evidence=ev)
    else:
        ctx.record(group, name, "PASS",
                   f"entry #{uefi['index']} LBA {uefi['lba']} load size {uefi['sector_count']} sectors "
                   f"path {(ux or {}).get('path')}", evidence=ev)

    name = "UEFI boot image: bytes match ISO, FAT volume with EFI/BOOT/BOOTX64.EFI (PE32+ x64 EFI application)"
    if uefi is None:
        ctx.record(group, name, "BLOCKED", "no UEFI El Torito entry to inspect")
    elif not ux or not ux.get("extracted_sha256"):
        ctx.record(group, name, "FAIL", f"UEFI boot image could not be extracted: "
                   f"{(ux or {}).get('extract_error', 'xorriso lists no file path for it')}", evidence=ev)
    else:
        data = ux["data"]
        problems, notes = [], []
        if not ux["at_lba_equal"]:
            problems.append("extracted file differs from the bytes at the catalog LBA")
        if uefi["sector_count"] < 2:
            notes.append(f"catalog load size is {uefi['sector_count']} sector(s): the firmware then exposes the rest "
                         f"of the disc as the El Torito volume (EDK2 behaviour); the OVMF boot below is the real test")
        elif uefi["sector_count"] * 512 < len(data):
            notes.append(f"load size {uefi['sector_count']}x512={uefi['sector_count'] * 512} B is smaller than the "
                         f"{len(data)} B image (firmware sizes the El Torito volume from the catalog)")
        efi_sha = None
        if not shutil.which("mcopy"):
            problems.append("mtools (mcopy) is not installed; cannot read the FAT image")
        else:
            image_file = work / f"entry{uefi['index']}-{Path(ux['path']).name}"
            efi_out = work / "BOOTX64.EFI"
            efi_out.unlink(missing_ok=True)
            proc = run_tool(["mcopy", "-n", "-i", image_file, "::EFI/BOOT/BOOTX64.EFI", efi_out], env=mtools_env())
            if not efi_out.is_file():
                problems.append(f"no readable ::EFI/BOOT/BOOTX64.EFI in the image ({(proc.stderr or proc.stdout).strip()[-200:]})")
            else:
                blob = efi_out.read_bytes()
                efi_sha = sha256_bytes(blob)
                pe = pe_summary(blob)
                if not pe or pe["machine"] != 0x8664 or pe["optional_magic"] != 0x20B or pe["subsystem"] != 10:
                    problems.append(f"BOOTX64.EFI is not a PE32+ x64 EFI application: {pe}")
                reference = ROOT / "build" / "shizukudos" / "supervisor" / "BOOTX64.EFI"
                if reference.is_file():
                    same = sha256_bytes(reference.read_bytes()) == efi_sha
                    notes.append("BOOTX64.EFI " + ("is identical to" if same else "DIFFERS from") + f" {rel(reference)}")
            listing = run_tool(["mdir", "-i", image_file, "-/", "-b", "::"], env=mtools_env())
            (work / "efi_image_listing.txt").write_text(listing.stdout + listing.stderr)
        ctx.record(group, name, "FAIL" if problems else "PASS",
                   "; ".join(problems) or f"{len(data)} bytes, BOOTX64.EFI sha256 {efi_sha}" + ("; " + "; ".join(notes) if notes else ""),
                   evidence=ev + [rel(work / "efi_image_listing.txt")])


# ------------------------------------------------------------ guest handling
class GuestDied(RuntimeError):
    pass


class Guest:
    """One bounded QEMU process."""

    def __init__(self, argv: list, run_dir: Path) -> None:
        self.argv = [str(a) for a in argv]
        self.run_dir = run_dir
        (run_dir / "qemu.cmdline").write_text(" ".join(shlex.quote(a) for a in self.argv) + "\n")
        self.stderr_path = run_dir / "qemu.stderr"
        self._stderr = self.stderr_path.open("wb")
        self.proc = subprocess.Popen(self.argv, cwd=run_dir, stdout=subprocess.DEVNULL, stderr=self._stderr,
                                     start_new_session=True)
        _LIVE.append(self.proc)
        self.qmp: qemu_tools.QMP | None = None

    def alive(self) -> bool:
        return self.proc.poll() is None

    def stderr_tail(self) -> str:
        try:
            return self.stderr_path.read_text(errors="replace")[-600:].strip()
        except OSError:
            return ""

    def wait_socket(self, path: Path, timeout: float) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if path.exists():
                return
            if not self.alive():
                raise GuestDied(f"QEMU exited with code {self.proc.returncode}: {self.stderr_tail()}")
            time.sleep(0.1)
        raise GuestDied(f"socket {path} never appeared")

    def connect_qmp(self, path: Path, timeout: float = 20) -> qemu_tools.QMP:
        self.wait_socket(path, timeout)
        self.qmp = qemu_tools.QMP(path, timeout=timeout)
        return self.qmp

    def wait_log(self, path: Path, pattern: str, timeout: float, flat: bool = False, step: float = 0.25):
        """Poll a serial capture for a regex. Returns (match_or_None, text)."""
        rx = re.compile(pattern)
        deadline = time.time() + timeout
        while True:
            text = read_clean(path, flat)
            m = rx.search(text)
            if m:
                return m, text
            if time.time() > deadline or not self.alive():
                text = read_clean(path, flat)
                return rx.search(text), text
            time.sleep(step)

    def screenshot(self, base: Path) -> list[str]:
        """Write base.ppm and base.png through QMP screendump. Returns the files written."""
        files = []
        if self.qmp is None or not self.alive():
            return files
        ppm, png = base.with_suffix(".ppm"), base.with_suffix(".png")
        try:
            self.qmp.call("screendump", {"filename": str(ppm)})
            files.append(rel(ppm))
        except (RuntimeError, OSError, ValueError):
            pass
        try:
            self.qmp.call("screendump", {"filename": str(png), "format": "png"})
            files.append(rel(png))
        except (RuntimeError, OSError, ValueError):
            if ppm.is_file():
                try:
                    from PIL import Image
                    Image.open(ppm).save(png)
                    files.append(rel(png))
                except Exception:  # noqa: BLE001 - PIL missing or unreadable PPM: PPM stays as evidence
                    pass
        return files

    def text_screen(self, out: Path) -> list[str]:
        """Decode the 80x25 VGA text page (only meaningful in BIOS text mode)."""
        if self.qmp is None or not self.alive():
            return []
        try:
            raw = qemu_tools.read_guest_memory(self.qmp, 0xB8000, 4000, out.with_suffix(".bin"))
        except (RuntimeError, OSError, ValueError):
            return []
        lines = qemu_tools.decode_text_page(raw)
        out.write_text("\n".join(lines) + "\n")
        return lines

    def stop(self) -> None:
        if self.qmp is not None:
            try:
                self.qmp.call("quit")
            except (RuntimeError, OSError, ValueError):
                pass
            self.qmp.close()
        try:
            self.proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=6)
        self._stderr.close()


def ppm_stats(path: Path) -> dict:
    """Cheap sanity numbers for a PPM (P6) screendump: size and share of non-zero bytes."""
    try:
        data = path.read_bytes()
    except OSError:
        return {}
    parts = data.split(b"\n", 3)
    if len(parts) < 4 or parts[0] != b"P6":
        return {}
    width, height = (int(v) for v in parts[1].split()[:2])
    pixels = parts[3]
    nonzero = len(pixels) - pixels.count(b"\x00")
    return {"width": width, "height": height, "nonblank_ratio": round(nonzero / max(1, len(pixels)), 4)}


def connect_unix(path: Path, timeout: float) -> socket.socket:
    deadline = time.time() + timeout
    while True:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(str(path))
            sock.settimeout(0.5)
            return sock
        except OSError:
            sock.close()
            if time.time() > deadline:
                raise
            time.sleep(0.1)


def cpu_for(ctx: Context) -> str:
    return "host" if ctx.accel == "kvm" else "qemu64"


# ----------------------------------------------------------------- bios group
def test_bios(ctx: Context) -> None:
    group = "bios"
    names = ["ISO boots under SeaBIOS to the ShizukuDOS prompt (A:\\> on COM1)",
             "ShizukuDOS prompt visible on the emulated VGA text screen",
             "DIR lists NTW32.DLL, NTWRAP9X.VXD, NTWGPROB.EXE and the prompt returns",
             "screendump PNG evidence captured"]
    if ctx.qemu_unavailable(group, names):
        return
    work = ctx.group_dir(group)
    serial_log = work / "serial.log"
    with tempfile.TemporaryDirectory(prefix="shz-se-") as tmp:
        tmp = Path(tmp)
        serial_sock, qmp_sock = tmp / "serial.sock", tmp / "qmp.sock"
        argv = [ctx.qemu, "-name", "shz-se-iso-bios", "-machine", "pc", "-accel", ctx.accel, "-cpu", cpu_for(ctx),
                "-m", "64", "-boot", "order=d,menu=off", "-cdrom", ctx.iso, "-vga", "std", "-display", "none",
                "-nic", "none", "-no-reboot",
                "-chardev", f"socket,id=ser0,path={serial_sock},server=on,wait=off,logfile={serial_log}",
                "-serial", "chardev:ser0", "-qmp", f"unix:{qmp_sock},server=on,wait=off"]
        guest = Guest(argv, work)
        stop_drain = threading.Event()
        shots: list[str] = []
        try:
            try:
                guest.connect_qmp(qmp_sock)
                guest.wait_socket(serial_sock, 10)
            except GuestDied as exc:
                for name in names:
                    ctx.record(group, name, "BLOCKED", f"QEMU did not start: {exc}")
                return
            serial = connect_unix(serial_sock, 10)

            def drain() -> None:  # keep QEMU's chardev from backing up; content is in serial.log
                while not stop_drain.is_set():
                    try:
                        if not serial.recv(4096):
                            return
                    except socket.timeout:
                        continue
                    except OSError:
                        return

            threading.Thread(target=drain, daemon=True).start()

            m, text = guest.wait_log(serial_log, re.escape(PROMPT), ctx.timeout)
            ev = [rel(serial_log), rel(work / "qemu.cmdline")]
            if not m:
                ctx.record(group, names[0], "FAIL",
                           f"no {PROMPT!r} within {ctx.timeout}s under {ctx.accel}; serial tail {text[-300:]!r}; "
                           f"qemu alive={guest.alive()} {guest.stderr_tail()}", evidence=ev)
            else:
                ctx.record(group, names[0], "PASS",
                           f"prompt after boot from the ISO CD-ROM (order=d, no other bootable device), accel={ctx.accel}",
                           evidence=ev)
            time.sleep(0.5)
            shots += guest.screenshot(work / "boot")
            lines = guest.text_screen(work / "boot-screen.txt")
            if lines:
                ev2 = [rel(work / "boot-screen.txt")]
                if any(PROMPT in line for line in lines):
                    ctx.record(group, names[1], "PASS", "found on the VGA text page read from guest memory", evidence=ev2)
                else:
                    ctx.record(group, names[1], "FAIL",
                               "not found on the VGA text page: " + " | ".join(l for l in lines if l)[:300], evidence=ev2)
            else:
                ctx.record(group, names[1], "FAIL", "could not read the VGA text page through QMP pmemsave")

            if not m:
                ctx.record(group, names[2], "BLOCKED", "no ShizukuDOS prompt, DIR was not sent")
            else:
                before = read_clean(serial_log)
                start = len(before)
                serial.sendall(b"DIR\r")
                found, missing = [], []
                deadline = time.time() + min(ctx.timeout, 30)
                patterns = {n: re.compile(re.escape(n.split(".")[0]) + r"\s*\.\s*" + re.escape(n.split(".")[1]))
                            for n in DIR_EXPECTED}
                text = before
                while time.time() < deadline:
                    text = read_clean(serial_log)
                    tail = text[start:]
                    if all(p.search(tail) for p in patterns.values()) and tail.count(PROMPT) >= 1:
                        break
                    if not guest.alive():
                        break
                    time.sleep(0.25)
                tail = text[start:]
                found = [n for n, p in patterns.items() if p.search(tail)]
                missing = [n for n in DIR_EXPECTED if n not in found]
                prompt_back = PROMPT in tail
                (work / "dir-output.txt").write_text(tail)
                ev3 = [rel(serial_log), rel(work / "dir-output.txt")]
                if not missing and prompt_back:
                    ctx.record(group, names[2], "PASS", f"found {', '.join(found)}; prompt returned", evidence=ev3)
                else:
                    ctx.record(group, names[2], "FAIL",
                               f"missing {missing}; prompt returned={prompt_back}; DIR output tail {tail[-300:]!r}",
                               evidence=ev3)
                time.sleep(0.5)
                shots += guest.screenshot(work / "dir")
                guest.text_screen(work / "dir-screen.txt")

            png = [s for s in shots if s.endswith(".png")]
            stats = ppm_stats(work / "boot.ppm")
            if png and stats and stats.get("nonblank_ratio", 0) > 0:
                ctx.record(group, names[3], "PASS", f"{len(png)} PNG(s); boot.ppm {stats}", evidence=shots)
            else:
                ctx.record(group, names[3], "FAIL", f"screenshots={shots}, boot.ppm stats={stats}", evidence=shots)
        finally:
            stop_drain.set()
            guest.stop()


# ----------------------------------------------------------------- uefi group
def uefi_argv(ctx: Context, work: Path, tmp: Path, cpu: str, memory: str) -> tuple[list, Path, Path, Path]:
    variables = work / "OVMF_VARS.fd"
    shutil.copyfile(ctx.ovmf_vars, variables)  # per-run copy: the system template is never touched
    qmp_sock = tmp / "qmp.sock"
    serial_log = work / "serial.log"
    argv = [ctx.qemu, "-name", "shz-se-iso-uefi", "-machine", "q35", "-accel", ctx.accel, "-cpu", cpu,
            "-m", memory, "-smp", "1", "-nodefaults", "-nic", "none", "-display", "none", "-device", "VGA",
            "-no-reboot",
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={ctx.ovmf_code.resolve()}",
            "-drive", f"if=pflash,format=raw,unit=1,file={variables}",
            "-drive", f"if=none,id=cd0,media=cdrom,format=raw,file={ctx.iso},readonly=on",
            "-device", "ide-cd,drive=cd0,bus=ide.0,bootindex=1",
            "-serial", f"file:{serial_log}",
            "-debugcon", f"file:{work / 'ovmf-debugcon.log'}", "-global", "isa-debugcon.iobase=0x402",
            "-qmp", f"unix:{qmp_sock},server=on,wait=off"]
    return argv, qmp_sock, serial_log, variables


def bds_lines(text: str) -> list[str]:
    return [l.strip() for l in text.splitlines() if "BdsDxe" in l]


def test_uefi(ctx: Context) -> None:
    group = "uefi"
    n_load = "El Torito EFI image loaded and BOOTX64.EFI (Shizuku Supervisor loader) started under OVMF"
    n_vmx = "UEFI loader started; VMX-unavailable path"
    n_back = "control returned to firmware after the loader refused (no hand-over to the Supervisor)"
    domains = ["DOS16", "Kernel32", "Kernel64", "Win64"]
    domain_names = [f"multikernel domain {d} under the Supervisor" for d in domains]
    full = ctx.full_supervisor_possible
    all_names = [n_load] + ([] if full else [n_vmx, n_back] + domain_names)
    if ctx.qemu_unavailable(group, all_names):
        return
    missing_fw = [str(p) for p in (ctx.ovmf_code, ctx.ovmf_vars) if not p.is_file()]
    if missing_fw:
        for name in all_names:
            ctx.record(group, name, "BLOCKED", "OVMF firmware not found: " + ", ".join(missing_fw))
        return
    if ctx.layout is not None:
        has_uefi_entry = find_entry(ctx.layout, "UEFI") is not None
    else:
        try:
            has_uefi_entry = find_entry({"entries": parse_el_torito_raw(ctx.iso)["entries"]}, "UEFI") is not None
        except (OSError, ValueError, struct.error):
            has_uefi_entry = False
    work = ctx.group_dir(group)
    cpu = "host,+vmx" if full else "Nehalem,-vmx"  # Intel vendor, Long Mode, no VMX: the loader's refusal path
    with tempfile.TemporaryDirectory(prefix="shz-se-") as tmp:
        argv, qmp_sock, serial_log, _vars = uefi_argv(ctx, work, Path(tmp), cpu, "512M")
        guest = Guest(argv, work)
        try:
            try:
                guest.connect_qmp(qmp_sock)
            except GuestDied as exc:
                for name in all_names:
                    ctx.record(group, name, "BLOCKED", f"QEMU did not start: {exc}")
                return
            # 1. Firmware finds the El Torito EFI image and starts BOOTX64.EFI.
            end_markers = r"Shell>|UEFI Interactive Shell|failed to start Boot|failed to load Boot"
            m, text = guest.wait_log(serial_log, LOADER_BANNER.pattern + "|" + end_markers, ctx.timeout,
                                     flat=False, step=0.05)
            banner = LOADER_BANNER.search(read_clean(serial_log))
            ev = [rel(serial_log), rel(work / "qemu.cmdline")]
            bds = bds_lines(read_clean(serial_log))
            if not banner:
                shots = guest.screenshot(work / "no-loader")
                hint = "; the ISO has no UEFI El Torito entry (see layout group)" if not has_uefi_entry else ""
                ctx.record(group, n_load, "FAIL",
                           f"loader banner never seen within {ctx.timeout}s under {ctx.accel}{hint}; "
                           f"firmware lines: {bds[:4]}", evidence=ev + shots)
                blocked = "BOOTX64.EFI did not start"
                for name in all_names[1:]:
                    ctx.record(group, name, "BLOCKED", blocked)
                return

            starting = [l for l in bds if "starting Boot" in l]
            origin = starting[0] if starting else ("firmware logged no boot-option lines; the ISO CD-ROM is the "
                                                   "only boot device attached")
            ctx.record(group, n_load, "PASS",
                       f"banner '{banner.group(0)}' on serial after OVMF booted the ISO CD-ROM (ide-cd on AHCI, "
                       f"bootindex=1); {origin}", evidence=ev)

            if full:
                uefi_full(ctx, group, guest, work, serial_log, ev)
                return

            # 2. No VMX in the guest: the loader must refuse and return to firmware.
            m, text = guest.wait_log(serial_log, r"Returning to firmware", min(ctx.timeout, 30), flat=True, step=0.05)
            shots: list[str] = []
            if m:
                try:  # freeze the VM so the screenshot still shows the loader message
                    guest.qmp.call("stop")
                    shots += guest.screenshot(work / "loader-refused")
                    guest.qmp.call("cont")
                except (RuntimeError, OSError, ValueError):
                    pass
            flat = read_clean(serial_log, flat=True)
            refusal = re.search(r"REFUSED: Intel VMX backend unusable: (.*?)(?: Enable Intel VT-x| Returning to firmware|$)", flat)
            handed_over = "Handing over to the Supervisor" in flat
            if refusal and m and not handed_over:
                ctx.record(group, n_vmx, "PASS",
                           f"loader reported 'Intel VMX backend unusable: {refusal.group(1).strip()}' and 'Returning to "
                           f"firmware.'; guest CPU {cpu} under {ctx.accel} has no VMX, as expected on this host "
                           f"(kvm={ctx.kvm_device}, nested_vmx={ctx.nested_vmx})", evidence=ev + shots)
            else:
                ctx.record(group, n_vmx, "FAIL",
                           f"refusal line seen={bool(refusal)}, 'Returning to firmware' seen={bool(m)}, "
                           f"handed over to Supervisor={handed_over}; serial tail {flat[-400:]!r}", evidence=ev + shots)
            # 3. Firmware regained control.
            m2, text = guest.wait_log(serial_log, r"failed to start Boot\d+[^\n]*|Shell>|UEFI Interactive Shell",
                                      min(ctx.timeout, 60), flat=False)
            shots += guest.screenshot(work / "final")
            if m2 and refusal and not handed_over:
                ctx.record(group, n_back, "PASS", f"firmware line after the refusal: {m2.group(0).strip()[:200]!r}",
                           evidence=ev + shots)
            else:
                ctx.record(group, n_back, "FAIL", f"no firmware activity after the refusal; serial tail "
                           f"{read_clean(serial_log, flat=True)[-300:]!r}", evidence=ev + shots)
            for d, name in zip(domains, domain_names):
                ctx.record(group, name, "BLOCKED", VMX_REASON, domain=d)
        finally:
            guest.stop()
            log = work / "ovmf-debugcon.log"
            if log.exists() and log.stat().st_size == 0:
                log.unlink()


def uefi_full(ctx: Context, group: str, guest: Guest, work: Path, serial_log: Path, ev: list[str]) -> None:
    """Best effort: run shizukudos/supervisor/test_qemu.py's checks against the ISO-booted Supervisor.

    Needs /dev/kvm plus nested Intel VMX. This code path could not be executed on the host that
    developed it (no /dev/kvm), so a harness error is recorded as BLOCKED, never as PASS."""
    import importlib.util
    try:
        spec = importlib.util.spec_from_file_location("shz_supervisor_test_qemu",
                                                      ROOT / "shizukudos" / "supervisor" / "test_qemu.py")
        tq = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tq)
        shzinfo, verify = tq.shzinfo, tq.verify
        shzinfo.selfcheck(ROOT)
    except Exception as exc:  # noqa: BLE001
        ctx.record(group, "full Supervisor run against the ISO", "BLOCKED",
                   f"could not load the shizukudos/supervisor/test_qemu.py helpers: {exc!r}", evidence=ev)
        return

    def to_records(checks: list[dict]) -> None:
        for c in checks:
            ctx.record(group, c["check"], c["status"], c.get("detail", ""), evidence=ev)

    info = final = None
    try:
        deadline = time.time() + ctx.timeout
        while time.time() < deadline and guest.alive():
            time.sleep(0.5)
            raw = qemu_tools.read_guest_memory(guest.qmp, shzinfo.REGION_BASE, shzinfo.INFO_BYTES, work / "info.bin")
            cur = shzinfo.Info.parse(raw)
            if cur.magic != shzinfo.MAGIC:
                continue
            info = cur
            if info.stage in (6, 0xDEAD):
                break
        if info is not None and info.stage >= 4:
            time.sleep(0.5)
            guest.screenshot(work / "screen")
            text = qemu_tools.read_guest_memory(guest.qmp, info.guest_ram_base + 0xB8000, 4000, work / "b8000.bin")
            screen = qemu_tools.decode_text_page(text)
            qemu_tools.read_guest_memory(guest.qmp, info.disk_base, info.disk_size, work / "disk_after.img")
            final = info
    except Exception as exc:  # noqa: BLE001
        ctx.record(group, "full Supervisor run against the ISO", "BLOCKED",
                   f"harness error while sampling the info page: {exc!r}", evidence=ev)
        return
    serial_text = read_clean(serial_log)
    checks = [verify._check("Supervisor reached guest-exit stage", final is not None and final.stage == 6,
                            (info.stage_name() + ": " + info.last_error.decode(errors="replace")) if info else
                            "Supervisor info page never appeared; serial tail " + repr(serial_text[-300:]))]
    if final is not None:
        caps = set(final.caps())
        checks.append(verify._check("capabilities detected from inside L1",
                                    {"LONG_MODE", "VMX", "VMX_ENABLED", "EPT", "UNRESTRICTED", "BACKEND_VMX"} <= caps,
                                    ",".join(sorted(caps))))
        checks.append(verify._check("guest requested exit code 0",
                                    final.guest_exit_requested == 1 and final.guest_exit_code == 0))
        disk_after = work / "disk_after.img"
        if disk_after.exists():
            d_checks, _result = verify.verify_disk(disk_after)
            checks += [dict(c, check="L2 " + c["check"]) for c in d_checks]
            checks += verify.verify_screen(screen)
        domain_info = final.to_dict()["domains"]
        if "KERNEL32" in domain_info:
            checks += tq.check_kernel32(domain_info["KERNEL32"])
        if "KERNEL64" in domain_info:
            checks += tq.check_kernel64(domain_info["KERNEL64"])
        checks.append(verify._check("DOS16, KERNEL32 and KERNEL64 domains were scheduled",
                                    {"DOS16", "KERNEL32", "KERNEL64"} <= set(domain_info), ",".join(domain_info)))
    checks.append(verify._check("guest console marker SHZ-EXIT:0 in the serial log", "SHZ-EXIT:0" in serial_text))
    to_records(checks)


# -------------------------------------------------------------- install group
def test_install(ctx: Context) -> None:
    group = "install"
    full_name = "unattended Windows 98 installation to completion"
    media = ctx.args.win98_iso
    if media is None:
        present = [f"{p}: {'present' if (ROOT / p.split(' ')[0]).exists() else 'missing'}" for p in MISSING_MEDIA]
        ctx.record(group, full_name, "BLOCKED",
                   "no Windows 98 media supplied (--win98-iso). Media checked: " + "; ".join(present) +
                   ". Windows 98 installation to completion is NOT verified.")
        return
    names = ["Windows 98 media boot/setup screen appears (PARTIAL evidence: boot screen only, install NOT verified)"]
    if not media.is_file():
        ctx.record(group, names[0], "BLOCKED", f"--win98-iso {media} is not a readable file")
        ctx.record(group, full_name, "BLOCKED", "not implemented; also no readable media")
        return
    with media.open("rb") as fh:
        fh.seek(16 * SECTOR)
        if fh.read(8)[1:6] != b"CD001":
            ctx.record(group, names[0], "BLOCKED", f"{media} has no ISO 9660 volume descriptor at sector 16")
            ctx.record(group, full_name, "BLOCKED", "not implemented; also no usable media")
            return
    if ctx.qemu_unavailable(group, names):
        ctx.record(group, full_name, "BLOCKED", "not implemented; also QEMU/accelerator unavailable")
        return
    work = ctx.group_dir(group)
    blank = work / "blank-hdd.img"
    with blank.open("wb") as fh:
        fh.truncate(2 * 1024 ** 3)  # sparse blank raw HDD
    serial_log = work / "serial.log"
    with tempfile.TemporaryDirectory(prefix="shz-se-") as tmp:
        qmp_sock = Path(tmp) / "qmp.sock"
        argv = [ctx.qemu, "-name", "shz-se-iso-install", "-machine", "pc", "-accel", ctx.accel, "-cpu", cpu_for(ctx),
                "-m", "256", "-vga", "std", "-display", "none", "-nic", "none", "-no-reboot",
                "-drive", f"if=none,id=win98,media=cdrom,format=raw,file={media},readonly=on",
                "-device", "ide-cd,drive=win98,bus=ide.1,unit=0,bootindex=1",
                "-drive", f"if=none,id=shz,media=cdrom,format=raw,file={ctx.iso},readonly=on",
                "-device", "ide-cd,drive=shz,bus=ide.1,unit=1,bootindex=2",
                "-drive", f"if=none,id=hd,format=raw,file={blank}",
                "-device", "ide-hd,drive=hd,bus=ide.0,unit=0,bootindex=3",
                "-serial", f"file:{serial_log}", "-qmp", f"unix:{qmp_sock},server=on,wait=off"]
        guest = Guest(argv, work)
        shots: list[str] = []
        try:
            try:
                guest.connect_qmp(qmp_sock)
            except GuestDied as exc:
                ctx.record(group, names[0], "BLOCKED", f"QEMU did not start: {exc}")
                ctx.record(group, full_name, "BLOCKED", "not implemented")
                return
            keywords = re.compile(r"windows 98|setup|startup menu|microsoft", re.I)
            hit = None
            lines: list[str] = []
            deadline = time.time() + min(ctx.timeout, 120)
            tick = 0
            while time.time() < deadline and guest.alive():
                time.sleep(4)
                tick += 1
                lines = guest.text_screen(work / "screen.txt")
                joined = "\n".join(lines)
                # ShizukuDOS on our own ISO must not be mistaken for the Microsoft media.
                if "ShizukuDOS" not in joined and PROMPT not in joined:
                    hit = keywords.search(joined)
                    if hit:
                        break
            shots += guest.screenshot(work / "win98-boot")
            ev = shots + ([rel(work / "screen.txt")] if (work / "screen.txt").exists() else [])
            if hit:
                ctx.record(group, names[0], "PASS",
                           f"PARTIAL evidence: VGA text page matched {hit.group(0)!r} after boot from the Windows 98 "
                           f"media; nothing was installed or checked beyond this screen", evidence=ev, partial=True)
            elif guest.alive() and shots:
                ctx.record(group, names[0], "SKIP",
                           "screenshot captured but no boot/setup text recognised on the VGA text page (graphics "
                           "or localized screen?); review the PNG manually", evidence=ev, partial=True)
            else:
                ctx.record(group, names[0], "FAIL", f"no screen captured; qemu alive={guest.alive()} "
                           f"{guest.stderr_tail()}", evidence=ev)
        finally:
            guest.stop()
    ctx.record(group, full_name, "BLOCKED",
               "not implemented: only the media's boot/setup screen is captured; a full unattended Windows 98 "
               "installation check does not exist in this harness, so installation is NOT verified")


# ----------------------------------------------------------------------- main
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--iso", default=None, help=f"ISO under test (default {DEFAULT_ISO})")
    p.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto",
                   help="auto = kvm only if /dev/kvm is usable, else tcg")
    p.add_argument("--timeout", type=int, default=180, help="seconds to wait for each boot milestone (default 180)")
    p.add_argument("--only", action="append", metavar="GROUP",
                   help="run only these groups (bios,uefi,layout,install); repeat or comma-separate")
    p.add_argument("--win98-iso", default=None, help="user-supplied Windows 98 media (optional; never downloaded)")
    p.add_argument("--evidence-dir", default=None, help=f"default {DEFAULT_EVIDENCE}")
    p.add_argument("--qemu", default=None, help="qemu-system-x86_64 binary (default: $QEMU, PATH, /usr/libexec/qemu-kvm)")
    p.add_argument("--ovmf-code", default=None)
    p.add_argument("--ovmf-vars", default=None)
    args = p.parse_args(argv)
    args.iso = Path(args.iso) if args.iso else ROOT / DEFAULT_ISO
    args.evidence_dir = Path(args.evidence_dir) if args.evidence_dir else ROOT / DEFAULT_EVIDENCE
    args.win98_iso = Path(args.win98_iso) if args.win98_iso else None
    selected = []
    for item in args.only or list(GROUPS):
        for name in item.split(","):
            name = name.strip()
            if name not in GROUPS:
                p.error(f"--only: unknown group {name!r} (choose from {', '.join(GROUPS)})")
            if name not in selected:
                selected.append(name)
    args.only = [g for g in GROUPS if g in selected]
    return args


def tool_versions(ctx: Context) -> dict:
    out = {"qemu_path": ctx.qemu, "qemu": qemu_tools.qemu_version(ctx.qemu) if ctx.qemu else None,
           "xorriso": (shzlib.tool_version("xorriso") or {}).get("version"),
           "mtools": bool(shutil.which("mcopy"))}
    return out


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    signal.signal(signal.SIGTERM, _on_signal)
    ctx = Context(args)
    ctx.evidence.mkdir(parents=True, exist_ok=True)
    tee = Tee(sys.stdout, ctx.evidence / "report.txt")
    sys.stdout = tee
    print(f"ISO      {ctx.iso}")
    print(f"accel    {ctx.accel} (/dev/kvm usable={ctx.kvm_device}, nested Intel VMX={ctx.nested_vmx})")
    print(f"QEMU     {ctx.qemu or 'NOT FOUND'}")
    print(f"evidence {ctx.evidence}\n", flush=True)

    iso_bytes = 0
    exit_early = False
    if not ctx.iso.is_file():
        exit_early = True
        for group in args.only:
            ctx.record(group, "ISO under test exists", "BLOCKED", f"{ctx.iso} does not exist; nothing was tested")
    else:
        iso_bytes = ctx.iso.stat().st_size
        ctx.iso_sha256 = shzlib.sha256_file(ctx.iso)
        for group, func in (("layout", test_layout), ("bios", test_bios), ("uefi", test_uefi), ("install", test_install)):
            if group not in args.only:
                ctx.record(group, "group not run", "SKIP", f"--only excluded '{group}'; it was not verified")
                continue
            print(f"--- {group} ---", flush=True)
            try:
                func(ctx)
            except Exception as exc:  # noqa: BLE001 - a harness crash must not read as a pass
                import traceback
                ctx.record(group, f"{group} harness error", "FAIL", f"{exc!r}\n{traceback.format_exc()[-800:]}")
        after = shzlib.sha256_file(ctx.iso) if ctx.iso.is_file() else ""
        ctx.record("layout" if "layout" in args.only else "meta", "ISO unchanged during the run",
                   "PASS" if after == ctx.iso_sha256 else "FAIL",
                   f"sha256 {ctx.iso_sha256}" if after == ctx.iso_sha256 else
                   f"sha256 changed from {ctx.iso_sha256} to {after}: results mix two ISOs, rerun")

    counts = {s: sum(1 for r in ctx.results if r["status"] == s) for s in shzlib.RESULTS}
    complete = counts["FAIL"] == 0 and counts["SKIP"] == 0 and counts["BLOCKED"] == 0
    verdict = "VERIFIED" if complete else ("FAILED" if counts["FAIL"] else "INCOMPLETE")
    summary = {
        "tool": "tools/test_shizuku_se_iso.py", "utc": shzlib.utc_now(), "verdict": verdict, "counts": counts,
        "groups_selected": args.only,
        "iso": {"path": str(ctx.iso), "bytes": iso_bytes, "sha256": ctx.iso_sha256,
                "has_uefi_el_torito_entry": (find_entry(ctx.layout, "UEFI") is not None) if ctx.layout else None},
        "environment": {"accel_requested": args.accel, "accel_used": ctx.accel, "kvm_device": ctx.kvm_device,
                        "nested_intel_vmx": ctx.nested_vmx, "full_supervisor_run_possible": ctx.full_supervisor_possible,
                        "ovmf_code": str(ctx.ovmf_code), "ovmf_vars": str(ctx.ovmf_vars), **tool_versions(ctx)},
        "win98_iso": str(args.win98_iso) if args.win98_iso else None,
        "notes": ["Development-only QEMU runs; not claims about real hardware.",
                  "Windows 98 installation to completion is never verified by this tool.",
                  "Multikernel domains need Intel VMX in the guest (/dev/kvm + nested)."],
        "git": shzlib.git_state(), "results": ctx.results,
    }
    result_path = ctx.evidence / "result.json"
    shzlib.write_json(result_path, summary)
    print(f"\ncounts {counts} -> {verdict}")
    print(f"result {result_path}")
    sys.stdout = tee.stream
    tee.close()
    if exit_early:
        return 2
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
