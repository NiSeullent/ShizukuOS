#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Remaster the verified public hybrid ISO with a frozen main continuation kit.

This packages historical boot binaries; it does not recompile the integrated
runtime, authenticate modern applications, or distribute Microsoft media.
Every output belongs to a newly created directory. No downloads or VMs run.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import signal
import struct
import subprocess
import sys
import tarfile
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
SITE = "https://m98.nyase.kr"
BASE_SHA = "998e0717cb3dc094ed740ae431088f1f91c9fcc37ad90753ccda125ed9d65424"
RECEIPT_SHA = "09eacc70dd5a5c133a025213be6a187918995e85c61f9ad54335a0a8e27aa971"
BASE_BYTES = 161480704
FLOOR = 20 << 30
RAM_FLOOR = 6 << 30
ISO_NAME = "windows98-modern-continuation-20261001.iso"
BOOT = "/isolinux/isolinux.bin"
EFI = "/ShizukuDOS10/efiboot.img"
LBA_LINE = re.compile(r"^File data lba:\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*'(/.*)'$")
REQUIRED = {
    "/NOMSBASE.TXT", "/ShizukuDOS10/GPL-NOTICE.TXT",
    "/ShizukuDOS10/SOURCE/shizukudos-source.tar.gz",
    "/ShizukuDOS10/SOURCE/csmwrap-7f30b740c352.tar.gz",
    "/ShizukuDOS10/SOURCE/freedos-freecom-04fc21a9f679.tar.gz",
    "/ShizukuDOS10/SOURCE/freedos-kernel-5ffb5502d39a.tar.gz",
    "/ShizukuDOS10/SOURCE/wine-db11d0fe6a16.tar.gz",
    "/ShizukuDOS10/SOURCE/freetype-42608f77f207.tar.gz",
}
FALSE_CLAIMS = {
    "integrated_boot_runtime_recompiled": False,
    "full_modern_javascript_css_wasm_webgl_webgpu_verified": False,
    "all_requested_modern_apps_verified": False,
    "windows98_installer_or_complete_os_image": False,
    "fresh_iso_boot_execution_verified": False,
}


def need(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def stamp(st: os.stat_result) -> tuple[int, ...]:
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def canonical(path: Path) -> Path:
    path = path.absolute()
    need(path.resolve(strict=True) == path, f"symlink or noncanonical input: {path}")
    need(path.is_file(), f"not a regular input file: {path}")
    return path


def pin(path: Path) -> dict:
    path = canonical(path)
    before = path.stat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        need(stamp(os.fstat(handle.fileno())) == stamp(before), "input changed before opening")
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
        need(stamp(os.fstat(handle.fileno())) == stamp(before), "input changed while hashing")
    need(stamp(path.stat()) == stamp(before), "input path changed while hashing")
    return {"path": str(path), "bytes": before.st_size, "sha256": digest,
            "stat": list(stamp(before))}


def read_small(path: Path, maximum: int = 2 << 20) -> bytes:
    need(path.stat().st_size <= maximum, f"oversized metadata: {path}")
    return path.read_bytes()


def memory_available() -> int:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    raise RuntimeError("MemAvailable is unavailable")


class Budget:
    def __init__(self, out: Path, maximum: int):
        self.out, self.maximum, self.highwater = out, maximum, 0

    def check(self, admission: bool = False) -> dict:
        total = 0
        if self.out.exists():
            for directory, dirs, files in os.walk(self.out):
                for name in dirs + files:
                    path = Path(directory) / name
                    need(not path.is_symlink(), "output acquired a symlink")
                total += sum((Path(directory) / name).stat().st_size for name in files)
        self.highwater = max(self.highwater, total)
        free = shutil.disk_usage(self.out.parent).free
        mem = memory_available()
        need(total <= self.maximum, "owned output budget exceeded")
        need(free >= FLOOR + (self.maximum if admission else 0), "20 GiB disk reserve unavailable")
        need(mem >= RAM_FLOOR, "6 GiB available-memory floor unavailable")
        return {"free_bytes": free, "memory_available_bytes": mem,
                "owned_output_bytes": total, "owned_output_highwater_bytes": self.highwater}


def run(command: list[str], out: Path, label: str, budget: Budget, timeout: int = 180) -> str:
    """Monitor only the new child process group; preserve all failed logs."""
    budget.check()
    stdout, stderr = out / f"{label}.stdout.log", out / f"{label}.stderr.log"
    need(not stdout.exists() and not stderr.exists(), f"log path already exists: {label}")

    def limits() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (budget.maximum, budget.maximum))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    with stdout.open("xb") as a, stderr.open("xb") as b:
        proc = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                stdout=a, stderr=b, start_new_session=True, preexec_fn=limits)
        start = time.monotonic()
        try:
            while proc.poll() is None:
                budget.check()
                need(time.monotonic() - start <= timeout, f"command timed out: {label}")
                need(stdout.stat().st_size <= 4 << 20 and stderr.stat().st_size <= 4 << 20,
                     f"oversized tool log: {label}")
                time.sleep(0.05)
            need(proc.returncode == 0, f"{label} failed: exit {proc.returncode}")
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
    budget.check()
    return read_small(stdout, 4 << 20).decode("utf-8", "strict")


def write_new(path: Path, data: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def write_json(path: Path, obj: dict) -> None:
    write_new(path, (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode())


def inspect_source(path: Path) -> dict:
    total, files, seen, roots = 0, [], set(), set()
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            need(not name.is_absolute() and ".." not in name.parts and name.parts,
                 "source archive has an unsafe path")
            need(member.name not in seen, "source archive has duplicate paths")
            seen.add(member.name)
            need(len(seen) <= 30000, "source archive member count bound exceeded")
            roots.add(name.parts[0])
            need(member.isdir() or member.isreg(), "source archive has links/devices")
            parts, base = [p.lower() for p in name.parts], name.name.lower()
            need(not any(p in {".git", ".ssh", ".codex", "build"} for p in parts),
                 f"private/build path in source archive: {member.name}")
            need(base not in {"io.sys", "msdos.sys", "command.com", "setup.exe", "suwin.exe",
                              "id_rsa", "id_ed25519", ".env"} and
                 re.fullmatch(r"(?:win98_\d+|precopy\d+|mini|base\d+|driver\d+)\.cab", base) is None,
                 f"private media/key path in source archive: {member.name}")
            need(not base.endswith((".qcow2", ".qcow2.xz", ".raw", ".iso", ".vmdk", ".pfx", ".p12", ".key")),
                 f"private media/key extension in source archive: {member.name}")
            if member.isreg():
                total += member.size
                need(member.size <= 64 << 20 and total <= 256 << 20, "source archive size bound exceeded")
                handle = archive.extractfile(member)
                need(handle is not None, "source file could not be read")
                digest, tail, actual = hashlib.sha256(), b"", 0
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(chunk)
                    actual += len(chunk)
                    scan = tail + chunk
                    need(re.search(rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", scan) is None,
                         f"private key material in source archive: {member.name}")
                    tail = scan[-128:]
                need(actual == member.size, "truncated source archive member")
                files.append({"path": member.name, "bytes": actual, "sha256": digest.hexdigest()})
    need(len(roots) == 1 and files, "source archive needs exactly one project root")
    root = next(iter(roots))
    need(f"{root}/LICENSE" in seen and f"{root}/tools/remaster_continuation_iso.py" in seen,
         "integrated source archive is missing its licence or this build recipe")
    return {"root": root, "regular_files": len(files), "uncompressed_bytes": total, "files": files}


def inspect_bundle(path: Path, commit: str) -> dict:
    with path.open("rb") as handle:
        version = handle.readline(128)
        need(version in (b"# v2 git bundle\n", b"# v3 git bundle\n"), "unsupported bundle header")
        refs, used = {}, len(version)
        while True:
            line = handle.readline(4096)
            used += len(line)
            need(used <= 1 << 20 and line.endswith(b"\n"), "invalid bundle header")
            if line == b"\n":
                break
            need(not line.startswith(b"-"), "incremental bundle cannot restore another environment independently")
            if line.startswith(b"@"):
                need(line == b"@object-format=sha1\n", "unsupported bundle capability")
                continue
            match = re.fullmatch(rb"([0-9a-f]{40}) (refs/[^\s]+|HEAD)\n", line)
            need(match is not None, "invalid bundle ref")
            ref = match[2].decode()
            need(ref not in refs, "duplicate bundle ref")
            refs[ref] = match[1].decode()
        need(handle.read(4) == b"PACK", "bundle pack is missing")
    need(refs.get("refs/heads/main") == commit, "bundle main does not match integrated source commit")
    return {"version": version.decode().strip(), "self_contained_header": True,
            "main_commit": commit, "refs": refs,
            "pack_object_integrity_checked_here": False}


def catalogue(iso: Path) -> dict:
    with iso.open("rb") as handle:
        boot_record = None
        for lba in range(16, 64):
            handle.seek(lba * 2048)
            data = handle.read(2048)
            need(len(data) == 2048 and data[1:6] == b"CD001", "invalid volume descriptor")
            if data[0] == 0 and data[7:30] == b"EL TORITO SPECIFICATION":
                boot_record = data
                break
            if data[0] == 255:
                break
        need(boot_record is not None, "El Torito boot record absent")
        catalog_lba = struct.unpack_from("<I", boot_record, 0x47)[0]
        handle.seek(catalog_lba * 2048)
        data = handle.read(2048)
    need(len(data) == 2048 and data[0] == 1 and data[30:32] == b"\x55\xaa" and
         sum(struct.unpack_from("<16H", data)) & 65535 == 0, "invalid boot catalog validation")

    def entry(pos: int, platform: int) -> dict:
        return {"platform": platform, "bootable": data[pos] == 0x88, "media": data[pos + 1] & 15,
                "sector_count": struct.unpack_from("<H", data, pos + 6)[0],
                "lba": struct.unpack_from("<I", data, pos + 8)[0]}

    entries, pos = [entry(32, data[1])], 64
    while pos + 32 <= len(data) and data[pos] in (0x90, 0x91):
        final, platform, count = data[pos] == 0x91, data[pos + 1], struct.unpack_from("<H", data, pos + 2)[0]
        need(count > 0 and pos + 32 * (count + 1) <= len(data), "invalid boot catalog section")
        entries.extend(entry(pos + 32 * (n + 1), platform) for n in range(count))
        pos += 32 * (count + 1)
        if final:
            break
    need(len(entries) == 2 and [e["platform"] for e in entries] == [0, 0xEF] and
         all(e["bootable"] and e["media"] == 0 for e in entries) and
         entries[0]["sector_count"] == 4, "expected exactly one BIOS and one UEFI boot entry")
    return {"catalog_lba": catalog_lba, "entries": entries}


def iso_extents(iso: Path, out: Path, label: str, budget: Budget) -> dict:
    text = run(["xorriso", "-indev", str(iso), "-find", "/", "-type", "f", "-exec", "report_lba", "--"],
               out, label, budget)
    records = {}
    for line in text.splitlines():
        if not line.startswith("File data lba:"):
            continue
        match = LBA_LINE.fullmatch(line)
        need(match is not None, "unrecognized file extent record")
        xt, lba, blocks, size = map(int, match.groups()[:4])
        name = match[5]
        need(xt == 0 and name not in records, "multi-extent files need a separate verifier")
        need(size <= blocks * 2048 and (lba + blocks) * 2048 <= iso.stat().st_size,
             "file extent exceeds ISO bounds")
        need(not name.upper().startswith("/WIN98/") and name.upper() != "/MSBASE.TXT",
             "private Microsoft media on ISO")
        with iso.open("rb") as handle:
            handle.seek(lba * 2048)
            digest, remaining = hashlib.sha256(), size
            while remaining:
                data = handle.read(min(remaining, 1 << 20))
                need(bool(data), "truncated ISO extent")
                digest.update(data)
                remaining -= len(data)
        records[name] = {"lba": lba, "blocks": blocks, "bytes": size, "sha256": digest.hexdigest()}
    need(records and REQUIRED <= set(records), "ISO lacks required corresponding source/licences")
    return records


def extent_bytes(iso: Path, record: dict) -> bytes:
    need(record["bytes"] <= 2 << 20, "oversized metadata extent")
    with iso.open("rb") as handle:
        handle.seek(record["lba"] * 2048)
        data = handle.read(record["bytes"])
    need(len(data) == record["bytes"], "truncated metadata extent")
    return data


def check_hybrid(iso: Path, cat: dict, records: dict, original_mbr: bytes) -> dict:
    with iso.open("rb") as handle:
        mbr, header = handle.read(512), handle.read(512)
        handle.seek(iso.stat().st_size - 512)
        backup = handle.read(512)
        need(mbr[:432] == original_mbr[:432] and mbr[510:512] == b"\x55\xaa", "isohybrid MBR changed")
        parts = [struct.unpack_from("<BBBxB3xII", mbr, 446 + n * 16) for n in range(4)]
        total = iso.stat().st_size // 512
        need(parts[0][0] == 0x80 and parts[0][-2:] == (0, total), "MBR whole-image partition wrong")
        need(parts[1][3] == 0xEF and parts[1][-2:] ==
             (records[EFI]["lba"] * 4, records[EFI]["bytes"] // 512), "MBR EFI partition wrong")
        arrays = []
        for label, value, expected_current, expected_backup in (
                ("primary", header, 1, total - 1), ("backup", backup, total - 1, 1)):
            need(value[:8] == b"EFI PART", f"{label} GPT signature absent")
            length, crc = struct.unpack_from("<II", value, 12)
            need(92 <= length <= 512, "GPT header length wrong")
            clean = bytearray(value[:length]); clean[16:20] = b"\0" * 4
            need(zlib.crc32(clean) & 0xFFFFFFFF == crc, f"{label} GPT header checksum wrong")
            current_lba, other_lba, first_usable, last_usable = struct.unpack_from("<QQQQ", value, 24)
            need((current_lba, other_lba) == (expected_current, expected_backup) and
                 2 <= first_usable <= last_usable < total - 1, f"{label} GPT geometry wrong")
            array_lba, count, stride, array_crc = struct.unpack_from("<QIII", value, 72)
            need(128 <= stride <= 4096 and 0 < count <= 1024, "GPT array size bound exceeded")
            need(array_lba >= 2 and array_lba * 512 + count * stride <= iso.stat().st_size,
                 "GPT array exceeds ISO bounds")
            handle.seek(array_lba * 512); array = handle.read(count * stride)
            need(len(array) == count * stride and zlib.crc32(array) & 0xFFFFFFFF == array_crc,
                 f"{label} GPT entry checksum wrong")
            arrays.append(array)
            efi_start = records[EFI]["lba"] * 4
            efi_end = efi_start + records[EFI]["bytes"] // 512 - 1
            entries = [array[n * stride:(n + 1) * stride] for n in range(count)]
            need(any(e[:16] != b"\0" * 16 and struct.unpack_from("<QQ", e, 32) == (efi_start, efi_end)
                     for e in entries), f"{label} GPT does not expose the actual EFI image")
        need(arrays[0] == arrays[1] and header[56:72] == backup[56:72], "GPT copies disagree")
        bios, efi = cat["entries"]
        need(bios["lba"] == records[BOOT]["lba"] and efi["lba"] == records[EFI]["lba"],
             "boot catalog file locations wrong")
        binary = extent_bytes(iso, records[BOOT])
        pvd, lba, length, checksum = struct.unpack_from("<IIII", binary, 8)
        payload = binary[64:] + b"\0" * (-(len(binary) - 64) % 4)
        expected = sum(struct.unpack(f"<{len(payload) // 4}I", payload)) & 0xFFFFFFFF
        need((pvd, lba, length, checksum) == (16, bios["lba"], len(binary), expected),
             "ISOLINUX boot-info-table does not describe the new ISO")
        handle.seek(efi["lba"] * 2048); fat = handle.read(512)
        need(fat[0] in (0xEB, 0xE9) and fat[510:512] == b"\x55\xaa", "UEFI image is not a FAT volume")
    return {"mbr_code_preserved": True, "mbr_whole_image_and_efi_partitions": True,
            "primary_and_backup_gpt_checksums": True, "isolinux_boot_info_table": True,
            "bios_and_uefi_catalog_locations": True}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-iso", required=True, type=Path)
    ap.add_argument("--base-receipt", required=True, type=Path)
    ap.add_argument("--source-archive", required=True, type=Path, help="gzip tar of frozen integrated main")
    ap.add_argument("--source-sha256", required=True)
    ap.add_argument("--bundle", required=True, type=Path)
    ap.add_argument("--bundle-sha256", required=True)
    ap.add_argument("--source-commit", required=True)
    ap.add_argument("--output-dir", required=True, type=Path, help="a new canonical directory; never overwritten")
    ap.add_argument("--budget-mib", type=int, default=512)
    args = ap.parse_args()
    out = args.output_dir.absolute()
    need(re.fullmatch(r"[0-9a-f]{40}", args.source_commit) is not None, "source commit must be full SHA-1")
    need(all(re.fullmatch(r"[0-9a-f]{64}", s) for s in (args.source_sha256, args.bundle_sha256)),
         "input hashes must be full SHA-256")
    need(256 <= args.budget_mib <= 1024, "budget must be 256..1024 MiB")
    need(not out.exists() and not out.is_symlink() and out.parent.resolve(strict=True) == out.parent,
         "output directory must be new with canonical existing parent")
    inputs = [pin(p) for p in (args.base_iso, args.base_receipt, args.source_archive, args.bundle)]
    need(inputs[0]["sha256"] == BASE_SHA and inputs[0]["bytes"] == BASE_BYTES and
         inputs[1]["sha256"] == RECEIPT_SHA, "public baseline authority differs")
    need(inputs[2]["sha256"] == args.source_sha256 and inputs[3]["sha256"] == args.bundle_sha256,
         "frozen source/bundle hash differs")
    need(len({p["path"] for p in inputs}) == 4, "input paths must be distinct")
    base, receipt, source, bundle = [Path(p["path"]) for p in inputs]
    metadata = json.loads(read_small(receipt))
    need(metadata.get("private") is False and metadata.get("sha256") == BASE_SHA and
         metadata.get("bytes") == BASE_BYTES, "base receipt is not the approved public image")
    source_info, bundle_info = inspect_source(source), inspect_bundle(bundle, args.source_commit)
    budget = Budget(out, args.budget_mib << 20)
    before_resources = budget.check(admission=True)
    need(BASE_BYTES + source.stat().st_size + bundle.stat().st_size + (16 << 20) <= budget.maximum,
         "new ISO cannot fit the selected output budget")
    out.mkdir(mode=0o700)
    try:
        originals = iso_extents(base, out, "base-extents", budget)
        need(len(originals) == 98, "approved baseline file count differs")
        kit = out / "continuation-files"; kit.mkdir()
        provenance = {"schema": 1, "official_site": SITE, "integrated_source_commit": args.source_commit,
                      "base_iso": inputs[0], "base_iso_receipt": inputs[1],
                      "historical_boot_build_git": metadata["git"], "historical_boot_inputs": metadata["inputs"],
                      "historical_boot_profile": metadata.get("boot_profile"),
                      "existing_licences_and_corresponding_source_preserved": True,
                      "claims": FALSE_CLAIMS,
                      "publication_kind": "hybrid bootable development continuation snapshot"}
        write_json(kit / "BOOT-BINARY-PROVENANCE.json", provenance)
        write_new(kit / "BASE-ISO-RECEIPT.json", read_small(receipt))
        write_json(kit / "INTEGRATED-SOURCE.json", {"commit": args.source_commit, "source": inputs[2],
                  "bundle": inputs[3], "tar": source_info, "bundle_header": bundle_info})
        write_new(kit / "CONTINUE-ko.md", (
            f"# Windows 98 Modern 개발 이어가기\n\n공식 홈페이지·다운로드: {SITE}\n\n"
            f"통합 main 커밋: `{args.source_commit}`\n\n"
            "이 ISO는 기존 공개 BIOS/UEFI 부팅 이미지에 통합 소스와 Git bundle을 추가한 개발 스냅샷입니다. "
            "부팅 Kernel64/Win64/DOS16 바이너리는 BOOT-BINARY-PROVENANCE.json에 기록된 기존 빌드입니다. "
            "최신 JavaScript·CSS·WASM·WebGL·WebGPU 전체 지원과 요청한 모든 앱의 실행은 아직 인증되지 않았습니다. "
            "Windows 98 설치본·Microsoft 파일·제품 키·개인 VM 디스크는 배포하지 않습니다.\n\n"
            "소스만 열려면 `SOURCE.tar.gz`를 풀면 됩니다. Git 기록과 main을 복원하려면 "
            "`git clone MAIN.bundle Win98-Modern` 다음 `git -C Win98-Modern checkout main`을 사용합니다. "
            "프로젝트의 `docs/CONTINUE_IN_ANOTHER_ENVIRONMENT.md`를 이어서 읽으세요. "
            "디스크 여유 20 GiB와 가용 RAM 6 GiB를 유지하며 필요한 구성요소를 다시 빌드하고 검증해야 합니다.\n\n"
            "기존 GPL/LGPL/OFL 소스·라이선스·패치는 ShizukuDOS10/SOURCE 및 LICENSES에 그대로 있습니다. "
            "ISO 자체의 실제 부팅 검증은 별도 외부 영수증에 기록합니다.\n"
        ).encode())
        additions = {f"/CONTINUE/{p.name}": p for p in kit.iterdir()}
        additions.update({"/CONTINUE/SOURCE.tar.gz": source, "/CONTINUE/MAIN.bundle": bundle})
        write_new(kit / "SHA256SUMS", "".join(f"{pin(path)['sha256']}  {name.rsplit('/', 1)[1]}\n"
                  for name, path in sorted(additions.items())).encode())
        additions["/CONTINUE/SHA256SUMS"] = kit / "SHA256SUMS"
        temporary, final = out / f"{ISO_NAME}.partial", out / ISO_NAME
        command = ["xorriso", "-indev", str(base), "-outdev", str(temporary),
                   "-assess_indev_features", "replay", "-boot_image", "any", "replay"]
        for name, path in sorted(additions.items()):
            command += ["-map", str(path), name]
        command += ["-commit", "-end"]
        run(command, out, "remaster", budget)
        records = iso_extents(temporary, out, "new-extents", budget)
        need(set(records) == set(originals) | set(additions), "new ISO file set differs")
        exceptions = []
        for name, original in originals.items():
            current = records[name]
            if name == BOOT:
                a, b = extent_bytes(base, original), extent_bytes(temporary, current)
                need(a[:8] == b[:8] and a[64:] == b[64:], "ISOLINUX changed outside its boot-info-table")
                exceptions.append({"path": name, "only_mutable_byte_range": [8, 64]})
            else:
                need((original["bytes"], original["sha256"]) == (current["bytes"], current["sha256"]),
                     f"historical ISO payload changed: {name}")
        for name, path in additions.items():
            actual = pin(path)
            need((actual["bytes"], actual["sha256"]) == (records[name]["bytes"], records[name]["sha256"]),
                 f"new continuation payload changed: {name}")
        cat = catalogue(temporary)
        with base.open("rb") as handle:
            mbr = handle.read(512)
        hybrid = check_hybrid(temporary, cat, records, mbr)
        layout_text = run(["xorriso", "-indev", str(temporary), "-report_el_torito", "plain",
                           "-report_system_area", "plain"], out, "new-layout", budget)
        need(re.search(r"El Torito boot img\s*:\s*1\s+BIOS\s+y\s+none", layout_text) is not None and
             re.search(r"El Torito boot img\s*:\s*2\s+UEFI\s+y\s+none", layout_text) is not None and
             "isohybrid" in layout_text and "GPT" in layout_text,
             "xorriso does not independently report BIOS, UEFI, isohybrid MBR and GPT")
        need([pin(Path(p["path"])) for p in inputs] == inputs, "original/source inputs changed before publication")
        iso_pin = pin(temporary)
        budget.check()
        # New directory ownership makes this rename an immutable publication step.
        need(not final.exists() and not final.is_symlink(), "final ISO already exists")
        temporary.rename(final)
        iso_pin["path"] = str(final)
        iso_pin = pin(final)
        result = {"schema": 1, "status": "ISO_REMASTER_AND_BYTE_LAYOUT_VERIFIED",
                  "completed_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "official_site": SITE,
                  "source_commit": args.source_commit, "iso": iso_pin, "original_inputs": inputs,
                  "source_tar": source_info, "bundle": bundle_info, "catalog": cat, "hybrid": hybrid,
                  "original_regular_payloads_preserved": len(originals), "boot_catalog_regenerated": True,
                  "payload_exceptions": exceptions, "new_files": records, "claims": FALSE_CLAIMS,
                  "resources_before": before_resources, "resources_after": budget.check(),
                  "owned_output_budget_bytes": budget.maximum,
                  "resource_monitor": {"poll_seconds": 0.05, "per_child_file_limit_bytes": budget.maximum,
                                       "aggregate_and_free_space_checks_are_sampled": True,
                                       "peer_resource_changes_may_trigger_owned_child_termination": True},
                  "vm_started": False, "download_performed": False, "github_upload_performed": False}
        write_json(out / "result.json", result)
        write_new(out / "SHA256SUMS", f"{iso_pin['sha256']}  {final.name}\n".encode())
        budget.check()
        print(json.dumps({"status": result["status"], "iso": iso_pin,
                          "receipt": str(out / "result.json"), "boot_execution_verified": False}, indent=2))
        return 0
    except Exception as exc:
        # Preserve partial ISO, every original input, and every command log.
        write_json(out / "failure.json", {"status": "FAILED", "error": str(exc),
                   "claims": FALSE_CLAIMS, "original_inputs": inputs, "vm_started": False})
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, tarfile.TarError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
