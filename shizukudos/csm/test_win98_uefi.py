#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Cold-boot a disposable Windows 98 installed-disk snapshot via OVMF/CSMWrap.

Only new files below build/shizukudos/csm are writable. The immutable XZ archive
and its checkpoint record are verified before and after the run. Offline snapshot
conversion restores disk contents only, never the old VM's CPU/RAM/device state.
CSMWrap and its serial configuration are added to the cloned Windows FAT volume;
its original MBR and Windows boot sector remain intact. At least two CPUs are
required because CSMWrap reserves an AP for BIOS services.

Firmware serial markers establish the UEFI compatibility path, not Windows GUI
success. Actual QMP screenshots, VGA text and registers are retained for review;
a graphical screen alone is not automatically classified as a working desktop.
Guest installation diagnostics affect only a new owned clone. No network,
host configuration changes, original-disk writeback or active-VM access is used.
"""
import argparse
import hashlib
import json
import lzma
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import qemu  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD, sha256_file  # noqa: E402

GIB = 1024 ** 3
RESERVE = 20 * GIB
DIRTY_BUDGET = 256 * 1024 ** 2
CSM = BUILD / "csm"
MARKERS = [
    ("OVMF starts disk UEFI application", r"BdsDxe: starting Boot\w+ .*\("),
    ("CSMWrap reads serial configuration", r"serial = true"),
    ("CSMWrap unlocks legacy BIOS region", r"Unlock!"),
    ("CSM16 placed below 1 MiB", r"csm_bin_base: 0xe0000"),
    ("BIOS proxy runs on reserved AP", r"BIOS proxy ready \(AP \d+\)"),
    ("legacy target is the cloned HDD", r"bootdev: Boot device: PCI [0-9a-f:.]+ type=HDD"),
    ("CSMWrap builds legacy memory map", r"csmwrap e820 map has \d+ items"),
]
INI = "serial=true\r\nserial_port=0x3f8\r\nserial_baud=115200\r\n"
FATAL_STDERR = re.compile(r"emulation failure|KVM internal error|qemu: fatal|failed to initialize kvm", re.I)


def command(argv, cwd=None, timeout=120):
    result = subprocess.run([str(x) for x in argv], cwd=cwd, capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{argv[0]} failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def restore_archive(archive, output, expected):
    """One bounded CRC64 XZ stream, with exact raw length/hash and no trailing data."""
    digest, total = hashlib.sha256(), 0
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 * 1024 ** 2)
    with archive.open("rb") as source, output.open("xb") as dest:
        while not decoder.eof:
            data = source.read(1024 ** 2) if decoder.needs_input else b""
            if decoder.needs_input and not data:
                raise RuntimeError("Truncated checkpoint archive")
            raw = decoder.decompress(data, max_length=1024 ** 2)
            total += len(raw)
            if total > expected["raw_bytes"]:
                raise RuntimeError("Checkpoint expansion exceeds recorded size")
            # The retained qcow2 contains large zero ranges. Keep those as holes,
            # while hashing the complete original byte stream independently.
            for start in range(0, len(raw), 4096):
                page = raw[start:start + 4096]
                if page == b"\0" * len(page):
                    dest.seek(len(page), os.SEEK_CUR)
                else:
                    dest.write(page)
            digest.update(raw)
            if shutil.disk_usage(output.parent).free < RESERVE + DIRTY_BUDGET:
                raise RuntimeError("Sparse restoration would consume the selected reserve/dirty budget")
        if decoder.unused_data or source.read(1) or decoder.check != lzma.CHECK_CRC64:
            raise RuntimeError("Checkpoint must be one CRC64 XZ stream without trailing data")
        dest.truncate(total)
    if total != expected["raw_bytes"] or digest.hexdigest() != expected["raw_sha256"]:
        raise RuntimeError("Restored checkpoint length/hash mismatch")


def add_uefi_files(disk, run_dir, efi, firmware_gop=False):
    with disk.open("rb") as stream:
        mbr = stream.read(512)
    if len(mbr) != 512 or mbr[510:] != b"\x55\xaa":
        raise RuntimeError("Windows clone has no MBR signature")
    partitions = []
    for i in range(4):
        entry = mbr[446 + i * 16:462 + i * 16]
        start, sectors = struct.unpack_from("<II", entry, 8)
        if entry[4] in (0x06, 0x0b, 0x0c, 0x0e) and start and sectors:
            partitions.append((entry[0] == 0x80, start, sectors, entry[4]))
    if not partitions:
        raise RuntimeError("No Windows FAT16/FAT32 primary partition in clone")
    active, start, sectors, kind = max(partitions)
    spec = f"{disk}@@{start * 512}"
    if (start + sectors) * 512 > disk.stat().st_size:
        raise RuntimeError("Windows partition exceeds cloned disk")
    before = sha256_file(disk)
    boot = run_dir / "windows-boot-sector.bin"
    with disk.open("rb") as stream:
        stream.seek(start * 512)
        boot.write_bytes(stream.read(512))
    command(["mdir", "-a", "-i", spec, "::IO.SYS"])
    command(["mdir", "-a", "-i", spec, "::WINDOWS/WIN.COM"])
    if efi is None:
        return {"start_lba": start, "sectors": sectors, "type": kind, "active": active,
                "mbr_sha256": hashlib.sha256(mbr).hexdigest(), "boot_sector_sha256": sha256_file(boot),
                "snapshot_disk_sha256": before, "raw_disk_sha256": before,
                "efi_injection": "none; native SeaBIOS diagnostic control"}
    for directory in ("EFI", "EFI/BOOT"):
        existing = subprocess.run(["mdir", "-i", spec, f"::{directory}"], capture_output=True)
        if existing.returncode:
            command(["mmd", "-i", spec, f"::{directory}"])
    ini = run_dir / "csmwrap.ini"
    ini.write_bytes((INI + ("gop_only=true\r\n" if firmware_gop else "")).encode("ascii"))
    command(["mcopy", "-o", "-i", spec, efi, "::EFI/BOOT/BOOTX64.EFI"])
    command(["mcopy", "-o", "-i", spec, ini, "::EFI/BOOT/csmwrap.ini"])
    with disk.open("rb") as stream:
        if stream.read(512) != mbr:
            raise RuntimeError("EFI injection changed the Windows MBR")
        stream.seek(start * 512)
        if stream.read(512) != boot.read_bytes():
            raise RuntimeError("EFI injection changed the Windows boot sector")
    return {"start_lba": start, "sectors": sectors, "type": kind, "active": active,
            "mbr_sha256": hashlib.sha256(mbr).hexdigest(), "boot_sector_sha256": sha256_file(boot),
            "snapshot_disk_sha256": before, "uefi_disk_sha256": sha256_file(disk),
            "efi_config_sha256": sha256_file(ini), "firmware_gop_opt_in": firmware_gop}


def capture_vga_scanout(qmp, run_dir, stem, locator):
    """Read only the verified QEMU standard VGA adapter's documented MMIO."""
    evidence = {"scope": "optional adapter-specific scanout diagnostic; no mode parameter writes",
                "capture_limitation": "sequential live PCI/MMIO reads; normal device-read side effects recorded"}
    try:
        if locator.get("validation_status") != "PASS":
            raise RuntimeError("Scanout capture requires a validated firmware-GOP locator")
        pci = qmp.call("query-pci")
        path = run_dir / f"{stem}-query-pci.json"
        shzlib.write_json(path, pci)
        evidence["pci"] = {"path": str(path), "sha256": sha256_file(path)}
        devices = []
        def visit(value):
            if isinstance(value, dict):
                identity = value.get("id", {})
                if (isinstance(identity, dict) and identity.get("vendor") == 0x1234
                        and identity.get("device") == 0x1111 and "regions" in value):
                    devices.append(value)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)
        visit(pci)
        if len(devices) != 1:
            raise RuntimeError("Expected exactly one actual 1234:1111 QEMU standard VGA adapter")
        device = devices[0]
        bars = {x["bar"]: x for x in device["regions"] if "bar" in x}
        fb, mmio = bars.get(0, {}), bars.get(2, {})
        if (fb.get("type") != "memory" or fb.get("address") != locator["framebuffer_base"]
                or fb.get("size", 0) < locator["framebuffer_size"]
                or mmio.get("type") != "memory" or mmio.get("size", 0) < 4096
                or not 0 < mmio.get("address", 0) <= 0xfffff000):
            raise RuntimeError("Actual standard VGA BAR0/2 does not match validated GOP framebuffer/MMIO bounds")
        base = mmio["address"]
        evidence.update(device=device, mmio_physical=base, normal_read_side_effects=[
            "Reading BAR2+0x41a (3DA status) resets the VGA attribute controller flip-flop",
            "Reading dispi MMIO selects the adapter's internal dispi register index; mode values are not written"])
        samples = {}
        for label, offset, size in (("attribute_initial", 0x400, 1), ("status_flipflop_reset", 0x41a, 1),
                                    ("attribute_after_reset", 0x400, 1), ("dispi", 0x500, 22), ("qext", 0x600, 8)):
            sample_path = run_dir / f"{stem}-vga-mmio-{label}.bin"
            raw = qemu.read_guest_memory(qmp, base + offset, size, sample_path)
            if len(raw) != size:
                raise RuntimeError("VGA MMIO diagnostic returned an incomplete sample")
            samples[label] = {"physical": base + offset, "bytes": size, "path": str(sample_path),
                              "sha256": sha256_file(sample_path), "hex": raw.hex()}
        evidence.update(status="captured", samples=samples,
                        dispi_u16_le=list(struct.unpack("<11H", bytes.fromhex(samples["dispi"]["hex"]))),
                        attribute_display_enable=bool(int(samples["attribute_after_reset"]["hex"], 16) & 0x20))
    except Exception as error:
        evidence.update(status="unavailable", diagnostic_error=str(error))
    return evidence


def capture(qmp, run_dir, number, csm16=None, cpu_count=2, memory_mib=128, firmware_gop=False, framebuffer_requested=False, scanout_requested=False):
    stem = f"screen-{number:03d}"
    frame = {}
    if firmware_gop:
        # A stock VGA driver can leave the forced GOP display unresponsive to
        # QEMU's display-update request. Preserve CPU/physical evidence first.
        frame["firmware_gop_handover"] = capture_gop_handover(qmp, run_dir, stem)
        evidence = {"scope": "read-only RAM BIOS data area; no BIOS call, device access or DCC override"}
        try:
            path = run_dir / f"{stem}-bios-data-area.bin"
            raw = qemu.read_guest_memory(qmp, 0x400, 256, path)
            if len(raw) != 256:
                raise RuntimeError("BIOS data area sample is incomplete")
            evidence.update(status="captured", physical=0x400, bytes=256, path=str(path), sha256=sha256_file(path),
                            video_mode=raw[0x49], video_columns=struct.unpack_from("<H", raw, 0x4a)[0],
                            video_rows_minus_one=raw[0x84], character_height=struct.unpack_from("<H", raw, 0x85)[0],
                            crtc_address=struct.unpack_from("<H", raw, 0x63)[0], dcc_index=raw[0x8a])
        except Exception as error:
            evidence.update(status="unavailable", diagnostic_error=str(error))
        frame["bios_display_data"] = evidence
    text = qemu.decode_text_page(qemu.read_guest_memory(qmp, 0xb8000, 4000, run_dir / f"{stem}-vga.bin"))
    (run_dir / f"{stem}-text.txt").write_text("\n".join(text) + "\n")
    registers = qemu.cpu_state(qmp)
    (run_dir / f"{stem}-registers.txt").write_text(registers)
    frame["vga_text"] = text
    # Code dumps are optional evidence: debug translation can reject even a
    # valid sampled PC, especially during concurrent segment/mode changes.
    try:
        capture_cpu0_code(qmp, run_dir, stem, registers, frame)
    except Exception as error:
        frame["cpu0_code"] = {"status": "unavailable", "diagnostic_error": str(error),
                              "capture_limitation": "optional sequential live code capture failed; screenshot/registers retained"}
    frame["proxy_diagnostics"] = capture_proxy_diagnostics(qmp, run_dir, stem, csm16, cpu_count, memory_mib)
    if framebuffer_requested:
        evidence = {"scope": "requested bounded physical framebuffer sample; compare independently with guest diagnostic pattern and coordinates"}
        try:
            locator = frame.get("firmware_gop_handover", {}).get("persistent_locator", {})
            if locator.get("validation_status") != "PASS" or not 0 < locator.get("visible_bytes", 0) <= 16 * 1024 ** 2:
                raise RuntimeError("Physical framebuffer capture requires exact validated persistent locator and <=16MiB visible range")
            path = run_dir / f"{stem}-physical-framebuffer.bin"
            raw = qemu.read_guest_memory(qmp, locator["framebuffer_base"], locator["visible_bytes"], path)
            if len(raw) != locator["visible_bytes"]:
                raise RuntimeError("Physical framebuffer returned an incomplete sample")
            evidence.update(status="captured", physical=locator["framebuffer_base"], bytes=len(raw),
                            width=locator["width"], height=locator["height"], pitch=locator["pitch"],
                            bits_per_pixel=locator["bits_per_pixel"], path=str(path), sha256=sha256_file(path))
        except Exception as error:
            evidence.update(status="unavailable", diagnostic_error=str(error))
        frame["physical_framebuffer"] = evidence
    if scanout_requested:
        frame["vga_scanout"] = capture_vga_scanout(qmp, run_dir, stem,
                              frame.get("firmware_gop_handover", {}).get("persistent_locator", {}))
    screenshot = run_dir / f"{stem}.png"
    try:
        try:
            qmp.call("screendump", {"filename": str(screenshot), "format": "png"})
        except RuntimeError:
            screenshot = run_dir / f"{stem}.ppm"
            qmp.call("screendump", {"filename": str(screenshot)})
        frame.update(screenshot=str(screenshot), sha256=sha256_file(screenshot), screenshot_status="captured")
    except Exception as error:
        if not firmware_gop:
            raise
        frame.update(screenshot=None, screenshot_status="unavailable", screenshot_error=str(error))
        # Python's buffered socket cannot resume reading after a timeout. A
        # new connection drops the outstanding screen request, preserving the
        # owned guest and the independent fatal/status gates.
        socket_path = qmp.socket.getpeername()
        qmp.close()
        replacement = qemu.QMP(socket_path)
        qmp.__dict__.update(replacement.__dict__)
        frame["qmp_recovery"] = "fresh connection after unavailable forced-GOP screenshot"
    return frame


def cb_checksum(raw):
    total = sum(byte << (8 if index & 1 else 0) for index, byte in enumerate(raw))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def validate_gop_handover(table, descriptor, serial_values):
    """Validate only the documented locator/descriptor; never scan for substitute signatures."""
    address, serial_base, serial_size, serial_visible = serial_values
    if len(table) < 24 or table[:4] != b"LBIO":
        raise RuntimeError("Coreboot locator at physical 0x500 is absent or overwritten")
    _, header_bytes, _, table_bytes, table_sum, entries = struct.unpack_from("<6I", table)
    if header_bytes != 24 or table_bytes > len(table) - header_bytes or not 1 <= entries <= 64:
        raise RuntimeError("Coreboot header bounds are invalid")
    records = table[header_bytes:header_bytes + table_bytes]
    if cb_checksum(table[:header_bytes]) != 0 or cb_checksum(records) != table_sum:
        raise RuntimeError("Coreboot header/table checksum mismatch")
    parsed, cursor = [], 0
    for _ in range(entries):
        if cursor + 8 > len(records):
            raise RuntimeError("Coreboot entry header exceeds table")
        tag, size = struct.unpack_from("<2I", records, cursor)
        if size < 8 or cursor + size > len(records):
            raise RuntimeError("Coreboot entry bounds are invalid")
        parsed.append((tag, records[cursor:cursor + size])); cursor += size
    if cursor != len(records):
        raise RuntimeError("Coreboot entry count does not consume exact table")
    private = [raw for tag, raw in parsed if tag == 0x53485a47]
    framebuffer = [raw for tag, raw in parsed if tag == 0x12]
    if len(private) != 1 or len(private[0]) != 24 or len(framebuffer) != 1 or len(framebuffer[0]) < 37:
        raise RuntimeError("Coreboot lacks exactly one valid SHZGOP1 and framebuffer record")
    pointer, size, reserved = struct.unpack_from("<QII", private[0], 8)
    if pointer != address or size != 96 or reserved != 0:
        raise RuntimeError("Coreboot descriptor locator differs from serial or ABI")
    if len(descriptor) < 96 or descriptor[:8] != b"SHZGOP1\0":
        raise RuntimeError("Reserved descriptor magic/length mismatch")
    major, minor, wire_size = struct.unpack_from("<HHI", descriptor, 8)
    if (major, minor, wire_size) != (1, 0, 96) or sum(struct.unpack_from("<24I", descriptor)) & 0xffffffff:
        raise RuntimeError("Reserved descriptor ABI/checksum mismatch")
    flags = struct.unpack_from("<I", descriptor, 20)[0]
    base, actual_size, visible = struct.unpack_from("<3Q", descriptor, 24)
    width, height, pitch, bpp = struct.unpack_from("<4I", descriptor, 48)
    masks = struct.unpack_from("<4I", descriptor, 64)
    if (base, actual_size, visible) != (serial_base, serial_size, serial_visible):
        raise RuntimeError("Reserved descriptor final framebuffer differs from serial")
    if flags not in (3, 7) or not width or not height or bpp != 32 or pitch < width * 4 or visible != pitch * height or not 0 < visible <= actual_size:
        raise RuntimeError("Reserved descriptor geometry/flags/range invalid")
    if not base or base + actual_size > 0x100000000 or struct.unpack_from("<I", descriptor, 92)[0] != 0:
        raise RuntimeError("Reserved descriptor is outside native 32-bit mapping bounds")
    fb = framebuffer[0]
    cb_base, cb_width, cb_height, cb_pitch = struct.unpack_from("<QIII", fb, 8)
    cb_masks = []
    for index in range(4):
        pos, bits = fb[29 + index * 2:31 + index * 2]
        if pos + bits > 32:
            raise RuntimeError("Coreboot framebuffer channel bounds invalid")
        cb_masks.append(((1 << bits) - 1) << pos if bits else 0)
    if (cb_base, cb_width, cb_height, cb_pitch, fb[28], tuple(cb_masks)) != (base, width, height, pitch, bpp, masks):
        raise RuntimeError("Standard coreboot framebuffer differs from reserved descriptor")
    return {"validation_status": "PASS", "descriptor_physical": address, "framebuffer_base": base,
            "framebuffer_size": actual_size, "visible_bytes": visible, "width": width, "height": height,
            "pitch": pitch, "bits_per_pixel": bpp, "masks": list(masks), "flags": flags,
            "scope": "locator and reserved descriptor intact at sampled guest stage; not native driver rendering proof"}


def capture_gop_handover(monitor, run_dir, stem):
    evidence = {"utc": shzlib.utc_now(), "capture_limitation": "sequential live physical-memory samples, not atomic"}
    try:
        path = run_dir / f"{stem}-coreboot-table.bin"
        table = qemu.read_guest_memory(monitor, 0x500, 0xb00, path)
        evidence["coreboot_table"] = {"physical": 0x500, "bytes": len(table), "path": str(path), "sha256": sha256_file(path)}
        serial = (run_dir / "serial.log").read_text(errors="replace")
        values = re.findall(r"SHZGOP1 handover=((?:0x)?[0-9a-f]+) base=0x([0-9a-f]+) size=0x([0-9a-f]+) visible=0x([0-9a-f]+)", serial, re.I)
        if len(values) != 1:
            raise RuntimeError("No unique SHZGOP1 handover serial address yet")
        serial_values = tuple(int(value, 16) for value in values[0])
        address = serial_values[0]
        if address < 0x100000 or address > 0xfffff000 or address & 4095:
            raise RuntimeError("SHZGOP1 serial descriptor page is outside documented bounds")
        path = run_dir / f"{stem}-shzgop-descriptor-page.bin"
        descriptor = qemu.read_guest_memory(monitor, address, 4096, path)
        evidence["descriptor_page"] = {"physical": address, "bytes": len(descriptor), "path": str(path), "sha256": sha256_file(path)}
        evidence.update(validate_gop_handover(table, descriptor, serial_values), status="captured")
    except Exception as error:
        evidence.update(status="unavailable", validation_status="FAIL", diagnostic_error=str(error))
    anchor_evidence = {}
    try:
        path = run_dir / f"{stem}-bios-fseg.bin"
        fseg = qemu.read_guest_memory(monitor, 0xf0000, 65536, path)
        anchor_evidence["fseg"] = {"physical": 0xf0000, "bytes": len(fseg), "path": str(path), "sha256": sha256_file(path)}
        marker = re.findall(r"SHZLOC1 anchor=0x([0-9a-f]+) descriptor=0x([0-9a-f]+) checksum=0x([0-9a-f]+)", serial, re.I)
        if len(marker) != 1 or "descriptor" not in locals():
            raise RuntimeError("No unique persistent locator marker and captured descriptor yet")
        anchor_evidence.update(validate_gop_locator(fseg, descriptor, serial_values,
                               tuple(int(value, 16) for value in marker[0])), status="captured")
    except Exception as error:
        anchor_evidence.update(status="unavailable", validation_status="FAIL", diagnostic_error=str(error))
    evidence["persistent_locator"] = anchor_evidence
    return evidence


def validate_gop_locator(fseg, descriptor, serial_values, anchor_marker):
    """Accept the versioned self-validating F-segment anchor; no low-RAM scan fallback."""
    if len(fseg) != 65536:
        raise RuntimeError("Persistent locator capture is not the exact reserved F-segment")
    offsets = [offset for offset in range(0, 65536 - 8 + 1, 16) if fseg[offset:offset + 8] == b"SHZLOC1\0"]
    if len(offsets) != 1:
        raise RuntimeError("Persistent locator scan does not contain exactly one aligned full-magic anchor")
    offset = offsets[0]; anchor = fseg[offset:offset + 48]
    if len(anchor) != 48:
        raise RuntimeError("Persistent locator full magic does not contain its complete 48-byte anchor")
    major, minor, wire_size, checksum, self_phys, pointer, length, descriptor_sum, flags, reserved = struct.unpack_from("<HHIIIQ4I", anchor, 8)
    if ((major, minor, wire_size, self_phys, length, flags, reserved) != (1, 0, 48, 0xf0000 + offset, 96, 1, 0)
            or sum(struct.unpack("<12I", anchor)) & 0xffffffff):
        raise RuntimeError("Persistent locator version/bounds/self-address/checksum invalid")
    if (self_phys, pointer, descriptor_sum) != anchor_marker or pointer != serial_values[0] or pointer <= 0x100000 or pointer > 0xfffff000 or pointer & 4095:
        raise RuntimeError("Persistent locator differs from exact firmware marker or descriptor-page bounds")
    if len(descriptor) < 96 or descriptor[:8] != b"SHZGOP1\0" or struct.unpack_from("<HHI", descriptor, 8) != (1, 0, 96):
        raise RuntimeError("Persistent locator descriptor ABI/magic mismatch")
    if sum(struct.unpack_from("<24I", descriptor)) & 0xffffffff or struct.unpack_from("<I", descriptor, 16)[0] != descriptor_sum:
        raise RuntimeError("Persistent locator descriptor checksum mismatch")
    base, actual, visible, width, height, pitch, bpp = struct.unpack_from("<3Q4I", descriptor, 24)
    if (base, actual, visible) != serial_values[1:] or not width or not height or bpp != 32 or pitch < width * 4 or visible != pitch * height or not 0 < visible <= actual or not base or base + actual > 0x100000000:
        raise RuntimeError("Persistent locator final framebuffer geometry/range invalid")
    if struct.unpack_from("<I", descriptor, 20)[0] not in (3, 7) or struct.unpack_from("<I", descriptor, 92)[0] != 0:
        raise RuntimeError("Persistent locator descriptor flags/reserved fields invalid")
    return {"validation_status": "PASS", "anchor_physical": self_phys, "descriptor_physical": pointer,
            "descriptor_checksum": descriptor_sum, "framebuffer_base": base, "framebuffer_size": actual,
            "visible_bytes": visible, "width": width, "height": height, "pitch": pitch, "bits_per_pixel": bpp,
            "scope": "reserved F-segment anchor and descriptor intact at sampled stage; native rendering requires separate proof"}


def capture_cpu0_code(qmp, run_dir, stem, registers, frame):
    # Only claim a physical instruction address for real mode. Protected-mode
    # paging needs a separate translation and must not be guessed from CS:EIP.
    cs = re.search(r"^CS =\w+\s+([0-9a-f]+)", registers, re.M | re.I)
    ip = re.search(r"\bEIP=([0-9a-f]+)", registers, re.I)
    cr0 = re.search(r"\bCR0=([0-9a-f]+)", registers, re.I)
    a20 = re.search(r"\bA20=([01])", registers)
    if cs and ip and cr0 and a20 and not (int(cr0[1], 16) & 1):
        linear = int(cs[1], 16) + int(ip[1], 16)
        physical = linear if a20[1] == "1" else linear & ~(1 << 20)
        code = run_dir / f"{stem}-cpu0-code.bin"
        qemu.read_guest_memory(qmp, physical, 128, code)
        disassembly = command(["objdump", "-D", "-b", "binary", "-m", "i386", "-M", "addr16,data16", code])
        assembly = run_dir / f"{stem}-cpu0-code.txt"
        assembly.write_text(f"CPU0 real mode; CS base+EIP={linear:#x}; A20={a20[1]}; physical={physical:#x}\n" + disassembly)
        frame["cpu0_code"] = {"linear": linear, "physical": physical, "a20": int(a20[1]),
                              "path": str(code), "sha256": sha256_file(code),
                              "disassembly": str(assembly), "decode": "real-mode 16-bit"}
        windows = {}
        for label, address in (("masked", physical), ("unmasked", linear)):
            start = max(0, address - 32)
            window = run_dir / f"{stem}-cpu0-{label}-window.bin"
            qemu.read_guest_memory(qmp, start, 192, window)
            listing = run_dir / f"{stem}-cpu0-{label}-window.txt"
            decoded = command(["objdump", "-D", "-b", "binary", "-m", "i386", "-M", "addr16,data16",
                               "--adjust-vma", str(start), window])
            listing.write_text(f"{label} physical read window {start:#x}; sampled target {address:#x}\n" + decoded)
            windows[label] = {"start": start, "target": address, "path": str(window),
                              "sha256": sha256_file(window), "disassembly": str(listing)}
        ivt = run_dir / f"{stem}-ivt.bin"
        qemu.read_guest_memory(qmp, 0, 1024, ivt)
        windows["ivt"] = {"path": str(ivt), "sha256": sha256_file(ivt)}
        ss = re.search(r"^SS =\w+\s+([0-9a-f]+)", registers, re.M | re.I)
        sp = re.search(r"\bESP=([0-9a-f]+)", registers, re.I)
        if ss and sp:
            stack_linear = int(ss[1], 16) + int(sp[1], 16)
            stack_address = stack_linear if a20[1] == "1" else stack_linear & ~(1 << 20)
            stack = run_dir / f"{stem}-cpu0-stack.bin"
            qemu.read_guest_memory(qmp, max(0, stack_address - 16), 144, stack)
            windows["stack"] = {"linear_top": stack_linear, "physical_top": stack_address,
                                "start": max(0, stack_address - 16), "path": str(stack), "sha256": sha256_file(stack)}
        frame["cpu0_code"]["windows"] = windows
        frame["cpu0_code"]["capture_limitation"] = "register and memory reads are sequential QMP samples while guest runs, not an atomic stop"
    elif cs and ip and cr0 and (int(cr0[1], 16) & 1):
        # memsave asks CPU0's debug translation for virtual memory. This retains
        # paged Win98 VMM/device-init code without pretending linear=physical.
        linear = int(cs[1], 16) + int(ip[1], 16)
        code = run_dir / f"{stem}-cpu0-virtual-code.bin"
        qmp.call("memsave", {"val": linear, "size": 192, "filename": str(code), "cpu-index": 0})
        protected32 = bool(re.search(r"^CS =.*CS32", registers, re.M))
        mode = "addr32,data32" if protected32 else "addr16,data16"
        decoded = command(["objdump", "-D", "-b", "binary", "-m", "i386", "-M", mode,
                           "--adjust-vma", str(linear), code])
        listing = run_dir / f"{stem}-cpu0-virtual-code.txt"
        listing.write_text(f"CPU0 virtual {linear:#x}; QMP memsave CPU-index0 debug translation; decode {mode}\n" + decoded)
        frame["cpu0_code"] = {"linear": linear, "address_space": "CPU0-virtual; QMP debug translation",
                              "path": str(code), "sha256": sha256_file(code), "disassembly": str(listing),
                              "decode": mode, "capture_limitation": "sequential live QMP register/memory samples"}


def capture_proxy_diagnostics(monitor, run_dir, stem, csm16, cpu_count, memory_mib):
    """Best-effort, read-only proxy/AP evidence; never turn a dump error into a boot failure."""
    evidence = {"capture_limitation": "sequential live register/physical-memory samples, not an atomic stop",
                "cpus": []}
    for index in range(cpu_count):
        item = {"cpu_index": index}
        try:
            registers = monitor.call("human-monitor-command", {"command-line": "info registers", "cpu-index": index})
            if f"CPU#{index}" not in registers:
                raise RuntimeError(f"QMP register capture did not select CPU {index}")
            path = run_dir / f"{stem}-cpu{index}-registers.txt"
            path.write_text(registers)
            item.update(status="captured", path=str(path), sha256=sha256_file(path))
            if index == 1:
                esp = re.search(r"\bESP=([0-9a-f]+)", registers, re.I)
                cr0 = re.search(r"\bCR0=([0-9a-f]+)", registers, re.I)
                ss = re.search(r"^SS =\w+\s+([0-9a-f]+)", registers, re.M | re.I)
                if esp and cr0 and ss and int(cr0[1], 16) & 1 and not int(cr0[1], 16) & (1 << 31) and int(ss[1], 16) == 0:
                    page = int(esp[1], 16) & ~4095
                    if 0x100000 <= page and page + 4096 <= memory_mib * 1024 ** 2:
                        path = run_dir / f"{stem}-cpu1-stack-page.bin"
                        raw = qemu.read_guest_memory(monitor, page, 4096, path)
                        item["stack_page"] = {"physical": page, "esp": int(esp[1], 16), "path": str(path),
                                              "sha256": sha256_file(path), "first_words": list(struct.unpack_from("<3I", raw)),
                                              "interpretation": "ESP-derived page; first words retained without assuming initialized thread_info"}
                    else:
                        item["stack_page"] = {"status": "unavailable", "reason": "ESP-derived page outside configured ordinary RAM bound"}
                else:
                    item["stack_page"] = {"status": "unavailable", "reason": "CPU1 is not flat, unpaged protected mode"}
        except Exception as error:
            item["diagnostic_error"] = str(error)
            item.setdefault("status", "unavailable")
        evidence["cpus"].append(item)
    if csm16 is not None:
        try:
            raw = csm16.read_bytes()
            signature = b"CSMPPrxy"
            offset = raw.find(signature)
            if offset < 0 or raw.find(signature, offset + 1) >= 0:
                raise RuntimeError("Selected receipt-verified Csm16 does not have one unique proxy mailbox signature")
            address = 0xe0000 + offset
            path = run_dir / f"{stem}-proxy-mailbox.bin"
            raw = qemu.read_guest_memory(monitor, address, 48, path)
            if len(raw) != 48 or raw[:8] != signature:
                raise RuntimeError("Runtime proxy mailbox signature/length differs from selected Csm16")
            names = ("request_pending", "func_ptr", "eax", "edx", "ecx", "result", "helper_core_id",
                     "reset_cr3", "reset_fn_lo", "reset_fn_hi")
            evidence["mailbox"] = {"status": "captured", "physical": address, "csm16_offset": offset,
                                   "path": str(path), "sha256": sha256_file(path),
                                   "fields": dict(zip(names, struct.unpack_from("<10I", raw, 8)))}
        except Exception as error:
            evidence["mailbox"] = {"status": "unavailable", "diagnostic_error": str(error)}
    return evidence


def capture_failure_cpus(monitor, run_dir, count, stem="failure"):
    """Retain both the BIOS proxy AP and BSP state, not just the selected CPU."""
    path = run_dir / f"{stem}-cpus.txt"
    pieces = [monitor.hmp("info cpus")]
    for index in range(count):
        registers = monitor.call("human-monitor-command", {"command-line": "info registers", "cpu-index": index})
        if f"CPU#{index}" not in registers:
            raise RuntimeError(f"QMP register capture did not select CPU {index}")
        pieces += [f"\nCPU {index}\n", registers]
    path.write_text("\n".join(pieces))
    return str(path)


def reuse_prepared(run, run_dir, disk, args, immutable, efi, resume_owned=False):
    """Copy a verified, unchanged prior raw image; never boot the retained file."""
    run = run.resolve(strict=True)
    if not run.is_relative_to(CSM.resolve()):
        raise RuntimeError("Prepared run must be an owned CSM artifact directory")
    receipt_path, source = run / "result.json", run / "windows-uefi.raw"
    receipt = json.loads(receipt_path.read_text())
    if (receipt.get("profile") != "actual-win98-uefi-csmwrap" or
            receipt.get("archive") != str(args.archive) or
            receipt.get("checkpoint_record") != str(args.checkpoint_record) or
            receipt.get("snapshot") != args.snapshot or not receipt.get("originals_unchanged")):
        raise RuntimeError("Prepared receipt does not identify the selected immutable checkpoint")
    # Older receipts can supply hashes from an explicitly labelled subsequent
    # audit. These establish reuse provenance, never retrospective execution.
    source_hashes = receipt.get("immutable_sources") or receipt.get("receipt_audit", {}).get("current_source_sha256")
    if source_hashes != immutable:
        raise RuntimeError("Prepared receipt immutable archive/record hashes do not match")
    old_efi = receipt.get("csmwrap", {}).get("sha256")
    new_efi = sha256_file(efi)
    if old_efi != new_efi and not args.replace_csmwrap:
        raise RuntimeError("Prepared disk CSMWrap differs from the current verified artifact")
    before = sha256_file(source)
    expected_disk = (receipt.get("owned_disk_sha256_after_run") or receipt.get("owned_disk_audit", {}).get("current_disk_sha256")) if resume_owned else receipt["partition"]["uefi_disk_sha256"]
    if not expected_disk or before != expected_disk or source.stat().st_size > 2 * GIB:
        raise RuntimeError("Owned raw image differs from the selected prepared/post-run hash; restore from the archive instead")
    allocated = source.stat().st_blocks * 512
    if shutil.disk_usage(run_dir).free < RESERVE + allocated + DIRTY_BUDGET:
        raise RuntimeError("Insufficient measured sparse-copy budget above reserve")
    command(["cp", "--reflink=never", "--sparse=always", "--", source, disk], timeout=300)
    if sha256_file(disk) != before or sha256_file(source) != before:
        raise RuntimeError("Prepared source or private sparse copy hash mismatch")
    partition = receipt["partition"].copy()
    if resume_owned:
        partition["prior_preparation_uefi_disk_sha256"] = partition["uefi_disk_sha256"]
        partition["uefi_disk_sha256"] = before
    return partition, {
        "source_run": str(run), "source_receipt_sha256": sha256_file(receipt_path),
        "source_disk_sha256": before, "source_allocated_bytes": allocated,
        "source_csmwrap_sha256": old_efi, "selected_csmwrap_sha256": new_efi,
        "requires_efi_replacement": old_efi != new_efi,
        "method": "verified private sparse post-run disk copy; cold hardware, new VARS, no CPU/RAM state" if resume_owned else "verified private sparse raw copy; no prior VARS or saved CPU/RAM state",
        "post_run_hash_provenance": receipt.get("owned_disk_audit") if resume_owned else None,
        "inherited_private_configuration": {key: receipt[key] for key in ("diagnostic_boot", "explicit_himem") if key in receipt} if resume_owned else None}


def send_chord(monitor, keys):
    monitor.call("send-key", {"keys": [{"type": "qcode", "data": key} for key in keys], "hold-time": 60})
    time.sleep(0.09)


def type_ascii(monitor, text):
    punctuation = {" ": ["spc"], ".": ["dot"], "\\": ["backslash"], ":": ["shift", "semicolon"], "-": ["minus"], "/": ["slash"]}
    for char in text:
        if char in punctuation:
            keys = punctuation[char]
        elif char.isascii() and char.isalnum():
            keys = (["shift"] if char.isupper() else []) + [char.lower()]
        else:
            raise RuntimeError(f"Unsupported GUI test character: {char!r}")
        send_chord(monitor, keys)


def interaction_steps(token):
    return [(0, "close-welcome", [["alt", "f4"]], None),
            (3, "desktop-review", [], None),
            (4, "open-start-menu", [["esc"], ["ctrl", "esc"]], None),
            (7, "start-menu-review", [], None),
            (8, "open-run-dialog", [["esc"], ["meta_l", "r"]], None),
            (11, "run-dialog-review", [], None),
            (12, "launch-notepad", [], "notepad"),
            (20, "notepad-review", [], None),
            (22, "type-proof", [], token),
            (28, "typed-proof-review", [], None),
            (30, "open-file-menu", [["alt", "f"]], None),
            (33, "file-menu-review", [], None),
            (34, "open-save-as", [["a"]], None),
            (38, "save-dialog-review", [], None),
            (39, "save-root-file", [["home"], ["shift", "end"], ["backspace"]], "c:\\uefiqa.txt"),
            (51, "saved-notepad-review", [], None)]


def collect_interaction_file(disk, run_dir, partition, token, baseline):
    spec = f"{disk}@@{partition['start_lba'] * 512}"
    path = run_dir / "UEFIQA.TXT.readback"
    item = {"guest_path": "C:\\UEFIQA.TXT", "expected_text": token, "status": "FAIL"}
    try:
        command(["mcopy", "-i", spec, "::UEFIQA.TXT", path])
        raw = path.read_bytes()
        item.update(path=str(path), sha256=sha256_file(path), bytes=len(raw))
        if baseline:
            old = subprocess.run(["mtype", "-i", f"{baseline}@@{partition['start_lba'] * 512}", "::UEFIQA.TXT"], capture_output=True)
            item["baseline_file_present"] = old.returncode == 0
            item["baseline_sha256"] = hashlib.sha256(old.stdout).hexdigest() if old.returncode == 0 else None
            item["freshness"] = "changed-in-owned-run" if old.returncode == 0 else "new-in-owned-run"
        if raw == (token + "\r\n").encode("ascii"):
            item["status"] = "PASS"
        else:
            item["error"] = "Guest-saved file bytes do not equal the typed unique token plus CRLF"
    except Exception as error:
        item["error"] = str(error)
    return item


def prepare_native_trial(disk, run_dir, partition, args):
    """Copy one frozen diagnostic fixture to VXDLAB on the new private disk."""
    manifest = args.native_trial_manifest.resolve(strict=True)
    if sha256_file(manifest) != args.native_trial_manifest_sha:
        raise RuntimeError("Native trial manifest differs from the explicitly selected frozen hash")
    data = json.loads(manifest.read_text())
    if data.get("schema") != 1 or data.get("kind") != "isolated-vxd-native-trial-inputs":
        raise RuntimeError("Unsupported native fixture manifest")
    entries = [entry for entry in data["variants"] if entry["variant"] == args.native_trial_variant]
    if len(entries) != 1:
        raise RuntimeError("Native fixture variant is not unique in the frozen manifest")
    entry = entries[0]
    if entry["command"] != "C:\\COMMAND.COM /C C:\\VXDLAB\\RUNMIN.BAT":
        raise RuntimeError("Native fixture command differs from the scoped DOS wrapper")
    spec = f"{disk}@@{partition['start_lba'] * 512}"
    sources = {str(manifest): args.native_trial_manifest_sha}
    for key in ("host_cpu_receipt", "build_receipt"):
        receipt = entry[key]
        path = Path(receipt["path"]).resolve(strict=True)
        if not path.is_relative_to(manifest.parent) or sha256_file(path) != receipt["sha256"]:
            raise RuntimeError(f"Native fixture {key} differs from its frozen receipt")
        sources[str(path)] = receipt["sha256"]
    guest_re = re.compile(r"C:\\VXDLAB\\[A-Z0-9]{1,8}\.[A-Z0-9]{1,3}")
    if not 1 <= len(entry["inputs"]) <= 8:
        raise RuntimeError("Native fixture input count exceeds bounded private-copy scope")
    for item in entry["inputs"]:
        source = Path(item["source"]).resolve(strict=True)
        if (not source.is_relative_to(manifest.parent) or not guest_re.fullmatch(item["guest"]) or
                source.stat().st_size != item["bytes"] or not 0 < item["bytes"] <= 1024 ** 2 or
                sha256_file(source) != item["sha256"]):
            raise RuntimeError("Native fixture source/guest path/size/hash mismatch")
        sources[str(source)] = item["sha256"]
    outputs = entry["outputs"]
    if not outputs or any(not guest_re.fullmatch(path) for path in outputs):
        raise RuntimeError("Native fixture output paths exceed VXDLAB scope")
    if set(outputs) & {item["guest"] for item in entry["inputs"]}:
        raise RuntimeError("Native output paths overlap injected inputs; fresh evidence would be false")
    for path in outputs:
        existing = subprocess.run(["mdir", "-i", spec, "::" + path[3:].replace("\\", "/")], capture_output=True)
        if existing.returncode == 0:
            raise RuntimeError("Native trial output already exists on selected clone; use the clean GUI source")
    existing = subprocess.run(["mdir", "-i", spec, "::VXDLAB"], capture_output=True)
    if existing.returncode:
        command(["mmd", "-i", spec, "::VXDLAB"])
    copied = []
    for item in entry["inputs"]:
        guest = "::" + item["guest"][3:].replace("\\", "/")
        command(["mcopy", "-o", "-i", spec, item["source"], guest])
        check = run_dir / ("prepared-fixture-" + item["guest"].rsplit("\\", 1)[1])
        command(["mcopy", "-i", spec, guest, check])
        if sha256_file(check) != item["sha256"]:
            raise RuntimeError("Private native fixture copy verification failed")
        copied.append(item | {"private_copy_sha256": sha256_file(check)})
    with disk.open("rb") as stream:
        mbr = stream.read(512)
        stream.seek(partition["start_lba"] * 512)
        boot = stream.read(512)
    if (hashlib.sha256(mbr).hexdigest() != partition["mbr_sha256"] or
            hashlib.sha256(boot).hexdigest() != partition["boot_sector_sha256"]):
        raise RuntimeError("Native fixture injection changed a legacy boot sector")
    return {"manifest": str(manifest), "manifest_sha256": args.native_trial_manifest_sha,
            "variant": entry["variant"], "inputs": copied, "command": entry["command"], "outputs": outputs,
            "immutable_sources": sources, "output_baseline": "all absent before private injection",
            "scope": "isolated diagnostic VXDLAB files on new clone; no production driver replacement",
            "native_verdict": "not-established"}


def collect_native_trial(disk, run_dir, partition, trial):
    logs = run_dir / "native-logs"
    logs.mkdir()
    spec = f"{disk}@@{partition['start_lba'] * 512}"
    files, raw_files = [], {}
    for guest in trial["outputs"]:
        name = guest.rsplit("\\", 1)[1]
        path = logs / name
        item = {"guest_path": guest, "status": "FAIL", "freshness": "absent-before-run"}
        try:
            command(["mcopy", "-i", spec, "::" + guest[3:].replace("\\", "/"), path])
            raw_files[name] = path.read_bytes()
            item.update(status="captured", path=str(path), bytes=len(raw_files[name]), sha256=sha256_file(path),
                        freshness="new-in-owned-run")
        except Exception as error:
            item["error"] = str(error)
        files.append(item)
    trial["readback"] = files
    log = raw_files.get("MINLDR.LOG", b"").decode("ascii", errors="replace")
    code = re.fullmatch(r"DOS_EXIT=(\d{1,3})", raw_files.get("MINEXIT.TXT", b"").decode("ascii", errors="replace").strip())
    trial["dos_exit"] = int(code[1]) if code and int(code[1]) <= 255 else None
    version = raw_files.get("GUESTVER.TXT", b"")
    trial["guest_version_text"] = version.decode("cp949", errors="replace")
    trial["windows98_version_confirmed"] = b"Windows 98" in version and b"4.10.2222" in version
    registers = {}
    for name in ("ENTRY", "VERSION", "LOAD", "UNLOAD"):
        match = re.search(rf"^{name}\s+FLAGS=([0-9a-f]{{4}}) AX=([0-9a-f]{{4}}) DX=([0-9a-f]{{4}})\s*$", log, re.M | re.I)
        if match:
            flags, ax, dx = (int(value, 16) for value in match.groups())
            registers[name] = {"flags": flags, "cf": flags & 1, "ax": ax, "dx": dx}
    trial["raw_register_results"] = registers
    candidate = next(item for item in trial["inputs"] if item["guest"].endswith("\\NTWMIN9X.VXD"))
    expected = re.search(r"^EXPECTED_SHA256=([0-9a-f]{64})\s*$", log, re.M | re.I)
    trial["candidate_identity_matches"] = bool(expected and expected[1].lower() == candidate["sha256"])
    result_code = re.search(r"^RESULT_CODE=([0-9a-f]{4})\s*$", log, re.M | re.I)
    trial["result_code"] = int(result_code[1], 16) if result_code else None
    loaded = registers.get("LOAD", {})
    unloaded = registers.get("UNLOAD", {})
    passed = (all(item["status"] == "captured" for item in files) and trial["windows98_version_confirmed"] and
              trial["candidate_identity_matches"] and trial["dos_exit"] == 0 and trial["result_code"] == 0 and
              loaded.get("cf") == 0 and loaded.get("ax") == 0 and unloaded.get("cf") == 0 and unloaded.get("ax") == 0 and
              f"PREFLIGHT=EXACT_{candidate['bytes']}_BYTES_AND_EOF" in log and "END=BEFORE_LOG_CLOSE" in log)
    trial["validation_status"] = "PASS" if passed else "FAIL"
    trial["native_verdict"] = ("guest-reported VXDLDR load/unload success in actual Windows98 DOS session with host-readback logs"
                               if passed else "not-established; inspect fresh raw loader registers and exact DOS exit")
    return trial


def prepare_guest_files(disk, run_dir, partition, args):
    """Bounded frozen installation/diagnostic inputs on a new private clone."""
    if getattr(args, "large_chromium_inputs", False):
        if (args.replace_installed_gop or args.native_bios_control or args.native_trial_manifest or
                args.application_manifest or not args.manual_gui or args.manual_purpose != "diagnostic"):
            raise RuntimeError("Exact Chromium staging cannot replace drivers or use alternate native/app workflows")
        import prepare_large_chromium_inputs
        if prepare_large_chromium_inputs.sha256(prepare_large_chromium_inputs.__file__) != args.large_chromium_plan["immutable_sources"][str(Path(prepare_large_chromium_inputs.__file__).resolve())]:
            raise RuntimeError("Exact Chromium staging helper changed after initial validation")
        # Account for both FAT allocation and exact host readback before copying.
        # The caller's selected reserve and VM dirty budget remain unchanged.
        staging_bytes = 2 * sum(item["bytes"] for item in args.large_chromium_plan["inputs"]) + 1024 ** 2
        if shutil.disk_usage(run_dir).free < RESERVE + DIRTY_BUDGET + staging_bytes:
            raise RuntimeError("Exact Chromium copies would cross the selected reserve/dirty budget")
        return prepare_large_chromium_inputs.stage(disk, run_dir, partition, args.large_chromium_plan, command)
    manifest = args.guest_files_manifest.resolve(strict=True)
    if sha256_file(manifest) != args.guest_files_manifest_sha:
        raise RuntimeError("Guest-file manifest differs from selected frozen hash")
    data = json.loads(manifest.read_text())
    if data.get("schema") != 1 or data.get("kind") != "isolated-guest-file-inputs":
        raise RuntimeError("Unsupported guest-file manifest")
    guest_re = re.compile(r"C:\\(?:GOPLAB|VXDLAB)\\[A-Z0-9]{1,8}\.[A-Z0-9]{1,3}")
    inputs, outputs = data["inputs"], data.get("outputs", [])
    if not 1 <= len(inputs) <= 8 or len({item["guest"] for item in inputs}) != len(inputs):
        raise RuntimeError("Guest inputs must be unique and bounded")
    if len(outputs) > 8 or len(set(outputs)) != len(outputs) or any(not guest_re.fullmatch(p) for p in outputs):
        raise RuntimeError("Guest outputs exceed bounded GOPLAB/VXDLAB scope")
    if set(outputs) & {item["guest"] for item in inputs}:
        raise RuntimeError("Guest output paths overlap injected inputs; fresh evidence would be false")
    sources = {str(manifest): args.guest_files_manifest_sha}
    for item in inputs:
        path = Path(item["source"]).resolve(strict=True)
        if (not path.is_relative_to(manifest.parent) or not guest_re.fullmatch(item["guest"]) or
                not 0 < item["bytes"] <= 1024 ** 2 or path.stat().st_size != item["bytes"] or
                sha256_file(path) != item["sha256"]):
            raise RuntimeError("Frozen guest input source/path/size/hash mismatch")
        sources[str(path)] = item["sha256"]
    for receipt in data.get("source_receipts", []):
        path = Path(receipt["path"]).resolve(strict=True)
        if not path.is_relative_to(BUILD.parents[0]) or sha256_file(path) != receipt["sha256"]:
            raise RuntimeError("Guest input source receipt differs from approved local build")
        sources[str(path)] = receipt["sha256"]
    allowed_backups = {"C:\\WINDOWS\\SYSTEM.INI", "C:\\WINDOWS\\WIN.INI", "C:\\WINDOWS\\SYSTEM.DAT", "C:\\WINDOWS\\USER.DAT"}
    requested_backups = data.get("backups", [])
    if len(set(requested_backups)) != len(requested_backups) or any(p not in allowed_backups for p in requested_backups):
        raise RuntimeError("Backup request exceeds Windows configuration/registry scope")
    spec = f"{disk}@@{partition['start_lba'] * 512}"
    for guest in outputs:
        if subprocess.run(["mdir", "-i", spec, "::" + guest[3:].replace("\\", "/")], capture_output=True).returncode == 0:
            raise RuntimeError("Requested output already exists; fresh evidence requires a new absent path")
    backups = []
    for guest in requested_backups:
        target = run_dir / ("before-install-" + guest.rsplit("\\", 1)[1])
        command(["mcopy", "-i", spec, "::" + guest[3:].replace("\\", "/"), target])
        if not 0 < target.stat().st_size <= 8 * 1024 ** 2:
            raise RuntimeError("Windows original backup exceeds bounded capture")
        attrs = command(["mattrib", "-i", spec, "::" + guest[3:].replace("\\", "/")])
        backups.append({"guest": guest, "path": str(target), "sha256": sha256_file(target),
                        "bytes": target.stat().st_size, "attributes": attrs})
    copied = []
    for item in inputs:
        folder = item["guest"].split("\\")[1]
        if subprocess.run(["mdir", "-i", spec, "::" + folder], capture_output=True).returncode:
            command(["mmd", "-i", spec, "::" + folder])
        guest = "::" + item["guest"][3:].replace("\\", "/")
        command(["mcopy", "-o", "-i", spec, item["source"], guest])
        target = run_dir / ("prepared-guest-" + item["guest"].rsplit("\\", 1)[1])
        command(["mcopy", "-i", spec, guest, target])
        if sha256_file(target) != item["sha256"]:
            raise RuntimeError("Private guest input readback hash mismatch")
        copied.append(item | {"private_copy_sha256": sha256_file(target)})
    replacements = []
    if args.replace_installed_gop:
        prior = json.loads((args.resume_owned_run / "result.json").read_text())
        records = {p["guest"]: p for p in prior.get("guest_files", {}).get("system_driver_file_readback", [])}
        for name in ("SHZGOP.DRV", "SHZGOP.VXD"):
            guest = "C:\\WINDOWS\\SYSTEM\\" + name
            old = records.get(guest, {})
            candidates = [item for item in inputs if item["guest"] == "C:\\GOPLAB\\" + name]
            if old.get("status") != "matching-file-present" or len(candidates) != 1:
                raise RuntimeError("Installed GOP replacement lacks exact verified prior and new driver input")
            candidate = candidates[0]; before = run_dir / ("before-replace-" + name)
            command(["mcopy", "-i", spec, "::WINDOWS/SYSTEM/" + name, before])
            if sha256_file(before) != old["sha256"]:
                raise RuntimeError("Prior installed GOP file differs from source-run receipt")
            command(["mcopy", "-o", "-i", spec, candidate["source"], "::WINDOWS/SYSTEM/" + name])
            check = run_dir / ("prepared-system-" + name)
            command(["mcopy", "-i", spec, "::WINDOWS/SYSTEM/" + name, check])
            if sha256_file(check) != candidate["sha256"]:
                raise RuntimeError("New installed GOP replacement readback hash mismatch")
            replacements.append({"guest": guest, "previous_sha256": old["sha256"], "new_sha256": candidate["sha256"],
                                 "backup": str(before), "scope": "two explicitly named driver files on new private cold clone; registry untouched"})
    with disk.open("rb") as stream:
        mbr = stream.read(512); stream.seek(partition["start_lba"] * 512); boot = stream.read(512)
    if hashlib.sha256(mbr).hexdigest() != partition["mbr_sha256"] or hashlib.sha256(boot).hexdigest() != partition["boot_sector_sha256"]:
        raise RuntimeError("Guest input injection changed original legacy boot sectors")
    return {"manifest": str(manifest), "manifest_sha256": args.guest_files_manifest_sha,
            "inputs": copied, "outputs": outputs, "backups": backups, "installed_gop_replacement": replacements, "immutable_sources": sources,
            "output_baseline": "all absent before private injection", "native_installed_and_rendered": "not-established"}


def collect_guest_files(disk, run_dir, partition, files):
    spec = f"{disk}@@{partition['start_lba'] * 512}"
    captures = []
    for guest in files["outputs"]:
        target = run_dir / ("guest-output-" + guest.rsplit("\\", 1)[1])
        entry = {"guest": guest, "status": "FAIL", "freshness": "absent-before-run"}
        try:
            command(["mcopy", "-i", spec, "::" + guest[3:].replace("\\", "/"), target])
            entry.update(status="captured", freshness="new-in-owned-run", path=str(target),
                         sha256=sha256_file(target), bytes=target.stat().st_size)
        except Exception as error:
            entry["error"] = str(error)
        captures.append(entry)
    files["readback"] = captures
    installed = []
    for item in files["inputs"]:
        name = item["guest"].rsplit("\\", 1)[1]
        if name not in ("SHZGOP.DRV", "SHZGOP.VXD"):
            continue
        target = run_dir / ("installed-copy-" + name)
        entry = {"guest": "C:\\WINDOWS\\SYSTEM\\" + name, "status": "absent-or-mismatch"}
        try:
            command(["mcopy", "-i", spec, "::WINDOWS/SYSTEM/" + name, target])
            entry.update(path=str(target), sha256=sha256_file(target), matches_frozen_input=sha256_file(target) == item["sha256"])
            entry["status"] = "matching-file-present" if entry["matches_frozen_input"] else "mismatch"
        except Exception as error:
            entry["error"] = str(error)
        installed.append(entry)
    files["system_driver_file_readback"] = installed
    files["acceptance_limit"] = "Matching system files prove file copy only; active backend, cold boot and native rendering require separate review"
    return files


def diagnostic_boot(disk, run_dir, partition):
    """Enable a logged, visible boot on this disposable clone only."""
    spec = f"{disk}@@{partition['start_lba'] * 512}"
    original, updated = run_dir / "MSDOS.SYS.original", run_dir / "MSDOS.SYS.diagnostic"
    command(["mcopy", "-i", spec, "::MSDOS.SYS", original])
    attributes = command(["mattrib", "-i", spec, "::MSDOS.SYS"])
    before = original.read_bytes()
    options = {"BootLog": "1", "Logo": "0", "BootDelay": "0",
               "BootMenu": "1", "BootMenuDefault": "2", "BootMenuDelay": "0"}
    body = before.decode("latin1")
    lines = body.splitlines()
    start = next(i for i, line in enumerate(lines) if line.lower() == "[options]") + 1
    end = next((i for i in range(start, len(lines)) if lines[i].startswith("[")), len(lines))
    lines[start:end] = [line for line in lines[start:end]
                        if line.split("=", 1)[0].strip().lower() not in {k.lower() for k in options}]
    lines[start:start] = [f"{key}={value}" for key, value in options.items()]
    after = ("\r\n".join(lines) + "\r\n").encode("latin1")
    if len(after) < 1024:
        raise RuntimeError("Diagnostic MSDOS.SYS must retain the >1024-byte compatibility padding")
    updated.write_bytes(after)
    command(["mattrib", "-i", spec, "-s", "-h", "-r", "::MSDOS.SYS"])
    command(["mcopy", "-o", "-i", spec, updated, "::MSDOS.SYS"])
    restore = [("+" if a in attributes.split("::", 1)[0] else "-") + a.lower() for a in "ASHR"]
    command(["mattrib", "-i", spec, *restore, "::MSDOS.SYS"])
    restored_attributes = command(["mattrib", "-i", spec, "::MSDOS.SYS"])
    if restored_attributes != attributes:
        raise RuntimeError("Diagnostic MSDOS.SYS attributes were not preserved")
    check = subprocess.run(["mtype", "-i", spec, "::MSDOS.SYS"], capture_output=True, check=True).stdout
    if check != after:
        raise RuntimeError("Diagnostic MSDOS.SYS copy verification failed")
    return {"changes": options, "original_sha256": sha256_file(original),
            "diagnostic_sha256": sha256_file(updated), "original_attributes": attributes.strip(),
            "scope": "MSDOS.SYS on the new private raw copy only; logged boot menu default 2"}


def explicit_himem(disk, run_dir, partition, machine):
    """Override HIMEM's A20 handler on the new clone, retaining other config bytes."""
    spec = f"{disk}@@{partition['start_lba'] * 512}"
    original, updated = run_dir / "CONFIG.SYS.original", run_dir / "CONFIG.SYS.himem"
    command(["mcopy", "-i", spec, "::CONFIG.SYS", original])
    before = original.read_bytes()
    attributes = command(["mattrib", "-i", spec, "::CONFIG.SYS"])
    if re.search(rb"(?im)^\s*device(?:high)?\s*=.*himem\.sys", before):
        raise RuntimeError("Explicit HIMEM comparison requires baseline CONFIG.SYS without an existing HIMEM line")
    added = f"device=C:\\WINDOWS\\HIMEM.SYS /MACHINE:{machine} /VERBOSE\r\n".encode("ascii")
    separator = b"" if not before or before.endswith(b"\n") else b"\r\n"
    after = before + separator + added
    updated.write_bytes(after)
    command(["mattrib", "-i", spec, "-s", "-h", "-r", "::CONFIG.SYS"])
    command(["mcopy", "-o", "-i", spec, updated, "::CONFIG.SYS"])
    restore = [("+" if a in attributes.split("::", 1)[0] else "-") + a.lower() for a in "ASHR"]
    command(["mattrib", "-i", spec, *restore, "::CONFIG.SYS"])
    check = subprocess.run(["mtype", "-i", spec, "::CONFIG.SYS"], capture_output=True, check=True).stdout
    if check != after or command(["mattrib", "-i", spec, "::CONFIG.SYS"]) != attributes:
        raise RuntimeError("Explicit HIMEM config bytes/attributes verification failed")
    return {"original_sha256": sha256_file(original), "updated_sha256": sha256_file(updated),
            "original_attributes": attributes.strip(), "appended_line": added.decode("ascii").strip(),
            "original_prefix_preserved": after[:len(before)] == before,
            "testmem": "default preserved", "scope": "CONFIG.SYS on new private image only"}


def collect_boot_logs(disk, run_dir, partition, baseline=None):
    """Read guest log files after the owned VM exits; label inherited content."""
    directory = run_dir / "guest-logs"
    directory.mkdir()
    spec = f"{disk}@@{partition['start_lba'] * 512}"
    baseline_spec = f"{baseline}@@{partition['start_lba'] * 512}" if baseline else None
    logs = []
    for name in ("BOOTLOG.TXT", "BOOTLOG.PRV", "WINDOWS/IOS.LOG"):
        target = directory / name.replace("/", "-")
        copied = subprocess.run(["mcopy", "-i", spec, f"::{name}", str(target)], capture_output=True)
        if copied.returncode:
            continue
        entry = {"guest_path": name, "path": str(target), "sha256": sha256_file(target),
                 "bytes": target.stat().st_size, "freshness": "not-established"}
        if baseline_spec:
            prior = subprocess.run(["mtype", "-i", baseline_spec, f"::{name}"], capture_output=True)
            if prior.returncode == 0:
                entry["baseline_sha256"] = hashlib.sha256(prior.stdout).hexdigest()
                entry["freshness"] = "inherited-unchanged" if entry["sha256"] == entry["baseline_sha256"] else "changed-in-owned-run"
            else:
                entry["freshness"] = "new-in-owned-run"
        logs.append(entry)
    return logs


def main():
    global RESERVE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--checkpoint-record", type=Path, required=True)
    parser.add_argument("--snapshot", default="windows98-clean-installed")
    parser.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    parser.add_argument("--firmware-code", type=Path, default=Path(qemu.DEFAULT_OVMF_CODE))
    parser.add_argument("--firmware-vars", type=Path, default=Path(qemu.DEFAULT_OVMF_VARS))
    parser.add_argument("--cdrom", type=Path)
    parser.add_argument("--prepared-run", type=Path,
                        help="Reuse an unchanged receipt-verified prepared raw disk through a new private sparse copy")
    parser.add_argument("--resume-owned-run", type=Path,
                        help="Cold boot a new sparse copy of a quiescent owned post-run disk with receipt/audit hash; no saved CPU/RAM/VARS")
    parser.add_argument("--csm-dir", type=Path, default=CSM,
                        help="Directory holding receipt-verified CSMWRAP.EFI; run outputs stay in the owned build/csm tree")
    parser.add_argument("--replace-csmwrap", action="store_true",
                        help="Explicitly replace EFI application/config on the new prepared clone, preserving legacy boot sectors")
    parser.add_argument("--firmware-gop", action="store_true",
                        help="Opt in to verified SHZGOP1 firmware build and private EFI config gop_only=true; not native display-driver acceptance")
    parser.add_argument("--disable-s3", action="store_true",
                        help="Disable the selected machine's S3 support for a separate firmware-memory comparison")
    parser.add_argument("--diagnostic-boot", action="store_true",
                        help="Private-clone MSDOS.SYS: visible boot and logged boot-menu selection; preserve original bytes")
    parser.add_argument("--himem-machine", type=int, choices=range(1, 17),
                        help="Append explicit HIMEM /MACHINE:n /VERBOSE to private CONFIG.SYS; preserve default memory testing")
    parser.add_argument("--native-bios-control", action="store_true",
                        help="Restore clean checkpoint and boot pc/TCG SeaBIOS directly; diagnostic control, never UEFI acceptance")
    parser.add_argument("--native-bios", type=Path, default=Path("/usr/share/seabios/bios-256k.bin"))
    parser.add_argument("--machine", choices=("q35", "pc"), default="q35")
    parser.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    parser.add_argument("--smp", type=int, default=2)
    parser.add_argument("--memory", type=int, default=128)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--capture-interval", type=int, default=30)
    parser.add_argument("--gui-interaction-after", type=int,
                        help="Seconds before bounded QMP keyboard Start/Notepad/save sequence; requires screenshot review and exact host readback")
    parser.add_argument("--manual-gui", action="store_true",
                        help="Accept numbered keyboard/capture requests from owned run/gui-control.json during a bounded visually steered GUI test")
    parser.add_argument("--manual-purpose", choices=("gui-proof", "display-install", "display-probe", "diagnostic"), default="gui-proof",
                        help="Keep installation/probe actions distinct from GUI file-save acceptance")
    parser.add_argument("--guest-files-manifest", type=Path,
                        help="Frozen bounded GOPLAB/VXDLAB file inputs and configuration backup plan on new private clone")
    parser.add_argument("--guest-files-manifest-sha")
    parser.add_argument("--large-chromium-inputs", action="store_true",
                        help="Explicit exact three-input CHRLAB original Chromium read-only structure fixture only")
    parser.add_argument("--application-manifest", type=Path,
                        help="Separate frozen application assets staged only into an allowlisted absent NPPLAB or VLCLAB tree on a new private cold clone")
    parser.add_argument("--application-manifest-sha")
    parser.add_argument("--replace-installed-gop", action="store_true",
                        help="Explicitly replace only receipt-verified installed SHZGOP.DRV/VXD on new owned cold clone; back up exact old files")
    parser.add_argument("--native-trial-manifest", type=Path,
                        help="Frozen isolated VXDLAB native trial manifest; copies only listed diagnostic files to new clone")
    parser.add_argument("--native-trial-manifest-sha")
    parser.add_argument("--native-trial-variant")
    parser.add_argument("--reserve-gib", type=int, default=20,
                        help="Per-run free-space floor in GiB (8..64, default 20); no global setting changes")
    parser.add_argument("--run-name", default="run-win98-uefi-" + time.strftime("%Y%m%d-%H%M%S", time.gmtime()))
    args = parser.parse_args()
    minimum_cpus = 1 if args.native_bios_control else 2
    if not minimum_cpus <= args.smp <= 8 or not 64 <= args.memory <= 512 or not 10 <= args.timeout <= 900:
        raise SystemExit(f"Require {minimum_cpus}..8 CPUs, 64..512 MiB RAM, and 10..900 seconds")
    if args.prepared_run and args.resume_owned_run:
        raise SystemExit("Choose prepared reuse or owned post-run cold clone, not both")
    if args.resume_owned_run and (args.diagnostic_boot or args.himem_machine):
        raise SystemExit("Owned post-run cold clone inherits private configuration; do not append it again")
    if args.gui_interaction_after is not None and not 10 <= args.gui_interaction_after <= args.timeout - 60:
        raise SystemExit("GUI interaction needs 10+ seconds before starting and 60+ seconds remaining")
    if args.manual_gui and args.gui_interaction_after is not None:
        raise SystemExit("Choose timed or visually steered GUI interaction")
    if args.manual_purpose != "gui-proof" and not args.manual_gui:
        raise SystemExit("A separate manual purpose requires visually steered GUI mode")
    if (args.guest_files_manifest or args.guest_files_manifest_sha) and (not args.manual_gui or args.native_bios_control or
            not args.guest_files_manifest or not re.fullmatch(r"[0-9a-f]{64}", args.guest_files_manifest_sha or "") or args.native_trial_manifest):
        raise SystemExit("Frozen guest files require exact manifest/hash and separate manual UEFI workflow")
    if args.manual_purpose in ("display-install", "display-probe") and not args.guest_files_manifest:
        raise SystemExit("Display workflows require explicit frozen guest input manifest")
    if args.large_chromium_inputs:
        if (not args.guest_files_manifest or not args.manual_gui or args.manual_purpose != "diagnostic" or
                args.native_bios_control or args.native_trial_manifest or args.native_trial_manifest_sha or
                args.native_trial_variant or args.application_manifest or args.application_manifest_sha or
                args.replace_installed_gop or args.diagnostic_boot or args.himem_machine or
                not args.resume_owned_run):
            raise SystemExit("Exact large Chromium inputs require a separate owned manual diagnostic cold clone without alternate staging or OS changes")
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
        import prepare_large_chromium_inputs
        # Verify every source receipt/asset before creating or mutating a clone.
        args.large_chromium_plan = prepare_large_chromium_inputs.validate(
            args.guest_files_manifest, args.guest_files_manifest_sha)
    application_plan = None
    if args.application_manifest or args.application_manifest_sha:
        if (not args.application_manifest or not re.fullmatch(r"[0-9a-f]{64}", args.application_manifest_sha or "") or
                not args.manual_gui or args.native_bios_control or args.native_trial_manifest or
                not args.resume_owned_run or args.manual_purpose != "diagnostic"):
            raise SystemExit("Application staging requires exact manifest/hash and a separate manual diagnostic UEFI cold clone")
        import app_staging
        application_plan = app_staging.validate(args.application_manifest, args.application_manifest_sha,
                                                Path(__file__).resolve().parents[2])
        if application_plan["outputs"]:
            raise SystemExit("Application staging currently supports assets only; declare native output evidence through a separate diagnostic manifest")
    if args.replace_installed_gop and (not args.resume_owned_run or not args.guest_files_manifest or args.native_bios_control):
        raise SystemExit("Installed GOP replacement requires explicit frozen guest files and owned post-run cold clone")
    native_options = (args.native_trial_manifest, args.native_trial_manifest_sha, args.native_trial_variant)
    if any(native_options) and (not all(native_options) or not args.manual_gui or args.native_bios_control or
                                args.manual_purpose != "gui-proof" or
                                not re.fullmatch(r"[0-9a-f]{64}", args.native_trial_manifest_sha or "")):
        raise SystemExit("Native trial requires manifest/path/hash/variant, visually steered UEFI GUI, and a lowercase SHA256")
    if args.native_bios_control and (args.prepared_run or args.resume_owned_run or args.machine != "pc" or args.accel != "tcg"
                                    or args.disable_s3 or args.diagnostic_boot or args.himem_machine):
        raise SystemExit("Native control requires pc/TCG and clean archive restore without CSM/S3/config diagnostic variants")
    if args.replace_csmwrap and (not (args.prepared_run or args.resume_owned_run) or args.native_bios_control):
        raise SystemExit("CSMWrap replacement requires explicit prepared-clone reuse in a UEFI run")
    if args.firmware_gop and (args.native_bios_control or
                             ((args.prepared_run or args.resume_owned_run) and not args.replace_csmwrap)):
        raise SystemExit("Firmware GOP requires UEFI and explicit private EFI/config replacement on a reused clone")
    if not 5 <= args.capture_interval <= 60 or not re.fullmatch(r"[a-zA-Z0-9_-]+", args.run_name):
        raise SystemExit("Invalid capture interval or run name")
    if not 8 <= args.reserve_gib <= 64:
        raise SystemExit("Require a per-run reserve of 8..64 GiB")
    RESERVE = args.reserve_gib * GIB
    args.archive = args.archive.resolve(strict=True)
    args.checkpoint_record = args.checkpoint_record.resolve(strict=True)
    if args.native_bios_control:
        args.native_bios = args.native_bios.resolve(strict=True)
    else:
        args.firmware_code = args.firmware_code.resolve(strict=True)
        args.firmware_vars = args.firmware_vars.resolve(strict=True)
        args.csm_dir = args.csm_dir.resolve(strict=True)
    if args.cdrom:
        args.cdrom = args.cdrom.resolve(strict=True)
    expected = json.loads(args.checkpoint_record.read_text())
    if not 0 < expected["raw_bytes"] <= 2 * GIB + 256 * 1024 ** 2:
        raise SystemExit("Checkpoint size exceeds the retained 2 GiB lab image bound")
    if Path(expected["archive"]).resolve() != args.archive or sha256_file(args.archive) != expected["archive_sha256"]:
        raise SystemExit("Archive differs from the selected checkpoint record")
    immutable = {str(args.archive): sha256_file(args.archive), str(args.checkpoint_record): sha256_file(args.checkpoint_record)}
    efi, csm16, csm_receipt = None, None, None
    if not args.native_bios_control:
        efi = args.csm_dir / "CSMWRAP.EFI"
        csm_receipt = json.loads((args.csm_dir / "build-result.json").read_text())
        if sha256_file(efi) != csm_receipt["artifacts"]["CSMWRAP.EFI"]["sha256"]:
            raise SystemExit("CSMWrap artifact differs from its build receipt")
        csm16 = args.csm_dir / "Csm16.bin"
        if sha256_file(csm16) != csm_receipt["artifacts"]["Csm16.bin"]["sha256"]:
            raise SystemExit("Csm16 diagnostic artifact differs from its build receipt")
        if args.firmware_gop:
            feature = csm_receipt.get("firmware_gop", {})
            abi = {"magic": "SHZGOP1", "major": 1, "minor": 0, "descriptor_bytes": 96, "coreboot_tag": 0x53485a47}
            patch_present = any(item.get("patch") == "shizukudos/csm/patches/0002-force-firmware-gop.patch" and
                                re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", "")) for item in csm_receipt.get("patches", []))
            if feature.get("compiled_support") is not True or feature.get("abi") != abi or not patch_present:
                raise SystemExit("Selected build does not receipt-verify the exact SHZGOP1 firmware capability")
    firmware_paths = (args.native_bios,) if args.native_bios_control else (args.firmware_code, args.firmware_vars)
    for path in (*firmware_paths, *([args.cdrom] if args.cdrom else [])):
        if not path.is_file():
            raise SystemExit(f"Required firmware/media missing: {path}")
    CSM.mkdir(parents=True, exist_ok=True)
    run_dir = CSM / args.run_name
    run_dir.mkdir(mode=0o700)
    result = {"profile": "actual-win98-native-seabios-control" if args.native_bios_control else "actual-win98-uefi-csmwrap",
              "utc": shzlib.utc_now(), "status": "FAIL",
              "archive": str(args.archive), "checkpoint_record": str(args.checkpoint_record),
              "snapshot": args.snapshot, "boot_path": ("QEMU SeaBIOS -> retained Win98 MBR/IO.SYS (diagnostic control; not UEFI acceptance)"
                         if args.native_bios_control else "OVMF -> CSMWrap -> SeaBIOS CSM16 -> retained Win98 MBR/IO.SYS"),
              "source_sha256": sha256_file(Path(__file__)), "captures": [], "gui_verdict": "not-established",
              "gui_review_required": "Inspect actual QMP screenshots; firmware markers do not prove GUI success",
              "firmware_code_sha256": None if args.native_bios_control else sha256_file(args.firmware_code),
              "firmware_vars_template_sha256": None if args.native_bios_control else sha256_file(args.firmware_vars),
              "csmwrap": None if args.native_bios_control else csm_receipt["artifacts"]["CSMWRAP.EFI"],
              "csm_build_receipt_sha256": None if args.native_bios_control else sha256_file(args.csm_dir / "build-result.json"),
              "csm16_diagnostic_artifact": None if args.native_bios_control else csm_receipt["artifacts"]["Csm16.bin"],
              "firmware_gop_opt_in": args.firmware_gop,
              "firmware_gop_feature": csm_receipt.get("firmware_gop") if args.firmware_gop else None,
              "hardware": vars(args) | {"network": "none"}}
    if args.native_bios_control:
        result["native_bios_sha256"] = sha256_file(args.native_bios)
    result["immutable_sources"] = immutable
    source_run = args.prepared_run or args.resume_owned_run
    gui_enabled = args.gui_interaction_after is not None or args.manual_gui
    if gui_enabled:
        token = "windows98 uefi gui proof " + hashlib.sha256((args.run_name + result["utc"]).encode()).hexdigest()[:16]
        result["gui_interaction"] = {"unique_token": token, "start_after_seconds": args.gui_interaction_after,
                                     "mode": "owned control queue; visually steered" if args.manual_gui else "timed keyboard sequence",
                                     "actions": [], "verdict": "not-established"}
        steps = interaction_steps(token)
        shzlib.write_json(run_dir / "gui-test-plan.json", {"unique_token": token, "guest_file": "C:\\UEFIQA.TXT",
                       "manual_required_actions": ({"display-install": ["install-driver-have-disk"], "display-probe": ["run-display-probe"], "diagnostic": []}.get(args.manual_purpose)
                                                   if args.manual_purpose != "gui-proof" else ["run-native-fixture"] if args.native_trial_manifest
                                                   else ["open-start-menu", "launch-notepad", "type-proof", "save-root-file"]),
                       "manual_purpose": args.manual_purpose,
                       "control_schema": {"sequence": "strictly increasing integer, starting 1", "name": "recorded action label",
                                          "keys": "list of QMP key-code chords", "text": "ASCII or $PROOF", "enter": "boolean",
                                          "framebuffer_capture": "optional boolean: read only validated firmware-GOP visible framebuffer, bounded to16MiB",
                                          "vga_scanout_capture": "optional boolean: verified 1234:1111 adapter BAR2 normal MMIO reads; records attribute flip-flop reset/read side effects",
                                          "finish": "boolean: stop owned VM after final captures"}})
    source_copy = run_dir / "runner-source.py"
    shutil.copyfile(Path(__file__), source_copy)
    if sha256_file(source_copy) != result["source_sha256"]:
        raise SystemExit("Runner source changed during provenance capture")
    result["source_snapshot"] = str(source_copy)
    if application_plan is not None:
        helper_source = Path(app_staging.__file__).resolve()
        helper_copy = run_dir / "app-staging-source.py"
        shutil.copyfile(helper_source, helper_copy)
        helper_sha = sha256_file(helper_source)
        if sha256_file(helper_copy) != helper_sha:
            raise SystemExit("Application staging helper changed during source capture")
        result["application_staging_helper"] = {"source": str(helper_source), "sha256": helper_sha,
                                                  "source_snapshot": str(helper_copy)}
    result["minimum_free_bytes"] = shutil.disk_usage(run_dir).free
    vm_started = False
    qcow = run_dir / "checkpoint.qcow2"
    disk = run_dir / ("windows-native.raw" if args.native_bios_control else "windows-uefi.raw")
    try:
        if source_run:
            result["partition"], result["prepared_reuse"] = reuse_prepared(source_run, run_dir, disk, args, immutable, efi, bool(args.resume_owned_run))
            if args.replace_csmwrap:
                prior = result["partition"]
                replacement = add_uefi_files(disk, run_dir, efi, args.firmware_gop)
                if any(replacement[key] != prior[key] for key in ("mbr_sha256", "boot_sector_sha256")):
                    raise RuntimeError("Private EFI replacement did not preserve original legacy boot sectors")
                replacement["snapshot_disk_sha256"] = prior["snapshot_disk_sha256"]
                result["partition"] = replacement
                result["csmwrap_replacement"] = {"scope": "EFI application/config on new private raw copy only",
                        "previous_prepared_uefi_disk_sha256": result["prepared_reuse"]["source_disk_sha256"],
                        "source_csmwrap_sha256": result["prepared_reuse"]["source_csmwrap_sha256"],
                        "selected_csmwrap_sha256": result["prepared_reuse"]["selected_csmwrap_sha256"],
                        "legacy_boot_sectors_preserved": True}
            result["sparse_budget"] = {"reserve_bytes": RESERVE, "dirty_budget_bytes": DIRTY_BUDGET,
                                      "raw_allocated_bytes": disk.stat().st_blocks * 512,
                                      "policy": "verified sparse prepared copy; monitored reserve and dirty allocation"}
        else:
            prepare_from_archive(args, expected, run_dir, qcow, disk, efi, result)
        if args.diagnostic_boot:
            result["diagnostic_boot"] = diagnostic_boot(disk, run_dir, result["partition"])
        if args.himem_machine:
            result["explicit_himem"] = explicit_himem(disk, run_dir, result["partition"], args.himem_machine)
        if args.native_trial_manifest:
            result["native_trial"] = prepare_native_trial(disk, run_dir, result["partition"], args)
            shzlib.write_json(run_dir / "native-trial-plan.json", result["native_trial"])
        if args.guest_files_manifest:
            result["guest_files"] = prepare_guest_files(disk, run_dir, result["partition"], args)
            shzlib.write_json(run_dir / "guest-files-plan.json", result["guest_files"])
        if application_plan is not None:
            source_disk = Path(result["prepared_reuse"]["source_run"]) / "windows-uefi.raw"
            source_tree_baseline = app_staging.directory_absent(
                f"{source_disk}@@{result['partition']['start_lba'] * 512}", application_plan["staging_prefix"])
            source_tree_baseline.update(disk=str(source_disk),
                                        disk_sha256=result["prepared_reuse"]["source_disk_sha256"])
            result["application_staging"] = app_staging.stage(disk, run_dir, result["partition"], application_plan, command)
            result["application_staging"]["source_tree_baseline"] = source_tree_baseline
            shzlib.write_json(run_dir / "application-staging-plan.json", result["application_staging"])
        if args.diagnostic_boot or args.himem_machine or args.native_trial_manifest or args.guest_files_manifest or application_plan is not None:
            result["private_preparation_disk_sha256"] = sha256_file(disk)
        if shutil.disk_usage(run_dir).free < RESERVE + DIRTY_BUDGET:
            raise RuntimeError("Preparation would leave less than selected reserve/dirty budget")
        result["sparse_budget"]["free_before_vm"] = shutil.disk_usage(run_dir).free
        initial_raw_allocation = disk.stat().st_blocks * 512
        result["sparse_budget"]["raw_allocation_before_vm"] = initial_raw_allocation
        print(json.dumps({"stage": "prepared", "run": str(run_dir), "raw_allocated_bytes": initial_raw_allocation,
                          "free_bytes": result["sparse_budget"]["free_before_vm"]}), flush=True)
        vars_copy = run_dir / "OVMF_VARS.fd"
        if not args.native_bios_control:
            shutil.copyfile(args.firmware_vars, vars_copy)
        serial = run_dir / "serial.log"
        with tempfile.TemporaryDirectory(prefix="shz-win98-uefi-") as temporary:
            sock = Path(temporary) / "qmp.sock"
            argv = [args.qemu, "-name", "shz-disposable-win98-uefi", "-machine", args.machine + ",hpet=off",
                    "-accel", args.accel, "-cpu", "qemu64", "-smp", str(args.smp), "-m", str(args.memory),
                    "-nodefaults", "-nic", "none", "-display", "none", "-device", "VGA",
                    "-drive", f"if=pflash,unit=0,format=raw,readonly=on,file={args.firmware_code}",
                    "-drive", f"if=pflash,unit=1,format=raw,file={vars_copy}",
                    "-drive", f"file={disk},format=raw,if=none,id=win98",
                    "-device", "ide-hd,drive=win98,bus=ide.0,bootindex=1",
                    "-serial", f"file:{serial}", "-qmp", f"unix:{sock},server=on,wait=off", "-no-reboot"]
            if args.native_bios_control:
                argv = [args.qemu, "-name", "shz-disposable-win98-native-control", "-machine",
                        "pc-i440fx-rhel10.0.0,acpi=off,hpet=off", "-accel", "tcg", "-cpu", "qemu64",
                        "-smp", str(args.smp), "-m", str(args.memory), "-nodefaults", "-nic", "none",
                        "-display", "none", "-device", "VGA", "-rtc", "base=localtime",
                        "-bios", str(args.native_bios), "-boot", "order=c,menu=off",
                        "-drive", f"file={disk},if=ide,index=0,format=raw",
                        "-serial", f"file:{serial}", "-qmp", f"unix:{sock},server=on,wait=off", "-no-reboot"]
            if args.disable_s3:
                device = "ICH9-LPC" if args.machine == "q35" else "PIIX4_PM"
                argv += ["-global", f"{device}.disable_s3=1"]
            if args.cdrom:
                argv += ["-drive", f"file={args.cdrom},format=raw,if=none,id=cdrom,media=cdrom,readonly=on",
                         "-device", "ide-cd,drive=cdrom,bus=ide.1,bootindex=2"]
            result["command"] = argv
            started, next_capture = time.monotonic(), 10
            interaction_index = 0
            control_sequence = 0
            child = qemu.launch(argv, run_dir)
            print(json.dumps({"stage": "vm-started", "pid": child.pid, "machine": args.machine, "accel": args.accel}), flush=True)
            vm_started = True
            monitor = None
            try:
                monitor = qemu.QMP(sock)
                while child.poll() is None and time.monotonic() - started < args.timeout:
                    free = shutil.disk_usage(run_dir).free
                    result["minimum_free_bytes"] = min(result["minimum_free_bytes"], free)
                    if free < RESERVE:
                        raise RuntimeError("Disk free space reached the selected reserve floor; stopping owned guest")
                    if disk.stat().st_blocks * 512 - initial_raw_allocation > DIRTY_BUDGET:
                        raise RuntimeError("Owned guest exceeded the 256 MiB dirty allocation budget")
                    status = monitor.call("query-status")
                    result["guest_status"] = status
                    stderr = (run_dir / "qemu.stderr").read_text(errors="replace")
                    fatal = FATAL_STDERR.search(stderr)
                    if not status.get("running") or fatal:
                        result["runtime_failure"] = f"QMP guest status {status.get('status')}" + (f"; stderr: {fatal.group()}" if fatal else "")
                        result["captures"].append(capture(monitor, run_dir, len(result["captures"]), csm16, args.smp, args.memory, args.firmware_gop))
                        result["failure_cpus"] = capture_failure_cpus(monitor, run_dir, args.smp)
                        break
                    elapsed = time.monotonic() - started
                    if elapsed >= next_capture:
                        frame = capture(monitor, run_dir, len(result["captures"]), csm16, args.smp, args.memory, args.firmware_gop)
                        result["captures"].append(frame | {"seconds": round(elapsed, 1)})
                        next_capture += args.capture_interval
                    if args.gui_interaction_after is not None and interaction_index < len(steps) and elapsed >= args.gui_interaction_after + steps[interaction_index][0]:
                        delay, name, chords, typed = steps[interaction_index]
                        action = {"name": name, "utc": shzlib.utc_now(), "seconds": round(elapsed, 1), "keys": chords, "typed": typed}
                        try:
                            for keys in chords:
                                send_chord(monitor, keys)
                            if typed:
                                type_ascii(monitor, typed)
                                send_chord(monitor, ["ret"])
                            frame = capture(monitor, run_dir, len(result["captures"]), csm16, args.smp, args.memory, args.firmware_gop)
                            result["captures"].append(frame | {"seconds": round(time.monotonic() - started, 1), "interaction_stage": name})
                            action["screenshot"] = frame["screenshot"]
                            action["status"] = "sent; application effect requires screenshot/readback verification"
                        except Exception as error:
                            action["status"], action["error"] = "FAIL", str(error)
                            interaction_index = len(steps)
                        result["gui_interaction"]["actions"].append(action)
                        interaction_index += 1
                    if args.manual_gui:
                        control_file = run_dir / "gui-control.json"
                        if control_file.exists():
                            request = json.loads(control_file.read_text())
                            sequence = request.get("sequence")
                            if not isinstance(sequence, int):
                                raise RuntimeError("GUI control sequence must be an integer")
                            if sequence > control_sequence:
                                if sequence != control_sequence + 1:
                                    raise RuntimeError("GUI control sequence skipped an action")
                                control_sequence = sequence
                                action = {"name": request.get("name", "manual-action"), "sequence": sequence,
                                          "utc": shzlib.utc_now(), "seconds": round(elapsed, 1), "keys": request.get("keys", [])}
                                try:
                                    for keys in action["keys"]:
                                        send_chord(monitor, keys)
                                    typed = request.get("text")
                                    if typed:
                                        if typed == "$PROOF":
                                            typed = token
                                        elif typed == "$NATIVE_COMMAND":
                                            typed = result["native_trial"]["command"]
                                        type_ascii(monitor, typed)
                                        action["typed"] = typed
                                    if request.get("enter"):
                                        send_chord(monitor, ["ret"])
                                    frame = capture(monitor, run_dir, len(result["captures"]), csm16, args.smp, args.memory, args.firmware_gop,
                                                    bool(request.get("framebuffer_capture")), bool(request.get("vga_scanout_capture")))
                                    result["captures"].append(frame | {"seconds": round(time.monotonic() - started, 1), "interaction_stage": action["name"]})
                                    action["screenshot"] = frame["screenshot"]
                                    action["status"] = "sent; application effect requires screenshot/readback verification"
                                except Exception as error:
                                    action["status"], action["error"] = "FAIL", str(error)
                                result["gui_interaction"]["actions"].append(action)
                                shzlib.write_json(run_dir / "gui-control-receipt.json", action)
                                if request.get("finish"):
                                    result["manual_finish_requested"] = True
                                    break
                    time.sleep(0.2)
                if child.poll() is None:
                    if not result.get("runtime_failure"):
                        result["captures"].append(capture(monitor, run_dir, len(result["captures"]), csm16, args.smp, args.memory, args.firmware_gop))
                        result["final_cpus"] = capture_failure_cpus(monitor, run_dir, args.smp, stem="final")
                    result["guest_status"] = monitor.call("query-status")
                    monitor.call("quit")
            finally:
                if monitor:
                    # Preserve processor evidence even if an essential screen
                    # capture or another operation aborted the bounded run.
                    if not result.get("final_cpus") and not result.get("failure_cpus") and child.poll() is None:
                        try:
                            result["final_cpus"] = capture_failure_cpus(monitor, run_dir, args.smp, stem="final")
                        except Exception as error:
                            result["final_cpu_diagnostic_error"] = str(error)
                        result["final_proxy_diagnostics"] = capture_proxy_diagnostics(monitor, run_dir, "final", csm16, args.smp, args.memory)
                    monitor.close()
                try:
                    child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            result["qemu_exit_code"] = child.returncode
            result["seconds"] = round(time.monotonic() - started, 1)
        baseline = source_run / "windows-uefi.raw" if source_run else None
        result["guest_logs"] = collect_boot_logs(disk, run_dir, result["partition"], baseline)
        if args.native_trial_manifest:
            result["native_trial"] = collect_native_trial(disk, run_dir, result["partition"], result["native_trial"])
            result["gui_interaction"]["verdict"] = "native trial fresh raw-log validation " + result["native_trial"]["validation_status"]
        elif gui_enabled and args.manual_purpose == "gui-proof":
            result["gui_interaction"]["file_readback"] = collect_interaction_file(disk, run_dir, result["partition"], token, baseline)
            result["gui_interaction"]["verdict"] = "exact-guest-file-readback-PASS; screenshot review required" if result["gui_interaction"]["file_readback"]["status"] == "PASS" else "not-established"
        elif gui_enabled:
            result["gui_interaction"]["verdict"] = "separate " + args.manual_purpose + " evidence; native acceptance requires review"
        if args.guest_files_manifest:
            result["guest_files"] = collect_guest_files(disk, run_dir, result["partition"], result["guest_files"])
        serial_text = serial.read_text(errors="replace") if serial.exists() else ""
        checks, position = [], 0
        for name, pattern in ([] if args.native_bios_control else MARKERS):
            found = re.search(pattern, serial_text[position:])
            checks.append({"check": name, "status": "PASS" if found else "FAIL"})
            if found:
                position += found.end()
        result["firmware_checks"] = checks
        stderr = (run_dir / "qemu.stderr").read_text(errors="replace")
        healthy = (not result.get("runtime_failure") and result.get("guest_status", {}).get("running")
                   and result.get("qemu_exit_code") == 0 and not FATAL_STDERR.search(stderr))
        if args.firmware_gop:
            gop_checks = [
                ("explicit GOP configuration parsed", r"gop_only = true"),
                ("firmware GOP retained through SeaVGABIOS", r"gop_only: forced firmware GOP \+ SeaVGABIOS; no VGA OpROM"),
                ("reserved native framebuffer handover emitted", r"SHZGOP1 handover="),
            ]
            result["firmware_gop_checks"] = [{"check": name, "status": "PASS" if re.search(pattern, serial_text) else "FAIL"}
                                             for name, pattern in gop_checks]
            oprom_absent = "Video Initialisation Succeed with OpROM" not in serial_text
            result["firmware_gop_checks"].append({"check": "legacy VGA OpROM path absent", "status": "PASS" if oprom_absent else "FAIL"})
            healthy = healthy and all(item["status"] == "PASS" for item in result["firmware_gop_checks"])
        if gui_enabled:
            interaction = result["gui_interaction"]
            purpose_actions = {"display-install": {"install-driver-have-disk"}, "display-probe": {"run-display-probe"}, "diagnostic": set()}
            expected_actions = (purpose_actions[args.manual_purpose] if args.manual_purpose != "gui-proof" else
                                {"run-native-fixture"} if args.native_trial_manifest else
                                {"open-start-menu", "launch-notepad", "type-proof", "save-root-file"}
                                if args.manual_gui else {step[1] for step in steps})
            actions_complete = (expected_actions.issubset({action["name"] for action in interaction["actions"]}) and
                                all(action.get("status", "").startswith("sent;") for action in interaction["actions"]))
            interaction["all_actions_completed"] = actions_complete
            readback_pass = (True if args.manual_purpose in ("display-install", "diagnostic") else
                             bool(result["guest_files"]["readback"]) and all(p["status"] == "captured" for p in result["guest_files"]["readback"])
                             if args.manual_purpose == "display-probe" else
                             result["native_trial"]["validation_status"] == "PASS" if args.native_trial_manifest
                             else interaction["file_readback"]["status"] == "PASS")
            if args.native_trial_manifest:
                actions_complete = actions_complete and any(action["name"] == "run-native-fixture" and
                                   action.get("typed") == result["native_trial"]["command"] for action in interaction["actions"])
                interaction["all_actions_completed"] = actions_complete
            if not actions_complete or not readback_pass:
                healthy = False
                result["interaction_failure"] = "Requested GUI actions did not all complete with exact fresh guest-file readback"
        result["status"] = "NEEDS-VISUAL-REVIEW" if healthy and all(c["status"] == "PASS" for c in checks) else "FAIL"
        result["serial_log"] = str(serial)
    except Exception as error:
        result["error"] = str(error)
    finally:
        if not vm_started:
            for temporary in (qcow, disk):
                temporary.unlink(missing_ok=True)
            result["temporary_images_removed"] = True
        result["free_after_run"] = shutil.disk_usage(run_dir).free
        result["minimum_free_bytes"] = min(result["minimum_free_bytes"], result["free_after_run"])
        result["originals_unchanged"] = all(sha256_file(Path(p)) == digest for p, digest in immutable.items())
        if source_run and result.get("prepared_reuse"):
            prepared_disk = source_run / "windows-uefi.raw"
            result["prepared_source_unchanged"] = sha256_file(prepared_disk) == result["prepared_reuse"]["source_disk_sha256"]
            if not result["prepared_source_unchanged"]:
                result["status"] = "FAIL"
        if not result["originals_unchanged"]:
            result["status"] = "FAIL"
        if result.get("native_trial"):
            result["native_trial"]["immutable_sources_unchanged"] = all(sha256_file(Path(path)) == digest for path, digest in result["native_trial"]["immutable_sources"].items())
            if not result["native_trial"]["immutable_sources_unchanged"]:
                result["status"] = "FAIL"
        if result.get("guest_files"):
            result["guest_files"]["immutable_sources_unchanged"] = all(sha256_file(Path(path)) == digest for path, digest in result["guest_files"]["immutable_sources"].items())
            if not result["guest_files"]["immutable_sources_unchanged"]:
                result["status"] = "FAIL"
        if result.get("application_staging"):
            staged = result["application_staging"]
            staged["immutable_sources_unchanged"] = all(sha256_file(Path(path)) == digest for path, digest in staged["immutable_sources"].items())
            helper = result["application_staging_helper"]
            staged["helper_source_unchanged"] = sha256_file(Path(helper["source"])) == helper["sha256"]
            if not staged["immutable_sources_unchanged"] or not staged["helper_source_unchanged"]:
                result["status"] = "FAIL"
        if vm_started and disk.exists():
            result["owned_disk_sha256_after_run"] = sha256_file(disk)
        shzlib.write_json(run_dir / "result.json", json.loads(json.dumps(result, default=str)))
    print(json.dumps({"status": result["status"], "result": str(run_dir / "result.json"),
                      "captures": len(result["captures"]), "error": result.get("error")}, indent=2))
    return 0 if result["status"] == "NEEDS-VISUAL-REVIEW" else 1


def prepare_from_archive(args, expected, run_dir, qcow, disk, efi, result):
    if shutil.disk_usage(CSM).free < RESERVE + 2 * expected["raw_bytes"] + DIRTY_BUDGET:
        raise RuntimeError("Insufficient space for twice the expected clone writes above the selected reserve/dirty budget")
    restore_archive(args.archive, qcow, expected)
    info = json.loads(command(["qemu-img", "info", "--output=json", qcow]))
    if info["format"] != "qcow2" or info["virtual-size"] > 2 * GIB or info.get("backing-filename"):
        raise RuntimeError("Checkpoint must be a self-contained <=2 GiB qcow2")
    if args.snapshot not in {s["name"] for s in info.get("snapshots", [])}:
        raise RuntimeError(f"Required installed-disk snapshot absent: {args.snapshot}")
    command(["qemu-img", "check", qcow])
    # Only the private decompressed container is changed. Activating its disk
    # snapshot permits a map of selected data, excluding other snapshots' RAM
    # and later installed applications from the sparse-conversion bound.
    command(["qemu-img", "snapshot", "-a", args.snapshot, qcow])
    map_text = command(["qemu-img", "map", "--output=json", qcow])
    extents = json.loads(map_text)
    position = 0
    for extent in extents:
        if extent["start"] != position or extent["length"] <= 0 or "data" not in extent or "zero" not in extent:
            raise RuntimeError("Incomplete selected-snapshot data map")
        position += extent["length"]
    if position != info["virtual-size"]:
        raise RuntimeError("Selected-snapshot map does not cover the virtual disk")
    raw_estimate = sum(e["length"] for e in extents if e["data"] and not e["zero"])
    (run_dir / "selected-snapshot-map.json").write_text(map_text)
    result["selected_snapshot_map"] = {"snapshot": args.snapshot, "source_disk_sha256": sha256_file(qcow),
                                       "map_sha256": sha256_file(run_dir / "selected-snapshot-map.json"),
                                       "data_extent_bytes": raw_estimate,
                                       "method": "qemu-img map after snapshot -a on the private container only"}
    result["sparse_budget"] = {"reserve_bytes": RESERVE, "dirty_budget_bytes": DIRTY_BUDGET,
                               "restored_logical_bytes": qcow.stat().st_size,
                               "restored_allocated_bytes": qcow.stat().st_blocks * 512,
                               "raw_estimate_bytes": raw_estimate,
                               "clone_write_multiplier": 2,
                               "free_before_conversion": shutil.disk_usage(run_dir).free,
                               "policy": "measured sparse allocation; no full logical 2 GiB reservation"}
    if shutil.disk_usage(run_dir).free < RESERVE + 2 * raw_estimate + DIRTY_BUDGET:
        raise RuntimeError("Insufficient measured sparse conversion budget above the selected reserve")
    command(["qemu-img", "convert", "-f", "qcow2", "-O", "raw", "-S", "4k", qcow, disk], timeout=300)
    result["sparse_budget"]["raw_allocated_bytes"] = disk.stat().st_blocks * 512
    if shutil.disk_usage(run_dir).free < RESERVE + DIRTY_BUDGET:
        raise RuntimeError("Sparse conversion would leave less than the selected reserve/dirty budget")
    result["partition"] = add_uefi_files(disk, run_dir, efi, args.firmware_gop)
    # Conversion plus sector equality checks preserve all boot evidence in the
    # raw clone; the disposable decompressed container is no longer needed.
    qcow.unlink()
    result["decompressed_checkpoint_removed_after_conversion"] = True


if __name__ == "__main__":
    raise SystemExit(main())
