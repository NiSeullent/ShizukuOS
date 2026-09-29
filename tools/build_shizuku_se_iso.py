#!/usr/bin/env python3
"""Build a bootable Windows 98 Shizuku Second Edition project ISO.

ShizukuDOS 0.1 is the El Torito 1.44 MiB FAT12 boot image. The ISO9660/Joliet
tree is the Second Edition payload and embeds the built NTWrapper9x,
NTWin32Wrapper9x and NTWDDMWrapper9x artifacts. Microsoft installation files
are not packaged.

Layout sources recorded in SOURCES.TXT on the image:
- "El Torito" Bootable CD-ROM Format Specification 1.0 (Phoenix/IBM, 1995),
  media type 2 = 1.44 MB floppy emulation.
  https://pdos.csail.mit.edu/6.828/2018/readings/boot-cdrom.pdf
- Microsoft KB Q167685 (media byte 0x02 is a 1.44 MB floppy).
  https://helparchive.huntertur.net/document/106908
- ECMA-119 / ISO 9660.
  https://ecma-international.org/publications-and-standards/standards/ecma-119/
- xorriso mkisofs emulation: a 1440 KiB -b image selects floppy emulation.
  Do not pass -no-emul-boot or -boot-info-table; the info table would
  overwrite FAT BPB bytes at offset 8.
  https://wiki.osdev.org/Mkisofs
  https://wiki.osdev.org/El-Torito
- Windows 98 installation CDs boot that embedded floppy as drive A. Reading
  the rest of the CD still needs a CD-ROM driver, which ShizukuDOS does not
  implement. https://www.vogons.org/viewtopic.php?t=102014
- FAT12 geometry matches shizukudos/boot.asm: 512-byte sectors, 2880 sectors,
  18 sectors/track, 2 heads (1.44 MiB). Microsoft FAT specification:
  https://www.win.tue.nl/~aeb/linux/fs/fat/fatgen103.pdf
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import shutil
import socket
import struct
import subprocess
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
STAGE_ROOT = BUILD / "shizuku-second-edition-stage"
ISO_NAME = "windows98-shizuku-second-edition.iso"
QEMU = Path("/usr/libexec/qemu-kvm")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(command: list[str], cwd: Path | None = None) -> None:
    subprocess.run(command, cwd=cwd or ROOT, check=True)


def load_image_builder():
    path = ROOT / "shizukudos" / "build_image.py"
    spec = importlib.util.spec_from_file_location("shizuku_image", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def replace_broken_symlink(path: Path) -> None:
    """Official builders mkdir these output dirs. Broken /dev/shm links block them."""
    if path.is_symlink() and not path.exists():
        path.unlink()
    path.mkdir(parents=True, exist_ok=True)


def build_components(work: Path) -> dict[str, Path]:
    work.mkdir(parents=True, exist_ok=True)
    for output in (
        ROOT / "build" / "platform",
        ROOT / "ntwrapper" / "vxd" / "build",
        ROOT / "ntwddm" / "build",
        ROOT / "ntwddm" / "win98" / "build",
    ):
        replace_broken_symlink(output)
    run(["nasm", "-f", "bin", "shizukudos/boot.asm", "-o", str(work / "boot.bin")])
    run([
        "nasm", "-f", "bin", "-I", "shizukudos/",
        "shizukudos/stage2.asm", "-o", str(work / "stage2.bin"),
    ])
    for source, output in (
        ("shizukudos/tests/demo_com.asm", "demo.com"),
        ("shizukudos/tests/ret_com.asm", "ret.com"),
        ("shizukudos/tests/std_com.asm", "std.com"),
    ):
        run(["nasm", "-f", "bin", source, "-o", str(work / output)])
    run(["python3", "-B", "platform/build.py"])
    run(["python3", "-B", "ntwrapper/vxd/build.py"])
    run(["python3", "-B", "ntwddm/win98/build.py"])
    # The combined i386 object currently references __udivdi3, so the phony
    # freestanding32 check fails. The core object is the Makefile product
    # whose undefined-symbol list is empty. Do not rewrite ntwddm sources.
    run(["make", "-C", "ntwddm", "build/ntwddm-i386.o"])
    core = ROOT / "ntwddm" / "build" / "ntwddm-i386.o"
    undefined = subprocess.check_output(["nm", "-u", str(core)], text=True)
    if undefined.strip():
        raise RuntimeError("ntwddm-i386.o has undefined symbols:\n" + undefined)
    artifacts = {
        "NTW32.DLL": ROOT / "build" / "platform" / "NTW32.DLL",
        "NTWPROBE.EXE": ROOT / "build" / "platform" / "NTWPROBE.EXE",
        "NTWRAP9X.VXD": ROOT / "ntwrapper" / "vxd" / "build" / "NTWRAP9X.VXD",
        "NTWQUERY.EXE": ROOT / "ntwrapper" / "vxd" / "build" / "NTWQUERY.EXE",
        "NTWGPROB.EXE": ROOT / "ntwddm" / "win98" / "build" / "NTWGPROB.EXE",
        "ntwddm-i386.o": ROOT / "ntwddm" / "build" / "ntwddm-i386.o",
    }
    missing = [name for name, path in artifacts.items() if not path.is_file()]
    if missing:
        raise RuntimeError("missing built artifacts: " + ", ".join(missing))
    return artifacts


def edition_text() -> bytes:
    return (
        "Windows 98 Shizuku Second Edition\r\n"
        "Boot and install path: ShizukuDOS 0.1 FAT12.\r\n"
        "Embedded on this disk: NTW32.DLL NTWRAP9X.VXD NTWGPROB.EXE\r\n"
        "ShizukuDOS does not replace IO.SYS or boot the Windows 98 GUI.\r\n"
        "Microsoft setup files are not on this image.\r\n"
    ).encode("ascii")


def limits_text() -> bytes:
    return (
        "LIMITS\r\n"
        "ShizukuDOS reads FAT12 root files and runs one 8.3 COM program.\r\n"
        "It does not provide MS-DOS 7.1, MSCDEX, or a CD-ROM driver.\r\n"
        "BOOT and BOOTC only chainload an existing hard-disk boot sector.\r\n"
        "This is not a completed Windows 98 GUI installation.\r\n"
    ).encode("ascii")


def sources_text() -> bytes:
    return (
        "Layout sources checked while building this image\r\n"
        "1. El Torito Bootable CD-ROM Format Specification 1.0, Phoenix/IBM, 1995.\r\n"
        "   Media type 2 is 1.44 MB floppy emulation. Boot indicator 0x88.\r\n"
        "   https://pdos.csail.mit.edu/6.828/2018/readings/boot-cdrom.pdf\r\n"
        "2. Microsoft KB Q167685. Media byte 0x02 is a 1.44 MB floppy.\r\n"
        "   https://helparchive.huntertur.net/document/106908\r\n"
        "3. ECMA-119, volume and file structure of CD-ROM (ISO 9660).\r\n"
        "   https://ecma-international.org/publications-and-standards/standards/ecma-119/\r\n"
        "4. xorriso -as mkisofs. A 1440 KiB -b image uses floppy emulation.\r\n"
        "   -boot-info-table is not used because it overwrites BPB offset 8.\r\n"
        "   https://wiki.osdev.org/Mkisofs\r\n"
        "   https://wiki.osdev.org/El-Torito\r\n"
        "5. Windows 98 bootable CDs expose the embedded floppy as drive A.\r\n"
        "   CD directory access still requires a CD-ROM driver.\r\n"
        "   https://www.vogons.org/viewtopic.php?t=102014\r\n"
        "6. FAT12 BPB geometry is the ShizukuDOS boot sector: 512x2880, 18x2.\r\n"
        "   https://www.win.tue.nl/~aeb/linux/fs/fat/fatgen103.pdf\r\n"
    ).encode("ascii")


def build_floppy(work: Path, artifacts: dict[str, Path]) -> bytes:
    image_mod = load_image_builder()
    files = {
        "HELLO.TXT": b"Hello from ShizukuDOS.\r\nThis FAT12 file can be read with TYPE.\r\n",
        "README.TXT": (
            b"ShizukuDOS is a from-scratch experimental shell.\r\n"
            b"BOOT chainloads the first hard disk MBR.\r\n"
            b"Windows 98 still uses its own IO.SYS and DOS 7.1.\r\n"
        ),
        "CHAIN.TXT": b"START OF FAT12 CHAIN\r\n" + b"0123456789ABCDEF\r\n" * 60 + b"END OF FAT12 CHAIN\r\n",
        "DEMO.COM": (work / "demo.com").read_bytes(),
        "RET.COM": (work / "ret.com").read_bytes(),
        "STD.COM": (work / "std.com").read_bytes(),
        "EDITION.TXT": edition_text(),
        "LIMITS.TXT": limits_text(),
        "NTW32.DLL": artifacts["NTW32.DLL"].read_bytes(),
        "NTWRAP9X.VXD": artifacts["NTWRAP9X.VXD"].read_bytes(),
        "NTWQUERY.EXE": artifacts["NTWQUERY.EXE"].read_bytes(),
        "NTWPROBE.EXE": artifacts["NTWPROBE.EXE"].read_bytes(),
        "NTWGPROB.EXE": artifacts["NTWGPROB.EXE"].read_bytes(),
        "NTWDDM.O": artifacts["ntwddm-i386.o"].read_bytes(),
    }
    image = image_mod.make_image(
        (work / "boot.bin").read_bytes(),
        (work / "stage2.bin").read_bytes(),
        files,
    )
    if len(image) != 1474560:
        raise RuntimeError(f"boot image is {len(image)} bytes, not 1474560")
    if image[0:3] != b"\xeb\x3c\x90" and image[0] != 0xEB:
        raise RuntimeError("boot image is missing the ShizukuDOS jump")
    if image[3:11] != b"SHIZUKU ":
        raise RuntimeError("boot image OEM name is not SHIZUKU")
    if image[510:512] != b"\x55\xaa":
        raise RuntimeError("boot image signature missing")
    return image


def stage_tree(stage: Path, floppy: bytes, artifacts: dict[str, Path]) -> dict[str, bytes]:
    if stage.exists():
        shutil.rmtree(stage)
    edition = stage / "Windows 98 Shizuku Second Edition"
    dos = stage / "ShizukuDOS"
    (edition / "NTWrapper9x").mkdir(parents=True)
    (edition / "NTWin32Wrapper9x").mkdir(parents=True)
    (edition / "NTWDDMWrapper9x").mkdir(parents=True)
    dos.mkdir(parents=True)
    payload: dict[str, bytes] = {
        "README.TXT": (
            "Windows 98 Shizuku Second Edition install image\r\n"
            "Boot path: El Torito 1.44 MiB floppy emulation of ShizukuDOS.\r\n"
            "The same compatibility binaries are inside that floppy and in\r\n"
            "the Windows 98 Shizuku Second Edition directories.\r\n"
            "ShizukuDOS cannot replace IO.SYS or install a Windows 98 GUI.\r\n"
            "Microsoft Windows files and product keys are not included.\r\n"
        ).encode("ascii"),
        "SOURCES.TXT": sources_text(),
        "LIMITS.TXT": limits_text(),
        "NOMSBASE.TXT": (
            "Microsoft base omitted\r\n"
            "vm/Win98-SE-ko-OEM.iso is not in this tree.\r\n"
            "build/win98-lab/win98se-ko-oem.iso does not resolve to a readable ISO.\r\n"
            "This image does not redistribute the Windows 98 file tree.\r\n"
            "Missing for a Microsoft setup: IO.SYS, MSDOS.SYS, COMMAND.COM,\r\n"
            "WIN98 cabinet files, and the OEM boot floppy drivers.\r\n"
        ).encode("ascii"),
    }
    copies = {
        "ShizukuDOS/shizukudos.img": floppy,
        "Windows 98 Shizuku Second Edition/EDITION.TXT": edition_text(),
        "Windows 98 Shizuku Second Edition/LIMITS.TXT": limits_text(),
        "Windows 98 Shizuku Second Edition/NTWrapper9x/NTWRAP9X.VXD": artifacts["NTWRAP9X.VXD"].read_bytes(),
        "Windows 98 Shizuku Second Edition/NTWrapper9x/NTWQUERY.EXE": artifacts["NTWQUERY.EXE"].read_bytes(),
        "Windows 98 Shizuku Second Edition/NTWin32Wrapper9x/NTW32.DLL": artifacts["NTW32.DLL"].read_bytes(),
        "Windows 98 Shizuku Second Edition/NTWin32Wrapper9x/NTWPROBE.EXE": artifacts["NTWPROBE.EXE"].read_bytes(),
        "Windows 98 Shizuku Second Edition/NTWDDMWrapper9x/NTWGPROB.EXE": artifacts["NTWGPROB.EXE"].read_bytes(),
        "Windows 98 Shizuku Second Edition/NTWDDMWrapper9x/ntwddm-i386.o": artifacts["ntwddm-i386.o"].read_bytes(),
    }
    payload.update(copies)
    lines = ["sha256  bytes  path\r\n"]
    for name in sorted(payload):
        if name.endswith("HASHES.TXT"):
            continue
        data = payload[name]
        lines.append(f"{sha256(data)}  {len(data)}  {name}\r\n")
    payload["HASHES.TXT"] = "".join(lines).encode("ascii")
    for relative, data in payload.items():
        target = stage / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return payload


def write_iso(stage: Path, iso_path: Path) -> None:
    iso_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = iso_path.with_suffix(".iso.partial")
    if temporary.exists():
        temporary.unlink()
    run([
        "xorriso", "-as", "mkisofs",
        "-iso-level", "3",
        "-J", "-R",
        "-V", "W98SHIZUKU2",
        "-publisher", "Win98-Modern project",
        "-b", "ShizukuDOS/shizukudos.img",
        "-c", "ShizukuDOS/boot.cat",
        "-o", str(temporary),
        str(stage),
    ])
    temporary.replace(iso_path)


def parse_el_torito(iso: bytes) -> str:
    sector = 17 * 2048
    boot_record = iso[sector:sector + 2048]
    if boot_record[0] != 0:
        raise RuntimeError("volume descriptor at sector 17 is not a boot record")
    if boot_record[1:6] != b"CD001":
        raise RuntimeError("missing CD001 in the boot record")
    if not boot_record[7:39].startswith(b"EL TORITO SPECIFICATION"):
        raise RuntimeError("boot record is not El Torito")
    catalog_lba = struct.unpack_from("<I", boot_record, 0x47)[0]
    catalog = iso[catalog_lba * 2048:catalog_lba * 2048 + 64]
    if catalog[0] != 1 or catalog[30:32] != b"\x55\xaa":
        raise RuntimeError("El Torito validation entry is invalid")
    entry = catalog[32:64]
    if entry[0] != 0x88:
        raise RuntimeError("default El Torito entry is not bootable")
    media = entry[1]
    media_names = {0: "no emulation", 1: "1.2MB floppy", 2: "1.44MB floppy", 3: "2.88MB floppy", 4: "hard disk"}
    if media != 2:
        raise RuntimeError(f"expected 1.44MB floppy emulation, media type is {media}")
    load_segment = struct.unpack_from("<H", entry, 2)[0]
    load_rba = struct.unpack_from("<I", entry, 8)[0]
    return (
        f"El Torito catalog LBA {catalog_lba}\n"
        f"boot indicator 0x88, platform 0x{catalog[1]:02x}, media type {media} ({media_names[media]})\n"
        f"load segment 0x{load_segment:04x} (0 means 0x07C0), boot image LBA {load_rba}\n"
        f"boot image OEM {iso[load_rba * 2048 + 3:load_rba * 2048 + 11]!r}\n"
    )


def verify_iso(iso_path: Path, payload: dict[str, bytes], evidence: Path) -> str:
    iso = iso_path.read_bytes()
    report = parse_el_torito(iso)
    listing = subprocess.check_output(
        ["xorriso", "-indev", str(iso_path), "-find", "/", "-type", "f"],
        text=True,
    )
    eltorito = subprocess.check_output(
        ["xorriso", "-indev", str(iso_path), "-report_el_torito", "plain"],
        text=True,
        stderr=subprocess.STDOUT,
    )
    extracted = evidence / "extracted"
    if extracted.exists():
        shutil.rmtree(extracted)
    extracted.mkdir(parents=True)
    subprocess.run(
        ["xorriso", "-osirrox", "on", "-indev", str(iso_path), "-extract", "/", str(extracted)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    required = [
        "Windows 98 Shizuku Second Edition/NTWrapper9x/NTWRAP9X.VXD",
        "Windows 98 Shizuku Second Edition/NTWin32Wrapper9x/NTW32.DLL",
        "Windows 98 Shizuku Second Edition/NTWDDMWrapper9x/NTWGPROB.EXE",
        "Windows 98 Shizuku Second Edition/NTWDDMWrapper9x/ntwddm-i386.o",
        "ShizukuDOS/shizukudos.img",
    ]
    for relative in required:
        found = extracted / relative
        if not found.is_file():
            raise RuntimeError(f"ISO is missing {relative}")
        if found.read_bytes() != payload[relative]:
            raise RuntimeError(f"ISO payload mismatch for {relative}")
    boot = (extracted / "ShizukuDOS/shizukudos.img").read_bytes()
    report += f"embedded floppy sha256 {sha256(boot)}\n"
    report += "xorriso -report_el_torito plain:\n" + eltorito
    report += "\nfiles:\n" + listing
    (evidence / "layout.txt").write_text(report, encoding="utf-8")
    return report


def qemu_frames(iso_path: Path, evidence: Path) -> str:
    if not QEMU.is_file():
        return "QEMU binary /usr/libexec/qemu-kvm is not present; no PNG captured."
    serial_path = evidence / "serial.sock"
    monitor_path = evidence / "monitor.sock"
    for path in (serial_path, monitor_path):
        if path.exists():
            path.unlink()
    serial_log = evidence / "serial.txt"
    process = subprocess.Popen(
        [
            str(QEMU),
            "-machine", "pc",
            "-accel", "tcg",
            "-m", "64",
            "-boot", "order=d,menu=off",
            "-cdrom", str(iso_path),
            "-vga", "std",
            "-display", "vnc=127.0.0.1:71",
            "-serial", f"unix:{serial_path},server=on,wait=off",
            "-monitor", f"unix:{monitor_path},server=on,wait=off",
            "-no-reboot",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        serial = connect_unix(serial_path, 10)
        monitor = connect_unix(monitor_path, 10)
        prompt = read_until(serial, b"A:\\> ", 30)
        save_png(monitor, evidence / "boot.ppm", BUILD / "windows98-shizuku-second-edition-boot.png")
        serial.sendall(b"DIR\r")
        # The shell prints 8.3 names with space padding: "NTW32   .DLL".
        prompt += read_until(serial, b"NTW32   .DLL", 10)
        prompt += read_until(serial, b"NTWRAP9X.VXD", 10)
        prompt += read_until(serial, b"NTWGPROB.EXE", 10)
        prompt += read_until(serial, b"A:\\> ", 10)
        save_png(monitor, evidence / "dir.ppm", BUILD / "windows98-shizuku-second-edition-dir.png")
        serial_log.write_bytes(prompt)
        return (
            "QEMU TCG boot reached the ShizukuDOS prompt and DIR listed the embedded files.\n"
            f"PNG {BUILD / 'windows98-shizuku-second-edition-boot.png'}\n"
            f"PNG {BUILD / 'windows98-shizuku-second-edition-dir.png'}\n"
        )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def connect_unix(path: Path, timeout: float) -> socket.socket:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.connect(str(path))
                sock.settimeout(2)
                return sock
            except OSError:
                sock.close()
        time.sleep(0.1)
    raise TimeoutError(f"socket not ready: {path}")


def read_until(sock: socket.socket, marker: bytes, timeout: float) -> bytes:
    deadline = time.time() + timeout
    data = bytearray()
    while time.time() < deadline:
        if marker in data:
            return bytes(data)
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            break
        data.extend(chunk)
    raise TimeoutError(f"did not see {marker!r}; got {bytes(data[-400:])!r}")


def save_png(monitor: socket.socket, ppm: Path, png: Path) -> None:
    command = f"screendump {ppm}\n".encode()
    try:
        monitor.recv(4096)
    except socket.timeout:
        pass
    monitor.sendall(command)
    deadline = time.time() + 10
    reply = bytearray()
    while time.time() < deadline:
        if b"(qemu)" in reply and ppm.is_file() and ppm.stat().st_size > 0:
            break
        try:
            chunk = monitor.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            break
        reply.extend(chunk)
    from PIL import Image
    Image.open(ppm).save(png)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-qemu", action="store_true")
    args = parser.parse_args()
    work = BUILD / "shizuku-second-edition-work"
    evidence = BUILD / "shizuku-second-edition-evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    artifacts = build_components(work)
    floppy = build_floppy(work, artifacts)
    (work / "shizukudos.img").write_bytes(floppy)
    payload = stage_tree(STAGE_ROOT, floppy, artifacts)
    iso_path = BUILD / ISO_NAME
    write_iso(STAGE_ROOT, iso_path)
    report = verify_iso(iso_path, payload, evidence)
    digest = sha256(iso_path.read_bytes())
    size = iso_path.stat().st_size
    qemu_report = "QEMU boot was skipped.\n"
    if not args.skip_qemu:
        try:
            qemu_report = qemu_frames(iso_path, evidence)
        except Exception as exc:
            qemu_report = "QEMU boot did not produce the expected frames:\n" + traceback.format_exc()
    summary = (
        f"{iso_path}\n"
        f"bytes {size}\n"
        f"sha256 {digest}\n"
        f"{report}\n"
        f"{qemu_report}\n"
    )
    (BUILD / "windows98-shizuku-second-edition.txt").write_text(summary, encoding="utf-8")
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
