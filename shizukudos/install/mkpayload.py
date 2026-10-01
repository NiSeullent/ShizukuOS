#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the ShizukuDOS installation payload (host side of SHZSETUP.EXE).

Outputs (build/shizukudos/install/):
  esp.img                 the EFI System Partition, FAT32, built on the host and written by SHZSETUP sector by sector
                          (deterministic: fixed volume id/label, --invariant, fixed file times, fixed order)
  payload/ESP.SIM         esp.img as a SHZSIMG1 sparse image (zero 4 KiB blocks omitted; SHZSETUP writes them as zeros)
  payload/SYSTEM.ARC      the ShizukuFS system tree (\\SHZ\\SYS64, \\SHZ\\DRIVERS, ...) as a SHZARC01 archive
  payload/GPTMBR.BIN      440 bytes of legacy BIOS boot code for the protective MBR (install/gptmbr.asm)
  payload/manifest.json   sizes and SHA-256 of esp.img, of every ESP file and of every system file
  shzsetup.ini            the answer file packed with the payload (default: install/shzsetup.ini)
  INSTALL.IMG             initial RAM archive for the installer boot: Win64 runtime, T_HELLO.EXE (boot self-test),
                          \\SHZ\\SETUP\\SHZSETUP.EXE, \\SHZ\\SETUP\\SHZSETUP.INI and \\SHZ\\SETUP\\PAYLOAD\\*
  mkpayload-result.json   receipt (inputs, outputs, hashes)
Boot the installer: Multiboot stub build/shizukudos/kernel64s/boot.elf with modules KERNEL64S.BIN and INSTALL.IMG and
the kernel command line `shz.setup=auto` (tests/run_install.py does this under QEMU; the install ISO does it with
isolinux/mboot.c32, agent C3).

ESP layout: \\EFI\\BOOT\\BOOTX64.EFI (Shizuku UEFI loader), \\EFI\\SHIZUKU\\BOOT.INI (mode = kernel64),
\\EFI\\SHIZUKU\\CSMWRAP.EFI (when built), \\SHZDOS\\KERNEL64S.BIN, WIN64.IMG, DISK.IMG (DOS16), KERNEL32.BIN, KERNEL64.BIN,
K64STUB.ELF (Multiboot stub for a BIOS boot loader). Nothing from Microsoft is ever included.
Legacy BIOS boot of the installed disk (agent C3): the pinned syslinux 6.04 (upstream/manifest.json "syslinux") is
installed into esp.img on the host: its FAT32 boot sector (which GPTMBR.BIN chains to) loads \\syslinux\\ldlinux.sys,
and \\syslinux\\syslinux.cfg boots Kernel64 by default (mboot.c32 \\SHZDOS\\K64STUB.ELF --- KERNEL64S.BIN --- WIN64.IMG)
or DOS16 (memdisk \\SHZDOS\\DISK.IMG). --no-bios-boot leaves the ESP boot sector as mkfs.fat's non-system stub.

Inputs are the outputs of kbuild.py, win64/build.py, dos16/build.py, supervisor/build.py and (optional) csm/build.py;
`--build` runs the missing ones first.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import shzlib  # noqa: E402
from shzlib import BUILD, SHZ, run, sha256_file  # noqa: E402

OUT = BUILD / "install"
PAYLOAD = OUT / "payload"
FIXED_EPOCH = 1785283200            # same fixed stamp as tools/fatimg.py and csm/build.py
SCHEMA = "shizukudos-install-manifest/1"
PRODUCT = "ShizukuDOS 10.0-dev"
ESP_LABEL, ESP_VOLID = "SHZESP", "53485A45"
ESP_FIRST_LBA = 2048                # p1 starts at 1 MiB; esp.img's BPB hidden-sectors field says so
SYS_LABEL = "SHZSYS"
SIMG_BLOCK = 4096
MIB = 1024 * 1024

INPUTS = {
    "loader": BUILD / "supervisor" / "BOOTX64.EFI",
    "csmwrap": BUILD / "csm" / "CSMWRAP.EFI",
    "kernel64s": BUILD / "kernel64s" / "KERNEL64S.BIN",
    "stub": BUILD / "kernel64s" / "boot.elf",
    "kernel64": BUILD / "kernel64" / "KERNEL64.BIN",
    "kernel32": BUILD / "kernel32" / "KERNEL32.BIN",
    "dos16": BUILD / "dos16" / "shizukudos-dos16-hd32.img",
    "win64": BUILD / "win64",
}
BUILDERS = [("kernel64s", ["kbuild.py"]), ("win64", ["win64/build.py"]), ("dos16", ["dos16/build.py"]),
            ("csmwrap", ["csm/build.py"]), ("loader", ["supervisor/build.py"])]

# Kernel64 built-in drivers, described as packages under \SHZ\DRIVERS\<name>\DRIVER.INI. A package exists only when its
# source file is in the tree, so drivers of other tracks appear once they are merged. Kernel64 has no loadable driver
# model yet: these are descriptors of drivers compiled into the kernel, for the future device manager and for the
# answer file's [Drivers] selection.
DRIVERS = [
    ("rtl8139", "net_rtl8139.c", "Realtek RTL8139 Fast Ethernet", ["10ec:8139"]),
    ("bochs-vbe", "gfx_fb.c", "Bochs/QEMU VBE linear framebuffer (-vga std)", ["1234:1111"]),
    ("ram", "blk_ram.c", "RAM block device (QEMU ivshmem-plain BAR2; installer test target)", ["1af4:1110"]),
    ("ahci", "ahci_blk.c", "AHCI SATA disks", ["class 01:06:01"]),
    ("nvme", "nvme.c", "NVM Express SSDs", ["class 01:08:02"]),
    ("sdhci", "sdhci.c", "SD Host Controller / eMMC", ["class 08:05"]),
    ("virtio", "virtio_pci.c", "virtio-pci modern transport", ["1af4:1040-107f"]),
]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def mtools_env():
    env = dict(os.environ)
    env.update({"MTOOLS_SKIP_CHECK": "1", "SOURCE_DATE_EPOCH": str(FIXED_EPOCH), "TZ": "UTC", "LC_ALL": "C"})
    return env


def load_win64_build():
    spec = importlib.util.spec_from_file_location("shz_win64_build", SHZ / "win64" / "build.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def ensure_inputs(build):
    for key, script in BUILDERS:
        path = INPUTS[key]
        present = (path / "WIN64.IMG").exists() if key == "win64" else path.exists()
        if not present and build:
            print(f"== building {key}: {' '.join(script)}", flush=True)
            subprocess.run([sys.executable, str(SHZ / script[0])], check=True, timeout=3600)
    missing = [k for k in INPUTS if k != "csmwrap" and not ((INPUTS[k] / "WIN64.IMG") if k == "win64" else INPUTS[k]).exists()]
    if missing:
        raise SystemExit("missing inputs: " + ", ".join(f"{k} ({INPUTS[k]})" for k in missing) + "; run with --build")


def runtime_files(desktop=False):
    """The Win64 runtime of this build: every system DLL plus T_HELLO.EXE (Kernel64's boot self-test runs it)."""
    w = INPUTS["win64"]
    receipt = json.loads((w / "build-result.json").read_text())
    dlls = ["ntdll", "kernel32", *sorted(receipt.get("modules", {}))]
    if desktop:
        from desktop_profile import desktop_runtime
        files = desktop_runtime((w / "WIN64.IMG").read_bytes(), receipt["archive"]["sha256"])
    else:
        files = [(f"\\SHZ\\SYS64\\{n}.dll", (w / f"{n}.dll").read_bytes()) for n in dlls]
    return files, (w / "t_hello.exe").read_bytes(), (w / "SHZSETUP.EXE").read_bytes()


def build_esp(members, size_mib):
    """members: list of (FAT path with '/', bytes). Returns the image bytes."""
    img = OUT / "esp.img"
    stage = OUT / "esp-src"
    shutil.rmtree(stage, ignore_errors=True)
    img.unlink(missing_ok=True)
    with open(img, "wb") as fh:
        fh.truncate(size_mib * MIB)
    run(["mkfs.fat", "--invariant", "-F", "32", "-S", "512", "-s", "2", "-h", str(ESP_FIRST_LBA), "-n", ESP_LABEL,
         "-i", ESP_VOLID, str(img)], env=mtools_env(), capture=True)
    env = mtools_env()
    dirs = sorted({"/".join(p.split("/")[:i]) for p, _ in members for i in range(1, p.count("/") + 1)},
                  key=lambda d: (d.count("/"), d))
    for d in dirs:
        run(["mmd", "-i", str(img), f"::/{d}"], env=env)
    for path, data in members:
        local = stage / path
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(data)
        os.utime(local, (FIXED_EPOCH, FIXED_EPOCH))
        run(["mcopy", "-m", "-i", str(img), str(local), f"::/{path}"], env=env, timeout=300)
    shutil.rmtree(stage)
    check = subprocess.run(["fsck.fat", "-n", str(img)], capture_output=True, text=True)
    if check.returncode != 0:
        raise SystemExit("fsck.fat rejects esp.img:\n" + check.stdout + check.stderr)
    data = img.read_bytes()
    if struct.unpack_from("<I", data, 0x1C)[0] != ESP_FIRST_LBA or data[0x52:0x5A] != b"FAT32   ":
        raise SystemExit("esp.img: unexpected BPB (hidden sectors / FAT32 type)")
    return data


SYSLINUX_MODULES = ("libcom32.c32", "libutil.c32", "menu.c32", "mboot.c32")
SYSLINUX_CFG = (
    "# ShizukuDOS 10 installed system: legacy BIOS boot menu (written by install/mkpayload.py).\r\n"
    "# GPT protective MBR (GPTMBR.BIN) -> this ESP's syslinux boot sector -> ldlinux.sys -> this file.\r\n"
    "SERIAL 0 115200\r\n"
    "UI menu.c32\r\n"
    "PROMPT 0\r\n"
    "TIMEOUT 50\r\n"
    "MENU TITLE ShizukuDOS 10 (installed)\r\n"
    "DEFAULT kernel64\r\n"
    "LABEL kernel64\r\n"
    "  MENU LABEL ^Kernel64 + Win64 runtime\r\n"
    "  KERNEL mboot.c32\r\n"
    "  APPEND /SHZDOS/K64STUB.ELF --- /SHZDOS/KERNEL64S.BIN --- /SHZDOS/WIN64.IMG\r\n"
    "LABEL dos16\r\n"
    "  MENU LABEL ^DOS16 - FreeDOS profile (disk image in RAM)\r\n"
    "  KERNEL memdisk\r\n"
    "  INITRD /SHZDOS/DISK.IMG\r\n"
    "  APPEND harddisk\r\n"
).encode("ascii")


def syslinux_members(desktop=False):
    """Files of the pinned syslinux that go into \\syslinux on the ESP (ldlinux.sys/.c32 come from the installer)."""
    up = shzlib.ensure_deb_upstream("syslinux")
    root = up["root"]
    members = [(f"syslinux/{name}", (root / "usr/lib/syslinux/modules/bios" / name).read_bytes())
               for name in SYSLINUX_MODULES]
    members.append(("syslinux/memdisk", (root / "usr/lib/syslinux/memdisk").read_bytes()))
    cfg = SYSLINUX_CFG
    if desktop:
        cfg = cfg.replace(b"APPEND /SHZDOS/K64STUB.ELF ---", b"APPEND /SHZDOS/K64STUB.ELF shz.desktop ---")
    members.append(("syslinux/syslinux.cfg", cfg))
    return members, root / "usr/bin/syslinux"


def install_syslinux(esp_data, installer):
    """Runs the pinned mtools-based syslinux installer on the ESP placed at LBA ESP_FIRST_LBA of a scratch disk, i.e.
    exactly where SHZSETUP writes it (the geometry tools/build_shizuku_se_disk.py boots), and returns the partition's
    bytes: FAT32 boot sector with the syslinux loader, \\syslinux\\ldlinux.sys and ldlinux.c32 added."""
    offset = ESP_FIRST_LBA * 512
    scratch = OUT / "syslinux-scratch.img"
    tmp = OUT / "syslinux-tmp"
    tmp.mkdir(exist_ok=True)
    with open(scratch, "wb") as fh:
        fh.truncate(offset + len(esp_data))
        fh.seek(offset)
        fh.write(esp_data)
    env = mtools_env()
    env["TMPDIR"] = str(tmp)
    run([str(installer), "--install", "--directory", "/syslinux", "--offset", str(offset), str(scratch)], env=env)
    with open(scratch, "rb") as fh:
        head = fh.read(offset)
        data = fh.read()
    scratch.unlink()
    shutil.rmtree(tmp, ignore_errors=True)
    if head != bytes(offset):
        raise SystemExit("the syslinux installer wrote outside the ESP")
    if data[3:11] != b"SYSLINUX" or struct.unpack_from("<I", data, 0x1C)[0] != ESP_FIRST_LBA or data[510:512] != b"\x55\xaa":
        raise SystemExit("esp.img: the syslinux boot sector was not installed as expected")
    return data


def read_esp_file(img, path):
    out = OUT / "esp-readback.bin"
    out.unlink(missing_ok=True)
    run(["mcopy", "-n", "-i", str(img), f"::/{path}", str(out)], env=mtools_env())
    data = out.read_bytes()
    out.unlink()
    return data


def sparse_image(data):
    """SHZSIMG1: header, chunk table {u64 first_block, u32 blocks, u32 0}, chunk data. Zero blocks are omitted."""
    assert len(data) % SIMG_BLOCK == 0
    zero = bytes(SIMG_BLOCK)
    chunks, cur = [], None
    for i in range(len(data) // SIMG_BLOCK):
        nonzero = data[i * SIMG_BLOCK:(i + 1) * SIMG_BLOCK] != zero
        if nonzero and cur and cur[0] + cur[1] == i:
            cur[1] += 1
        elif nonzero:
            cur = [i, 1]
            chunks.append(cur)
    out = bytearray(b"SHZSIMG1" + struct.pack("<IIII", SIMG_BLOCK, 0, len(chunks), 0) + struct.pack("<Q", len(data)))
    out += hashlib.sha256(data).digest()
    for first, count in chunks:
        out += struct.pack("<QII", first, count, 0)
    for first, count in chunks:
        out += data[first * SIMG_BLOCK:(first + count) * SIMG_BLOCK]
    return bytes(out), len(chunks)


def expand_sparse(blob):
    """Independent decoder used as a self-check of sparse_image()."""
    magic, bs, _, n, _, total = struct.unpack_from("<8sIIIIQ", blob, 0)
    assert magic == b"SHZSIMG1" and bs == SIMG_BLOCK
    out = bytearray(total)
    off = 64 + 16 * n
    for i in range(n):
        first, count, _ = struct.unpack_from("<QII", blob, 64 + 16 * i)
        out[first * bs:(first + count) * bs] = blob[off:off + count * bs]
        off += count * bs
    return bytes(out)


def driver_packages():
    pkgs = []
    for name, src, desc, ids in DRIVERS:
        path = SHZ / "kernel64" / src
        if not path.exists():
            continue
        text = (f"; ShizukuDOS driver package descriptor (generated by install/mkpayload.py)\r\n"
                f"[Driver]\r\nName={name}\r\nDescription={desc}\r\nKind=builtin\r\n"
                f"Note=compiled into KERNEL64S.BIN/KERNEL64.BIN; Kernel64 has no loadable driver model yet\r\n"
                f"Source=shizukudos/kernel64/{src}\r\nSourceSha256={sha256_file(path)}\r\n"
                f"Devices={', '.join(ids)}\r\n")
        pkgs.append((name, desc, text.encode("ascii")))
    return pkgs


def system_tree(runtime, pkgs):
    """(dirs, files) of the ShizukuFS volume: dirs = [(path, package)], files = [(path, package, bytes)]."""
    dirs = [("/SHZ", "base"), ("/SHZ/SYS64", "base"), ("/SHZ/DRIVERS", "base"), ("/SHZ/SETUP", "base"),
            ("/SHZ/SETUP/log", "base"), ("/Users", "base"), ("/Users/Public", "base")]
    files = [(p.replace("\\", "/"), "base", data) for p, data in runtime]
    existing_dirs = {p for p, _ in dirs}
    for path, _, _ in files:
        parts = path.split("/")
        for end in range(2, len(parts)):
            directory = "/".join(parts[:end])
            if directory not in existing_dirs:
                dirs.append((directory, "base"))
                existing_dirs.add(directory)
    readme = ("ShizukuDOS system volume (ShizukuFS v1, ext4 on-disk format), created by SHZSETUP.\r\n"
              "\\SHZ\\SYS64        Win64 runtime (ntdll, kernel32, system DLLs)\r\n"
              "\\SHZ\\DRIVERS      driver package descriptors\r\n"
              "\\SHZ\\SETUP        answer file, manifest, log\\install.log of the installation\r\n"
              "\\SHZ\\SYSTEM.INI   host name and the identifiers of this installation\r\n"
              "\\Users            user profiles\r\n"
              "The boot files are on the EFI System Partition (\\SHZDOS, \\EFI).\r\n")
    files.append(("/SHZ/README.TXT", "base", readme.encode("ascii")))
    for name, _, text in pkgs:
        dirs.append((f"/SHZ/DRIVERS/{name}", f"driver-{name}"))
        files.append((f"/SHZ/DRIVERS/{name}/DRIVER.INI", f"driver-{name}", text))
    return dirs, files


def main():
    global OUT, PAYLOAD                 # --out rebinds the module-level output paths used by the helpers
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build", action="store_true", help="run the input builds that have no output yet")
    ap.add_argument("--esp-mib", type=int, default=128)
    ap.add_argument("--answer", default=str(HERE / "shzsetup.ini"), help="answer file to pack (default: install/shzsetup.ini)")
    ap.add_argument("--no-bios-boot", action="store_true",
                    help="do not install syslinux into the ESP (the installed disk then boots on UEFI only)")
    ap.add_argument("--desktop", action="store_true",
                    help="install the built persistent desktop and start it on BIOS and UEFI boots")
    ap.add_argument("--out", type=Path, default=OUT,
                    help=f"output directory (default {OUT}); the install media use their own, with the shipped answer file")
    args = ap.parse_args()
    OUT, PAYLOAD = args.out.resolve(), args.out.resolve() / "payload"
    for tool in ("mkfs.fat", "mmd", "mcopy", "fsck.fat", "nasm"):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool}")
    ensure_inputs(args.build)
    OUT.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(PAYLOAD, ignore_errors=True)
    PAYLOAD.mkdir(parents=True)
    w64 = load_win64_build()

    runtime, t_hello, setup_exe = runtime_files(args.desktop)
    runtime_img = w64.pack_archive([*runtime, ("\\SHZ\\TESTS\\T_HELLO.EXE", t_hello)])

    # ---- ESP
    esp_members = [("EFI/BOOT/BOOTX64.EFI", INPUTS["loader"].read_bytes()),
                   ("EFI/SHIZUKU/BOOT.INI",
                    b"; ShizukuDOS boot manager policy (written by the installer payload, install/mkpayload.py)\r\n"
                    b"; kernel64: start Kernel64 directly (no Supervisor, no VMX needed); see supervisor/loader/bootini.h\r\n"
                    b"mode = kernel64\r\n")]
    csm_present = INPUTS["csmwrap"].exists()
    if csm_present:
        esp_members.append(("EFI/SHIZUKU/CSMWRAP.EFI", INPUTS["csmwrap"].read_bytes()))
    esp_members += [("SHZDOS/KERNEL64S.BIN", INPUTS["kernel64s"].read_bytes()),
                    ("SHZDOS/WIN64.IMG", runtime_img),
                    ("SHZDOS/DISK.IMG", INPUTS["dos16"].read_bytes()),
                    ("SHZDOS/KERNEL32.BIN", INPUTS["kernel32"].read_bytes()),
                    ("SHZDOS/KERNEL64.BIN", INPUTS["kernel64"].read_bytes()),
                    ("SHZDOS/K64STUB.ELF", INPUTS["stub"].read_bytes())]
    if args.desktop:
        esp_members.append(("SHZDOS/KERNEL64.INI", b"cmdline = shz.desktop\r\n"))
    bios_boot = not args.no_bios_boot
    if bios_boot:
        sysl_members, installer = syslinux_members(args.desktop)
        esp_members += sysl_members
    esp = build_esp(esp_members, args.esp_mib)
    if bios_boot:
        esp = install_syslinux(esp, installer)
        (OUT / "esp.img").write_bytes(esp)
        check = subprocess.run(["fsck.fat", "-n", str(OUT / "esp.img")], capture_output=True, text=True)
        if check.returncode != 0:
            raise SystemExit("fsck.fat rejects esp.img after the syslinux install:\n" + check.stdout + check.stderr)
        for name in ("ldlinux.sys", "ldlinux.c32"):         # written by the installer: listed with their final bytes
            esp_members.append((f"syslinux/{name}", read_esp_file(OUT / "esp.img", f"syslinux/{name}")))
    sim, nchunks = sparse_image(esp)
    assert expand_sparse(sim) == esp, "sparse image does not round-trip"
    (PAYLOAD / "ESP.SIM").write_bytes(sim)

    # ---- MBR boot code
    mbr = PAYLOAD / "GPTMBR.BIN"
    run(["nasm", "-f", "bin", "-w+all", "-o", str(mbr), str(HERE / "gptmbr.asm")])
    if mbr.stat().st_size != 440:
        raise SystemExit("GPTMBR.BIN must be 440 bytes")

    # ---- system tree
    pkgs = driver_packages()
    dirs, files = system_tree(runtime, pkgs)
    arc = w64.pack_archive([(p.replace("/", "\\"), data) for p, _, data in files])
    (PAYLOAD / "SYSTEM.ARC").write_bytes(arc)

    manifest = {
        "schema": SCHEMA,
        "product": PRODUCT,
        "source_date_epoch": FIXED_EPOCH,
        "boot_profile": "desktop" if args.desktop else "self-test",
        "sector_size": 512,
        "mbr": {"file": "GPTMBR.BIN", "bytes": 440, "sha256": sha256_file(mbr)},
        "esp": {"image": "ESP.SIM", "bytes": len(esp), "sha256": sha256(esp), "sparse_chunks": nchunks,
                "first_lba": ESP_FIRST_LBA, "fat": "FAT32", "label": ESP_LABEL, "volume_id": ESP_VOLID,
                "csmwrap": csm_present, "bios_boot": "syslinux 6.04 (pinned)" if bios_boot else None,
                "files": [{"path": "/" + p, "bytes": len(d), "sha256": sha256(d)} for p, d in esp_members]},
        "system": {"archive": "SYSTEM.ARC", "archive_sha256": sha256(arc), "label": SYS_LABEL,
                   "filesystem": "ShizukuFS v1 (ext4 on-disk format)",
                   "dirs": [{"path": p, "package": k} for p, k in dirs],
                   "files": [{"path": p, "package": k, "bytes": len(d), "sha256": sha256(d)} for p, k, d in files]},
        "packages": [{"name": "base", "required": True, "description": "Win64 runtime, directory layout"}] +
                    [{"name": f"driver-{n}", "required": False, "description": d} for n, d, _ in pkgs],
    }
    text = json.dumps(manifest, indent=1, sort_keys=False) + "\n"
    (PAYLOAD / "manifest.json").write_text(text)
    answer = Path(args.answer).read_bytes()
    (OUT / "shzsetup.ini").write_bytes(answer)

    # ---- installer boot archive
    install = [*runtime, ("\\SHZ\\TESTS\\T_HELLO.EXE", t_hello), ("\\SHZ\\SETUP\\SHZSETUP.EXE", setup_exe),
               ("\\SHZ\\SETUP\\SHZSETUP.INI", answer)]
    for name in ("manifest.json", "ESP.SIM", "SYSTEM.ARC", "GPTMBR.BIN"):
        install.append((f"\\SHZ\\SETUP\\PAYLOAD\\{name}", (PAYLOAD / name).read_bytes()))
    img = OUT / "INSTALL.IMG"
    img.write_bytes(w64.pack_archive(install))

    receipt = {
        "built_utc": shzlib.utc_now(), "git": shzlib.git_state(), "schema": SCHEMA,
        "inputs": {k: (sha256_file(v) if v.is_file() else str(v)) for k, v in INPUTS.items() if v.exists()},
        "outputs": {p.name: {"bytes": p.stat().st_size, "sha256": sha256_file(p)}
                    for p in [OUT / "esp.img", OUT / "INSTALL.IMG", OUT / "shzsetup.ini", *sorted(PAYLOAD.iterdir())]},
        "esp_files": len(esp_members), "system_files": len(files), "system_dirs": len(dirs),
        "driver_packages": [n for n, _, _ in pkgs], "csmwrap_included": csm_present, "bios_boot": bios_boot,
    }
    shzlib.write_json(OUT / "mkpayload-result.json", receipt)
    print(json.dumps({k: v["sha256"] for k, v in receipt["outputs"].items()}, indent=1))
    print(f"esp.img {len(esp) // MIB} MiB ({nchunks} data chunks, ESP.SIM {len(sim)} bytes); "
          f"{len(files)} system files; INSTALL.IMG {img.stat().st_size} bytes")


if __name__ == "__main__":
    main()
