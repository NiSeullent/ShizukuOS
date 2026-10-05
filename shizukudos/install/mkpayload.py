#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the ShizukuOS installation payload (host side of SHZSETUP.EXE).

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
the kernel command line `shz.setup=interactive` (the public medium opens the self-developed installer).
The explicit unattended QA profile uses `shz.setup=auto` and mkpayload.py (default component route, no desktop).
The default is the component profile. --native-shell installs the pinned ShizukuOS executable shell,
Noto outline fonts, caption cache and licenses from stage_runtime.py output, using the existing kernel desktop entry path.
The explicit development-only --desktop option retains the older diagnostic desktop.

ESP layout: \\EFI\\BOOT\\BOOTX64.EFI (Shizuku UEFI loader), \\EFI\\SHIZUKU\\BOOT.INI (mode = kernel64),
\\EFI\\SHIZUKU\\CSMWRAP.EFI (when built), \\SHZDOS\\KERNEL64S.BIN, WIN64.IMG, DISK.IMG (DOS16), KERNEL32.BIN, KERNEL64.BIN,
K64STUB.ELF (Multiboot stub for a BIOS boot loader), SHZBOOT.MAN (installed-target boot manifest TEMPLATE, see
build_boot_manifest(); SHZSETUP stamps install_generation/install_id in place on the target). Nothing from Microsoft is
ever included.
Legacy BIOS boot of the installed disk (agent C3): the pinned syslinux 6.04 (upstream/manifest.json "syslinux") is
installed into esp.img on the host: its FAT32 boot sector (which GPTMBR.BIN chains to) loads \\syslinux\\ldlinux.sys,
and \\syslinux\\syslinux.cfg boots Kernel64 by default (mboot.c32 \\SHZDOS\\K64STUB.ELF --- KERNEL64S.BIN --- WIN64.IMG
--- SHZBOOT.MAN)
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
PRODUCT = "ShizukuOS 1.0.0 development candidate"
ESP_LABEL, ESP_VOLID = "SHZESP", "53485A45"
ESP_FIRST_LBA = 2048                # p1 starts at 1 MiB; esp.img's BPB hidden-sectors field says so
SYS_LABEL = "SHZSYS"
SIMG_BLOCK = 4096
MIB = 1024 * 1024

def input_layout(root):
    return {
        "loader": root / "supervisor" / "BOOTX64.EFI",
        "csmwrap": root / "csm" / "CSMWRAP.EFI",
        "kernel64s": root / "kernel64s" / "KERNEL64S.BIN",
        "stub": root / "kernel64s" / "boot.elf",
        "kernel64": root / "kernel64" / "KERNEL64.BIN",
        "kernel32": root / "kernel32" / "KERNEL32.BIN",
        "dos16": root / "dos16" / "shizukudos-dos10.img",
        "win64": root / "win64",
    }


INPUTS = input_layout(BUILD)
WIN64_FILES = ("WIN64.IMG", "build-result.json", "SHZSETUP.EXE", "t_hello.exe", "t_w64con.exe")
BUILDERS = [("kernel64s", ["kbuild.py"]), ("win64", ["win64/build.py"]), ("dos16", ["dos16/build.py"]),
            ("csmwrap", ["csm/build.py"]), ("loader", ["supervisor/build.py"])]

# Kernel64 built-in drivers, described as packages under \SHZ\DRIVERS\<name>\DRIVER.INI. A package exists only when its
# source file is in the tree, so drivers of other tracks appear once they are merged. Kernel64 has no loadable driver
# model yet: these are descriptors of drivers compiled into the kernel, for the future device manager and for the
# answer file's [Drivers] selection.
# Only drivers with a linked native provider that shz_catalog_builtin_driver() (kernel64/ntdrv_catalog.c) maps are
# advertised. Not listed on purpose: the blk_ram.c RAM test target (1af4:1110, no native builtin mapping) and the generic
# virtio-pci transport (1af4:1040-107f, a library, not a device provider). See docs/NATIVE_DRIVER_PACKAGE_SUPPORT.md.
DRIVERS = [
    ("rtl8139", "net_rtl8139.c", "Realtek RTL8139 Fast Ethernet", ["10ec:8139"]),
    ("bochs-vbe", "gfx_fb.c", "Bochs/QEMU VBE linear framebuffer (-vga std)", ["1234:1111"]),
    ("ahci", "ahci_blk.c", "AHCI SATA disks", ["class 01:06:01"]),
    ("nvme", "nvme.c", "NVM Express SSDs", ["class 01:08:02"]),
    ("sdhci", "sdhci.c", "SD Host Controller / eMMC", ["class 08:05"]),
    ("virtio-gpu", "gfx_virtio.c", "virtio-gpu 2D display backend (modern device 1af4:1050)", ["1af4:1050"]),
]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


# ---- installed-target boot manifest SHZBOOT.MAN (layout: supervisor/src/boot_manifest.h v1, contract routing02 C1)
BMAN_MAGIC = 0x314E414D54425A53          # "SZBTMAN1"
BMAN_VERSION = 1
BMAN_HEADER, BMAN_ENTRY = 96, 176
BMAN_MAX_ENTRIES, BMAN_MAX_BYTES = 16, 4096
# magic version header_size entry_size entry_count total_size loader_profile install_generation required_caps flags
# entries_sha256 install_id reserved[2]
BMAN_HEADER_FMT = "<QHHHHIIQII32s16s8s"
# component parent blob install_path kind domain_id depends flags required_caps reserved size sha256
BMAN_ENTRY_FMT = "<16s16s16s64sIIIIIIQ32s"
BMAN_STAMP = {"generation_offset": 24, "install_id_offset": 72}
BMAN_KIND_CORE, BMAN_KIND_CHILD, BMAN_KIND_RESOURCE = 0, 1, 2
BMAN_REQUIRED = 1
SHZ_CAP_LONG_MODE = 1 << 0
DOM_DOS16, DOM_KERNEL32, DOM_KERNEL64, DOM_WIN98 = 2, 3, 4, 5
LOADER_PROFILE_SUPERVISOR = 0            # shz_info_t.loader_flags of the installed Supervisor route (no WIN98CFG.BIN)
# ShizukuOS (CHILD dom 5) is listed non-required and blobless (contract C1 entry 4): core.c admit_manifest() accepts the
# other owner profile's child on loader_profile 0 only in that form and never treats it as live.
BMAN_INCLUDE_WIN98_CHILD = True
# (component, parent, blob, install_path, kind, domain_id, depends (component names), REQUIRED, required_caps)
# Dependencies follow core.c: every child needs the Core; Shizuku32 is the DOS owner's channel-1 peer; Shizuku64 is the
# channel-0 peer of Shizuku32 and consumes WIN64.IMG as its initial RAM image (verify_kernel_load). Resources never
# depend on their owning child. ShizukuDOS is REQUIRED (admit_manifest requires the profile-0 owner REQUIRED);
# Shizuku32/64 and WIN64.IMG are REQUIRED because the installer always places them and an installed 64-bit target that
# silently comes up DOS-only is not the installed product. KERNEL64S.BIN is not a Supervisor blob (optional there); the
# direct UEFI/Multiboot routes require it by rule (contract C3).
BMAN_LAYOUT = [
    ("ShizukuCore", "", None, "", BMAN_KIND_CORE, 0, (), True, 0),
    ("ShizukuDOS", "ShizukuCore", None, "", BMAN_KIND_CHILD, DOM_DOS16, ("ShizukuCore",), True, 0),
    ("Shizuku32", "ShizukuCore", "KERNEL32.BIN", "\\SHZDOS\\KERNEL32.BIN", BMAN_KIND_CHILD, DOM_KERNEL32,
     ("ShizukuCore", "ShizukuDOS"), True, 0),
    ("Shizuku64", "ShizukuCore", "KERNEL64.BIN", "\\SHZDOS\\KERNEL64.BIN", BMAN_KIND_CHILD, DOM_KERNEL64,
     ("ShizukuCore", "Shizuku32", "Win64Runtime"), True, SHZ_CAP_LONG_MODE),
    *([("ShizukuOS", "ShizukuCore", None, "", BMAN_KIND_CHILD, DOM_WIN98, ("ShizukuCore",), False, 0)]
      if BMAN_INCLUDE_WIN98_CHILD else []),
    ("Win64Runtime", "Shizuku64", "WIN64.IMG", "\\SHZDOS\\WIN64.IMG", BMAN_KIND_RESOURCE, 0, ("ShizukuCore",), True, 0),
    ("Kernel64S", "Shizuku64", "KERNEL64S.BIN", "\\SHZDOS\\KERNEL64S.BIN", BMAN_KIND_RESOURCE, 0, ("ShizukuCore",),
     False, 0),
]


def _field(text, size):
    raw = text.encode("ascii")
    if len(raw) >= size:
        raise ValueError(f"manifest field {text!r} does not fit {size} bytes with its NUL")
    return raw + bytes(size - len(raw))


def build_boot_manifest(blobs, loader_profile=LOADER_PROFILE_SUPERVISOR, header_caps=0):
    """Pure SHZBOOT.MAN template builder. blobs: {blob name: exact bytes placed on the ESP} for every blob the layout
    names. Returns (template bytes, entry list for manifest.json). install_generation and install_id are zero: SHZSETUP
    stamps header bytes [24,32) and [72,88) on the target. entries_sha256 covers the entry table only, so stamping never
    changes it and the manifest never hashes itself."""
    names = [row[0] for row in BMAN_LAYOUT]
    if len(names) > BMAN_MAX_ENTRIES or len(set(names)) != len(names):
        raise ValueError("boot manifest layout: too many or duplicate components")
    table, listed = b"", []
    for index, (comp, parent, blob, path, kind, dom, deps, required, caps) in enumerate(BMAN_LAYOUT):
        depends = 0
        for d in deps:
            depends |= 1 << names.index(d)
        if depends & (1 << index):
            raise ValueError(f"{comp} depends on itself")
        data = b""
        if blob is not None:
            if blob not in blobs:
                raise ValueError(f"boot manifest: blob {blob} for {comp} was not supplied")
            data = bytes(blobs[blob])
            if not data:
                raise ValueError(f"boot manifest: blob {blob} is empty")
        digest = hashlib.sha256(data).digest() if blob is not None else bytes(32)
        flags = BMAN_REQUIRED if required else 0
        table += struct.pack(BMAN_ENTRY_FMT, _field(comp, 16), _field(parent, 16), _field(blob or "", 16),
                             _field(path, 64), kind, dom, depends, flags, caps, 0, len(data), digest)
        listed.append({"index": index, "component": comp, "parent": parent, "blob": blob or "", "install_path": path,
                       "kind": ("core", "child", "resource")[kind], "domain_id": dom, "depends": depends,
                       "required": bool(required), "required_caps": caps, "bytes": len(data),
                       "sha256": digest.hex() if blob is not None else ""})
    count = len(BMAN_LAYOUT)
    total = BMAN_HEADER + count * BMAN_ENTRY
    assert len(table) == count * BMAN_ENTRY and total <= BMAN_MAX_BYTES
    entries_sha = hashlib.sha256(table).digest()
    header = struct.pack(BMAN_HEADER_FMT, BMAN_MAGIC, BMAN_VERSION, BMAN_HEADER, BMAN_ENTRY, count, total, loader_profile,
                         0, header_caps, 0, entries_sha, bytes(16), bytes(8))
    assert len(header) == BMAN_HEADER
    return header + table, listed


def stamp_boot_manifest(template, generation, install_id):
    """What SHZSETUP does on the target (reference for host fixtures): same size, only [24,32) and [72,88) change."""
    if not generation or len(install_id) != 16 or not any(install_id):
        raise ValueError("generation and install_id must be nonzero")
    out = bytearray(template)
    struct.pack_into("<Q", out, BMAN_STAMP["generation_offset"], generation)
    out[BMAN_STAMP["install_id_offset"]:BMAN_STAMP["install_id_offset"] + 16] = install_id
    return bytes(out)


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


def select_inputs_root(root, out, build):
    """Rebinds INPUTS to a build-layout tree other than build/shizukudos and fails early on an incoherent one. Inputs
    are only read: the output must be disjoint from every input so nothing is overwritten or rmtree'd."""
    global INPUTS
    root = root.resolve()
    if build:
        raise SystemExit("--build builds into the default build/shizukudos only; refusing it with --inputs-root")
    if not root.is_dir():
        raise SystemExit(f"--inputs-root is not a directory: {root}")
    layout = input_layout(root)
    for key, path in layout.items():
        if out == path or out in path.parents or path in out.parents:
            raise SystemExit(f"--out {out} overlaps input {key} ({path}); inputs and output must be separate")
    INPUTS = layout
    check_inputs()


def check_inputs():
    missing = [f"{k} ({v})" for k, v in INPUTS.items() if k not in ("csmwrap", "win64") and not v.is_file()]
    missing += [f"win64/{n}" for n in WIN64_FILES if not (INPUTS["win64"] / n).is_file()]
    if missing:
        raise SystemExit("missing inputs: " + ", ".join(missing))


def pinned_input_hashes():
    """SHA-256 of every input file actually read (a pin of these bytes, not proof of one build cohort or acceptance)."""
    h = {k: sha256_file(v) for k, v in INPUTS.items() if v.is_file()}
    receipt = json.loads((INPUTS["win64"] / "build-result.json").read_text())
    names = {*WIN64_FILES, "ntdll.dll", "kernel32.dll",
             *(f"{name}.dll" for name in receipt.get("modules", {}))}
    h.update({f"win64/{n}": sha256_file(INPUTS["win64"] / n) for n in sorted(names)})
    return h


def runtime_files(desktop=False, native_shell=False):
    # desktop=True is the explicit development-only SHZDESK diagnostic; the default is the truthful component route.
    """The Win64 runtime of this build: every system DLL plus both apps used by the kernel bridge self-test."""
    w = INPUTS["win64"]
    receipt = json.loads((w / "build-result.json").read_text())
    dlls = ["ntdll", "kernel32", *sorted(receipt.get("modules", {}))]
    if desktop or native_shell:
        from desktop_profile import desktop_runtime, SOUND_PATHS, THEME_LICENSE_PATHS
        themes = receipt.get("theme_sha256", {}) if native_shell else {}
        if not isinstance(themes, dict):
            raise ValueError("invalid native shell theme receipt")
        sounds = receipt.get("sound_sha256", {}) if native_shell else {}
        if not isinstance(sounds, dict) or (sounds and set(sounds) != SOUND_PATHS):
            raise ValueError("invalid or incomplete native sound asset receipt")
        theme_licenses = receipt.get("theme_license_sha256", {}) if native_shell else {}
        data_license = receipt.get("theme_data_license") if native_shell else None
        source = receipt.get("shell_source_sha256", {}) if native_shell else {}
        new_notice_source = "integration/shizuku-shell/themes/THEME-NOTICE.TXT"
        if not isinstance(theme_licenses, dict) or data_license not in (None, "GPL-3.0") or \
                (bool(theme_licenses) != (data_license == "GPL-3.0")) or \
                (theme_licenses and set(theme_licenses) != THEME_LICENSE_PATHS) or \
                (isinstance(source, dict) and new_notice_source in source and not theme_licenses):
            raise ValueError("invalid or missing native GPL3 theme notice/license receipt")
        files = desktop_runtime((w / "WIN64.IMG").read_bytes(), receipt["archive"]["sha256"], themes, sounds, theme_licenses)
        if native_shell:
            if receipt.get("status") != "STAGED_PENDING_GUI_VALIDATION" or receipt.get("kernel_entry_alias") != \
                    "SHZDESK.EXE contains the exact new shizuku-shell.exe bytes":
                raise ValueError("--native-shell requires the staged native shell runtime receipt")
            expected = receipt.get("member_sha256", {})
            required = {"\\SHZ\\SYS64\\SHZDESK.EXE", "\\SHZ\\FONTS\\SHZKR-OFL.TXT",
                        "\\SHZ\\SYS64\\SHELL-LICENSE.TXT", "\\SHZ\\SYS64\\SHELL-GPL2.TXT"}
            required.update(themes)
            fonts = receipt.get("font_sha256", {})
            allowed_fonts = {"\\SHZ\\FONTS\\" + name for name in
                             ("NOTOSANS.TTF", "NOTOSANSKR.OTF", "OFL-LATIN.TXT", "OFL-KR.TXT", "NOTOCAP.BIN", "NOTICE.TXT")}
            if not isinstance(fonts, dict) or not set(fonts) <= allowed_fonts:
                raise ValueError("invalid native font asset receipt")
            if fonts and not allowed_fonts - {"\\SHZ\\FONTS\\NOTOCAP.BIN", "\\SHZ\\FONTS\\NOTICE.TXT"} <= set(fonts):
                raise ValueError("incomplete native outline font assets")
            if "\\SHZ\\FONTS\\NOTOCAP.BIN" in fonts and "\\SHZ\\FONTS\\NOTICE.TXT" not in fonts:
                raise ValueError("caption cache copyright notice is missing")
            required.update(fonts)
            required.update(sounds)
            required.update(theme_licenses)
            actual = {p.upper(): sha256(data) for p, data in files}
            if not required <= actual.keys() or any(actual[p] != expected.get(p) for p in required):
                raise ValueError("native shell executable or bundled licenses differ from stage receipt")
            if any(actual[p] != digest for p, digest in fonts.items()):
                raise ValueError("native outline fonts differ from stage receipt")
            if any(actual[p] != digest for p, digest in themes.items()):
                raise ValueError("native shell themes differ from stage receipt")
            if any(actual[p] != digest for p, digest in sounds.items()):
                raise ValueError("native sound scheme or assets differ from stage receipt")
            if any(actual[p] != digest for p, digest in theme_licenses.items()):
                raise ValueError("native theme notice or GPL3 license differs from stage receipt")
    else:
        files = [(f"\\SHZ\\SYS64\\{n}.dll", (w / f"{n}.dll").read_bytes()) for n in dlls]
        files.append(("\\SHZ\\TESTS\\T_W64CON.EXE", (w / "t_w64con.exe").read_bytes()))
    t_hello = (w / "t_hello.exe").read_bytes()
    names = [p.upper() for p, _ in files]
    if len(names) != len(set(names)) or any(p.upper() == "\\SHZ\\TESTS\\T_HELLO.EXE" and d != t_hello for p, d in files):
        raise ValueError("ambiguous runtime paths or T_HELLO differs from the built executable")
    return files, t_hello, (w / "SHZSETUP.EXE").read_bytes()


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
    "MENU TITLE ShizukuOS development (installed)\r\n"
    "DEFAULT kernel64\r\n"
    "LABEL kernel64\r\n"
    "  MENU LABEL ^ShizukuDOS Kernel64 component diagnostics\r\n"
    "  KERNEL mboot.c32\r\n"
    "  APPEND /SHZDOS/K64STUB.ELF --- /SHZDOS/KERNEL64S.BIN --- /SHZDOS/WIN64.IMG --- /SHZDOS/SHZBOOT.MAN\r\n"
    "LABEL dos16\r\n"
    "  MENU LABEL ^DOS10 compatibility shell (disk image in RAM)\r\n"
    "  KERNEL memdisk\r\n"
    "  INITRD /SHZDOS/DISK.IMG\r\n"
    "  APPEND harddisk\r\n"
).encode("ascii")


def syslinux_members(desktop=False, native_shell=False):
    """Files of the pinned syslinux that go into \\syslinux on the ESP (ldlinux.sys/.c32 come from the installer)."""
    up = shzlib.ensure_deb_upstream("syslinux")
    root = up["root"]
    members = [(f"syslinux/{name}", (root / "usr/lib/syslinux/modules/bios" / name).read_bytes())
               for name in SYSLINUX_MODULES]
    members.append(("syslinux/memdisk", (root / "usr/lib/syslinux/memdisk").read_bytes()))
    cfg = SYSLINUX_CFG
    if desktop or native_shell:
        cfg = cfg.replace(b"MENU LABEL ^ShizukuDOS Kernel64 component diagnostics",
                          b"MENU LABEL ^Start ShizukuOS native shell" if native_shell else
                          b"MENU LABEL ^Start ShizukuOS development desktop")
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


DRIVER_CATALOG_MAX = 32
DRIVER_MATCH_MAX = 8


def driver_metadata(pkgs, kernel64s_sha256):
    """manifest.json "drivers" (contract C5): one row per present package. Every current package is a driver compiled
    into Kernel64 (kind builtin, image = KERNEL64S.BIN); there is no NT .sys service package yet, so none is listed."""
    ids = {name: m for name, _, _, m in DRIVERS}
    rows = []
    for name, _, _ in pkgs:
        match = ids[name]
        if not match or len(match) > DRIVER_MATCH_MAX:
            raise ValueError(f"driver {name}: 1..{DRIVER_MATCH_MAX} match ids required")
        rows.append({"name": name, "package": f"driver-{name}", "kind": "builtin", "match": match, "service": None,
                     "image": "/SHZDOS/KERNEL64S.BIN", "image_sha256": kernel64s_sha256, "start": "boot"})
    if len(rows) > DRIVER_CATALOG_MAX:
        raise ValueError("more driver packages than the installed catalog allows")
    return rows


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
    ap.add_argument("--desktop", action=argparse.BooleanOptionalAction, default=False,
                    help="DEVELOPMENT-ONLY diagnostic: install the unrelated SHZDESK framebuffer desktop and start it on BIOS and "
                         "UEFI boots. It is not the Windows98 shell and is never the default; the default is the component route "
                         "(Kernel64 component diagnostics) until a retained Windows98 shell route is qualified")
    ap.add_argument("--native-shell", action="store_true",
                    help="install the pinned ReactOS-derived ShizukuOS native shell runtime, including Korean bitmap "
                         "font and licenses, and start it on BIOS/UEFI; requires stage_runtime.py output as win64 inputs")
    ap.add_argument("--inputs-root", type=Path, default=None,
                    help=f"read the build-layout inputs (supervisor/, kernel64s/, kernel64/, kernel32/, dos16/, win64/, optional "
                         f"csm/) from this tree instead of {BUILD}; read only, incompatible with --build")
    ap.add_argument("--out", type=Path, default=OUT,
                    help=f"output directory (default {OUT}); the install media use their own, with the shipped answer file")
    args = ap.parse_args()
    if args.native_shell and (args.desktop or args.build):
        raise SystemExit("--native-shell is incompatible with --desktop and --build; supply frozen native runtime inputs")
    OUT, PAYLOAD = args.out.resolve(), args.out.resolve() / "payload"
    for tool in ("mkfs.fat", "mmd", "mcopy", "fsck.fat", "nasm"):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool}")
    if args.inputs_root is not None and args.inputs_root.resolve() != BUILD.resolve():
        select_inputs_root(args.inputs_root, OUT, args.build)
    else:
        ensure_inputs(args.build)
        select_inputs_root(BUILD, OUT, False)
    pinned = pinned_input_hashes()
    OUT.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(PAYLOAD, ignore_errors=True)
    PAYLOAD.mkdir(parents=True)
    w64 = load_win64_build()

    runtime, t_hello, setup_exe = runtime_files(args.desktop, args.native_shell)
    boot_runtime = runtime if any(p.upper() == "\\SHZ\\TESTS\\T_HELLO.EXE" for p, _ in runtime) else [*runtime, ("\\SHZ\\TESTS\\T_HELLO.EXE", t_hello)]
    runtime_img = w64.pack_archive(boot_runtime)

    # ---- ESP
    esp_members = [("EFI/BOOT/BOOTX64.EFI", INPUTS["loader"].read_bytes()),
                   ("EFI/SHIZUKU/BOOT.INI",
                    b"; ShizukuOS boot manager policy (written by the installer payload, install/mkpayload.py)\r\n"
                    b"; kernel64: start Kernel64 directly (no Supervisor, no VMX needed); see supervisor/loader/bootini.h\r\n"
                    b"mode = kernel64\r\nmenu_timeout = 0\r\n")]
    csm_present = INPUTS["csmwrap"].exists()
    if csm_present:
        esp_members.append(("EFI/SHIZUKU/CSMWRAP.EFI", INPUTS["csmwrap"].read_bytes()))
    esp_members += [("SHZDOS/KERNEL64S.BIN", INPUTS["kernel64s"].read_bytes()),
                    ("SHZDOS/WIN64.IMG", runtime_img),
                    ("SHZDOS/DISK.IMG", INPUTS["dos16"].read_bytes()),
                    ("SHZDOS/KERNEL32.BIN", INPUTS["kernel32"].read_bytes()),
                    ("SHZDOS/KERNEL64.BIN", INPUTS["kernel64"].read_bytes()),
                    ("SHZDOS/K64STUB.ELF", INPUTS["stub"].read_bytes())]
    if args.desktop or args.native_shell:
        esp_members.append(("SHZDOS/KERNEL64.INI", b"cmdline = shz.desktop\r\n"))
    placed = {p.split("/")[-1]: d for p, d in esp_members if p.startswith("SHZDOS/")}
    boot_man, boot_man_entries = build_boot_manifest(placed)
    esp_members.append(("SHZDOS/SHZBOOT.MAN", boot_man))
    bios_boot = not args.no_bios_boot
    if bios_boot:
        sysl_members, installer = syslinux_members(args.desktop, args.native_shell)
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
    man_off = esp.find(boot_man)
    if man_off < 0 or esp.find(boot_man, man_off + 1) >= 0 or man_off % 512:
        raise SystemExit("esp.img: SHZBOOT.MAN is not one contiguous sector-aligned extent (stamp masking needs it)")
    if read_esp_file(OUT / "esp.img", "SHZDOS/SHZBOOT.MAN") != boot_man:
        raise SystemExit("esp.img: SHZBOOT.MAN read back differently")
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
        "release_target": "1.0.0", "release_channel": "development",
        "architecture": "ShizukuCore with subordinate DOS(SZRm), Shizuku32(SZPrtm), Shizuku64(SZLm) and Windows-compatible userland",
        "source_date_epoch": FIXED_EPOCH,
        "boot_profile": "native-shell" if args.native_shell else "desktop" if args.desktop else "self-test",
        "desktop_shell": ("ReactOS-derived ShizukuOS native Win32 shell; Korean bitmap labels; Windows10 full compatibility unverified" if args.native_shell else
                          "SHZDESK development diagnostic; NOT the Windows98 shell" if args.desktop
                          else "none: component route; retained Windows98 shell not yet qualified"),
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
        "boot_manifest": {"path": "/SHZDOS/SHZBOOT.MAN", "format": "SZBTMAN1 v1 (supervisor/src/boot_manifest.h)",
                          "template_sha256": sha256(boot_man), "bytes": len(boot_man),
                          "entries_sha256": hashlib.sha256(boot_man[BMAN_HEADER:]).hexdigest(),
                          "loader_profile": LOADER_PROFILE_SUPERVISOR, "stamp": dict(BMAN_STAMP),
                          "image_offset": man_off, "entries": boot_man_entries},
        "drivers": driver_metadata(pkgs, sha256(placed["KERNEL64S.BIN"])),
    }
    text = json.dumps(manifest, indent=1, sort_keys=False) + "\n"
    (PAYLOAD / "manifest.json").write_text(text)
    answer = Path(args.answer).read_bytes()
    (OUT / "shzsetup.ini").write_bytes(answer)

    # ---- installer boot archive
    install = [*boot_runtime, ("\\SHZ\\SETUP\\SHZSETUP.EXE", setup_exe),
               ("\\SHZ\\SETUP\\SHZSETUP.INI", answer)]
    for name in ("manifest.json", "ESP.SIM", "SYSTEM.ARC", "GPTMBR.BIN"):
        install.append((f"\\SHZ\\SETUP\\PAYLOAD\\{name}", (PAYLOAD / name).read_bytes()))
    img = OUT / "INSTALL.IMG"
    img.write_bytes(w64.pack_archive(install))

    if pinned != pinned_input_hashes():
        raise SystemExit("installation inputs changed during image generation; outputs remain unqualified")
    receipt = {
        "built_utc": shzlib.utc_now(), "git": shzlib.git_state(), "schema": SCHEMA,
        "inputs": {k: (sha256_file(v) if v.is_file() else str(v)) for k, v in INPUTS.items() if v.exists()},
        "inputs_root": str(next(iter(INPUTS.values())).parents[1]), "inputs_pinned_sha256": pinned,
        "inputs_unchanged_during_run": pinned == pinned_input_hashes(),
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
