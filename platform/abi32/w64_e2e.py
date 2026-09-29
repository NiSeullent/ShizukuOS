#!/usr/bin/env python3
"""WIN64 subsystem end-to-end test: actual NTW32.DLL + NTW64RUN.EXE PE32 code and NTWRAP9X.VXD's bridge logic
against a Python model of Kernel64 that uses shizukudos/abi/test_abi.py's independent wire decoder.

Chain under test (see w64_harness.c for what is real and what is modeled):
  NTW64RUN.EXE (PE32) -> NTW32.DLL (PE32, ntw64.c) -> DeviceIoControl mock -> bridge.c (the VxD's logic)
  -> shz_ipc.h rings in a real channel region -> doorbell -> k64model.py (test_abi.py decode/encode)

No Windows loader, VMM, Supervisor or Kernel64 runs here. All output stays in platform/abi32/build/w64/.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import threading

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import build  # noqa: E402  (inspect/relocate of the DLL, parser loader)
import k64model  # noqa: E402

OUT = HERE / "build" / "w64"
EXE_BASE = 0x00400000
EXE_IMPORTS = {"GetCommandLineA", "GetStdHandle", "WriteFile", "ReadFile", "ExitProcess", "MultiByteToWideChar",
               "GetLastError", "SetLastError"}
MSG_FRAME, MSG_TICK, MSG_DONE, MSG_NOTE = 1, 2, 3, 4
SOURCES = ["platform/abi32/w64_e2e.py", "platform/abi32/w64_harness.c", "platform/abi32/w64_gate.S",
           "platform/abi32/k64model.py", "shizukudos/abi/test_abi.py", "shizukudos/abi/shz_ipc.h",
           "shizukudos/abi/shz_abi.h", "ntwrapper/vxd/bridge.c", "ntwrapper/vxd/bridge.h", "ntwrapper/core.c",
           "ntwrapper/include/ntwrapper.h", "ntwin32/win64/ntw64.h"]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def map_exe(data: bytes):
    """Maps NTW64RUN.EXE at its preferred base and returns (image, entry rva, [(dll, name, iat rva)])."""
    pe = build.parser_module().PE(data)
    size, preferred, entry = pe.u32(pe.opt + 56), pe.u32(pe.opt + 28), pe.u32(pe.opt + 16)
    if preferred != EXE_BASE or not 0 < size <= 1024 * 1024 or pe.u16(pe.pe + 22) & 0x2000:
        raise ValueError("NTW64RUN.EXE must be a small EXE based at 0x00400000")
    if pe.u16(pe.opt + 68) != 3 or (pe.u16(pe.opt + 48), pe.u16(pe.opt + 50)) != (4, 10):
        raise ValueError("NTW64RUN.EXE must be a Windows 4.10 console program")
    for index in (9, 10, 13, 14):
        if any(pe.directory(index)):
            raise ValueError("TLS, load-config, delay imports or CLR in NTW64RUN.EXE")
    image = bytearray(size)
    image[:pe.headers] = data[:pe.headers]
    for va, span, raw, raw_size in pe.sections:
        if va + span > size:
            raise ValueError("Section exceeds mapped image")
        image[va:va + raw_size] = data[raw:raw + raw_size]
    imports = []
    for descriptor in pe.imports():
        dll = descriptor["dll"].upper()
        for _, name, iat in descriptor["entries"]:
            imports.append((dll, name, iat))
    ntw = {name for dll, name, _ in imports if dll == "NTW32.DLL"}
    k32 = {name for dll, name, _ in imports if dll == "KERNEL32.DLL"}
    if {dll for dll, _, _ in imports} != {"NTW32.DLL", "KERNEL32.DLL"} or ntw != build.W64_EXPORTS or k32 != EXE_IMPORTS:
        raise ValueError(f"NTW64RUN.EXE import inventory differs: {sorted(imports)}")
    return image, entry, imports


def build_binary(dll: Path, exe: Path) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    pe, image, preferred, entry, imports, exports = build.inspect(dll.read_bytes())
    mapped, _ = build.relocate(pe, image, preferred, preferred)
    exe_image, exe_entry, exe_imports = map_exe(exe.read_bytes())
    (OUT / "pe-image.bin").write_bytes(mapped)
    (OUT / "exe-image.bin").write_bytes(exe_image)
    (OUT / "pe_config.h").write_text(
        "/* Generated from the actual NTW32.DLL. */\n"
        f"#define PE_BASE UINT32_C(0x{preferred:08x})\n#define PE_ENTRY UINT32_C(0x{entry:08x})\n"
        f"#define PE_IMAGE_SIZE 0x{len(mapped):x}u\n" +
        "".join(f"#define RVA_{name} UINT32_C(0x{rva:08x})\n" for name, rva in sorted(exports.items())))
    (OUT / "pe_imports.inc").write_text("".join(
        f"*(volatile uint32_t *)(uintptr_t)(PE_BASE + UINT32_C(0x{iat:08x})) = (uint32_t)(uintptr_t)&mock_{name};\n"
        for name, iat in imports))
    (OUT / "exe_config.h").write_text(
        "/* Generated from the actual NTW64RUN.EXE. */\n"
        f"#define EXE_BASE UINT32_C(0x{EXE_BASE:08x})\n#define EXE_ENTRY UINT32_C(0x{exe_entry:08x})\n"
        f"#define EXE_IMAGE_SIZE 0x{len(exe_image):x}u\n")
    (OUT / "exe_imports.inc").write_text("".join(
        f"*(volatile uint32_t *)(uintptr_t)(EXE_BASE + UINT32_C(0x{iat:08x})) = " +
        (f"PE_BASE + RVA_{name};\n" if dll == "NTW32.DLL" else f"(uint32_t)(uintptr_t)&mock_{name};\n")
        for dll, name, iat in exe_imports))
    (OUT / "images.S").write_text(
        '.section .exeimage,"awx",@progbits\n.balign 4096\n'
        f'.incbin "{OUT / "exe-image.bin"}"\n'
        '.section .peimage,"awx",@progbits\n.balign 4096\n'
        f'.incbin "{OUT / "pe-image.bin"}"\n'
        '.section .note.GNU-stack,"",@progbits\n')
    (OUT / "link.ld").write_text(f"""ENTRY(_start)
PHDRS {{ exe PT_LOAD FLAGS(7); text PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); pe PT_LOAD FLAGS(7); }}
SECTIONS {{
 . = 0x{EXE_BASE:08x};
 .exeimage : {{ KEEP(*(.exeimage)) }} :exe
 . = 0x08048000;
 __harness_start = .;
 .text : {{ *(.text.start) *(.text*) *(.rodata*) }} :text
 . = ALIGN(4096);
 .data : {{ *(.data*) }} :data
 .bss : {{ *(.bss*) *(COMMON) }} :data
 __harness_end = .;
 . = 0x{preferred:08x};
 .peimage : {{ KEEP(*(.peimage)) }} :pe
 /DISCARD/ : {{ *(.comment) *(.note*) *(.eh_frame*) }}
}}
""")
    harness_flags = ["clang", "--target=i486-none-elf", "-std=c11", "-O2", "-g", "-ffreestanding", "-fno-builtin",
                     "-fno-stack-protector", "-fno-pic", "-mno-sse", "-mno-mmx", "-Wall", "-Wextra", "-Werror",
                     "-Wpedantic", "-Wshadow", "-Wstrict-prototypes", "-Wno-gnu-binary-literal"]
    # The VxD's own flags (ntwrapper/vxd/build.py): the same C, compiled for the same i386 bare-metal target.
    vxd_flags = ["clang", "--target=i386-unknown-none-elf", "-march=i486", "-std=c11", "-Oz", "-ffreestanding",
                 "-fno-builtin", "-fno-pic", "-fno-pie", "-fno-stack-protector", "-fno-unwind-tables",
                 "-fno-asynchronous-unwind-tables", "-mno-sse", "-mno-mmx", "-msoft-float", "-Wall", "-Wextra",
                 "-Werror", "-Wpedantic", "-Wconversion", "-Wshadow"]
    build.run([*harness_flags, "-I", OUT, "-c", HERE / "w64_harness.c", "-o", OUT / "w64_harness.o"])
    build.run([*vxd_flags, "-c", ROOT / "ntwrapper/vxd/bridge.c", "-o", OUT / "bridge.o"])
    build.run([*vxd_flags, "-c", ROOT / "ntwrapper/core.c", "-o", OUT / "core.o"])
    build.run(["clang", "--target=i486-none-elf", "-c", HERE / "w64_gate.S", "-o", OUT / "w64_gate.o"])
    build.run(["clang", "--target=i486-none-elf", "-c", OUT / "images.S", "-o", OUT / "images.o"])
    binary = OUT / "w64-e2e"
    build.run(["ld.lld", "-m", "elf_i386", "-static", "-T", OUT / "link.ld", "-o", binary, OUT / "w64_gate.o",
               OUT / "w64_harness.o", OUT / "bridge.o", OUT / "core.o", OUT / "images.o"])
    undefined = build.run(["nm", "-u", binary], capture_output=True, text=True).stdout
    if undefined.strip():
        raise RuntimeError(f"Unexpected unresolved host dependency: {undefined}")
    return binary


def read_exact(stream, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = stream.read(n - len(data))
        if not chunk:
            return data
        data += chunk
    return data


def run_binary(binary: Path, timeout: int = 300):
    model = k64model.Kernel64Model()
    counts = {"frames": 0, "ticks": 0, "notes": 0, "done": 0}
    with tempfile.TemporaryFile() as err:
        proc = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err)
        watchdog = threading.Timer(timeout, proc.kill)
        watchdog.start()
        try:
            while True:
                header = read_exact(proc.stdout, 8)
                if len(header) < 8:
                    break
                kind, length = struct.unpack("<II", header)
                data = read_exact(proc.stdout, length)
                if len(data) != length:
                    break
                if kind == MSG_FRAME:
                    slots = model.on_frame(data[:256], data[256:])
                    counts["frames"] += 1
                elif kind == MSG_TICK:
                    slots = model.on_tick(struct.unpack("<I", data)[0])
                    counts["ticks"] += 1
                elif kind == MSG_NOTE:
                    slots = model.on_note(data.decode("ascii"))
                    counts["notes"] += 1
                elif kind == MSG_DONE:
                    slots = []
                    counts["done"] += 1
                else:
                    raise RuntimeError(f"unknown harness message {kind}")
                proc.stdin.write(struct.pack("<I", len(slots)) + b"".join(slots))
                proc.stdin.flush()
            proc.stdin.close()
            code = proc.wait(timeout=30)
        finally:
            watchdog.cancel()
            if proc.poll() is None:
                proc.kill()
        err.seek(0)
        stderr = err.read().decode("utf-8", "replace")
    return code, stderr, model.report(), counts


def check(code, stderr, report, counts):
    stats = report["stats"]
    problems = []
    if code != 0 or not stderr.startswith("PASS NTW32 WIN64 end-to-end:"):
        problems.append(f"harness exit {code}: {stderr.strip()[-2000:]}")
    if report["violations"]:
        problems.append(f"model violations: {report['violations'][:20]}")
    expectations = {
        "every VxD frame decoded identically by C and Python": stats["c_python_agree"] == stats["frames"] > 0,
        "two pool-carried CREATEs, the largest 4,016 bytes": stats["pool_creates"] == 2 and stats["max_pool_bytes"] == 4016,
        "output window of 8 reached, never exceeded": stats["max_unacked"] == 8 and stats["window_full_events"] > 0,
        "acknowledgements and stdin frames seen": stats["acks"] > 0 and stats["input_frames"] == 8 and stats["eof"] == 6,
        "two failed creations (missing image), one NOMEM": stats["failed"] == 2 and stats["nomem"] == 1,
        "six kills, every process released": stats["killed"] == 6 and not report["slots_still_used"] and
                                             stats["released"] == stats["started"],
        "one corrupted slot sent, one request muted": stats["corrupted_sent"] == 1 and stats["muted"] == 1,
        "working directories carried": stats["cwd_seen"] == ["\\SHZ\\TESTS", "\\SHZ"],
        "no stale or unsupported frames": stats["stale"] == 0 and stats["unsupported"] == 0,
        "the harness finished the conversation": counts["done"] == 1,
    }
    problems += [name for name, ok in expectations.items() if not ok]
    return problems, expectations


def run_e2e(dll: Path, exe: Path) -> dict:
    before = {name: sha(ROOT / name) for name in SOURCES}
    binary = build_binary(dll, exe)
    code, stderr, report, counts = run_binary(binary)
    problems, expectations = check(code, stderr, report, counts)
    if {name: sha(ROOT / name) for name in SOURCES} != before:
        problems.append("sources changed during the run")
    result = {"schema": "ntwin32.abi32.w64.v1", "status": "PASS" if not problems else "FAIL",
              "problems": problems, "harness_stdout": stderr.strip(),
              "dll_sha256": sha(dll), "exe_sha256": sha(exe), "binary_sha256": sha(binary),
              "sources_sha256": before, "messages": counts, "model": report,
              "expectations": {name: bool(ok) for name, ok in expectations.items()},
              "executed_for_real": ["NTW32.DLL PE32 code (ntw64.c)", "NTW64RUN.EXE PE32 code",
                                    "ntwrapper/vxd/bridge.c + core.c compiled for i386 bare metal",
                                    "shz_ipc.h rings and pool in a shz_channel_init() region"],
              "modeled": ["KERNEL32 imports", "VWIN32 DeviceIoControl dispatch and dynamic VxD load/unload",
                          "VMM page services (identity model)", "Supervisor hypercalls and physical mapping",
                          "Kernel64 subsystem service and the Win64 programs (k64model.py)"],
              "windows_guest_verified": False, "supervisor_verified": False}
    (OUT / "w64-results.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--dll", type=Path, default=ROOT / "build/platform/NTW32.DLL")
    args.add_argument("--exe", type=Path, default=ROOT / "build/platform/NTW64RUN.EXE")
    options = args.parse_args()
    result = run_e2e(options.dll.resolve(), options.exe.resolve())
    print(result["harness_stdout"])
    print(json.dumps({k: result[k] for k in ("status", "problems", "messages", "expectations")}, indent=2))
    print(json.dumps(result["model"]["stats"], indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"WIN64 end-to-end failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stdout or "", file=sys.stderr)
            print(error.stderr or "", file=sys.stderr)
        sys.exit(1)
