#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host tests for VEH adapter, CFG/delay bind, and the Chromium-shaped fixture."""
from __future__ import annotations
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "build/evidence/chromium-156"
sys.path.insert(0, str(ROOT / "ntwin32/loader"))
import evidence


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return result


def compile_and_run(compiler: str, sources: list[Path], exe: Path, includes: list[Path]) -> dict:
    command = [compiler, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               *[str(path) for path in sources], *[f"-I{path}" for path in includes], "-o", str(exe)]
    run(command)
    result = run([str(exe)])
    return json.loads(result.stdout)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    veh = compile_and_run("gcc",
                          [ROOT / "ntwin32/exception/veh.c", ROOT / "ntwin32/exception/k32veh.c",
                           ROOT / "ntwin32/exception/test_k32veh.c"],
                          OUT / "test-k32veh", [ROOT / "ntwin32/exception"])
    guard = compile_and_run("gcc",
                            [ROOT / "ntwin32/loader/guard.c", ROOT / "ntwin32/loader/test_guard.c"],
                            OUT / "test-guard", [ROOT / "ntwin32/loader"])
    compile_and_run("clang",
                    [ROOT / "ntwin32/exception/veh.c", ROOT / "ntwin32/exception/k32veh.c",
                     ROOT / "ntwin32/exception/test_k32veh.c"],
                    OUT / "test-k32veh-clang", [ROOT / "ntwin32/exception"])
    objects = []
    for name, sources, include in (
        ("tls", [ROOT / "ntwin32/tls/tls.c"], ROOT / "ntwin32/tls"),
        ("guard", [ROOT / "ntwin32/loader/guard.c"], ROOT / "ntwin32/loader"),
        ("veh", [ROOT / "ntwin32/exception/veh.c", ROOT / "ntwin32/exception/k32veh.c"],
         ROOT / "ntwin32/exception"),
    ):
        obj = OUT / f"{name}-i686.o"
        command = ["i686-w64-mingw32-gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                   "-march=i486", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
                   f"-I{include}", "-c", *[str(path) for path in sources], "-o", str(obj)]
        if name == "veh":
            command = ["i686-w64-mingw32-gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                       "-march=i486", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
                       f"-I{include}", "-c", str(sources[0]), "-o", str(OUT / "veh-i686.o")]
            run(command)
            run(["i686-w64-mingw32-gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 "-march=i486", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
                 f"-I{include}", "-c", str(sources[1]), "-o", str(OUT / "k32veh-i686.o")])
            objects.extend(["veh-i686.o", "k32veh-i686.o"])
            continue
        run(command)
        undefined = subprocess.run(["i686-w64-mingw32-nm", "-u", str(obj)],
                                   check=True, capture_output=True, text=True).stdout.strip()
        if undefined:
            raise SystemExit(f"{name} has undefined symbols:\n{undefined}")
        objects.append(obj.name)
    run([sys.executable, str(ROOT / "ntwin32/loader/test_fixture.py")])
    wine = shutil.which("wine")
    evidence.panel(OUT / "04-veh-callback-order.png",
                   "AddVectoredExceptionHandler order (host, not a CPU trap)",
                   [json.dumps(veh),
                    "First != 0 inserts at the head; zero appends",
                    "NULL handler is rejected and leaves the list unchanged",
                    "return -1 stops the chain; any other return continues",
                    "unknown remove returns NOT_FOUND, not success"])
    evidence.panel(OUT / "05-cfg-delay-cookie.png",
                   "CFG fail-closed, cookie replace, delay-import rollback",
                   [json.dumps(guard),
                    "targets 0x1000 and 0x2000 allowed; 0x1001 and RVA 0 denied",
                    "default cookie 0xBB40E64E rejects zero and itself",
                    "missing delay name restores both IAT slots"])
    evidence.panel(OUT / "06-build-and-missing-wine.png",
                   "i686 objects built; wine is not available to launch a PE",
                   [f"freestanding objects: {', '.join(objects)}",
                    "i686-w64-mingw32-gcc is installed",
                    "wine: " + (wine or "NOT INSTALLED — no guest or Wine process was started"),
                    "NTW32.DLL rebuild is recorded separately by platform/build.py",
                    "this panel is host evidence, not a Windows 98 screen"])
    evidence.panel(OUT / "07-chrome-still-blocked.png",
                   "chrome.exe still does not start",
                   ["Official chrome.exe / chrome_elf.dll bytes are not in this tree",
                    "Stock Win98 loader still rejects subsystem 10.0; the version was not downgraded",
                    "Static TLS runtime is not invoked by the Win98 process loader",
                    "VEH add/remove is not connected to a hardware trap or SEH",
                    "Most KERNEL32, ntdll, ADVAPI32 and USER32 imports are still unrouted",
                    "browser_functionality_verified remains false"],
                   banner=(128, 0, 0))
    print(json.dumps({"veh": veh, "guard": guard, "objects": objects, "wine": wine}, indent=2))


if __name__ == "__main__":
    main()
