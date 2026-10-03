#!/usr/bin/env python3
"""Cheap actual checks for the Legcord completion port provider.

SPDX-License-Identifier: GPL-2.0-only
Runs the host core regression (ASan/UBSan, real threads) and cross-links the
PE32 provider DLL, then verifies its KERNEL32 imports are the Win95/98 set and
its exports are exactly the five provider entry points. It never executes the
PE and is not Win98 guest evidence. Run under the repository compile lock.
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

SRC = pathlib.Path(__file__).resolve().parent
ALLOWED = {"CloseHandle", "CreateSemaphoreA", "DeleteCriticalSection", "EnterCriticalSection",
           "GetLastError", "InitializeCriticalSection", "LeaveCriticalSection",
           "ReleaseSemaphore", "SetLastError", "WaitForSingleObject"}
# Every import must also exist in the recorded Win98 SE export inventory.
INVENTORY = SRC.parents[1] / "benchmarks" / "win98se-ko-oem-native-exports-v1.json"
ALLOWED_WS2 = {"WSARecv", "WSASend", "WSARecvFrom", "WSASendTo", "WSAGetOverlappedResult",
               "WSAEventSelect", "WSAEnumNetworkEvents", "WSAGetLastError", "WSASetLastError",
               "getsockopt", "connect", "closesocket"}
ALLOWED |= {"CreateEventA", "ResetEvent", "SetEvent", "WaitForMultipleObjects", "CreateThread",
            "LoadLibraryA", "FreeLibrary", "FreeLibraryAndExitThread", "GetModuleFileNameA",
            "GetFileInformationByHandle", "SetFilePointer", "SetEndOfFile", "SetFileTime", "GetCurrentProcess",
            "GetCurrentProcessId", "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
            "GetVersionExA"}
EXPORTS = {"ShizukuLc_WSARecv", "ShizukuLc_WSASend", "ShizukuLc_WSARecvFrom", "ShizukuLc_WSASendTo",
           "ShizukuLc_ConnectEx", "ShizukuLc_closesocket","ShizukuLc_CreateIoCompletionPort", "ShizukuLc_PostQueuedCompletionStatus",
           "ShizukuLc_GetQueuedCompletionStatus", "ShizukuLc_GetQueuedCompletionStatusEx",
           "ShizukuLc_CloseIoCompletionPort",
           "ShizukuLc_RtlNtStatusToDosError", "ShizukuLc_NtQueryInformationFile", "ShizukuLc_NtSetInformationFile",
           "ShizukuLc_NtQueryVolumeInformationFile", "ShizukuLc_NtQueryInformationProcess",
           "ShizukuLc_NtQueryDirectoryFile", "ShizukuLc_NtDeviceIoControlFile",
           "ShizukuLc_NtQuerySystemInformation", "ShizukuLc_RtlGetVersion"}


def run(cmd):
    subprocess.run(cmd, check=True, timeout=80)


def main():
    host, cross, objdump = (shutil.which(n) for n in
                            ("clang", "i686-w64-mingw32-gcc", "i686-w64-mingw32-objdump"))
    if not (host and cross and objdump):
        sys.exit("missing clang or i686-w64-mingw32 toolchain")
    with tempfile.TemporaryDirectory(prefix="lciocp-") as tmp:
        out = pathlib.Path(tmp)
        run([host, "--no-default-config", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
             "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
             str(SRC / "lc_iocp.c"), str(SRC / "lc_iocp_host_test.c"), "-o", str(out / "host"), "-lpthread"])
        run([str(out / "host")])
        # Shutdown contract: close waits for quiescence, then lock/context are freed
        # before the getters are joined (UAF under ASan, race under TSan if violated).
        for name, san in (("quiesce_asan", "address,undefined"), ("quiesce_tsan", "thread")):
            run([host, "--no-default-config", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                 f"-fsanitize={san}", "-fno-sanitize-recover=all", "-D_POSIX_C_SOURCE=200809L",
                 str(SRC / "lc_iocp.c"), str(SRC / "lc_iocp_quiesce_test.c"), "-o", str(out / name), "-lpthread"])
            run([str(out / name)])
        run([host, "--no-default-config", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
             "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
             str(SRC / "lc_ntdll.c"), str(SRC / "lc_ntdll_host_test.c"), "-o", str(out / "ntdll")])
        run([str(out / "ntdll")])
        for name, san in (("sock_asan", "address,undefined"), ("sock_tsan", "thread")):
            run([host, "--no-default-config", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                 f"-fsanitize={san}", "-fno-sanitize-recover=all", "-D_POSIX_C_SOURCE=200809L",
                 str(SRC / "lc_iocp.c"), str(SRC / "lc_sock.c"), str(SRC / "lc_sock_host_test.c"),
                 "-o", str(out / name), "-lpthread"])
            run([str(out / name)])
        # Exported-wrapper error ordering, built with both compilers: gcc evaluates
        # call arguments right-to-left, which exposed the original defect.
        for cc, extra in ((host, ["--no-default-config"]), (shutil.which("gcc"), [])):
            if not cc:
                continue
            run([cc, *extra, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-DLC_NATIVE_HOST_TEST",
                 "-I", str(SRC / "host_shim"), "-I", str(SRC), str(SRC / "lc_iocp.c"), str(SRC / "lc_iocp_native.c"),
                 str(SRC / "lc_iocp_native_error_test.c"), "-o", str(out / "errtest")])
            run([str(out / "errtest")])
        dll = out / "LCIOCP.DLL"
        run([cross, "-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror", "-fno-builtin",
             "-fno-tree-loop-distribute-patterns", "-nostdlib", "-ffreestanding", "-shared",
             "-Wl,--entry,_dll_entry@12", "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4",
             "-Wl,--minor-os-version,0", "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat",
             "-Wl,--no-insert-timestamp", str(SRC / "lc_iocp.c"), str(SRC / "lc_iocp_native.c"),
             str(SRC / "lc_sock.c"), str(SRC / "lc_sock_native.c"),
             str(SRC / "lc_ntdll.c"), str(SRC / "lc_ntdll_native.c"),
             str(SRC / "lc_iocp_native.def"), "-o", str(dll), "-lws2_32", "-lkernel32", "-lgcc"])
        dump = subprocess.run([objdump, "-p", str(dll)], check=True, timeout=30,
                              capture_output=True, text=True).stdout
        exports = set(re.findall(r"\[\s*\d+\]\s+\+base\[\s*\d+\]\s+[0-9a-f]{4}\s+(\S+)", dump))
        per_dll, current = {}, None
        for line in dump.splitlines():
            m = re.match(r"\s*DLL Name: (\S+)", line)
            if m:
                current = per_dll.setdefault(m.group(1).upper(), set())
                continue
            m = re.match(r"^\s+[0-9a-f]{8}\s+<none>\s+[0-9a-f]{4}\s+(\S+)", line)
            if m and current is not None:
                current.add(m.group(1))
        inventory = json.loads(INVENTORY.read_text())["dlls"]
        expect = {"KERNEL32.DLL": ALLOWED, "WS2_32.DLL": ALLOWED_WS2}
        if set(per_dll) != set(expect):
            sys.exit(f"unexpected import DLLs {sorted(per_dll)}")
        for name, names in per_dll.items():
            extra = names - expect[name]
            missing98 = names - set(inventory[name])
            if not names or extra or missing98:
                sys.exit(f"{name}: unexpected {sorted(extra)} not-in-Win98SE {sorted(missing98)}")
        if exports != EXPORTS:
            sys.exit(f"unexpected exports {sorted(exports)}")
        if "Subsystem\t\t00000002" not in dump or "MajorOSystemVersion\t4" not in dump:
            sys.exit("PE header is not a Win98-loadable GUI DLL")
    print("legcord_iocp check: host core + shutdown quiescence (ASan/TSan) + socket bridge (ASan/TSan) + ntdll providers + PE32 Win98SE-inventory import/export static PASS (no guest execution)")


if __name__ == "__main__":
    main()
