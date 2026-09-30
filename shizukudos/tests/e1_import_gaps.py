#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""E1: which imports of the Electron-based products does the current Win64 runtime not resolve, and which of those are
Electron/Node-specific (absent from Chromium's own list)?

A wrapper around shizukudos/win64/tools/startup_chain.py (unchanged; run once per image with --json --delay):
  - every AMD64 executable/DLL at the top of each tree (electron.exe, VSCodium.exe/Code.exe, chrome.exe, chrome.dll,
    ffmpeg.dll, libEGL/libGLESv2, vk_swiftshader, vulkan-1, d3dcompiler_47, dxcompiler, dxil) and every Node addon
    (*.node) below it is used as the start of a load closure, so DLLs that are only LoadLibrary'd at run time are covered
    as well as the eager chain of the executable;
  - Node addons import the Node API from "node.exe" (or "electron.exe"); Electron's delay-load hook binds that name to the
    running executable, so those imports are checked against the product executable's own export table here instead of
    being reported as a missing DLL;
  - load-time and delay-load failures are kept apart (a load-time failure stops the image from loading; a delay-load
    failure raises only when that function is first called).
Output: a Markdown section (stdout, or --md) with the gaps grouped by DLL and ranked, split into "Needed from K4"
(kernel32/kernelbase/ntdll and the api-ms-win-core contracts they host) and "Needed from K5" (every other system DLL),
plus a JSON file (--json) with the full data.
"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pefile

REPO = Path(__file__).resolve().parents[2]
CHAIN = REPO / "shizukudos/win64/tools/startup_chain.py"
K4_DLLS = {"kernel32.dll", "kernelbase.dll", "ntdll.dll"}
# Functions Node (libuv), Electron's Node integration or VS Code's native modules need that a browser does not use much.
NODE_HINTS = (
    "CompletionPort", "GetQueuedCompletionStatus", "PostQueuedCompletionStatus", "SetFileCompletionNotificationModes",
    "CancelIo", "NamedPipe", "ConnectNamedPipe", "PeekNamedPipe", "WaitNamedPipe", "PseudoConsole", "ConsoleMode",
    "ReadConsole", "WriteConsole", "GetConsole", "SetConsole", "ConsoleCtrl", "ReadDirectoryChangesW", "FileInformationByHandle",
    "CreateSymbolicLink", "CreateHardLink", "GetFinalPathNameByHandle", "ProcThreadAttribute", "JobObject", "AssignProcessToJob",
    "RegisterWaitForSingleObject", "UnregisterWait", "QueueUserWorkItem", "Tp", "ConditionVariable", "SRWLock", "InitOnce",
    "GetSystemTimePreciseAsFileTime", "QueryPerformance", "NtQueryInformationFile", "NtSetInformationFile",
    "NtQueryDirectoryFile", "NtQueryVolumeInformationFile", "NtDeviceIoControlFile", "RtlNtStatusToDosError", "WSA",
    "AcceptEx", "GetAddrInfoEx", "SleepConditionVariable", "WakeConditionVariable", "GetModuleFileNameEx", "Process32",
    "Toolhelp32", "OpenProcessToken", "Reg", "Crypt", "Cert", "Mutex", "SetHandleInformation", "DuplicateHandle",
    "CreateProcess", "TerminateProcess", "GetExitCodeProcess", "GetProcessTimes", "GetProcessMemoryInfo", "UserName",
    "GetComputerName", "GetUserProfileDirectory", "SHGetKnownFolderPath", "GetTempPath", "GetEnvironment",
)


def pe_machine(path):
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
        if head[:2] != b"MZ":
            return None
        off = int.from_bytes(head[0x3c:0x40], "little")
        if off + 6 > len(head) or head[off:off + 4] != b"PE\0\0":
            return None
        return int.from_bytes(head[off + 4:off + 6], "little")
    except OSError:
        return None


def images_of(tree):
    tops = [p for p in sorted(tree.iterdir()) if p.suffix.lower() in (".exe", ".dll") and pe_machine(p) == 0x8664]
    addons = [p for p in sorted(tree.rglob("*.node")) if pe_machine(p) == 0x8664]
    return tops, addons


def chain(start, build):
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "c.json"
        r = subprocess.run([sys.executable, str(CHAIN), str(start), "--build", str(build), "--json", str(out), "--delay"],
                           capture_output=True, text=True)
        if not out.exists():
            raise SystemExit(f"startup_chain.py failed on {start}: {r.stderr[-2000:]}")
        return json.loads(out.read_text())


def exports_of(path):
    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    return {s.name.decode(errors="replace") for s in exp.symbols if s.name} if exp else set()


def parse_key(key):
    """'kernel32.dll [not exported by kernel32.dll]' -> (import dll, reason, resolved dll or None)."""
    dll, _, why = key.partition(" [")
    why = why.rstrip("]")
    resolved = why[len("not exported by "):].split(" ")[0].lower() if why.startswith("not exported by ") else None
    return dll.lower(), why, resolved


def owner(dll, resolved):
    if resolved:
        return "K4" if resolved in K4_DLLS else "K5"
    return "K4" if dll in K4_DLLS or dll.startswith("api-ms-win-core-") else "K5"


def collect(product, tree, build, host_exe):
    """{(owner, dll, fn): {"load": set(images), "delay": set(images)}} for one product tree."""
    tops, addons = images_of(tree)
    host_exports = exports_of(tree / host_exe) if host_exe else set()
    gaps, per_image = {}, {}
    for start in tops + addons:
        data = chain(start, build)
        rel = str(start.relative_to(tree))
        for name, rep in data["images"].items():
            label = rel if name.lower() == start.name.lower() else name
            for kind, field in (("load", "by_dll"), ("delay", "delay_by_dll")):
                for key, fns in rep.get(field, {}).items():
                    dll, why, resolved = parse_key(key)
                    for fn in fns:
                        if dll in ("node.exe", "electron.exe") and start.suffix.lower() == ".node":
                            if fn in host_exports:
                                continue             # bound to the running executable by Electron's delay-load hook
                            why = f"not exported by {host_exe}"
                        g = gaps.setdefault((owner(dll, resolved), dll, fn), {"load": set(), "delay": set(), "why": why})
                        g[kind].add(label)
            per_image[label] = {"missing_load": rep.get("missing", 0), "missing_delay": rep.get("delay_missing", 0),
                                "first_failure": rep.get("first_failure")}
    return gaps, per_image, [str(p.relative_to(tree)) for p in tops + addons]


def hint(fn):
    return any(h in fn for h in NODE_HINTS)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--electron", type=Path, required=True)
    ap.add_argument("--vscode", type=Path, required=True, help="VS Code or VSCodium tree")
    ap.add_argument("--chromium", type=Path, required=True, help="chrome-win tree")
    ap.add_argument("--build", type=Path, default=REPO / "build/shizukudos/win64")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--md", type=Path)
    args = ap.parse_args()
    vexe = next((c for c in ("Code.exe", "VSCodium.exe") if (args.vscode / c).exists()), None)
    prods = {"electron": collect("electron", args.electron, args.build, "electron.exe"),
             "vscode": collect("vscode", args.vscode, args.build, vexe),
             "chromium": collect("chromium", args.chromium, args.build, None)}
    chromium_fns = {(d, f) for (_, d, f) in prods["chromium"][0]}
    rows = {}
    for p in ("electron", "vscode"):
        for (own, dll, fn), g in prods[p][0].items():
            r = rows.setdefault((own, dll, fn), {"products": set(), "load": set(), "delay": set(), "why": g["why"]})
            r["products"].add(p)
            r["load"] |= {f"{p}:{i}" for i in g["load"]}
            r["delay"] |= {f"{p}:{i}" for i in g["delay"]}
    for r_key, r in rows.items():
        r["electron_specific"] = (r_key[1], r_key[2]) not in chromium_fns
        r["node_hint"] = hint(r_key[2])
    lines = ["<!-- generated by shizukudos/tests/e1_import_gaps.py -->"]
    for own in ("K4", "K5"):
        sel = [(k, r) for k, r in rows.items() if k[0] == own]
        by_dll = {}
        for (o, dll, fn), r in sel:
            by_dll.setdefault(dll, []).append((fn, r))
        lines.append(f"\n### Needed from {own}\n")
        lines.append(f"{len(sel)} distinct unresolved imports ({sum(1 for _, r in sel if r['load'])} needed at load time, "
                     f"{sum(1 for _, r in sel if r['electron_specific'])} not in Chromium's own list). Rank: load-time "
                     "first, then Electron/Node-specific, then by number of images needing it. `E` = not needed by "
                     "chrome.exe/chrome.dll/Chromium's DLLs (Electron/Node-specific); `N` = Node/libuv/VS Code native "
                     "module territory by name.\n")
        lines.append("| DLL | # | load-time (image count) | delay-load only | flags / reason |")
        lines.append("|---|---:|---|---|---|")
        for dll, items in sorted(by_dll.items(), key=lambda kv: (-sum(1 for _, r in kv[1] if r["load"]), -len(kv[1]))):
            items.sort(key=lambda it: (not it[1]["load"], not it[1]["electron_specific"],
                                       -(len(it[1]["load"]) + len(it[1]["delay"])), it[0]))
            load = [f"{fn}{' E' if r['electron_specific'] else ''}{' N' if r['node_hint'] else ''} ({len(r['load'])})"
                    for fn, r in items if r["load"]]
            delay = [f"{fn}{' E' if r['electron_specific'] else ''}{' N' if r['node_hint'] else ''}"
                     for fn, r in items if not r["load"]]
            reasons = sorted({r["why"] for _, r in items})
            lines.append(f"| {dll} | {len(items)} | {', '.join(load) or '—'} | {', '.join(delay) or '—'} | "
                         f"{'; '.join(reasons)[:200]} |")
    lines.append("\n### Per image (first load-time failure the loader would print)\n")
    lines.append("| product | image | missing load-time | missing delay-load | first failure |")
    lines.append("|---|---|---:|---:|---|")
    for p, (_, per, _) in prods.items():
        for img, s in per.items():
            if s["missing_load"] or s["missing_delay"]:
                lines.append(f"| {p} | {img} | {s['missing_load']} | {s['missing_delay']} | {s['first_failure'] or '—'} |")
    md = "\n".join(lines) + "\n"
    if args.md:
        args.md.write_text(md)
    else:
        print(md)
    if args.json:
        args.json.write_text(json.dumps({
            "images": {p: v[2] for p, v in prods.items()},
            "gaps": [{"owner": k[0], "dll": k[1], "fn": k[2], "products": sorted(r["products"]),
                      "load_time_images": sorted(r["load"]), "delay_images": sorted(r["delay"]), "reason": r["why"],
                      "electron_specific": r["electron_specific"], "node_hint": r["node_hint"]}
                     for k, r in sorted(rows.items())],
            "chromium_gap_count": len(chromium_fns)}, indent=1))
    print(f"electron+vscode gaps: {len(rows)} distinct; chromium gaps: {len(chromium_fns)}; "
          f"electron/node-specific: {sum(1 for r in rows.values() if r['electron_specific'])}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
