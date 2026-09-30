#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run an Electron application (plain Electron, a minimal Electron app, VS Code/VSCodium) inside the standalone Kernel64
guest and report how far it got. Modelled on run_k64_chromium.py (same boot profile, same autorun mechanism).

Profile: the standalone profile of run_k64_standalone.py (QEMU -kernel stub, no Supervisor, TCG or KVM, a Bochs VBE
adapter so the Win32 window manager exists, -display none). The application tree (read-only on the host, never inside
the repository) is copied into a FAT32 image and attached on AHCI, mounted by Kernel64 as D:\\. The kernel command line
`shz.noapps shz.autorun=D:\\K64RUN.TXT` starts the program named in the control file after the self-tests
(kernel64/autorun.c). The disk is attached with snapshot=on, so the image stays reusable.

Applications (--app):
  minimal  the Electron release tree as D:\\e1min with the probe app of tests/e1_minapp/ as resources\\app (the
           packaged-app layout: electron.exe starts it directly, without default_app.asar). main.js opens a hidden
           BrowserWindow on a local page whose script sets the title to "electron-min 42"; main reads it back and prints
           "SHZ-E1-MARKER electron-min 42" (console.log and stderr), then app.exit(0). Expected line = that marker.
  default  the pristine Electron release tree as D:\\electron, electron.exe with no application argument (Electron's
           default_app.asar). It opens a window and never quits, so it has no marker: the run can only report the
           furthest point reached (status FAIL by construction, see below).
  vscode   a VS Code-family tree (--tree; the official Code.exe archive or VSCodium, whose executable is found by name)
           as D:\\vscode, started as `<exe> --disable-gpu --no-sandbox --verbose` with a throwaway user-data and
           extensions directory on the D: disk. It does not quit by itself and has no marker (as for default).
No --single-process: Electron 44.5.0 dies with SIGTRAP right after "app ready" under --single-process on a Linux host
(the same app passes without it), so the runs use Electron's normal multi-process model (browser + renderer processes).
All three add --enable-logging=stderr so Chromium/Electron log lines reach the serial log. The Kernel64 autorun control
file holds at most 511 characters of command line; --args replaces the default arguments.

The run PASSES only when the serial log contains the expected line AND the process exited with code 0 AND no process
fault was reported. Anything else is a FAIL, and the result names the furthest point reached, in this order of
precedence: loader failure (an import that did not resolve), a fatal exception (process killed by the kernel), a
Node/V8 fatal line, a Chromium FATAL/CHECK line, the marker seen without a clean exit, the first explicitly
unsupported kernel32 call ("K32 unsupported: ..."), the furthest progress line the app printed, the exit code, or the
timeout.

Result: <out>/result.json (printed in short). Exit status 0 = PASS, 1 = FAIL (the expected state today), 2 = the run
could not be performed (missing inputs or tools).
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import qemu  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD, run  # noqa: E402

K64S = BUILD / "kernel64s"
WIN64 = BUILD / "win64"
MINAPP = HERE / "e1_minapp"
IMAGES = Path(os.environ.get("SHZ_E1_IMAGES", str(BUILD / "e1-images")))  # FAT32 images: large, never committed
FIXED_EPOCH = 1262304000
MARKER = "SHZ-E1-MARKER electron-min 42"
COMMON = "--no-sandbox --disable-gpu --enable-logging=stderr --v=0"
APPS = {
    "minimal": {"dir": "e1min", "exe": "electron.exe", "args": COMMON + " --no-first-run", "expect": MARKER},
    "default": {"dir": "electron", "exe": "electron.exe", "args": COMMON + " --no-first-run", "expect": None},
    "vscode": {"dir": "vscode", "exe": None,
               "args": "--disable-gpu --no-sandbox --verbose --enable-logging=stderr --skip-welcome --skip-release-notes "
                       "--disable-extensions --user-data-dir=D:\\vscud --extensions-dir=D:\\vscext",
               "expect": None},
}
# Progress lines, most advanced last: the furthest one seen is reported when nothing failed explicitly.
PROGRESS = [
    ("autorun started", r"K64 autorun: starting"),
    ("process created", r"K64 autorun: started pid"),
    ("app output (any line)", r"\[(win64|user) [^\]]+ pid \d+\]"),
    ("electron main: started", r"SHZ-E1 main: started"),
    ("electron main: app ready", r"SHZ-E1 main: app ready|\[main [0-9T:.\-Z ]+\]"),
    ("renderer: page script ran", r"SHZ-E1 page script ran|SHZ-E1 renderer console"),
    ("marker", re.escape(MARKER)),
]


def mtools_env():
    env = dict(os.environ)
    env.update({"MTOOLS_SKIP_CHECK": "1", "TZ": "UTC", "SOURCE_DATE_EPOCH": str(FIXED_EPOCH)})
    return env


def listing_of(tree):
    return sorted((str(p.relative_to(tree)), p.stat().st_size) for p in tree.rglob("*") if p.is_file())


def build_image(image, tree, volume_dir, overlay=None):
    """FAT32 image holding `tree` as \\<volume_dir>, plus overlay {host_dir: "<volume path>"} copied over it; rebuilt only
    when the tree or overlay listing changes (the key is stored next to the image)."""
    listing = listing_of(tree)
    over = {str(k): [(n, s, hashlib.sha256((Path(k) / n).read_bytes()).hexdigest()) for n, s in listing_of(Path(k))]
            for k in (overlay or {})}
    key = hashlib.sha256(json.dumps([volume_dir, listing, over, sorted((overlay or {}).values())]).encode()).hexdigest()
    stamp = Path(str(image) + ".json")
    if image.exists() and stamp.exists() and json.loads(stamp.read_text()).get("key") == key:
        return listing
    total = sum(s for _, s in listing)
    size_mib = (total * 11 // 10 >> 20) + 256
    image.parent.mkdir(parents=True, exist_ok=True)
    image.unlink(missing_ok=True)
    with open(image, "wb") as fh:
        fh.truncate(size_mib << 20)
    run(["mkfs.vfat", "-F", "32", "-s", "8", "-n", "ELECTRON", "--invariant", str(image)], capture=True)
    run(["mcopy", "-s", "-m", "-i", str(image), str(tree), "::" + volume_dir], env=mtools_env(), capture=True)
    for host, dest in (overlay or {}).items():
        parts = dest.split("/")
        for i in range(1, len(parts) + 1):
            subprocess.run(["mmd", "-D", "s", "-i", str(image), "::" + "/".join(parts[:i])], env=mtools_env(),
                           capture_output=True)
        for f in sorted(Path(host).iterdir()):
            run(["mcopy", "-s", "-o", "-m", "-i", str(image), str(f), "::" + dest + "/" + f.name], env=mtools_env(),
                capture=True)
    stamp.write_text(json.dumps({"key": key, "files": len(listing), "bytes": total}))
    return listing


def put_file(image, data, name, work):
    """Copies bytes into the FAT32 image as ::name (overwriting), with mtools."""
    host = work / ("put_" + name.replace("/", "_"))
    host.write_bytes(data)
    parts = name.split("/")
    for i in range(1, len(parts)):
        subprocess.run(["mmd", "-D", "s", "-i", str(image), "::" + "/".join(parts[:i])], env=mtools_env(),
                       capture_output=True)
    run(["mcopy", "-o", "-i", str(image), str(host), "::" + name], env=mtools_env(), capture=True)


def classify(serial, expect):
    """Furthest point reached, from the serial log after the autorun start (precedence in the module docstring).
    A runtime LoadLibrary that fails ("... LoadLibrary needs ...") is listed separately: programs probe optional DLLs."""
    all_lines = serial.splitlines()
    start = next((i for i, l in enumerate(all_lines) if l.startswith("K64 autorun: starting")), len(all_lines))
    lines = all_lines[start:]
    res = {}
    ldr_all = [l for l in lines if re.search(r"K64 ldr: .*(not loaded|imports|rejected|failed|cannot|lacks)", l)]
    runtime_misses = [l for l in ldr_all if ": LoadLibrary needs " in l]
    ldr = [l for l in ldr_all if l not in runtime_misses]
    res["runtime_loadlibrary_misses"] = sorted(set(runtime_misses))[:40]
    killed = [l for l in lines if re.search(r"K64: process .* killed|K64 EXCEPTION|unhandled exception", l)]
    node_fatal = [l for l in lines if re.search(r"FATAL ERROR:|Fatal error in|node::|Uncaught (Type|Reference)?Error|"
                                                r"A JavaScript error occurred|SHZ-E1 main: (load failed|renderer gone|"
                                                r"executeJavaScript failed|whenReady failed|watchdog)", l)]
    fatal = [l for l in lines if re.search(r"FATAL:|Check failed|CHECK failed|NOTREACHED", l)]
    unsup = [l for l in lines if "K32 unsupported:" in l or "K32 RECON called:" in l]
    auto = [l for l in lines if l.startswith("K64 autorun: result")]
    res["loader_failures"] = ldr[:20]
    res["exceptions"] = killed[:20]
    res["node_fatal"] = node_fatal[:20]
    res["chromium_fatal"] = fatal[:20]
    res["unsupported_calls"] = unsup[:60]
    res["autorun_result"] = auto[-1] if auto else None
    progress = None
    for name, rx in PROGRESS:
        hit = next((l for l in lines if re.search(rx, l)), None)
        if hit:
            progress = (name, hit)
    res["progress"] = list(progress) if progress else None
    m = re.search(r"K64 autorun: result (\w[\w-]*) exit=([0-9a-f]+) faulted=(\d)", auto[-1]) if auto else None
    res["exit_code"] = int(m.group(2), 16) if m else None
    res["faulted"] = bool(int(m.group(3))) if m else None
    res["ended_by"] = m.group(1) if m else None
    marker = bool(expect) and expect in serial
    if ldr:
        res["furthest"] = "loader: " + ldr[0]
    elif killed:
        res["furthest"] = "exception: " + killed[0]
    elif node_fatal:
        res["furthest"] = "node/electron fatal: " + node_fatal[0]
    elif fatal:
        res["furthest"] = "chromium fatal: " + fatal[0]
    elif marker:
        res["furthest"] = "marker seen" + (f", process {m.group(1)} exit {int(m.group(2), 16):#x}" if m else "")
    elif unsup:
        res["furthest"] = "first unsupported kernel32 call: " + unsup[0]
    elif progress and progress[0] not in ("autorun started", "process created"):
        res["furthest"] = f"progress: {progress[0]}: {progress[1]}" + (
            f"; process {m.group(1)} exit {int(m.group(2), 16):#x}" if m else "")
    elif m:
        res["furthest"] = f"process {m.group(1)} with exit code {int(m.group(2), 16):#x}"
    else:
        res["furthest"] = "no autorun result line (guest did not finish)"
    return res


def find_exe(tree, name):
    if name:
        return name if (tree / name).exists() else None
    for cand in ("Code.exe", "VSCodium.exe", "Code - Insiders.exe"):
        if (tree / cand).exists():
            return cand
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--app", choices=sorted(APPS), default="minimal")
    ap.add_argument("--tree", help="application tree (read-only): the Electron release tree for minimal/default, "
                                   "a VS Code/VSCodium tree for vscode")
    ap.add_argument("--image", help="FAT32 image path (default: $SHZ_E1_IMAGES/<app>.img, outside git)")
    ap.add_argument("--args", help="replaces the default arguments of --app")
    ap.add_argument("--expect", help="line that must appear for a PASS (default: the marker for minimal, none otherwise)")
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    ap.add_argument("--memory", default="4096")
    ap.add_argument("--display", choices=("vga", "none"), default="vga")
    ap.add_argument("--timeout", type=int, default=2400, help="host-side QEMU timeout (s)")
    ap.add_argument("--guest-timeout", type=int, default=1500, help="seconds the guest lets the program run")
    ap.add_argument("--out", help="result directory (default build/kernel64s/run_electron_<app>)")
    ap.add_argument("--no-trace", action="store_true", help="do not pass shz.k32trace and shz.exctrace")
    args = ap.parse_args()
    spec = APPS[args.app]
    stub, kernel, initrd = K64S / "boot.elf", K64S / "KERNEL64S.BIN", WIN64 / "WIN64.IMG"
    for f in (stub, kernel, initrd):
        if not f.exists():
            print(f"missing {f}: run shizukudos/kbuild.py and shizukudos/win64/build.py first")
            return 2
    if not args.tree:
        print("--tree is required (the Electron or VS Code tree, outside the repository)")
        return 2
    tree = Path(args.tree)
    exe = find_exe(tree, spec["exe"])
    if not exe:
        print(f"no {spec['exe'] or 'Code.exe/VSCodium.exe'} in {tree}")
        return 2
    for tool in ("mkfs.vfat", "mcopy", "mmd"):
        if not shutil.which(tool):
            print(f"required tool missing: {tool}")
            return 2
    expect = args.expect if args.expect is not None else spec["expect"]
    cargs = args.args if args.args is not None else spec["args"]
    vdir = spec["dir"]
    cmdline = f"{exe} {cargs}"
    if len(cmdline) > 511:
        print(f"command line is {len(cmdline)} characters; autorun.c keeps 511")
        return 2
    accel = ("kvm" if Path("/dev/kvm").exists() else "tcg") if args.accel == "auto" else args.accel
    out = Path(args.out or (K64S / f"run_electron_{args.app}"))
    out.mkdir(parents=True, exist_ok=True)
    image = Path(args.image or (IMAGES / f"{args.app}.img"))
    t0 = time.time()
    overlay = {str(MINAPP): f"{vdir}/resources/app"} if args.app == "minimal" else None
    listing = build_image(image, tree, vdir, overlay)
    control = (f"image=D:\\{vdir}\\{exe}\r\ncmdline={cmdline}\r\ncwd=D:\\{vdir}\r\n"
               f"timeout={args.guest_timeout}\r\n").encode()
    put_file(image, control, "K64RUN.TXT", out)
    image_s = round(time.time() - t0, 1)
    serial_path = out / "serial.log"
    serial_path.unlink(missing_ok=True)
    cmd = [args.qemu, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", args.memory, "-nodefaults", "-display", "none",
           *(["-vga", "std"] if args.display == "vga" else []),
           "-kernel", str(stub), "-initrd", f"{kernel},{initrd}",
           "-append", "shz.noapps shz.autorun=D:\\K64RUN.TXT" + ("" if args.no_trace else " shz.k32trace shz.exctrace"),
           "-serial", f"file:{serial_path}", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot",
           "-device", "ahci,id=ahci0", "-drive", f"if=none,id=d0,file={image},format=raw,snapshot=on",
           "-device", "ide-hd,drive=d0,bus=ahci0.0"]
    started = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        proc.wait(timeout=args.timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        timed_out = True
    seconds = round(time.time() - started, 1)
    qemu_out = (proc.stdout.read() if proc.stdout else b"").decode(errors="replace")
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    res = classify(serial, expect)
    app_lines = [l for l in serial.splitlines() if re.match(r"\[(win64|user) [^\]]+ pid \d+\]", l)]
    expect_seen = bool(expect) and expect in serial
    ok = expect_seen and res["exit_code"] == 0 and not res["faulted"] and not res["exceptions"] and not timed_out
    record = {
        "profile": f"kernel64-standalone + {args.app} Electron app on AHCI FAT32 (D:), autorun", "app": args.app,
        "accel": accel, "status": "PASS" if ok else "FAIL", "expected_line": expect, "expected_line_seen": expect_seen,
        "qemu_timed_out": timed_out, "seconds": seconds, "image_prepare_s": image_s, "image": str(image),
        "tree": str(tree), "tree_files": len(listing), "exe": exe, "command_line": cmdline, "command": cmd,
        **res,
        "app_output_lines": app_lines[:600], "app_output_line_count": len(app_lines),
        "serial_tail": serial[-8000:], "qemu_output": qemu_out[-1500:], "utc": shzlib.utc_now(), "git": shzlib.git_state(),
    }
    shzlib.write_json(out / "result.json", record)
    print(f"  app: {args.app} ({exe}), status: {record['status']} ({seconds} s, accel={accel})")
    print(f"  furthest point: {res['furthest']}")
    print(f"  autorun: {res['autorun_result']}")
    print(f"  expected line: {expect!r} seen: {expect_seen}")
    for k in ("loader_failures", "exceptions", "node_fatal", "chromium_fatal", "unsupported_calls"):
        for l in res[k][:8]:
            print(f"  [{k}] {l}")
    print(f"  app output lines: {len(app_lines)} (first 20 below; all in result.json)")
    for l in app_lines[:20]:
        print("    " + l[:300])
    print(f"  result: {out / 'result.json'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
