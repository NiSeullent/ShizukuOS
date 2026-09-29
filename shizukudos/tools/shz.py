#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""ShizukuDOS 10.0 build / test / package driver.

    shz.py doctor [--guest]
    shz.py build --profile {bios-legacy,uefi-multikernel,bios-multikernel}
    shz.py test  --suite {host,boot,interkernel,win64,win98-regression}
    shz.py package --channel dev

Results are PASS / FAIL / SKIP / BLOCKED. A prerequisite that is missing, or a
feature that is not implemented yet, is BLOCKED or SKIP -- never PASS -- and a
suite containing either is reported as incomplete rather than "verified".
"""
import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import shzlib  # noqa: E402
from shzlib import BUILD, REPO, SHZ, run, sha256_file  # noqa: E402

PROFILES = {
    "bios-legacy": {
        "summary": "Legacy BIOS/CSM -> real Real Mode -> FreeDOS DOS16",
        "steps": ["dos16"],
        "status": "implemented (DOS16 only; Kernel32 entry not implemented)",
    },
    "uefi-multikernel": {
        "summary": "UEFI x64 -> Supervisor (Intel VMX) -> virtual Real Mode DOS16",
        "steps": ["dos16", "supervisor"],
        "status": "partial: DOS16 domain only; Kernel32/Kernel64 domains and Win64 not implemented",
    },
    "bios-multikernel": {
        "summary": "BIOS loader -> Supervisor cold launch -> DOS16 / Win98 / Kernel64",
        "steps": [],
        "status": "not implemented",
    },
}


# ------------------------------------------------------------------ doctor
def host_facts():
    facts = {"utc": shzlib.utc_now(), "kernel": platform.release(), "python": platform.python_version()}
    cpuinfo = Path("/proc/cpuinfo").read_text() if Path("/proc/cpuinfo").exists() else ""
    m = re.search(r"model name\s*:\s*(.+)", cpuinfo)
    facts["cpu_model"] = m.group(1).strip() if m else "unknown"
    flags = set(re.search(r"flags\s*:\s*(.+)", cpuinfo).group(1).split()) if "flags" in cpuinfo else set()
    facts["host_cpu_flags"] = {f: f in flags for f in ("vmx", "svm", "ept", "lm", "hypervisor")}
    facts["dev_kvm"] = Path("/dev/kvm").exists()
    for vendor in ("kvm_intel", "kvm_amd"):
        p = Path(f"/sys/module/{vendor}/parameters/nested")
        if p.exists():
            facts[f"{vendor}_nested"] = p.read_text().strip()
    facts["git"] = shzlib.git_state()
    return facts


def cmd_doctor(args):
    tools = {}
    for name, vargs in (("nasm", ("-v",)), ("gcc", ("--version",)), ("clang", ("--version",)), ("ld", ("--version",)),
                        ("x86_64-w64-mingw32-gcc", ("--version",)), ("i686-w64-mingw32-gcc", ("--version",)),
                        ("mformat", ("--version",)), ("mkfs.vfat", ("--help",)), ("python3", ("--version",)),
                        ("make", ("--version",)), ("git", ("--version",))):
        tools[name] = shzlib.tool_version(name, vargs)
    for name, path in (("qemu-kvm", qemu_path()), ("ovmf_code", "/usr/share/edk2/ovmf/OVMF_CODE.fd"),
                       ("ovmf_vars", "/usr/share/edk2/ovmf/OVMF_VARS.fd")):
        tools[name] = {"path": path, "present": Path(path).exists()}
    ow = shzlib.TOOLS_DIR / "ow" / "binl64" / "wcc"
    tools["open-watcom"] = {"path": str(ow), "present": ow.exists(),
                            "note": "fetched into build/tools on first dos16 build"}
    report = {"section": "HOST (facts about this build/test machine, not about the product)",
              "host": host_facts(), "tools": tools}
    report["host"]["l1_vmx_expected"] = bool(report["host"]["host_cpu_flags"].get("vmx")
                                              and report["host"].get("kvm_intel_nested") in ("Y", "1"))
    if args.guest:
        report["guest"] = guest_capabilities()
    else:
        report["guest"] = {"section": "GUEST-INTERNAL capabilities (what the Supervisor detects inside L1)",
                           "status": "SKIP", "reason": "run `doctor --guest` to boot the Supervisor and read them"}
    print(json.dumps(report, indent=2))
    missing = [k for k, v in tools.items() if not (v and (v.get("present", True)))
               and k not in ("clang", "open-watcom", "i686-w64-mingw32-gcc")]
    return 1 if missing else 0


def qemu_path():
    return "/usr/libexec/qemu-kvm" if Path("/usr/libexec/qemu-kvm").exists() else (shutil.which("qemu-system-x86_64") or "")


def guest_capabilities():
    result = {"section": "GUEST-INTERNAL capabilities (what the Supervisor detects inside L1)"}
    rj = BUILD / "supervisor" / "run-uefi-vreal" / "result.json"
    proc = run([sys.executable, SHZ / "supervisor" / "test_qemu.py", "--timeout", "120"], capture=True, check=False,
               timeout=400)
    result["harness_exit"] = proc.returncode
    if rj.exists():
        data = json.loads(rj.read_text())
        info = data.get("info") or {}
        result.update({"status": "PASS" if data.get("status") == "PASS" else "FAIL",
                       "caps_seen_by_supervisor": info.get("caps"), "vendor_regs": info.get("cpu_vendor"),
                       "feature_control": info.get("feature_control"), "boot_path": data.get("boot_path"),
                       "layers": data.get("layers")})
    else:
        result["status"] = "BLOCKED"
        result["reason"] = "no Supervisor result was produced"
    return result


# ------------------------------------------------------------------ build
def cmd_build(args):
    profile = PROFILES[args.profile]
    print(f"profile {args.profile}: {profile['summary']}\nstatus: {profile['status']}")
    if not profile["steps"]:
        print("BLOCKED: this profile has no implementation yet")
        return 2
    for step in profile["steps"]:
        script = SHZ / step / "build.py"
        print(f"== build {step}")
        run([sys.executable, script], timeout=900)
    return 0


# ------------------------------------------------------------------ tests
def record(results, name, status, **details):
    results.append(shzlib.result_record(name, status, **details))
    print(f"[{status:7}] {name}" + (f"  {details['detail']}" if details.get("detail") else ""))


def run_script(results, name, argv, timeout=600, expect_marker=None):
    proc = run([sys.executable, *argv], capture=True, check=False, timeout=timeout)
    tail = (proc.stdout or "")[-600:]
    ok = proc.returncode == 0 and (expect_marker is None or expect_marker in proc.stdout)
    record(results, name, "PASS" if ok else "FAIL", detail=tail.strip().splitlines()[-1] if tail.strip() else "",
           exit_code=proc.returncode, command=" ".join(str(x) for x in [sys.executable, *argv]))
    return ok


def suite_host(results):
    import shzinfo
    try:
        size = shzinfo.selfcheck(REPO)
        record(results, "shz_info_t layout matches C compiler", "PASS", detail=f"sizeof={size}")
    except AssertionError as exc:
        record(results, "shz_info_t layout matches C compiler", "FAIL", detail=str(exc))
    run_script(results, "interkernel ABI host model", [SHZ / "abi" / "test_abi.py"]) if (SHZ / "abi" / "test_abi.py").exists() \
        else record(results, "interkernel ABI host model", "BLOCKED", detail="abi/ not implemented")
    # Determinism: rebuilding DOS16 twice must give identical bytes.
    hashes = []
    for _ in range(2):
        run([sys.executable, SHZ / "dos16" / "build.py"], capture=True, timeout=600)
        hashes.append((sha256_file(BUILD / "dos16" / "command.com"), sha256_file(BUILD / "dos16" / "kernel.sys"),
                       sha256_file(BUILD / "dos16" / "shizukudos-dos16-hd32.img")))
    record(results, "DOS16 build is reproducible (kernel, shell, image)", "PASS" if hashes[0] == hashes[1] else "FAIL",
           detail=hashes[0][2][:16])
    manifest = shzlib.load_manifest()
    for name, spec in manifest["upstreams"].items():
        head = subprocess.run(["git", "-C", str(shzlib.UPSTREAM_DIR / name), "rev-parse", "HEAD"],
                              capture_output=True, text=True).stdout.strip()
        record(results, f"upstream {name} pinned at {spec['commit'][:12]}", "PASS" if head == spec["commit"] else "FAIL",
               detail=head[:12])


def suite_boot(results):
    ok = run_script(results, "DOS16 on legacy BIOS (SeaBIOS, real Real Mode) [KVM]",
                    [SHZ / "dos16" / "test_csm.py", "--accel", "kvm"], expect_marker="PASS")
    run_script(results, "DOS16 on legacy BIOS (SeaBIOS) [TCG software CPU]",
               [SHZ / "dos16" / "test_csm.py", "--accel", "tcg", "--timeout", "240"], timeout=400,
               expect_marker="PASS")
    l1_vmx = Path("/sys/module/kvm_intel/parameters/nested").exists() and \
        Path("/sys/module/kvm_intel/parameters/nested").read_text().strip() in ("Y", "1")
    if not l1_vmx:
        record(results, "UEFI Supervisor: DOS16 in virtual Real Mode (Intel VMX)", "BLOCKED",
               detail="L0 lacks nested VMX; a TCG boot would not exercise the VMX backend")
        return
    build_ok = (BUILD / "supervisor" / "esp.img").exists()
    if not build_ok:
        run([sys.executable, SHZ / "supervisor" / "build.py"], capture=True, timeout=600)
    run_script(results, "UEFI Supervisor: DOS16 in virtual Real Mode (Intel VMX)",
               [SHZ / "supervisor" / "test_qemu.py"], timeout=400, expect_marker="PASS")
    run_script(results, "negative: VMX hidden from L1 -> loader refuses and returns to firmware",
               [SHZ / "supervisor" / "test_qemu.py", "--no-vmx", "--timeout", "40"], timeout=200, expect_marker="PASS")
    record(results, "AMD SVM backend", "BLOCKED", detail="loader detects SVM; backend not implemented, no AMD host")
    record(results, "Kernel32 (Protected Mode) domain", "BLOCKED", detail="not implemented")
    record(results, "Kernel64 (Long Mode) domain", "BLOCKED", detail="not implemented")


def suite_interkernel(results):
    abi = SHZ / "abi" / "test_abi.py"
    if abi.exists():
        run_script(results, "interkernel ABI host model + fuzz", [abi])
    else:
        record(results, "interkernel ABI host model", "BLOCKED", detail="not implemented")
    record(results, "Kernel32 <-> Kernel64 guest exchange", "BLOCKED", detail="kernels not implemented")


def suite_win64(results):
    for name in ("PE32+ loader host tests", "Kernel64 user-mode process", "Win64 console app", "external Win64 app"):
        record(results, name, "BLOCKED", detail="Win64 subsystem not implemented")


REGRESSION_STEPS = [
    ("platform build", ["platform/build.py"]),
    ("platform host tests (contracts, sanitizers, PE structure)", ["platform/test.py"]),
    ("ABI32 build", ["platform/abi32/build.py"]),
    ("ABI32 packer tests", ["platform/abi32/test_packer.py"]),
    ("NTWrapper9x VxD build", ["ntwrapper/vxd/build.py"]),
    ("NTWrapper9x VxD tests", ["ntwrapper/vxd/test.py"]),
    ("freestanding memory tests", ["platform/freestanding/test.py"]),
    ("USB descriptor parser tests", ["drivers/usb_native/test.py"]),
    ("ShizukuDOS 0.1-era UEFI x64 build", ["shizukudos/uefi/build.py"]),
    ("ShizukuDOS 0.1-era UEFI host contract", ["shizukudos/uefi/test.py"]),
    ("UEFI x64 -> own 32-bit protected-mode kernel (build)", ["shizukudos/uefi32/build.py"]),
    ("UEFI x64 -> own 32-bit protected-mode kernel (host contract)", ["shizukudos/uefi32/test.py"]),
    ("AHCI native core", ["drivers/ahci_native/test.py"]),
    ("FAT32 native reader", ["drivers/fat_native/test.py"]),
    ("xHCI native core", ["drivers/xhci_native/test.py"]),
    ("USB EP0 transfers", ["drivers/xhci_usb/test.py"]),
]
REGRESSION_QEMU = [
    ("UEFI x64 boot under KVM (existing ShizukuDOS UEFI)", "shizukudos/uefi/test_qemu.py"),
    ("UEFI x64 -> 32-bit PM handoff under KVM", "shizukudos/uefi32/test_qemu.py"),
]


def regression_tree():
    """Existing scripts create build/ directories next to their sources. Some of those are
    dangling symlinks into /dev/shm left by an earlier session, so the documented sequence is
    run on a disposable copy of the working tree; the user's tree is never modified."""
    dest = BUILD / "regression-tree"
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    run(["rsync", "-a", "--exclude=.git", "--exclude=build", "--exclude=third_party", "--exclude=__pycache__",
         "--exclude=vm/disks", "--exclude=vm/media", "--exclude=benchmarks/media", "--exclude=site",
         f"{REPO}/", f"{dest}/"], timeout=600)
    return dest


def suite_win98_regression(results):
    win98 = REPO / "build" / "win98-lab"
    tree = regression_tree()
    record(results, "isolated copy of the working tree (existing build dirs may be dangling /dev/shm links)",
           "PASS", detail=str(tree))
    for name, argv in REGRESSION_STEPS:
        script = tree / argv[0]
        if not script.exists():
            record(results, f"existing regression: {name}", "SKIP", detail="script absent")
            continue
        proc = run([sys.executable, script, *argv[1:]], cwd=tree, capture=True, check=False, timeout=900)
        last = (proc.stdout or "").strip().splitlines()[-1:] or [""]
        record(results, f"existing regression: {name}", "PASS" if proc.returncode == 0 else "FAIL",
               detail=last[0][:160], exit_code=proc.returncode, command=f"python3 {argv[0]}")
    if Path(qemu_path()).exists() and Path("/usr/share/edk2/ovmf/OVMF_CODE.fd").exists():
        for name, script in REGRESSION_QEMU:
            argv = [tree / script, "--qemu", qemu_path(), "--firmware-code", "/usr/share/edk2/ovmf/OVMF_CODE.fd",
                    "--firmware-vars", "/usr/share/edk2/ovmf/OVMF_VARS.fd"]
            if not argv[0].exists():
                record(results, f"existing regression: {name}", "SKIP", detail="script absent")
                continue
            proc = run([sys.executable, *argv], cwd=tree, capture=True, check=False, timeout=300)
            last = (proc.stdout or proc.stderr or "").strip().splitlines()[-1:] or [""]
            record(results, f"existing regression: {name}", "PASS" if proc.returncode == 0 else "FAIL",
                   detail=last[0][:160], exit_code=proc.returncode)
    else:
        record(results, "existing QEMU/UEFI regressions", "BLOCKED", detail="qemu-kvm or OVMF missing")
    if win98.exists():
        record(results, "installed Windows 98 checkpoint present (user-provided asset)", "PASS", detail=str(win98))
        record(results, "native Windows 98 guest regression (NTW32/GDI/VxD trials)", "BLOCKED",
               detail="needs the private win98lab supervisor and ~6 GiB RAM/20 GiB disk reserve; not run here")
    else:
        record(results, "installed Windows 98 checkpoint present (user-provided asset)", "BLOCKED",
               detail="no build/win98-lab")
    record(results, "Notepad++ launch/edit/save regression", "SKIP",
           detail="USER_REPORTED only; no guest run performed by this suite")


SUITES = {"host": suite_host, "boot": suite_boot, "interkernel": suite_interkernel, "win64": suite_win64,
          "win98-regression": suite_win98_regression}


def cmd_test(args):
    results = []
    SUITES[args.suite](results)
    counts = {s: sum(1 for r in results if r["status"] == s) for s in shzlib.RESULTS}
    complete = counts["FAIL"] == 0 and counts["SKIP"] == 0 and counts["BLOCKED"] == 0
    summary = {"suite": args.suite, "utc": shzlib.utc_now(), "counts": counts,
               "verdict": "VERIFIED" if complete else ("FAILED" if counts["FAIL"] else "INCOMPLETE"),
               "git": shzlib.git_state(), "results": results}
    out = BUILD / "results"
    shzlib.write_json(out / f"{args.suite}-{summary['utc'].replace(':', '')}.json", summary)
    shzlib.write_json(out / f"{args.suite}-latest.json", summary)
    print(f"\nsuite {args.suite}: {counts} -> {summary['verdict']}")
    return 1 if counts["FAIL"] else 0


# ------------------------------------------------------------------ package
def cmd_package(args):
    rev = shzlib.git_state()
    stamp = rev["revision"][:12] + ("-dirty" if rev["dirty"] else "")
    name = f"shizukudos-10.0-{args.channel}-{stamp}"
    out = BUILD / "packages"
    out.mkdir(parents=True, exist_ok=True)
    zpath = out / f"{name}.zip"
    files = []
    for sub in ("dos16", "supervisor"):
        base = BUILD / sub
        for item in ("build-result.json", "BOOTX64.EFI", "esp.img", "kernel.sys", "command.com",
                     "shizukudos-dos16-hd32.img", "vbios.bin", "payload.bin"):
            if (base / item).exists():
                files.append((base / item, f"artifacts/{sub}/{item}"))
        for result in base.glob("run-*/result.json"):
            files.append((result, f"evidence/{sub}/{result.parent.name}-result.json"))
    for item in ("shizukudos/dos16", "shizukudos/supervisor", "shizukudos/tools", "shizukudos/upstream",
                 "docs/shizukudos10", "licenses"):
        for path in sorted((REPO / item).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                files.append((path, f"source/{path.relative_to(REPO)}"))
    # GPL source offer: the exact upstream trees the binaries were built from.
    for upstream in shzlib.load_manifest()["upstreams"]:
        tree = shzlib.UPSTREAM_DIR / upstream
        if tree.exists():
            tar = out / f"{upstream}-{shzlib.load_manifest()['upstreams'][upstream]['commit'][:12]}.tar.gz"
            run(["tar", "--exclude=.git", "-czf", tar, "-C", tree.parent, upstream], timeout=300)
            files.append((tar, f"upstream-source/{tar.name}"))
    excluded = ("win98", "windows98", ".iso", ".qcow2", ".vdi", "OVMF")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        manifest = {"channel": args.channel, "git": rev, "utc": shzlib.utc_now(), "files": {}}
        for src, arc in files:
            if any(x in str(src) for x in excluded):
                continue
            z.write(src, arc)
            manifest["files"][arc] = sha256_file(src)
        z.writestr("PACKAGE-MANIFEST.json", json.dumps(manifest, indent=2))
    (out / f"{name}.zip.sha256").write_text(f"{sha256_file(zpath)}  {zpath.name}\n")
    print(json.dumps({"package": str(zpath), "sha256": sha256_file(zpath), "files": len(manifest["files"]),
                      "note": "no Windows media, keys, VM disks or firmware images included"}, indent=2))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("doctor")
    p.add_argument("--guest", action="store_true", help="boot the Supervisor and report capabilities seen from inside")
    p = sub.add_parser("build")
    p.add_argument("--profile", choices=sorted(PROFILES), required=True)
    p = sub.add_parser("test")
    p.add_argument("--suite", choices=sorted(SUITES), required=True)
    p = sub.add_parser("package")
    p.add_argument("--channel", choices=("dev",), required=True)
    args = parser.parse_args()
    return {"doctor": cmd_doctor, "build": cmd_build, "test": cmd_test, "package": cmd_package}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
