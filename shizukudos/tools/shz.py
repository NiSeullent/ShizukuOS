#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""ShizukuDOS 10.0 build / test / package driver.

    shz.py doctor [--guest]
    shz.py build --profile {bios-legacy,uefi-multikernel,bios-multikernel,dual-bios-uefi-csm}
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
import qemu as qemu_tools  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD, REPO, SHZ, run, sha256_file  # noqa: E402

PROFILES = {
    "bios-legacy": {
        "summary": "Legacy BIOS/CSM -> real Real Mode -> FreeDOS DOS16",
        "steps": ["dos16/build.py"],
        "status": "implemented (DOS16 only; no Kernel32/Kernel64 entry on the legacy BIOS path)",
    },
    "uefi-multikernel": {
        "summary": "UEFI x64 -> Supervisor (Intel VMX) -> virtual Real Mode DOS16",
        "steps": ["dos16/build.py", "kbuild.py", "win64/build.py", "supervisor/build.py"],
        "status": "built: DOS16, Kernel32, Kernel64 + Win64 initrd; running them needs Intel VMX in L1 "
                  "(see `test --suite boot`); without VMX the loader's boot manager chain-loads CSMWrap "
                  "(legacy BIOS profile) when \\EFI\\SHIZUKU\\CSMWRAP.EFI is on the boot volume",
    },
    "bios-multikernel": {
        "summary": "BIOS loader -> Supervisor cold launch -> DOS16 / Win98 / Kernel64",
        "steps": [],
        "status": "not implemented",
    },
    "dual-bios-uefi-csm": {
        "summary": "One disk (dual.img): legacy BIOS -> MBR -> FreeDOS DOS16, and UEFI -> CSMWrap (external, "
                   "LGPL-2.1) -> SeaBIOS CSM16 (LGPL-3.0) -> the same MBR -> FreeDOS DOS16",
        "steps": ["csm/build.py", "dos16/build.py"],
        "status": "implemented (DOS16 only); the UEFI path needs >= 2 logical CPUs because CSMWrap keeps one AP "
                  "as its system thread",
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
    for name, path in (("qemu-kvm", qemu_path()), ("ovmf_code", qemu_tools.DEFAULT_OVMF_CODE),
                       ("ovmf_vars", qemu_tools.DEFAULT_OVMF_VARS)):
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
    return qemu_tools.DEFAULT_QEMU if Path(qemu_tools.DEFAULT_QEMU).exists() else (shutil.which("qemu-system-x86_64") or "")


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
        script = SHZ / step
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
    # Determinism: rebuilding CSMWrap twice must give identical bytes (fixed BUILD_VERSION, no git describe).
    hashes = []
    for _ in range(2):
        run([sys.executable, SHZ / "csm" / "build.py"], capture=True, timeout=1800)
        hashes.append(tuple(sha256_file(BUILD / "csm" / f) for f in ("CSMWRAP.EFI", "Csm16.bin", "vgabios.bin")))
    record(results, "CSMWrap build is reproducible (CSMWRAP.EFI, Csm16.bin, vgabios.bin)",
           "PASS" if hashes[0] == hashes[1] else "FAIL", detail=hashes[0][0][:16])
    # Determinism: rebuilding DOS16 twice must give identical bytes.
    hashes = []
    for _ in range(2):
        run([sys.executable, SHZ / "dos16" / "build.py"], capture=True, timeout=600)
        hashes.append((sha256_file(BUILD / "dos16" / "command.com"), sha256_file(BUILD / "dos16" / "kernel.sys"),
                       sha256_file(BUILD / "dos16" / "shizukudos-dos16-hd32.img"),
                       sha256_file(BUILD / "dos16" / "shizukudos-dos16-dual.img")))
    record(results, "DOS16 build is reproducible (kernel, shell, image)", "PASS" if hashes[0][:3] == hashes[1][:3] else "FAIL",
           detail=hashes[0][2][:16])
    record(results, "DOS16 dual BIOS/UEFI image is reproducible (hd32 content + T_INTS + CSMWrap ESP files)",
           "PASS" if hashes[0][3] == hashes[1][3] else "FAIL", detail=hashes[0][3][:16])
    manifest = shzlib.load_manifest()
    for name, spec in manifest["upstreams"].items():
        head = subprocess.run(["git", "-C", str(shzlib.UPSTREAM_DIR / name), "rev-parse", "HEAD"],
                              capture_output=True, text=True).stdout.strip()
        subs = {sub: subprocess.run(["git", "-C", str(shzlib.UPSTREAM_DIR / name / sub), "rev-parse", "HEAD"],
                                    capture_output=True, text=True).stdout.strip() == info["commit"]
                for sub, info in spec.get("submodules", {}).items()}
        ok = head == spec["commit"] and all(subs.values())
        record(results, f"upstream {name} pinned at {spec['commit'][:12]}" + (f" (+{len(subs)} submodules)" if subs else ""),
               "PASS" if ok else "FAIL", detail=head[:12] + ("" if all(subs.values()) else
                                                             f" submodule drift: {[k for k, v in subs.items() if not v]}"))


def l1_vmx_available():
    nested = Path("/sys/module/kvm_intel/parameters/nested")
    return Path("/dev/kvm").exists() and nested.exists() and nested.read_text().strip() in ("Y", "1")


def supervisor_checks(prefix):
    """Checks named `prefix*` from the last Supervisor run, as (name, status, detail); None if it never ran."""
    rj = BUILD / "supervisor" / "run-uefi-vreal" / "result.json"
    if not rj.exists():
        return None
    return [(c["check"], c["status"], c.get("detail", "")) for c in json.loads(rj.read_text()).get("checks", [])
            if c["check"].startswith(prefix)]


def record_domain(results, label, prefix, vmx_reason):
    checks = supervisor_checks(prefix)
    if checks is None:
        record(results, label, "BLOCKED", detail=vmx_reason)
    elif not checks:
        record(results, label, "FAIL", detail=f"the Supervisor run contains no `{prefix}` checks (domain not started)")
    else:
        bad = [c for c in checks if c[1] != "PASS"]
        record(results, label, "FAIL" if bad else "PASS",
               detail=(f"{bad[0][0]}: {bad[0][2]}" if bad else f"{len(checks)} guest-evidence checks"))


def suite_bootmgr(results):
    """UEFI boot manager (loader BOOT.INI policy + CSMWrap legacy fallback) and the vBIOS host checks.
    Both run under TCG and need no VMX; neither is evidence for the VMX Supervisor path."""
    label = ("UEFI boot manager [TCG]: no VMX -> CSMWrap/SeaBIOS CSM16 legacy-boots FreeDOS from one MBR disk; "
             "mode=csm/supervisor, missing/invalid CSM image, malformed BOOT.INI, 1 CPU, same disk on SeaBIOS")
    vlabel = ("vBIOS host checks [TCG + host]: ROM reset path and INT 1Ah RTC/INT 1Eh under QEMU -bios; "
              "bios.c INT 13h/15h/16h/1Ah back end under ASan/UBSan (not a VMX run)")
    try:
        run([sys.executable, SHZ / "supervisor" / "build.py"], capture=True, timeout=900)
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        for name in (label, vlabel):
            record(results, name, "FAIL", detail=f"shizukudos/supervisor/build.py failed: {str(exc)[-300:]}")
        return
    for name, script, result_json, timeout in (
            (label, "test_bootmgr.py", BUILD / "bootmgr" / "result.json", 1800),
            (vlabel, "test_vbios.py", BUILD / "supervisor" / "vbios-host-test" / "result.json", 600)):
        result_json.unlink(missing_ok=True)
        proc = run([sys.executable, SHZ / "supervisor" / script], capture=True, check=False, timeout=timeout)
        data = json.loads(result_json.read_text()) if result_json.exists() else {}
        ok = proc.returncode == 0 and data.get("status") == "PASS"
        if "summary" in data:
            detail = ", ".join(f"{k} {v}" for k, v in data["summary"].items())
        elif data.get("checks"):
            detail = f"{sum(c['status'] == 'PASS' for c in data['checks'])}/{len(data['checks'])} checks"
        else:
            detail = ((proc.stdout or "").strip().splitlines() or ["no output"])[-1]
        record(results, name, "PASS" if ok else "FAIL", detail=detail, exit_code=proc.returncode,
               command=f"{sys.executable} shizukudos/supervisor/{script}", evidence=str(result_json))


def suite_boot(results):
    ok = run_script(results, "DOS16 on legacy BIOS (SeaBIOS, real Real Mode) [KVM]",
                    [SHZ / "dos16" / "test_csm.py", "--accel", "kvm"], expect_marker="PASS")
    run_script(results, "DOS16 on legacy BIOS (SeaBIOS) [TCG software CPU]",
               [SHZ / "dos16" / "test_csm.py", "--accel", "tcg", "--timeout", "240"], timeout=400,
               expect_marker="PASS")
    # One disk, two firmware paths (TCG, identical q35/AHCI/256 MiB/2 vCPU hardware; only the firmware differs).
    dual_ok = run_script(results, "DOS16 dual image on legacy BIOS (QEMU SeaBIOS, q35/AHCI) + T_INTS [TCG]",
                         [SHZ / "dos16" / "test_csm.py", "--image", "dual", "--machine", "q35", "--memory", "256",
                          "--smp", "2", "--accel", "tcg", "--timeout", "240", "--run-name", "run-csm-dual"],
                         timeout=400, expect_marker="PASS")
    run_script(results, "DOS16 dual image on UEFI (OVMF, no CSM) -> CSMWrap -> SeaBIOS CSM16, T_INTS compared with "
                        "the legacy run [TCG]",
               [SHZ / "csm" / "test_qemu.py", "--accel", "tcg", "--timeout", "300", "--memory", "256", "--smp", "2",
                *(["--legacy-result", BUILD / "dos16" / "run-csm-dual" / "result.json"] if dual_ok else [])],
               timeout=900, expect_marker="PASS")
    suite_bootmgr(results)
    run_script(results, "Kernel32 (Protected Mode) on QEMU, standalone stub (no Supervisor/VMX)",
               [SHZ / "tests" / "run_k32_standalone.py"], timeout=300, expect_marker="PASS")
    run_script(results, "Kernel64 (Long Mode) + Win64 apps on QEMU, standalone stub (no Supervisor/VMX)",
               [SHZ / "tests" / "run_k64_standalone.py"], timeout=400, expect_marker="PASS")
    if not l1_vmx_available():
        reason = "L0 lacks /dev/kvm or nested VMX; a TCG boot would not exercise the VMX backend"
        for label in ("UEFI Supervisor: DOS16 in virtual Real Mode (Intel VMX)", "Supervisor-run Kernel32 domain (Intel VMX)",
                      "Supervisor-run Kernel64 domain (Intel VMX)"):
            record(results, label, "BLOCKED", detail=reason)
        return
    build_ok = (BUILD / "supervisor" / "esp.img").exists()
    if not build_ok:
        run([sys.executable, SHZ / "supervisor" / "build.py"], capture=True, timeout=600)
    run_script(results, "UEFI Supervisor: DOS16 in virtual Real Mode (Intel VMX)",
               [SHZ / "supervisor" / "test_qemu.py"], timeout=400, expect_marker="PASS")
    run_script(results, "negative: VMX hidden from L1 -> loader refuses and returns to firmware",
               [SHZ / "supervisor" / "test_qemu.py", "--no-vmx", "--timeout", "40"], timeout=200, expect_marker="PASS")
    record(results, "AMD SVM backend", "BLOCKED", detail="loader detects SVM; backend not implemented, no AMD host")
    record_domain(results, "Supervisor-run Kernel32 domain (Intel VMX)", "K32 ", "no Supervisor result")
    record_domain(results, "Supervisor-run Kernel64 domain (Intel VMX)", "K64 ", "no Supervisor result")


def suite_interkernel(results):
    abi = SHZ / "abi" / "test_abi.py"
    if abi.exists():
        run_script(results, "interkernel ABI host model + fuzz", [abi])
    else:
        record(results, "interkernel ABI host model", "BLOCKED", detail="not implemented")
    record(results, "Kernel32 <-> Kernel64 guest exchange", "BLOCKED", detail="kernels not implemented")


def suite_win64(results):
    run_script(results, "PE32+ loader host tests (parser, fuzz, ASan/UBSan)", [SHZ / "win64" / "tests" / "test_pe_parse.py"])
    run_script(results, "Win64 runtime build: ntdll.dll + kernel32.dll + test apps (-Werror)", [SHZ / "win64" / "build.py"])
    run_script(results, "Kernel32/Kernel64 build (separate ELF32/ELF64 images)", [SHZ / "kbuild.py"])
    run_script(results, "Kernel64 + Win64 apps on QEMU (standalone stub, no Supervisor/VMX): self-tests, T_HELLO.EXE exit 7",
               [SHZ / "tests" / "run_k64_standalone.py"], timeout=400, expect_marker="PASS")
    reason = "needs Intel VMX in L1 (/dev/kvm + kvm_intel nested); run `test --suite boot` on such a host"
    if l1_vmx_available() and not supervisor_checks("Win64: "):
        run([sys.executable, SHZ / "supervisor" / "build.py"], capture=True, timeout=600)
        run([sys.executable, SHZ / "supervisor" / "test_qemu.py"], capture=True, check=False, timeout=400)
    record_domain(results, "Kernel64 user-mode process + Win64 console app (T_HELLO.EXE from WIN64.IMG)", "Win64: ", reason)
    record(results, "external Win64 app", "BLOCKED", detail="no third-party PE32+ application is supplied or run")


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
    ("UEFI x64 boot (existing ShizukuDOS UEFI)", "shizukudos/uefi/test_qemu.py"),
    ("UEFI x64 -> 32-bit PM handoff", "shizukudos/uefi32/test_qemu.py"),
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
    if Path(qemu_path()).exists() and Path(qemu_tools.DEFAULT_OVMF_CODE).exists():
        accel = "kvm" if Path("/dev/kvm").exists() else "tcg"      # neither test needs VMX; the accelerator is recorded
        for name, script in REGRESSION_QEMU:
            name = f"{name} [{accel.upper()}]"
            argv = [tree / script, "--qemu", qemu_path(), "--firmware-code", qemu_tools.DEFAULT_OVMF_CODE,
                    "--firmware-vars", qemu_tools.DEFAULT_OVMF_VARS, "--accel", accel]
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


def suite_iso(results):
    """Integrated Shizuku SE ISO: build if absent, then boot it (BIOS El Torito, UEFI El Torito) and record every check."""
    iso = REPO / "build" / "windows98-shizuku-second-edition.iso"
    if not iso.exists():
        run_script(results, "build the integrated Shizuku SE ISO", [REPO / "tools" / "build_shizuku_se_iso.py", "--skip-qemu"],
                   timeout=1800)
    run([sys.executable, REPO / "tools" / "test_shizuku_se_iso.py"], capture=True, check=False, timeout=900)
    rj = REPO / "build" / "shizuku-se-iso-tests" / "result.json"
    if not rj.exists():
        record(results, "ISO boot harness", "FAIL", detail="tools/test_shizuku_se_iso.py produced no result.json")
        return
    for r in json.loads(rj.read_text())["results"]:
        record(results, f"iso {r['group']}: {r['test']}", r["status"], detail=(r.get("detail") or "")[:200])


SUITES = {"host": suite_host, "boot": suite_boot, "interkernel": suite_interkernel, "win64": suite_win64,
          "win98-regression": suite_win98_regression, "iso": suite_iso}


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
    for sub in ("dos16", "csm", "supervisor"):
        base = BUILD / sub
        for item in ("build-result.json", "BOOTX64.EFI", "esp.img", "kernel.sys", "command.com",
                     "shizukudos-dos16-hd32.img", "shizukudos-dos16-dual.img", "csmwrap.ini", "CSMWRAP.EFI",
                     "Csm16.bin", "vgabios.bin", "vbios.bin", "payload.bin"):
            if (base / item).exists():
                files.append((base / item, f"artifacts/{sub}/{item}"))
        for result in base.glob("run-*/result.json"):
            files.append((result, f"evidence/{sub}/{result.parent.name}-result.json"))
    for item in ("shizukudos/dos16", "shizukudos/csm", "shizukudos/supervisor", "shizukudos/tools", "shizukudos/upstream",
                 "docs/shizukudos10", "licenses"):
        for path in sorted((REPO / item).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                files.append((path, f"source/{path.relative_to(REPO)}"))
    # GPL/LGPL source offer: the exact upstream trees the binaries were built from (submodules included:
    # CSMWrap LGPL-2.1 + SeaBIOS LGPL-3.0 + its BSD/MIT/Apache parts).
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
