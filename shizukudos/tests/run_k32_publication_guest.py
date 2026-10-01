#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build/run isolated Kernel32 startup-publication component regressions.

Runs the existing complete Kernel32 standalone self-tests and evaluator, including
ring-3 fault containment and page reclamation. No Windows 98 or SMP integration
claim follows from this component profile.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import kbuild  # noqa: E402
import run_k32_standalone  # noqa: E402


def source_hashes():
    paths = {p for name in ("kernel32", "kcommon", "abi") for p in (HERE.parent / name).rglob("*")
             if p.is_file() and p.suffix in (".c", ".h", ".asm", ".ld")}
    paths.update(HERE.parent / "kernel64/standalone" / name for name in ("boot_pm.asm", "boot32.c", "boot.ld"))
    paths.update((HERE.parent / "kbuild.py", HERE.parent / "tools/shzlib.py", Path(__file__).resolve()))
    return {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--build", action="store_true", help="build only Kernel32 standalone and its boot stub")
    ap.add_argument("--kernel-dir", type=Path, default=REPO / "build/pma-k32-publication/kernel32s")
    ap.add_argument("--qemu", default="/usr/libexec/qemu-kvm")
    ap.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    kernel_dir = args.kernel_dir.resolve()
    if args.build:
        if kernel_dir.name != "kernel32s":
            ap.error("--build requires --kernel-dir ending in kernel32s")
        before = source_hashes()
        kbuild.BUILD = kernel_dir.parent
        kernel = kbuild.build_kernel("kernel32s", "kernel32", kbuild.K32_FLAGS + ["-DSHZ_STANDALONE"],
                                    "elf32", "elf_i386", "KERNEL32S.BIN",
                                    extra_c=[kbuild.SHZ / "kernel32/standalone/standalone32.c"])
        stub = kbuild.build_standalone_stub(k32=True)
        if before != source_hashes():
            raise RuntimeError("Kernel32 build inputs changed during build; no verified receipt written")
        receipt = {"profile": "kernel32-standalone-publication", "sources_sha256": before,
                   "kernel_sha256": kernel["sha256"], "elf_sha256": kernel["elf_sha256"],
                   "stub_sha256": stub["sha256"], "bytes": kernel["bytes"],
                   "commands": [[str(x) for x in command] for command in kernel["commands"]]}
        (kernel_dir.parent / "kernel32s-build-result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    run_k32_standalone.K32S = kernel_dir
    artifacts = (kernel_dir / "boot.elf", kernel_dir / "KERNEL32S.BIN")
    before_artifacts = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts}
    sys.argv = ["run_k32_standalone.py", "--qemu", args.qemu, "--accel", args.accel,
                "--timeout", str(args.timeout), "--out", str(args.out)]
    status = run_k32_standalone.main()
    stable = before_artifacts == {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts}
    receipt_path = args.out / "result.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["artifacts_sha256"] = before_artifacts
    receipt["artifacts_stable"] = stable
    if not stable:
        receipt["status"] = "FAIL"
        receipt["checks"].append({"check": "guest input artifacts unchanged during execution", "status": "FAIL"})
        status = 1
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
