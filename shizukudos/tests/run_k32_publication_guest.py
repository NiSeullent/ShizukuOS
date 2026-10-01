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
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runner_hashes():
    paths = (Path(__file__).resolve(), HERE / "run_k32_standalone.py", HERE / "run_k64_standalone.py",
             HERE.parent / "kbuild.py", HERE.parent / "tools/shzlib.py", HERE.parent / "tools/qemu.py")
    return {str(p.relative_to(REPO)): digest(p) for p in paths}


# Capture evaluator/module files before importing them, so the receipt cannot
# silently bind newer on-disk bytes to code already loaded from older bytes.
LOADED_RUNNER_HASHES = runner_hashes()
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import kbuild  # noqa: E402
import run_k32_standalone  # noqa: E402


def source_hashes():
    paths = {p for name in ("kernel32", "kcommon", "abi") for p in (HERE.parent / name).rglob("*")
             if p.is_file() and p.suffix in (".c", ".h", ".asm", ".ld")}
    paths.update(HERE.parent / "kernel64/standalone" / name for name in
                 ("boot_pm.asm", "boot32.c", "boot.ld", "memholes.h"))
    paths.update(REPO / name for name in LOADED_RUNNER_HASHES)
    return {str(p.relative_to(REPO)): digest(p) for p in sorted(paths)}


def artifacts(kernel_dir):
    return {"kernel_sha256": kernel_dir / "KERNEL32S.BIN", "stub_sha256": kernel_dir / "boot.elf",
            "elf_sha256": kernel_dir / "kernel32s.elf"}


def artifact_hashes(kernel_dir):
    return {str(path): digest(path) if path.is_file() else "unavailable" for path in artifacts(kernel_dir).values()}


def validate_receipt(receipt_path, kernel_dir):
    if not receipt_path.is_file():
        raise ValueError(f"source-bound build receipt missing: {receipt_path}")
    raw = receipt_path.read_bytes()
    try:
        built = json.loads(raw)
    except (ValueError, UnicodeError) as error:
        raise ValueError(f"invalid source-bound build receipt: {error}") from error
    if not isinstance(built, dict) or built.get("receipt_version") != 2 or \
            built.get("profile") != "kernel32-standalone-publication":
        raise ValueError("unsupported build receipt; use --build in a fresh isolated kernel directory")
    before, after = built.get("sources_sha256_before"), built.get("sources_sha256_after")
    if not isinstance(before, dict) or not before or not isinstance(after, dict):
        raise ValueError("build receipt has no before/after source snapshots")
    if before != after or built.get("sources_sha256") != before:
        raise ValueError("build source snapshots differ")
    current = source_hashes()
    if before.keys() != current.keys():
        missing, extra = sorted(current.keys() - before.keys()), sorted(before.keys() - current.keys())
        raise ValueError(f"source closure mismatch: missing={missing}, extra={extra}")
    for name, expected in before.items():
        if current[name] != expected:
            raise ValueError(f"build source changed or unavailable: {name}")
    verified_artifacts = artifact_hashes(kernel_dir)
    for key, path in artifacts(kernel_dir).items():
        if not path.is_file() or built.get(key) != verified_artifacts[str(path)]:
            raise ValueError(f"artifact hash mismatch: {path}")
    if runner_hashes() != LOADED_RUNNER_HASHES:
        raise ValueError("runner or evaluator changed while loading; restart the runner")
    return built, hashlib.sha256(raw).hexdigest(), current, verified_artifacts


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--build", action="store_true", help="build only Kernel32 standalone and its boot stub")
    ap.add_argument("--kernel-dir", type=Path, default=REPO / "build/pma-k32-publication/kernel32s")
    ap.add_argument("--build-receipt", type=Path, help="version 2 source-bound receipt (default: kernel-dir parent)")
    ap.add_argument("--qemu", default="/usr/libexec/qemu-kvm")
    ap.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    kernel_dir = args.kernel_dir.resolve()
    build_receipt = (args.build_receipt or kernel_dir.parent / "kernel32s-build-result.json").resolve()
    if any((args.out / name).exists() for name in ("result.json", "serial.log")):
        ap.error("output already contains evidence; choose a fresh --out directory")
    if args.build:
        if kernel_dir.name != "kernel32s":
            ap.error("--build requires --kernel-dir ending in kernel32s")
        if build_receipt.exists() or any(path.exists() for path in artifacts(kernel_dir).values()):
            ap.error("build artifacts or receipt already exist; choose a fresh --kernel-dir to preserve evidence")
        before = source_hashes()
        if runner_hashes() != LOADED_RUNNER_HASHES:
            ap.error("runner or evaluator changed while loading; restart the runner")
        kbuild.BUILD = kernel_dir.parent
        kernel = kbuild.build_kernel("kernel32s", "kernel32", kbuild.K32_FLAGS + ["-DSHZ_STANDALONE"],
                                    "elf32", "elf_i386", "KERNEL32S.BIN",
                                    extra_c=[kbuild.SHZ / "kernel32/standalone/standalone32.c"])
        stub = kbuild.build_standalone_stub(k32=True)
        after = source_hashes()
        if before != after:
            raise RuntimeError("Kernel32 build inputs changed during build; no verified receipt written")
        receipt = {"receipt_version": 2, "profile": "kernel32-standalone-publication", "sources_sha256": before,
                   "sources_sha256_before": before, "sources_sha256_after": after,
                   "kernel_sha256": kernel["sha256"], "elf_sha256": kernel["elf_sha256"],
                   "stub_sha256": stub["sha256"], "bytes": kernel["bytes"],
                   "commands": [[str(x) for x in command] for command in kernel["commands"]],
                   "utc": datetime.now(timezone.utc).isoformat()}
        build_receipt.parent.mkdir(parents=True, exist_ok=True)
        with build_receipt.open("x") as output:
            output.write(json.dumps(receipt, indent=2) + "\n")
    try:
        built, receipt_before, sources_before, before_artifacts = validate_receipt(build_receipt, kernel_dir)
    except (OSError, ValueError) as error:
        ap.error(str(error))
    run_k32_standalone.K32S = kernel_dir
    sys.argv = ["run_k32_standalone.py", "--qemu", args.qemu, "--accel", args.accel,
                "--timeout", str(args.timeout), "--out", str(args.out)]
    status = run_k32_standalone.main()
    after_artifacts = artifact_hashes(kernel_dir)
    stable = before_artifacts == after_artifacts
    receipt_after = digest(build_receipt) if build_receipt.is_file() else "unavailable"
    try:
        sources_after = source_hashes()
    except OSError as error:
        sources_after = {"snapshot_error": str(error)}
    receipt_path = args.out / "result.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["artifacts_sha256"] = before_artifacts
    receipt["artifacts_sha256_before"] = before_artifacts
    receipt["artifacts_sha256_after"] = after_artifacts
    receipt["artifacts_stable"] = stable
    receipt["build_receipt"] = str(build_receipt)
    receipt["build_receipt_sha256_before"] = receipt_before
    receipt["build_receipt_sha256_after"] = receipt_after
    receipt["build_receipt_stable"] = receipt_before == receipt_after
    receipt["build_sources_sha256"] = built["sources_sha256"]
    receipt["sources_sha256_before"] = sources_before
    receipt["sources_sha256_after"] = sources_after
    receipt["sources_stable"] = sources_before == sources_after
    receipt["runner_sources_sha256"] = LOADED_RUNNER_HASHES
    for name, okay in (("guest input artifacts unchanged during execution", stable),
                       ("source-bound build receipt unchanged during execution", receipt_before == receipt_after),
                       ("build and evaluator sources unchanged during execution", sources_before == sources_after)):
        receipt["checks"].append({"check": name, "status": "PASS" if okay else "FAIL"})
        if not okay:
            receipt["status"] = "FAIL"
            status = 1
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"{receipt['status']} (source-bound Kernel32 provenance)")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
