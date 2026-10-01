#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Require useful native Kernel64 scheduling on every requested logical CPU.

The first baseline is expected to fail: the current native kernel runs on its
BSP even when QEMU provides four CPUs. Existing BIOS AP hash experiments do not
substitute for this execution. This profile does not execute Windows VMM or the
Supervisor; those have separate integration gates.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
HELPERS = (HERE.parent / "kbuild.py", HERE.parent / "tools/shzlib.py")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def helper_hashes():
    return {str(path.relative_to(REPO)): digest(path) for path in HELPERS}


HELPERS_AT_IMPORT = helper_hashes()
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "tools"))
import kbuild  # noqa: E402


def item(name, okay, detail):
    return {"check": name, "status": "PASS" if okay else "FAIL", "detail": detail}


def evaluate(serial, rc, cpus):
    """The worker records are emitted by native C, never synthesized here."""
    summaries = re.findall(r"^K64 PMA summary: failures=(\d+) ticks=(\d+) switches=(\d+) preemptions=(\d+) "
                           r"wakeups=(\d+) timeouts=(\d+) ready=(\d+) live=(\d+) cpus=(\d+)$", serial, re.M)
    online = int(summaries[0][-1]) if len(summaries) == 1 else None
    workers = re.findall(r"^K64 SMP CPU: index=(\d+) apic=(\d+) online=1 switches=(\d+) useful_loops=(\d+)$",
                         serial, re.M)
    progress = re.findall(r"^K64 SMP progress: bsp_seen=(\d+) ap_seen=(\d+)$", serial, re.M)
    invariants = re.findall(r"^K64 SMP invariants: affinity_violations=(\d+) duplicate_running=(\d+) "
                            r"queue_errors=(\d+) wake_lost=(\d+) migrations=(\d+) ipi_wakes=(\d+) "
                            r"free_before=(\d+) free_after=(\d+)$", serial, re.M)
    worker_ok = len(workers) == cpus
    if worker_ok:
        records = [tuple(map(int, row)) for row in workers]
        worker_ok = {row[0] for row in records} == set(range(cpus)) and len({row[1] for row in records}) == cpus and \
            all(row[2] >= 2 and row[3] > 1000 for row in records)
    progress_ok = len(progress) == 1 and tuple(map(int, progress[0])) == (cpus - 1, cpus - 1)
    invariants_ok = len(invariants) == 1
    if invariants_ok:
        affinity, duplicate, queues, lost, migrations, ipi, before, after = map(int, invariants[0])
        invariants_ok = affinity == duplicate == queues == lost == 0 and migrations > 0 and ipi > 0 and before == after
    return [
        item("native guest terminates successfully", rc == 1 and len(re.findall(r"^SHZ-EXIT:0$", serial, re.M)) == 1 and
             "K64 EXCEPTION" not in serial, {"qemu_rc": rc}),
        item("actual scheduler reports all requested CPUs online", online == cpus,
             {"requested": cpus, "observed": online}),
        item("distinct CPUs each execute multiple real contexts and useful worker bodies", worker_ok, workers),
        item("BSP and AP useful work overlap with bidirectional observations", progress_ok, progress),
        item("affinity, queue ownership, remote wakes, migration and stack pages are conserved", invariants_ok, invariants),
    ]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--qemu", default="/usr/libexec/qemu-kvm")
    ap.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    ap.add_argument("--cpus", type=int, choices=(2, 4, 8), default=4)
    ap.add_argument("--build-dir", type=Path, required=True)
    ap.add_argument("--build-receipt", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args()
    if args.timeout < 1 or args.timeout > 600:
        ap.error("timeout must be between 1 and 600 seconds")
    kernel, stub = args.build_dir / "KERNEL64S.BIN", args.build_dir / "boot.elf"
    if not all(path.is_file() for path in (kernel, stub, args.build_receipt)):
        ap.error("kernel, Multiboot stub and source-bound receipt are required")
    receipt_bytes = args.build_receipt.read_bytes()
    receipt = json.loads(receipt_bytes)
    sources = receipt.get("sources_sha256", {})
    if not sources or sources != kbuild.source_hashes():
        ap.error("complete current source closure differs from the compiled input receipt")
    before = {str(path.resolve()): digest(path) for path in (kernel, stub)}
    built = receipt.get("kernels", {}).get("kernel64-standalone", {})
    if built.get("sha256") != before[str(kernel.resolve())] or built.get("stub_sha256") != before[str(stub.resolve())]:
        ap.error("compiled artifact bytes differ from the source-bound receipt")
    helpers_before = helper_hashes()
    if helpers_before != HELPERS_AT_IMPORT:
        ap.error("Python helpers changed after their import")
    runner_before, receipt_before = digest(Path(__file__)), hashlib.sha256(receipt_bytes).hexdigest()
    qemu_path = Path(args.qemu).resolve()
    qemu_before = digest(qemu_path)
    if qemu_before is None:
        ap.error("QEMU executable is unavailable")
    args.out.mkdir(parents=True, exist_ok=True)
    serial_path = args.out.resolve() / "serial.log"
    if serial_path.exists() or (args.out / "result.json").exists():
        ap.error("use a fresh output directory; historical evidence is preserved")
    command = [str(qemu_path), "-machine", "pc", "-accel", args.accel, "-cpu", "max", "-smp", str(args.cpus),
               "-m", "256", "-nodefaults", "-display", "none", "-kernel", str(stub.resolve()),
               "-initrd", str(kernel.resolve()), "-append", "shz.pma=test smp=on", "-serial", f"file:{serial_path}",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot"]
    started = time.monotonic()
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    timed_out = False
    try:
        output = proc.communicate(timeout=args.timeout)[0].decode(errors="replace")
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        output = proc.communicate()[0].decode(errors="replace")
    serial = serial_path.read_text(errors="replace") if serial_path.is_file() else ""
    sources_after, helpers_after = kbuild.source_hashes(), helper_hashes()
    after = {str(path.resolve()): digest(path) for path in (kernel, stub)}
    stable = before == after and receipt_before == digest(args.build_receipt) and sources == sources_after and \
        runner_before == digest(Path(__file__)) and helpers_before == helpers_after and qemu_before == digest(qemu_path)
    checks = evaluate(serial, proc.returncode, args.cpus)
    checks.append(item("guest and all source/evaluator/tool inputs remain unchanged", stable, {"stable": stable}))
    checks.append(item("native execution completes within its declared bound", not timed_out, {"timeout_seconds": args.timeout}))
    record = {"profile": "Kernel64 SMP native acceptance requirements", "scope": "Actual native Kernel64; no Windows VMM or Supervisor execution",
              "status": "PASS" if all(check["status"] == "PASS" for check in checks) else "FAIL", "checks": checks,
              "command": command, "qemu_rc": proc.returncode, "seconds": round(time.monotonic() - started, 2),
              "sources_sha256": sources, "sources_sha256_after": sources_after, "inputs_sha256": before,
              "inputs_sha256_after": after, "build_receipt_sha256": receipt_before,
              "build_receipt_sha256_after": digest(args.build_receipt), "runner_sha256": runner_before,
              "runner_sha256_after": digest(Path(__file__)), "helpers_sha256": helpers_before,
              "helpers_sha256_after": helpers_after, "qemu_sha256": qemu_before, "inputs_stable": stable,
              "serial_sha256": digest(serial_path), "qemu_output": output}
    (args.out / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    for check in checks:
        print(f"[{check['status']}] {check['check']}: {check['detail']}")
    return 0 if record["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
