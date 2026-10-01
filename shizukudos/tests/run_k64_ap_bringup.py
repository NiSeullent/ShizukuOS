#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Require actual AP architecture, useful work and two-sided physical IPIs in normal main."""
import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PRODUCER = REPO / "shizukudos/tests/run_k64_native_firmware.py"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def expected_hash(cpu, loops):
    value = 0x5a17c0de ^ cpu
    for i in range(loops):
        value = (((value << 5) | (value >> 27)) & 0xffffffff) ^ 0x9e3779b9
        value = (value + i) & 0xffffffff
    return value


def evaluate(text, rc, cpus):
    workers = re.findall(r"SMP-AP CPU: cpu=(\d+) apic=(\d+) actual=(\d+) cr3=([0-9a-f]+) stack=([0-9a-f]+) "
                         r"gdt=([0-9a-f]+) idt=([0-9a-f]+) tss=([0-9a-f]+) hash=([0-9a-f]+) loops=(\d+) "
                         r"progress=(\d+) bsp_seen=(\d+) ap_seen=(\d+)", text)
    ipis = re.findall(r"SMP-AP IPI: cpu=(\d+) wake=(\d+) verify=(\d+) irqstack=([0-9a-f]+)", text)
    summary = re.findall(r"SMP-AP summary: discovered=(\d+) arch_online=(\d+) completed=(\d+) bad=(\d+) scheduler_cpus=(\d+)", text)
    correct = rc == 1 and "SHZ-EXIT:0\n" in text and len(workers) == len(ipis) == cpus and len(summary) == 1
    correct = correct and summary[0] == (str(cpus), str(cpus), str(cpus - 1), "0", "1")
    if correct:
        correct = {int(row[0]) for row in workers} == set(range(cpus)) and \
            {int(row[0]) for row in ipis} == set(range(cpus)) and len({row[1] for row in workers}) == cpus
        correct = correct and len({row[3] for row in workers}) == 1
        correct = correct and all(len({row[index] for row in workers}) == cpus for index in (4, 5, 6, 7))
        for row in workers:
            cpu, actual = int(row[0]), int(row[2])
            loops = 16000000 if cpu == 0 else 2000000
            correct = correct and cpu == actual and int(row[9]) == loops and int(row[8], 16) == expected_hash(cpu, loops)
            correct = correct and int(row[3], 16) >= 0xf00000 and int(row[3], 16) % 4096 == 0 and int(row[10]) > 1
            if cpu:
                correct = correct and row[11:] == ("1", "1")
        for cpu, wake, verify, stack in ipis:
            expected = 1 if int(cpu) else cpus - 1
            correct = correct and int(wake) == int(verify) == expected and bool(int(stack, 16))
        correct = correct and len({row[3] for row in ipis}) == cpus
    return bool(correct), {"worker_rows": len(workers), "ipi_rows": len(ipis), "summary": summary}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True, help="normal-main production build receipt")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cpus", type=int, choices=(2, 4), default=4)
    parser.add_argument("--expect-red", action="store_true", help="preserve missing-feature runtime RED, not a PASS")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    receipt_bytes = args.receipt.read_bytes()
    receipt_sha = hashlib.sha256(receipt_bytes).hexdigest()
    built = json.loads(receipt_bytes)
    if built.get("status") != "PASS":
        raise SystemExit("producer whole-kernel firmware gate must pass before this AP execution")
    spec = importlib.util.spec_from_file_location("kbuild", REPO / "shizukudos/kbuild.py")
    kbuild = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kbuild)
    def sources():
        return {**kbuild.source_hashes(), str(PRODUCER.relative_to(REPO)): digest(PRODUCER)}
    before = sources()
    if before != built["sources_sha256"]:
        raise SystemExit("complete compiled dependency closure differs from current sources")
    evaluator_sha = digest(__file__)
    inputs = built["compiled_inputs_sha256"]
    kernel = next(p for p in inputs if p.endswith("KERNEL64S.BIN"))
    stub = next(p for p in inputs if p.endswith("boot.elf"))
    tools = built["tools"]
    def stable():
        return sources() == before and digest(__file__) == evaluator_sha and digest(args.receipt) == receipt_sha and \
            all(digest(p) == h for p, h in inputs.items()) and \
            all(digest(row["path"]) == row["sha256"] for row in tools.values())
    if not stable():
        raise SystemExit("compiled input/evaluator/tool bytes changed before launch")
    serial = out / "serial.log"
    command = [tools["qemu"]["path"], "-machine", "pc", "-bios", tools["bios"]["path"], "-accel", "kvm",
               "-cpu", "max", "-m", "256", "-smp", str(args.cpus), "-kernel", stub, "-initrd", kernel,
               "-append", "shz.pma=test shz.smp=bringup", "-display", "none", "-monitor", "none",
               "-serial", f"file:{serial}", "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
    start = time.monotonic()
    try:
        run = subprocess.run(command, capture_output=True, text=True, timeout=60)
        rc, timeout, error = run.returncode, False, run.stderr
    except subprocess.TimeoutExpired as exc:
        rc, timeout, error = None, True, str(exc.stderr)
    (out / "qemu.log").write_text(error or "")
    text = serial.read_text(errors="replace") if serial.exists() else ""
    passed, evidence = evaluate(text, rc, args.cpus)
    unchanged = stable()
    observed_red = args.expect_red and not passed and not timeout and rc == 1 and "SHZ-EXIT:0\n" in text and \
        evidence["worker_rows"] == evidence["ipi_rows"] == 0 and "backend pending integration" in text
    valid = unchanged and not timeout and (observed_red if args.expect_red else passed)
    result = {"scope": "normal main AP bringup component; existing scheduler must still report1; not full SMP/Windows acceptance",
              "status": "RED" if observed_red else "PASS" if passed and unchanged else "FAIL",
              "expected_behavior": valid, "cpus": args.cpus, "command": command, "qemu_returncode": rc,
              "timed_out": timeout, "elapsed_seconds": time.monotonic() - start, "actual_evidence": evidence,
              "sources_sha256": before, "producer_receipt_sha256": receipt_sha, "evaluator_sha256": evaluator_sha,
              "inputs_sources_tools_unchanged": unchanged, "serial_sha256": digest(serial) if serial.exists() else None}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
