#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Modeled negative controls for the native result verifier; no VM executed."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUNNER = REPO / "shizukudos/tests/run_k64_smp_boot.py"


def sources():
    return {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest() for p in (RUNNER, Path(__file__).resolve())}


def trace(runner, cpus=2, ipi=True):
    lines = ["SMP-ADMISSION: initial=1000 final=f00000 wrong-initial=-2 wrong-active=-2 IF-on=-2",
             "SMP-BOOT-PAGES: retired=1000 initial=1000 active=f00000 bootstrap=f0d000 low-pages=1 bad=0 retry=-2 bootinfo=1"]
    for cpu in range(cpus):
        value = runner.hash_work(cpu, 16000000 if cpu == 0 else 2000000)
        stack = 0xffff800010000000 + cpu * 0x20000
        lines.append(f"SMP-CPU: slot={cpu} apic={cpu} actual={cpu} physical={cpu} cr3=f00000 stack={stack:x} hash={value:x} progress=123 overlap={int(cpu!=0)} observed={int(cpu!=0)}")
        count = (1 if cpu else cpus) if ipi else 0
        lines.append(f"SMP-IPI: slot={cpu} resched={count} tlb={count} irqstack={stack+0x8000 if ipi else 0:x}")
    lines += [f"SMP-COMPONENT: CPUs={cpus} completed={cpus-1} bad={0 if ipi else cpus}", f"SHZ-EXIT:{0 if ipi else 4}"]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    if out.exists():
        raise SystemExit("output must be a new unique directory")
    out.mkdir(parents=True)
    before = sources()
    spec = importlib.util.spec_from_file_location("smp_runner", RUNNER)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    good = trace(runner)
    controls = []

    def check(name, serial, rc, timeout=False, cpus=2, acpi=True, ipi=True, expected=False, returning=False):
        actual = runner.evaluate(serial, rc, timeout, cpus, acpi, ipi, returning=returning)
        controls.append({"name": name, "expected": expected, "actual": actual, "pass": expected == actual})
        if actual != expected:
            raise AssertionError(name)

    check("positive-two", good, 1, expected=True)
    check("positive-four", trace(runner, 4), 1, cpus=4, expected=True)
    check("positive-UP-control", trace(runner, 1), 1, cpus=1, expected=True)
    check("wrong-process-exit", good, 0)
    check("timeout-with-success-log", good, 1, timeout=True)
    check("wrong-CPU-count", good, 1, cpus=4)
    check("missing-IPI-record", "\n".join(x for x in good.splitlines() if not x.startswith("SMP-IPI: slot=1"))+"\n", 1)
    check("missing-admission-proof", good.replace("SMP-ADMISSION:", "OLD-ADMISSION:"), 1)
    check("wrong-initial-root", good.replace("initial=1000", "initial=2000"), 1)
    check("trampoline-GDT-alias", good.replace("retired=1000", "retired=5000"), 1)
    check("bootstrap-active-root-alias", good.replace("bootstrap=f0d000", "bootstrap=f00000"), 1)
    check("blanket-low-mapping", good.replace("low-pages=1", "low-pages=512"), 1)
    check("bootinfo-overwritten", good.replace("bootinfo=1", "bootinfo=0"), 1)
    check("repeat-start-admitted", good.replace("retry=-2", "retry=0"), 1)
    check("physical-APIC-mismatch", good.replace("physical=1", "physical=0"), 1)
    check("wrong-AP-hash", good.replace("hash=b2a50fa8", "hash=b2a50fa9"), 1)
    check("wrong-AP-CR3", good.replace("cr3=f00000", "cr3=f01000", 1), 1)
    check("no-two-sided-progress", good.replace("overlap=1", "overlap=0"), 1)
    check("wrong-IPI-count", good.replace("resched=1 tlb=1", "resched=0 tlb=0"), 1)
    check("duplicate-IRQ-stack", good.replace("irqstack=ffff800010028000", "irqstack=ffff800010008000"), 1)
    check("native-no-IPI-control", trace(runner, ipi=False), 9, ipi=False, expected=True)
    check("no-IPI-fake-green-exit", trace(runner, ipi=False), 1, ipi=False)
    check("no-ACPI-control", "SMP-COMPONENT: startup failed rc=-1\nSHZ-EXIT:2\n", 5, acpi=False, ipi=False, expected=True)
    check("no-ACPI-unrelated-failure", "SMP-COMPONENT: startup failed rc=-2\nSHZ-EXIT:2\n", 5, acpi=False, ipi=False)
    returned = good.splitlines()[0]+"\nSMP-RETURN-CONTROL: started=2 failed=1 online=1 cpu=1 physical=1 retained=1 rejected=-1 retry=-2 bootinfo=1\nSHZ-EXIT:6\n"
    check("returned-AP-control", returned, 13, ipi=False, returning=True, expected=True)
    check("returned-AP-still-online", returned.replace("failed=1 online=1", "failed=0 online=2"), 13, ipi=False, returning=True)
    check("returned-AP-IPI-admitted", returned.replace("rejected=-1", "rejected=0"), 13, ipi=False, returning=True)
    after = sources()
    valid = before == after and all(c["pass"] for c in controls)
    result = {"scope": "modeled native-verifier negative controls only; no VM/CPU/AP/IPI executed",
              "all_expected": valid, "sources_unchanged": before == after, "sources_sha256": before, "controls": controls}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"PASS modeled SMP runner controls: {len(controls)}")
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
