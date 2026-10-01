#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Require actual AP architecture, useful work and two-sided physical IPIs in normal main."""
import argparse
import hashlib
import json
import re
import subprocess
import time
import types
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PRODUCER = REPO / "shizukudos/tests/run_k64_native_firmware.py"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def capture_compiled_sources():
    # Reuse the independently reviewed producer loader, binding the producer
    # functions themselves to captured bytes before invoking either helper.
    producer_bytes=PRODUCER.read_bytes()
    producer=types.ModuleType("smp_bound_producer")
    producer.__file__=str(PRODUCER)
    exec(compile(producer_bytes,str(PRODUCER),"exec"),producer.__dict__)
    captured=producer.capture_sources()
    before={name:hashlib.sha256(data).hexdigest() for name,data in captured.items()}
    if before[str(PRODUCER.relative_to(REPO))]!=hashlib.sha256(producer_bytes).hexdigest():
        raise SystemExit("producer/source closure changed while loading; no VM launched")
    kbuild=producer.load_builder(captured)
    after={**kbuild.source_hashes(),str(PRODUCER.relative_to(REPO)):digest(PRODUCER)}
    if after!=before:
        raise SystemExit("helper/source closure changed while loading; no VM launched")
    return before,kbuild


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
    resources=re.findall(r"SMP-RESOURCE: owned=(\d+) final_cr3=([0-9a-f]+) bootstrap_cr3=([0-9a-f]+) identity_bytes=4096 before_INIT=1",text)
    correct = rc == 1 and "SHZ-EXIT:0\n" in text and len(workers) == len(ipis) == cpus and len(summary) == 1
    correct=correct and len(resources)==1 and resources[0][0]==str(cpus)
    correct = correct and summary[0] == (str(cpus), str(cpus), str(cpus - 1), "0", "1")
    if correct:
        correct = {int(row[0]) for row in workers} == set(range(cpus)) and \
            {int(row[0]) for row in ipis} == set(range(cpus)) and len({row[1] for row in workers}) == cpus
        correct = correct and len({row[3] for row in workers}) == 1
        correct=correct and resources[0][1]==workers[0][3] and \
            0xf00000<=int(resources[0][2],16)<0x100000000 and int(resources[0][2],16)%4096==0 and \
            resources[0][2]!=resources[0][1]
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
            correct = correct and int(wake) == int(verify) == expected and (cpus==1 or bool(int(stack, 16)))
        correct = correct and len({row[3] for row in ipis}) == cpus
    return bool(correct), {"worker_rows": len(workers), "ipi_rows": len(ipis), "summary": summary,"resources":resources}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True, help="normal-main production build receipt")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cpus", type=int, choices=(1, 2, 4), default=4)
    parser.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    parser.add_argument("--mode",choices=("bringup","off","no-acpi","no-ipi","withhold-verify","return-ap"),default="bringup")
    parser.add_argument("--expect-red", action="store_true", help="preserve missing-feature runtime RED, not a PASS")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    receipt_bytes = args.receipt.read_bytes()
    receipt_sha = hashlib.sha256(receipt_bytes).hexdigest()
    built = json.loads(receipt_bytes)
    if built.get("status") != "PASS":
        raise SystemExit("producer whole-kernel firmware gate must pass before this AP execution")
    evaluator_sha = digest(__file__)
    before,kbuild = capture_compiled_sources()
    def sources():
        return {**kbuild.source_hashes(), str(PRODUCER.relative_to(REPO)): digest(PRODUCER)}
    if before != built["sources_sha256"]:
        raise SystemExit("complete compiled dependency closure differs from current sources")
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
    option="bringup" if args.mode in ("off","no-acpi") else args.mode
    command = [tools["qemu"]["path"], "-machine", "pc,acpi=off" if args.mode=="no-acpi" else "pc", "-bios", tools["bios"]["path"], "-accel", args.accel,
               "-cpu", "max", "-m", "256", "-smp", str(args.cpus), "-kernel", stub, "-initrd", kernel,
               "-append", "shz.pma=test shz.smp="+option+(" smp=off" if args.mode=="off" else ""), "-display", "none", "-monitor", "none",
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
    mode_expected=passed
    healthy=not timeout and rc==1 and "SHZ-EXIT:0\n" in text
    if args.mode=="off":
        mode_expected=healthy and evidence["worker_rows"]==evidence["ipi_rows"]==0 and not evidence["resources"] and "SMP-FIRMWARE:" not in text
    elif args.mode=="no-acpi":
        mode_expected=healthy and evidence["worker_rows"]==evidence["ipi_rows"]==0 and not evidence["resources"] and "SMP-BRINGUP: ACPI unavailable" in text
    elif args.mode=="no-ipi":
        mode_expected=healthy and not passed and evidence["summary"]==[(str(args.cpus),str(args.cpus),"0","1","1")] and \
            "SMP-AP IPI: cpu=1 wake=0 verify=0 irqstack=0" in text
    elif args.mode=="withhold-verify":
        mode_expected=healthy and not passed and len(evidence["summary"])==1 and int(evidence["summary"][0][3])>0 and \
            bool(re.search(r"SMP-AP IPI: cpu=1 wake=1 verify=0 irqstack=[1-9a-f][0-9a-f]* delivered=1",text))
    elif args.mode=="return-ap":
        mode_expected=healthy and not passed and bool(re.search(r"SMP-AP aborted: discovered=2 arch_online=1 state1=3 retained=1 retry=-2 error=-7",text))
    valid = unchanged and not timeout and (observed_red if args.expect_red else mode_expected)
    result = {"scope": "normal main AP bringup component; existing scheduler must still report1; not full SMP/Windows acceptance",
              "status": "RED" if observed_red else "PASS" if valid else "FAIL",
              "ap_component_pass":passed,"expected_behavior": valid,"mode":args.mode,"cpus": args.cpus, "command": command, "qemu_returncode": rc,
              "timed_out": timeout, "elapsed_seconds": time.monotonic() - start, "actual_evidence": evidence,
              "sources_sha256": before, "producer_receipt_sha256": receipt_sha, "evaluator_sha256": evaluator_sha,
              "executed_helpers_sha256": {name:before[name] for name in ("shizukudos/kbuild.py","shizukudos/tools/shzlib.py")},
              "executed_producer_sha256": before[str(PRODUCER.relative_to(REPO))],
              "inputs_sources_tools_unchanged": unchanged, "serial_sha256": digest(serial) if serial.exists() else None}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({name:value for name,value in result.items() if name!="sources_sha256"}, indent=2))
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
