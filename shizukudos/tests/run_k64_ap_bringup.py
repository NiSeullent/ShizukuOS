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
FIXTURE_SHA = "6761e4cd35de1672406e01dc356303fa84773baf71096fe3fd3a15391f9fed3b"
KNOWN_FAILURE = "K64 PMA FAIL: each low-priority policy phase executes useful CPU work"


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


def admit_memory_component(args, built, before):
    """Admit only the recorded singleton Core failure, retaining whole FAIL.

    A terminal producer receipt exists only after both builds and all three
    native runs. Check its complete artifacts, captured helpers and raw runs;
    this grants no scheduler/UP/whole-kernel acceptance.
    """
    def require(condition, message):
        if not condition:
            raise SystemExit("known-failure component rejected: " + message)
    require(args.memory_test and args.mode == "bringup" and args.cpus in (2, 4) and
            args.accel == "kvm" and not args.expect_red, "only KVM AP-memory 2/4 profiles")
    require(built.get("status") == "FAIL" and built.get("sources_unchanged") is True,
            "terminal unchanged failed producer required")
    require(before.get("shizukudos/kernel64/pma_tests.c") == FIXTURE_SHA, "fixture changed")
    require(built.get("helper_execution") == "compile/exec of captured pre-import bytes; current closure checked before compiler" and
            built.get("compiled_input_provenance") == {"mode": "fresh build from captured source/helper closure"} and
            built.get("executed_helpers_sha256") == {name: before[name] for name in
                ("shizukudos/tools/shzlib.py", "shizukudos/kbuild.py")}, "compiled helper/build provenance changed")
    inputs = built.get("compiled_inputs_sha256", {})
    require(len(inputs) == 3 and {Path(p).name for p in inputs} == {"KERNEL64S.BIN", "kernel64s.elf", "boot.elf"},
            "complete compiled artifact set required")
    for path, sha in inputs.items():
        data = Path(path).read_bytes()
        require(bool(data) and hashlib.sha256(data).hexdigest() == sha and
                (not path.endswith(".elf") or data[:4] == b"\x7fELF"), "compiled artifact changed/incomplete")
    tools = built.get("tools", {})
    require(set(tools) == {"gcc", "nasm", "ld", "nm", "objcopy", "objdump", "cc1", "qemu", "bios", "python"},
            "complete compiler/runtime tool set required")
    require(all(digest(row["path"]) == row["sha256"] for row in tools.values()), "tool bytes changed")
    proof = {}
    build_log = args.receipt.resolve().parent / "build.log"
    build_bytes = build_log.read_bytes()
    require(not re.search(rb"(?:fatal error:|error:|undefined reference|compilation terminated)", build_bytes, re.I),
            "compiler/build error present")
    proof[str(build_log)] = hashlib.sha256(build_bytes).hexdigest()
    runs = built.get("runs", [])
    require(len(runs) == 3 and [(r.get("cpus"), r.get("firmware_enabled")) for r in runs] == [(2, True), (4, True), (4, False)],
            "exact original firmware 2/4/off terminal runs required")
    bin_path = next(p for p in inputs if p.endswith("KERNEL64S.BIN"))
    stub_path = next(p for p in inputs if p.endswith("boot.elf"))
    for index, row in enumerate(runs):
        command = row["command"]
        require(row.get("timed_out") is False and row.get("sources_and_inputs_unchanged") is True and
                row.get("qemu_returncode") == (3 if index == 2 else 1) and
                row.get("expected_behavior") is (index != 2), "original run failure/timeout/EXIT drift")
        serial_arg = command[command.index("-serial") + 1]
        require(serial_arg.startswith("file:"), "missing original serial file")
        serial = Path(serial_arg[5:])
        expected = [tools["qemu"]["path"], "-machine", "pc", "-bios", tools["bios"]["path"], "-accel", "kvm",
                    "-cpu", "max", "-m", "256", "-smp", str(row["cpus"]), "-kernel", stub_path,
                    "-initrd", bin_path, "-append", "shz.pma=test shz.smp=firmware-test" + (" smp=off" if index == 2 else ""),
                    "-display", "none", "-monitor", "none", "-serial", serial_arg, "-no-reboot", "-device",
                    "isa-debug-exit,iobase=0xf4,iosize=0x04"]
        require(command == expected, "original machine/profile drift")
        data = serial.read_bytes()
        require(hashlib.sha256(data).hexdigest() == row["serial_sha256"], "original serial bytes changed")
        text = data.decode("utf-8", errors="strict")
        errors = re.findall(r"^.*(?:FAIL|PANIC|ASSERT|EXCEPTION).*$", text, re.M)
        require(errors == ([KNOWN_FAILURE] if index == 2 else []), "additional/different failure")
        require(re.findall(r"^SHZ-EXIT:(\d+)$", text, re.M) == ["1" if index == 2 else "0"] and
                re.findall(r"^K64 PMA summary: failures=(\d+).* ready=0 live=2 cpus=1$", text, re.M) ==
                ["1" if index == 2 else "0"], "original terminal summary/EXIT drift")
        metadata = re.findall(r"SMP-FIRMWARE: retained=(\d+) original=(\d+) machine_ram=([0-9a-f]+) managed_ram=([0-9a-f]+)", text)
        ownership = re.findall(r"SMP-FIRMWARE: test page_admitted=(\d+) reserved_reads=(\d+)", text)
        if index == 2:
            require(not metadata and not ownership and "SMP-BRINGUP:" not in text, "off profile unexpectedly activated")
        else:
            require(len(metadata) == len(ownership) == 1 and 1 <= int(metadata[0][0]) <= 64 and
                    1 <= int(metadata[0][1]) <= 64 and int(metadata[0][2], 16) == 0x10000000 and
                    int(metadata[0][3], 16) < 0x10000000 and ownership[0][0] == "1" and int(ownership[0][1]) > 0,
                    "original firmware component did not pass")
        stderr = serial.with_name(serial.name.replace(".serial.log", ".qemu.log"))
        error_bytes = stderr.read_bytes()
        require(not re.search(rb"(?:error:|fatal|failed|could not)", error_bytes, re.I), "original QEMU error")
        proof[str(serial)] = row["serial_sha256"]
        proof[str(stderr)] = hashlib.sha256(error_bytes).hexdigest()
    return {"failure": KNOWN_FAILURE, "fixture_sha256": FIXTURE_SHA, "whole_status": "FAIL",
            "terminal_build_artifacts_verified": True, "original_logs_sha256": proof}


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
    parser.add_argument("--memory-test", action="store_true")
    parser.add_argument("--known-core-failure-component", action="store_true",
                        help="only AP-memory KVM2/4 after exact singleton Core failure; overall result remains FAIL")
    parser.add_argument("--mode",choices=("bringup","off","no-acpi","no-ipi","withhold-verify","return-ap"),default="bringup")
    parser.add_argument("--expect-red", action="store_true", help="preserve missing-feature runtime RED, not a PASS")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    receipt_bytes = args.receipt.read_bytes()
    receipt_sha = hashlib.sha256(receipt_bytes).hexdigest()
    built = json.loads(receipt_bytes)
    if built.get("status") != "PASS" and not args.known_core_failure_component:
        raise SystemExit("producer whole-kernel firmware gate must pass before this AP execution")
    evaluator_sha = digest(__file__)
    before,kbuild = capture_compiled_sources()
    def sources():
        return {**kbuild.source_hashes(), str(PRODUCER.relative_to(REPO)): digest(PRODUCER)}
    if before != built["sources_sha256"]:
        raise SystemExit("complete compiled dependency closure differs from current sources")
    admission = admit_memory_component(args, built, before) if args.known_core_failure_component else None
    inputs = built["compiled_inputs_sha256"]
    kernel = next(p for p in inputs if p.endswith("KERNEL64S.BIN"))
    stub = next(p for p in inputs if p.endswith("boot.elf"))
    tools = built["tools"]
    def stable():
        return sources() == before and digest(__file__) == evaluator_sha and digest(args.receipt) == receipt_sha and \
            all(digest(p) == h for p, h in inputs.items()) and \
            all(digest(row["path"]) == row["sha256"] for row in tools.values()) and \
            (not admission or all(digest(p) == h for p, h in admission["original_logs_sha256"].items()))
    if not stable():
        raise SystemExit("compiled input/evaluator/tool bytes changed before launch")
    serial = out / "serial.log"
    option="bringup" if args.mode in ("off","no-acpi") else args.mode
    command = [tools["qemu"]["path"], "-machine", "pc,acpi=off" if args.mode=="no-acpi" else "pc", "-bios", tools["bios"]["path"], "-accel", args.accel,
               "-cpu", "max", "-m", "256", "-smp", str(args.cpus), "-kernel", stub, "-initrd", kernel,
               "-append", "shz.pma=test shz.smp="+option+(" smp=off" if args.mode=="off" else "")+(" shz.memory=test" if args.memory_test else ""), "-display", "none", "-monitor", "none",
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
    if args.memory_test and args.mode=="bringup":
        memory=re.findall(r"SMP-MEM CPU: cpu=(\d+) actual=(\d+) rounds=(\d+) singles=(\d+) run_pages=(\d+) heaps=(\d+) IF=(\d+) bad=(\d+)",text)
        total=re.findall(r"SMP-MEM summary: cpus=(\d+) ready=(\d+) complete=(\d+) pages=(\d+)/(\d+) heap=(\d+)/(\d+) overlap_rounds=(\d+) duplicate=(\d+) corrupt=(\d+) bad=(\d+) scheduler_cpus=1",text)
        memory_ok=len(memory)==args.cpus and {int(row[0]) for row in memory}==set(range(args.cpus)) and len(total)==1
        if memory_ok:
            row=total[0]
            memory_ok=row[:3]==(str(args.cpus),)*3 and row[3]==row[4] and row[5]==row[6] and row[7:]==("128","0","0","0")
            for row in memory:
                cpu=int(row[0]);memory_ok=memory_ok and row==(str(cpu),str(cpu),"128","128",str(128*(1+cpu%4)),"128","1","0")
        mode_expected=passed and memory_ok;evidence["memory_rows"]=memory;evidence["memory_summary"]=total
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
              "status": "FAIL" if admission else "RED" if observed_red else "PASS" if valid else "FAIL",
              "whole_acceptance": False, "known_failure_preserved": bool(admission), "known_failure_admission": admission,
              "memory_component_pass": bool(valid and args.memory_test),
              "ap_component_pass":passed,"expected_behavior": valid,"mode":args.mode,"memory_test":args.memory_test,"cpus": args.cpus, "command": command, "qemu_returncode": rc,
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
