#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute the real UP Kernel64 PMA assertions using its PIT interrupt path.

This is a component acceptance profile, without Supervisor, VMX or Windows VMM.
Use a fresh kbuild output; the default run needs no Win64 archive or disk.
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
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "tools"))
sys.path.insert(0, str(HERE))
import kbuild  # noqa: E402 -- current source inventory; no build executes
import qemu  # noqa: E402
import shzlib  # noqa: E402
from run_k64_standalone import check, parse  # noqa: E402


def evaluate(serial, qemu_rc):
    evidence, exit_code = parse(serial)
    summary = re.findall(r"^K64 PMA summary: failures=(\d+) ticks=(\d+) switches=(\d+) preemptions=(\d+) "
                         r"wakeups=(\d+) timeouts=(\d+) ready=(\d+) live=(\d+) cpus=(\d+)$", serial, re.M)
    policy = re.findall(r"^K64 PMA policy: first=(\d+)/(\d+) changed=(\d+)/(\d+) low_wait=(\d+) observation_gap=(\d+) ticks$", serial, re.M)
    progress = re.findall(r"^K64 PMA progress: low_loops=(\d+)/(\d+)$", serial, re.M)
    sampler = re.findall(r"^K64 PMA sampler: raw_gap=(\d+) service_gaps=(\d+)/(\d+) ready_wait=(\d+) ticks$", serial, re.M)
    quantum = re.findall(r"^K64 PMA quantum: ticks=(\d+)/(\d+) preemptions=(\d+)$", serial, re.M)
    refresh = re.findall(r"^K64 PMA refresh: updates=(\d+) low_first=(\d+) low_loops=(\d+)$", serial, re.M)
    semaphore = re.findall(r"^K64 PMA semaphore: signaled=(\d+) timeout=(\d+) conserved=(\d+)/48$", serial, re.M)
    cohort = re.findall(r"^K64 PMA cohort: target=(\d+) created=(\d+) started=(\d+) done=(\d+) "
                        r"free_before=(\d+) free_after=(\d+)$", serial, re.M)
    checks = [check("PMA guest exited successfully with its computed evidence marker",
                    exit_code == 0 and qemu_rc == 1 and evidence.get(18) == 0x504d0000,
                    f"exit={exit_code} qemu_rc={qemu_rc} evidence18={evidence.get(18)}")]
    fail_lines = re.findall(r"^K64 (?:PMA|test) FAIL: (.*)$", serial, re.M)
    checks.append(check("executing kernel assertions reported no failure", not fail_lines and
                        "K64 EXCEPTION" not in serial, "; ".join(fail_lines)))
    summary_ok = len(summary) == 1
    if summary_ok:
        failures, ticks, switches, preemptions, wakes, timeouts, ready, live, cpus = map(int, summary[0])
        summary_ok = failures == 0 and ticks > 0 and switches > preemptions > 0 and wakes > 0 and timeouts > 0 and \
            ready == 0 and live == 2 and cpus == 1
    checks.append(check("queue snapshot contains only the UP main and idle threads", summary_ok,
                        str(summary)))
    policy_ok = len(policy) == 1
    if policy_ok:
        a, b, a2, b2, wait, observation_gap = map(int, policy[0])
        policy_ok = a > b * 2 and b >= 3 and b2 > a2 * 2 and a2 >= 3 and wait <= 40
    checks.append(check("actual CPU ticks follow priority changes with bounded low-priority progress", policy_ok,
                        str(policy)))
    progress_ok = len(progress) == 1 and all(int(loops) > 1000 for loops in progress[0])
    checks.append(check("each low-priority policy phase executes useful CPU work", progress_ok, str(progress)))
    sampler_ok = len(sampler) == 1
    if sampler_ok:
        raw, first, second, wait = map(int, sampler[0])
        sampler_ok = raw > 40 and first <= 40 and second <= 40 and wait <= 40
    checks.append(check("injected interrupted observations distinguish sample gaps from ready residence", sampler_ok,
                        str(sampler)))
    quantum_ok = len(quantum) == 1
    if quantum_ok:
        a, b, preemptions = map(int, quantum[0])
        quantum_ok = a > 5 and b >= a * 2 and preemptions >= 20
    checks.append(check("actual equal-priority workers receive one- and four-tick quantums", quantum_ok,
                        str(quantum)))
    refresh_ok = len(refresh) == 1
    if refresh_ok:
        updates, low_first, low_loops = map(int, refresh[0])
        refresh_ok = updates > 1000 and low_first <= 40 and low_loops > 1000
    checks.append(check("repeated policy updates cannot postpone an aged CPU-bound worker", refresh_ok,
                        str(refresh)))
    semaphore_ok = len(semaphore) == 1
    if semaphore_ok:
        signaled, timed_out, conserved = map(int, semaphore[0])
        semaphore_ok = signaled > 0 and timed_out > 0 and signaled + timed_out == conserved == 48
    checks.append(check("all timed semaphore races conserve the posted token", semaphore_ok, str(semaphore)))
    cohort_ok = len(cohort) == 1
    if cohort_ok:
        target, created, started, done, free_before, free_after = map(int, cohort[0])
        cohort_ok = target == created == started == done == 1000 and free_before == free_after
    checks.append(check("1000 concurrent real threads return every kernel-stack page", cohort_ok, str(cohort)))
    return checks, evidence


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    ap.add_argument("--build-dir", type=Path, default=shzlib.BUILD / "kernel64s")
    ap.add_argument("--build-receipt", type=Path, help="source-bound kbuild receipt (default: build-dir parent)")
    ap.add_argument("--memory", default="256")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--out", type=Path, default=shzlib.BUILD / "pma-validation/k64-focused")
    args = ap.parse_args()
    stub, kernel = args.build_dir / "boot.elf", args.build_dir / "KERNEL64S.BIN"
    for path in (stub, kernel):
        if not path.is_file():
            ap.error(f"fresh build input missing: {path}")
    receipt_path = args.build_receipt or args.build_dir.parent / "kernels-build-result.json"
    if not receipt_path.is_file():
        ap.error(f"source-bound build receipt missing: {receipt_path}")
    receipt_bytes = receipt_path.read_bytes()
    receipt = json.loads(receipt_bytes)
    built = receipt.get("kernels", {}).get("kernel64-standalone", {})
    inputs_before = {str(p.resolve()): shzlib.sha256_file(p) for p in (stub, kernel)}
    receipt_before = hashlib.sha256(receipt_bytes).hexdigest()
    if built.get("sha256") != inputs_before[str(kernel.resolve())] or built.get("stub_sha256") != inputs_before[str(stub.resolve())]:
        ap.error("kernel/stub hashes do not match the source-bound build receipt")
    sources = receipt.get("sources_sha256", {})
    if not sources:
        ap.error("build receipt has no source input hashes")
    current_closure = kbuild.source_hashes()
    missing = sorted(current_closure.keys() - sources.keys())
    if missing:
        ap.error("build receipt missing current kernel source inputs: " + ", ".join(missing))
    for name, expected in sources.items():
        path = (shzlib.REPO / name).resolve()
        if not path.is_relative_to(shzlib.REPO.resolve()) or not path.is_file() or shzlib.sha256_file(path) != expected:
            ap.error(f"build source changed or unavailable: {name}")
    source_paths = [HERE.parent / "kernel64" / name for name in ("sched.c", "k64.h", "pma_tests.c", "tests.c")]
    sources_at_launch = {str(p.relative_to(shzlib.REPO)): shzlib.sha256_file(p) for p in source_paths}
    runner_before = shzlib.sha256_file(Path(__file__))
    args.out.mkdir(parents=True, exist_ok=True)
    serial_path = args.out.resolve() / "serial.log"
    serial_path.unlink(missing_ok=True)
    command = [args.qemu, "-machine", "pc", "-accel", args.accel, "-cpu", "max", "-m", args.memory,
               "-nodefaults", "-display", "none", "-kernel", str(stub.resolve()), "-initrd", str(kernel.resolve()),
               "-append", "shz.pma=test", "-serial", f"file:{serial_path}",
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
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    checks, evidence = evaluate(serial, proc.returncode)
    inputs_after = {str(p.resolve()): shzlib.sha256_file(p) if p.is_file() else None for p in (stub, kernel)}
    receipt_after = shzlib.sha256_file(receipt_path) if receipt_path.is_file() else None
    sources_after = {name: shzlib.sha256_file(shzlib.REPO / name) if (shzlib.REPO / name).is_file() else None
                     for name in sources}
    current_closure_after = kbuild.source_hashes()
    sources_stable = sources == sources_after and current_closure == current_closure_after
    runner_after = shzlib.sha256_file(Path(__file__))
    inputs_stable = inputs_before == inputs_after and receipt_before == receipt_after and sources_stable and runner_before == runner_after
    checks.append(check("guest artifacts and their source-bound receipt stayed unchanged", inputs_stable,
                        f"artifacts={inputs_before == inputs_after} receipt={receipt_before == receipt_after} sources={sources_stable} runner={runner_before == runner_after}"))
    if timed_out:
        checks.insert(0, check("bounded guest run completed", False, f"timeout={args.timeout}s"))
    status = "PASS" if all(c["status"] == "PASS" for c in checks) else "FAIL"
    record = {"profile": "Kernel64 native UP PMA component (no Supervisor or Windows VMM)",
              "status": status, "accel": args.accel, "command": command, "qemu_rc": proc.returncode,
              "seconds": round(time.monotonic() - started, 2), "checks": checks,
              "evidence": {str(k): hex(v) for k, v in evidence.items()}, "qemu_output": output,
              "inputs_sha256": inputs_before, "inputs_sha256_after": inputs_after, "inputs_stable": inputs_stable,
              "build_receipt_sha256": receipt_before, "build_receipt_sha256_after": receipt_after,
              "runner_sha256": runner_before, "runner_sha256_after": runner_after,
              "serial_sha256": shzlib.sha256_file(serial_path) if serial_path.is_file() else None,
              "build_sources_sha256": sources, "build_sources_stable": sources_stable,
              "current_kernel_sources_sha256": current_closure,
              "current_kernel_sources_sha256_after": current_closure_after,
              "source_sha256_at_run": sources_at_launch, "source_sha256_at_launch": sources_at_launch,
              "source_sha256_after": {str(p.relative_to(shzlib.REPO)): sources_after.get(str(p.relative_to(shzlib.REPO))) for p in source_paths},
              "utc": shzlib.utc_now(), "git": shzlib.git_state()}
    shzlib.write_json(args.out / "result.json", record)
    for item in checks:
        print(f"[{item['status']}] {item['check']} {item['detail']}")
    print(status)
    if status != "PASS":
        print(serial[-5000:])
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
