#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read-only safety-component successor for one preserved native fault run.

Intel SDM Vol.3A 253668-084US (June 2024), section 4.10.2.2, printed 4-43:
https://cdrdv2-public.intel.com/825758/253668-sdm-vol-3a.pdf
TLB entries may be evicted at any time; warming does not guarantee retention.
The original strict stale-payload FAIL is reproduced and kept. This evaluator
requires no completion or frame repurposing without the target INVLPG/ACK.
It cannot compile or launch a guest and cannot admit another native epoch.
"""
import argparse
import hashlib
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORIGINAL = ROOT / "shizukudos/tests/run_k64_tlb_ap.py"
ORIGINAL_SHA = "964f06faf23f1b53f329c543279cafa96624fd335cc8d06ddd3ace5d118be5ec"
NATIVE_SHA = "fa62dde7e3b853dc5e763da9459b569a85525870fc12ea17dc1f10e020d32632"
BUILD_SHA = "6c7e3944378b4d6231fe51854196ebeae2654f04c2b77bd0975dfa44e7dafced"
PRIMARY = {"url": "https://cdrdv2-public.intel.com/825758/253668-sdm-vol-3a.pdf",
           "document": "Intel SDM Vol.3A 253668-084US, June 2024", "section": "4.10.2.2", "printed_page": "4-43", "pdf_page_zero_based": 142}

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def read_pinned(path, expected):
    raw = Path(path).read_bytes()
    if sha(raw) != expected:
        raise ValueError("pinned bytes changed: " + str(path))
    return raw

def verify_records(native, built):
    if (native.get("status") != "FAIL" or native.get("whole_acceptance") is not False or
        native.get("mode") != "no-invalidate" or native.get("cpus") != 2 or
        native.get("tlb_component_pass") is not False or native.get("expected_behavior") is not False or
        native.get("whole_native_gate_pass") is not True or native.get("qemu_returncode") != 1 or
        native.get("timed_out") is not False or not 0 < native.get("elapsed_seconds", 0) < 60 or
        native.get("inputs_sources_tools_unchanged") is not True or
        native.get("producer_receipt_sha256") != BUILD_SHA or
        native.get("evaluator_sha256") != ORIGINAL_SHA):
        raise ValueError("only the preserved, stable, terminal no-invalidate2 FAIL is admitted")
    if (built.get("status") != "BUILT" or built.get("whole_acceptance") is not False or
        built.get("sources_unchanged") is not True or built.get("evaluator_sha256") != ORIGINAL_SHA or
        len(built.get("sources_sha256", {})) != 243 or
        native.get("sources_sha256") != built.get("sources_sha256") or
        native.get("tools") != built.get("tools") or
        native.get("compiled_inputs_sha256") != built.get("compiled_inputs_sha256")):
        raise ValueError("captured source/tool/compiled build epoch differs")
    sources = built["sources_sha256"]
    helpers = ("shizukudos/kbuild.py", "shizukudos/tools/shzlib.py")
    if (built.get("executed_helpers_sha256") != {name: sources[name] for name in helpers} or
        built.get("executed_producer_sha256") != sources["shizukudos/tests/run_k64_native_firmware.py"]):
        raise ValueError("executed producer/helper capture differs")
    inputs = built["compiled_inputs_sha256"]
    if len(inputs) != 3 or {Path(path).name for path in inputs} != {"KERNEL64S.BIN", "kernel64s.elf", "boot.elf"}:
        raise ValueError("incomplete compiled artifact set")
    if set(built["tools"]) != {"gcc", "nasm", "ld", "nm", "objcopy", "objdump", "cc1", "qemu", "bios", "python"}:
        raise ValueError("incomplete tool identity set")

def verify_files(built, root, reader=lambda path: Path(path).read_bytes()):
    snapshot = {}
    for name, expected in built["sources_sha256"].items():
        path = root / name
        if path.resolve().is_relative_to(root.resolve()) is not True:
            raise ValueError("source escapes project root")
        actual = sha(reader(path))
        if actual != expected:
            raise ValueError("captured source changed: " + name)
        snapshot[str(path)] = actual
    files = dict(built["compiled_inputs_sha256"])
    files.update({tool["path"]: tool["sha256"] for tool in built["tools"].values()})
    for path, expected in files.items():
        actual = sha(reader(path))
        if actual != expected:
            raise ValueError("compiled input/tool changed: " + path)
        snapshot[path] = actual
    return snapshot

def evaluate_safety(original, text, rc):
    _, whole, evidence = original.evaluate(text, rc, 2, "no-invalidate")
    rows, total, ap = evidence["cpu_rows"], evidence["summary"], evidence["ap_summary"]
    component = len(rows) == 2 and {row[0] for row in rows} == {"0", "1"} and len(total) == 1
    stale = None
    if component:
        bsp = next(row for row in rows if row[0] == "0")
        victim = next(row for row in rows if row[0] == "1")
        t = tuple(map(int, total[0]))
        value, bad = int(victim[7], 16), int(victim[6])
        # Two post-replacement samples can independently see either valid live
        # payload. A final old value contributes a mismatch; a final new one
        # does not. Corrupt payloads and inconsistent counts remain failures.
        payload_consistent = ((value == 0x544c420000000000 and bad in (1, 2)) or
                              (value == 0x544c420000000001 and bad in (0, 1)))
        component = (tuple(map(int, bsp[:7])) == (0, 0, 1, 3, 1, 1, 0) and
                     int(bsp[7], 16) == 0x544c420000000001 and
                     tuple(map(int, victim[:6])) == (1, 1, 1, 3, 0, 0) and payload_consistent and
                     t[:7] == (2, 2, 1, 0, 0, 1, 1) and t[7] > 0 and t[7] == t[8] and t[9] == bad + 1 and
                     ap == [("2", "2", "1", "2")])
        stale = value == 0x544c420000000000
    evidence.update({"hardware_staleness_required": False, "observed_final_stale_payload": stale,
                     "staleness_qualifier": "TLB retention is not guaranteed; absence of stale payload does not prove invalidation.",
                     "primary_architectural_contract": PRIMARY})
    return bool(component), bool(whole), evidence

def load_original(raw):
    # This exact historical evaluator also supplies the reviewed captured-byte
    # producer/helper loader. No import cache or current-file exec is used.
    module = types.ModuleType("preserved_tlb_evaluator")
    module.__file__ = str(ORIGINAL)
    exec(compile(raw, str(ORIGINAL), "exec"), module.__dict__)
    return module

def verify_inventory(original, built):
    _, builder, captured, loaded = original.bound_builder()
    expected = built["sources_sha256"]
    without_producer = {name: value for name, value in expected.items() if name != "shizukudos/tests/run_k64_native_firmware.py"}
    if loaded != expected or builder.source_hashes() != without_producer:
        raise ValueError("source namespace/captured execution differs")
    return builder, loaded, without_producer

def runtime_bytes():
    paths = {Path(sys.executable).resolve()}
    for module in list(sys.modules.values()):
        name = getattr(module, "__file__", None)
        if name and Path(name).is_absolute() and (name.startswith("/usr/") or name.startswith("/opt/")):
            paths.add(Path(name).resolve())
    for line in Path("/proc/self/maps").read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and (fields[5].startswith("/usr/") or fields[5].startswith("/opt/")):
            paths.add(Path(fields[5]).resolve())
    return {str(path): path.read_bytes() for path in sorted(paths) if path.is_file()}

def main(executed_raw):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    own_raw = read_pinned(__file__, sha(executed_raw))
    # Historical identity and the full current closure are checked before any
    # repository helper is executed. Original receipts/logs are read-only.
    native_raw = read_pinned(args.native, NATIVE_SHA)
    built_raw = read_pinned(args.build, BUILD_SHA)
    original_raw = read_pinned(ORIGINAL, ORIGINAL_SHA)
    native, built = json.loads(native_raw), json.loads(built_raw)
    verify_records(native, built)
    before = verify_files(built, ROOT)
    serial_path = args.native.parent / "serial.log"
    serial_raw = read_pinned(serial_path, native["serial_sha256"])
    original = load_original(original_raw)
    builder, loaded, without_producer = verify_inventory(original, built)
    runtime = runtime_bytes()
    runtime_hashes = {name: sha(raw) for name, raw in runtime.items()}
    text = serial_raw.decode("utf-8", errors="replace")
    strict, strict_whole, strict_evidence = original.evaluate(text, 1, 2, "no-invalidate")
    if strict is not False or strict_whole is not True or json.loads(json.dumps(strict_evidence)) != native["actual_evidence"]:
        raise ValueError("original strict FAIL was not reproduced")
    component, whole, evidence = evaluate_safety(original, text, 1)
    after = verify_files(built, ROOT)
    stable = (before == after and read_pinned(args.native, NATIVE_SHA) == native_raw and
              read_pinned(args.build, BUILD_SHA) == built_raw and read_pinned(ORIGINAL, ORIGINAL_SHA) == original_raw and
              read_pinned(serial_path, native["serial_sha256"]) == serial_raw and
              read_pinned(__file__, sha(executed_raw)) == own_raw and builder.source_hashes() == without_producer and
              {name: sha(raw) for name, raw in runtime_bytes().items()} == runtime_hashes)
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "evaluator.py").write_bytes(own_raw)
    (args.out / "original-evaluator.py").write_bytes(original_raw)
    (args.out / "runtime").mkdir()
    for raw in runtime.values():
        (args.out / "runtime" / sha(raw)).write_bytes(raw)
    result = {"status": "PASS" if component and whole and stable else "FAIL",
              "scope": "read-only same-run no-invalidation resource-safety component; generic MM/SMP unsupported",
              "whole_acceptance": False, "guest_executed": False, "compiler_executed": False,
              "original_status": native["status"], "original_failure_preserved": True,
              "original_strict_component_pass": strict, "original_whole_native_gate_pass": strict_whole,
              "no_invalidation_safety_component_pass": component, "whole_native_gate_pass": whole,
              "inputs_sources_tools_unchanged": stable, "mode": "no-invalidate", "cpus": 2,
              "native_receipt_sha256": NATIVE_SHA, "build_receipt_sha256": BUILD_SHA,
              "serial_sha256": native["serial_sha256"], "sources_sha256": loaded,
              "compiled_inputs_sha256": built["compiled_inputs_sha256"], "tools": built["tools"],
              "original_evaluator_sha256": ORIGINAL_SHA, "successor_evaluator_sha256": sha(own_raw),
              "executed_successor_evaluator_sha256": sha(executed_raw), "evaluation_runtime_files_sha256": runtime_hashes,
              "executed_helpers_sha256": built["executed_helpers_sha256"],
              "executed_producer_sha256": built["executed_producer_sha256"], "actual_evidence": evidence,
              "primary_architectural_contract": PRIMARY}
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key not in ("sources_sha256", "tools", "compiled_inputs_sha256")}, indent=2))
    return 0 if result["status"] == "PASS" else 1

if __name__ == "__main__":
    # Re-execute the captured bytes, then pass the same bytes to the function
    # whose result records them. Initial Python import/pyc identity is not used.
    captured = Path(__file__).read_bytes()
    bound = types.ModuleType("captured_tlb_safety_rechecker")
    bound.__file__ = __file__
    exec(compile(captured, __file__, "exec"), bound.__dict__)
    raise SystemExit(bound.main(captured))
