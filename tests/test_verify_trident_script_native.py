# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic rejection controls; these bytes are never native execution proof."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("script_evidence", ROOT / "tools/verify_trident_script_native.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
sys.path.insert(0, str(ROOT / "tools"))
import stage_trident_script_native as S


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def log(fields):
    return "".join(f"{key}={value}\r\n" for key, value in fields.items()).encode("ascii")


class ScriptEvidence(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="script-evidence-SYNTHETIC-")
        self.root = Path(self.temporary.name)
        self.stage = self.root / "stage"
        self.run = self.root / "synthetic-owned-run"
        self.stage.mkdir(); self.run.mkdir()
        self.manifest_path = self.stage / "guest-files.json"
        self.run_path = self.run / "result.json"
        self.nonce = "synthetic-trial-v10"
        runner = self.run / "runner-source.py"
        runner.write_bytes(b"SYNTHETIC NONEXECUTABLE harness fixture\n")
        self.harness_sha = digest(runner)
        hashes = {}
        for name in sorted(M.H.RUNTIME_SOURCES | M.H.OBSERVER_SOURCES):
            path = self.stage / "source" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("SYNTHETIC project source: " + name).encode())
            hashes[name] = digest(path)
        prepared = {}
        for name in ("quickjs/quickjs.c", "math/src/math/round.c"):
            path = self.stage / "runtime-prepared" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("SYNTHETIC prepared input: " + name).encode())
            prepared["/never-read/build/prepared/" + name] = digest(path)
        originals = {"quickjs_original_sha256": {}, "musl_original_sha256": {}}
        for role, key, names in (("quickjs", "quickjs_original_sha256", ("LICENSE", "quickjs.c")),
                                 ("math", "musl_original_sha256", ("COPYRIGHT", "src/math/round.c"))):
            for name in names:
                path = self.stage / "runtime-original" / role / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(("SYNTHETIC original source/licence: " + name).encode())
                originals[key][name] = digest(path)
        dependency = dict(quickjs_version="2026-06-04", musl_revision="c4e1bb3994c14ed5112c894d15a451bf00f0d501", **originals)
        inputs, gates = [], {}
        for name in sorted(M.INPUTS):
            path = self.stage / name
            path.write_bytes(("SYNTHETIC NOT A PE: " + name).encode())
            (self.run / ("prepared-guest-" + name)).write_bytes(path.read_bytes())
            row = dict(source=str(path), guest=M.PREFIX + name, bytes=path.stat().st_size, sha256=digest(path))
            inputs.append(row)
            gates[name] = dict(sha256=row["sha256"], size=row["bytes"], pe98_gate="pass", stack_reserve=2097152,
                               stack_commit=65536 if name == "M98JSRUN.EXE" else 524288)
        for name in ("M98QJS.DLL", "QJS13PR.EXE"):
            gates[name]["exports"] = sorted(M.H.RUNTIME_EXPORTS) if name.endswith("DLL") else []
            gates[name]["i486_instructions"] = dict(instructions_decoded=100, post_i486_families="absent")
        gates["M98JSRUN.EXE"]["i486_instruction_gate"] = "pass"
        selected = self.stage / "runtime-selected.h"
        selected.write_bytes(b"SYNTHETIC selected header, never executed\n")
        self.builds = {
            "runtime-build.json": dict(profile="bounded-local-trident-quickjs-v1", passed=True, nonce=self.nonce,
                source_sha256={n: hashes[n] for n in sorted(M.H.RUNTIME_SOURCES)}, prepared_sha256=prepared,
                embedded_fixture_header_sha256=digest(selected), dependency=dependency,
                artifacts={n: gates[n] for n in ("M98QJS.DLL", "QJS13PR.EXE")}, selected_es2026_checks=34, selected_numeric_checks=24),
            "observer-build.json": dict(schema=1, kind="win98-trident-owned-child-observer-build", passed=True, nonce=self.nonce,
                source_sha256={n: hashes[n] for n in sorted(M.H.OBSERVER_SOURCES)}, artifacts={"M98JSRUN.EXE": gates["M98JSRUN.EXE"]},
                profiles={"script": dict(self=M.PREFIX + "M98JSRUN.EXE", supervisor_log=M.PREFIX + "JSRUN.LOG",
                    child_stdout=M.PREFIX + "JSOUT.LOG", child=M.PREFIX + "QJS13PR.EXE", child_log=M.PREFIX + "QJS13.LOG",
                    child_timeout_ms=60000, reap_timeout_ms=5000)})}
        for key in ("native_guest_execution_verified", "native_math_verified", "mshtml_dom_verified", "html5_verified", "wasm_verified",
                    "full_es2026_conformance_verified", "applications_verified", "user_objective_complete"):
            self.builds["runtime-build.json"][key] = False
        for name, build in self.builds.items():
            role = name.removesuffix("-build.json")
            path = self.stage / "build-logs" / role / "host-run.log"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"SYNTHETIC successful build log\n")
            build["steps"] = [dict(returncode=0, log="/never-read/host-run.log", sha256=digest(path))]
        self.manifest = dict(schema=1, kind="isolated-guest-file-inputs", nonce=self.nonce,
            command=M.PREFIX + "M98JSRUN.EXE", network_required=False, inputs=inputs,
            outputs=[M.PREFIX + n for n in ("QJS13.LOG", "JSRUN.LOG", "JSOUT.LOG")], source_receipts=[])
        self.component = dict(nonce=self.nonce, expected_runtime_sha256=gates["M98QJS.DLL"]["sha256"], original_x87_control_word="895",
            observed_internal_x87_control_word="895", selected_es2026_checks="34", selected_numeric_checks="24",
            **{f"check_{i}": label + ":PASS" for i, label in enumerate(M.CHECKS, 1)}, checks="307", component_result="PASS",
            mshtml_automation_verified="0", html5_verified="0", wasm_verified="0", es2026_conformance="0", applications_verified="0",
            actual_child_exit="externally_observed_only")
        self.observer = {"scope": "actual-win98-trident-owned-child-observer", "nonce": self.nonce, "profile": "runtime-only",
            "WIN98_IDENTIFIED": "1", "os.major": "4", "os.minor": "10", "os.build-low": "2222", "os.platform": "1",
            "child.path": M.PREFIX + "QJS13PR.EXE", "child.stdout": M.PREFIX + "JSOUT.LOG", "child.created": "1",
            "child.create-error": "0", "child.pid": "101", "child.wait": "0", "child.exit-query": "1", "child.exit-query-error": "0",
            "child.exit-code": "0", "child.stdout-flushed": "1", "child.handles-closed": "1", "child.success": "1",
            "supervisor.requested-exit-code": "0"}
        self.payloads = {"QJS13.LOG": self.native_log(), "JSRUN.LOG": log(self.observer), "JSOUT.LOG": b""}
        self.result = dict(profile="actual-win98-uefi-csmwrap", status="NEEDS-VISUAL-REVIEW", originals_unchanged=True,
            prepared_source_unchanged=True, qemu_exit_code=0, manual_finish_requested=True, source_snapshot=str(runner), source_sha256=self.harness_sha,
            hardware=dict(run_name=self.run.name, network="none", accel="kvm", memory=128, smp=2, reserve_gib=20, manual_gui=True, firmware_gop=True),
            firmware_gop_opt_in=True, prepared_reuse=dict(method="verified private sparse post-run disk copy; cold hardware; SYNTHETIC"),
            guest_files=dict(manifest=str(self.manifest_path), immutable_sources_unchanged=True, output_baseline="all absent before private injection",
                inputs=[r | {"private_copy_sha256": r["sha256"]} for r in inputs], readback=[]))
        for name, data in self.payloads.items():
            path = self.run / ("guest-output-" + name)
            path.write_bytes(data)
            self.result["guest_files"]["readback"].append(dict(guest=M.PREFIX + name, path=str(path), status="captured",
                freshness="new-in-owned-run", bytes=len(data), sha256=digest(path)))
        self.sync_builds()

    def tearDown(self):
        self.temporary.cleanup()

    def native_log(self, fields=None):
        return b"M98QJS runtime-only native probe v1\r\n" + log(self.component if fields is None else fields)

    def sync_builds(self):
        self.pins = {}; self.manifest["source_receipts"] = []
        for name, build in self.builds.items():
            path = self.stage / name; write(path, build)
            self.pins[name] = digest(path)
            self.manifest["source_receipts"].append(dict(path=str(path), sha256=self.pins[name]))
        self.sync()

    def sync(self):
        write(self.manifest_path, self.manifest); self.manifest_sha = digest(self.manifest_path)
        files = self.result["guest_files"]
        files["manifest_sha256"] = self.manifest_sha; files["outputs"] = self.manifest["outputs"].copy()
        files["immutable_sources"] = {str(self.manifest_path): self.manifest_sha} | {
            r["source"]: r["sha256"] for r in self.manifest["inputs"]} | {
            r["path"]: r["sha256"] for r in self.manifest["source_receipts"]}
        self.write_run()

    def write_run(self):
        write(self.run_path, self.result); self.run_sha = digest(self.run_path)

    def verify(self):
        return M.verify(self.run_path, self.run_sha, self.manifest_path, self.manifest_sha, self.harness_sha, self.pins)

    def reject(self):
        with self.assertRaises((M.EvidenceError, OSError, ValueError, TypeError, KeyError, AttributeError)):
            self.verify()

    def change_log(self, name, data):
        row = next(r for r in self.result["guest_files"]["readback"] if r["guest"] == M.PREFIX + name)
        path = Path(row["path"]); path.write_bytes(data)
        row["bytes"] = len(data); row["sha256"] = digest(path); self.write_run()

    def test_nominal_synthetic_control_has_component_scope_only(self):
        report = self.verify()
        self.assertEqual(len(M.CHECKS), 307)
        self.assertEqual(report["native_observations"]["selected_es2026_checks"], 34)
        self.assertEqual(report["native_observations"]["selected_numeric_checks"], 24)
        self.assertEqual(report["actual_owned_child"]["exit_code"], 0)
        for key in ("actual_supervisor_exit_verified", "native_mshtml_dom_verified", "standard_browser_navigation_verified",
                    "full_javascript_verified", "es2026_conformance_verified", "modern_css_verified", "webassembly_verified",
                    "webgpu_verified", "webgl_verified", "modern_apps_verified", "user_objective_complete"):
            self.assertIs(report[key], False, key)

    def test_every_native_check_failure_and_missing_check_rejected(self):
        for i in range(1, 308):
            with self.subTest(check=i):
                fields = self.component | {f"check_{i}": M.CHECKS[i-1] + ":FAIL"}
                with self.assertRaises(M.EvidenceError): M.component(self.native_log(fields), self.nonce, self.component["expected_runtime_sha256"])
                del fields[f"check_{i}"]
                with self.assertRaises(M.EvidenceError): M.component(self.native_log(fields), self.nonce, self.component["expected_runtime_sha256"])

    def test_check_labels_and_physical_order_must_match_native_fixture(self):
        fields = self.component.copy(); fields["check_1"], fields["check_2"] = fields["check_2"], fields["check_1"]
        self.change_log("QJS13.LOG", self.native_log(fields)); self.reject()
        data = self.payloads["QJS13.LOG"]
        one=b"check_1=win98se_4_10_2222:PASS\r\n"; two=b"check_2=probe_exact_path:PASS\r\n"
        self.change_log("QJS13.LOG", data.replace(one+two, two+one)); self.reject()

    def test_component_counts_nonce_hash_fpu_and_scope_cannot_be_substituted(self):
        for key, value in (("checks", "306"), ("selected_es2026_checks", "33"), ("selected_numeric_checks", "23"),
            ("nonce", "old-trial"), ("expected_runtime_sha256", "0"*64), ("observed_internal_x87_control_word", "639"),
            ("original_x87_control_word", "65536"), ("original_x87_control_word", "-1"), ("component_result", "FAIL"),
            ("mshtml_automation_verified", "1"), ("html5_verified", "1"), ("wasm_verified", "1"), ("es2026_conformance", "1"),
            ("applications_verified", "1"), ("actual_child_exit", "0")):
            with self.subTest(key=key):
                self.change_log("QJS13.LOG", self.native_log(self.component | {key:value})); self.reject()

    def test_partial_duplicate_nonascii_extra_or_wrong_generation_native_log_rejected(self):
        data = self.payloads["QJS13.LOG"]
        for value in (b"", data[:-2], data.replace(b"\r\n", b"\n"), data + b"component_result=PASS\r\n",
                      data + b"unexpected=PASS\r\n", data + b"bad=\xff\r\n", data.replace(b"probe v1", b"probe v2")):
            self.change_log("QJS13.LOG", value); self.reject()

    def test_qemu_zero_and_supervisor_request_cannot_replace_actual_child_exit(self):
        for key, value in (("child.created","0"), ("child.create-error","5"), ("child.wait","258"), ("child.exit-query","0"),
            ("child.exit-query-error","5"), ("child.exit-code","259"), ("child.exit-code","2"), ("child.stdout-flushed","0"),
            ("child.handles-closed","0"), ("child.success","0"), ("child.pid","0"), ("child.pid","4294967296"),
            ("supervisor.requested-exit-code","2"), ("os.build-low","1998"), ("profile","genuine-mshtml-direct-host"),
            ("nonce","old-trial"), ("child.path",M.PREFIX+"OTHER.EXE")):
            with self.subTest(key=key):
                self.change_log("JSRUN.LOG", log(self.observer | {key:value})); self.reject()
        fields=self.observer.copy(); del fields["child.exit-code"]
        self.change_log("JSRUN.LOG",log(fields)); self.reject()

    def test_partial_duplicate_or_diagnostic_observer_rejected(self):
        data=self.payloads["JSRUN.LOG"]
        for value in (data[:-2], data+b"child.exit-code=0\r\n", data+b"child.terminated=1\r\n", b""):
            self.change_log("JSRUN.LOG",value); self.reject()

    def test_unexpected_inherited_stdout_is_not_success(self):
        self.change_log("JSOUT.LOG",b"runtime exception\r\n"); self.reject()

    def test_exact_three_inputs_outputs_and_two_receipts_required(self):
        for key in ("inputs", "outputs", "source_receipts"):
            saved=copy.deepcopy(self.manifest[key])
            for values in (saved[:-1], saved+[saved[0]]):
                self.manifest[key]=values; self.sync(); self.reject()
            self.manifest[key]=saved

    def test_different_command_network_or_manifest_generation_rejected(self):
        for key, value in (("command",M.PREFIX+"QJS13PR.EXE"),("network_required",True),("schema",True),("kind","other"),("nonce","../bad")):
            old=self.manifest[key]; self.manifest[key]=value; self.sync(); self.reject(); self.manifest[key]=old

    def test_unapproved_receipt_hash_rejected(self):
        self.pins["runtime-build.json"]="0"*64; self.reject()

    def test_merged_source_profile_and_frozen_source_bytes_bound(self):
        path=self.stage/"source/src/m98_trident_script.h"; path.write_bytes(b"other ABI"); self.reject()

    def test_shared_source_pin_collision_rejected(self):
        self.builds["observer-build.json"]["source_sha256"]["benchmarks/win98se-ko-oem-native-exports-v1.json"]="0"*64
        self.sync_builds(); self.reject()

    def test_missing_or_extra_runtime_source_profile_rejected(self):
        hashes=self.builds["runtime-build.json"]["source_sha256"]; del hashes["src/m98_trident_script_fp.c"]
        self.sync_builds(); self.reject()

    def test_prepared_original_licence_and_embedded_fixture_drift_rejected(self):
        for relative in ("runtime-prepared/quickjs/quickjs.c", "runtime-original/quickjs/LICENSE",
                         "runtime-original/math/COPYRIGHT", "runtime-original/math/src/math/round.c", "runtime-selected.h"):
            path=self.stage/relative; old=path.read_bytes(); path.write_bytes(b"changed source")
            self.reject(); path.write_bytes(old)

    def test_missing_licence_pins_rejected_even_with_reapproved_receipt(self):
        del self.builds["runtime-build.json"]["dependency"]["musl_original_sha256"]["COPYRIGHT"]
        self.sync_builds(); self.reject()

    def test_dependency_paths_cannot_escape_frozen_snapshot(self):
        for value in ("../COPYRIGHT", "/COPYRIGHT", "src//round.c"):
            self.builds["runtime-build.json"]["dependency"]["musl_original_sha256"][value]="0"*64
            self.sync_builds(); self.reject()
            del self.builds["runtime-build.json"]["dependency"]["musl_original_sha256"][value]

    def test_dependency_and_observer_nonce_must_match(self):
        self.builds["observer-build.json"]["nonce"]="old-trial"; self.sync_builds(); self.reject()

    def test_step_logs_bytes_success_and_scope_bound(self):
        path=self.stage/"build-logs/runtime/host-run.log"; path.write_bytes(b"different log"); self.reject()

    def test_failed_step_is_not_successful_build(self):
        self.builds["runtime-build.json"]["steps"][0]["returncode"]=1; self.sync_builds(); self.reject()

    def test_all_linked_runtime_and_probe_i486_checks_are_required(self):
        for name in ("M98QJS.DLL", "QJS13PR.EXE"):
            artifact=self.builds["runtime-build.json"]["artifacts"][name]
            old=copy.deepcopy(artifact["i486_instructions"])
            for value in (100, {}, {"instructions_decoded":True,"post_i486_families":"absent"},
                          {"instructions_decoded":0,"post_i486_families":"absent"},
                          {"instructions_decoded":1048577,"post_i486_families":"absent"},
                          {"instructions_decoded":100,"post_i486_families":"fcomi"}, old|{"extra":"pass"}):
                artifact["i486_instructions"]=value; self.sync_builds(); self.reject()
            artifact["i486_instructions"]=old

    def test_exact_runtime_exports_and_distinct_stack_profiles_required(self):
        for name,role in (("M98QJS.DLL","runtime"),("QJS13PR.EXE","runtime"),("M98JSRUN.EXE","observer")):
            item=self.builds[role+"-build.json"]["artifacts"][name]; old=item["stack_commit"]
            item["stack_commit"]=65536 if role=="runtime" else 524288; self.sync_builds(); self.reject(); item["stack_commit"]=old
        self.builds["runtime-build.json"]["artifacts"]["M98QJS.DLL"]["exports"].append("fake")
        self.sync_builds(); self.reject()

    def test_selected_counts_and_unexecuted_build_claims_strict(self):
        build=self.builds["runtime-build.json"]
        for key,value in (("selected_es2026_checks",33),("selected_numeric_checks",True),("native_math_verified",True),("user_objective_complete",True)):
            old=build[key]; build[key]=value; self.sync_builds(); self.reject(); build[key]=old

    def test_native_input_size_hash_and_private_copy_bound(self):
        self.manifest["inputs"][0]["bytes"]=True; self.sync(); self.reject()

    def test_private_prepared_bytes_drift_rejected(self):
        (self.run/"prepared-guest-M98QJS.DLL").write_bytes(b"different DLL"); self.reject()

    def test_readback_must_be_fresh_captured_exact_path_and_size(self):
        row=self.result["guest_files"]["readback"][0]
        for key,value in (("freshness","existing"),("status","missing"),("bytes",True),("sha256","0"*64),
                          ("path",str(self.run/"OTHER.LOG"))):
            old=row[key]; row[key]=value; self.write_run(); self.reject(); row[key]=old

    def test_missing_and_duplicate_output_readback_rejected(self):
        self.result["guest_files"]["readback"].append(self.result["guest_files"]["readback"][0].copy())
        self.write_run(); self.reject()

    def test_immutable_scope_baseline_and_preservation_required(self):
        files=self.result["guest_files"]
        for key,value in (("immutable_sources_unchanged",False),("output_baseline","already present"),("immutable_sources",{})):
            old=files[key]; files[key]=value; self.write_run(); self.reject(); files[key]=old

    def test_exact_cold_offline_hardware_guards_required(self):
        hardware=self.result["hardware"]
        for key,value in (("network","user"),("accel","tcg"),("memory",256),("memory",True),("smp",1),
                          ("reserve_gib",19),("reserve_gib",True),("manual_gui",False),("firmware_gop",False),("run_name","other")):
            old=hardware[key]; hardware[key]=value; self.write_run(); self.reject(); hardware[key]=old

    def test_stopped_run_firmware_and_private_cold_clone_required(self):
        for key,value in (("qemu_exit_code",True),("qemu_exit_code",2),("manual_finish_requested",False),("firmware_gop_opt_in",False),
                          ("originals_unchanged",False),("prepared_source_unchanged",False),("runtime_failure",True),("error","fault")):
            old=self.result.get(key); self.result[key]=value; self.write_run(); self.reject()
            if old is None: del self.result[key]
            else: self.result[key]=old
        self.result["prepared_reuse"]["method"]="hot saved state"; self.write_run(); self.reject()

    def test_frozen_harness_source_and_run_receipt_hash_required(self):
        self.harness_sha="0"*64; self.reject()

    def test_manifest_build_and_run_json_duplicate_keys_fail_closed(self):
        for path in (self.manifest_path,self.run_path,self.stage/"runtime-build.json"):
            old=path.read_bytes(); path.write_bytes(old[:-2]+b',"passed":true,"passed":true}\n')
            if path==self.run_path: self.run_sha=digest(path)
            elif path==self.manifest_path: self.manifest_sha=digest(path)
            else:
                self.pins["runtime-build.json"]=digest(path)
                self.manifest["source_receipts"][0]["sha256"]=digest(path); self.sync()
            self.reject(); path.write_bytes(old)

    def test_nonfinite_json_rejected(self):
        self.run_path.write_text('{"value":NaN}\n'); self.run_sha=digest(self.run_path); self.reject()

    def test_symlink_evidence_and_parent_directories_rejected(self):
        path=self.run/"guest-output-QJS13.LOG"; target=self.run/"original.log"; path.rename(target); path.symlink_to(target)
        self.reject(); path.unlink(); target.rename(path)
        directory=self.stage/"runtime-original/math"; target=directory.with_name("original-math"); directory.rename(target); directory.symlink_to(target,target_is_directory=True)
        self.reject()

    def test_fifo_and_bounded_read_rejected_without_blocking(self):
        import os
        path=self.root/"fifo"; os.mkfifo(path)
        with self.assertRaises(M.EvidenceError): M.H.read(path,64)
        path=self.root/"large"; path.write_bytes(b"x"*65)
        with self.assertRaises(M.EvidenceError): M.H.read(path,64)

    def test_read_state_change_rejected(self):
        real=M.H.os.fstat; count=0
        def changing(fd):
            nonlocal count
            value=real(fd); count+=1
            if count%2==0:
                class Changed:
                    def __getattr__(self,name): return getattr(value,name)+1 if name=="st_mtime_ns" else getattr(value,name)
                return Changed()
            return value
        with mock.patch.object(M.H.os,"fstat",side_effect=changing):
            with self.assertRaises(M.EvidenceError): M.H.read(self.run_path)

    def test_helper_hash_is_checked_before_compilation(self):
        path=self.root/"changed-helper.py"; path.write_bytes(b'raise RuntimeError("must never execute")\n')
        with mock.patch.object(M,"HELPER_PATH",path):
            with self.assertRaisesRegex(ValueError,"hash differs"): M.helper()

    def test_cli_optimized_and_normal_cannot_pass_partial_child(self):
        self.change_log("JSRUN.LOG",log(self.observer | {"child.exit-query":"0"}))
        args=[str(ROOT/"tools/verify_trident_script_native.py"),"--run-result",str(self.run_path),"--run-result-sha256",self.run_sha,
              "--manifest",str(self.manifest_path),"--manifest-sha256",self.manifest_sha,"--harness-sha256",self.harness_sha,
              "--runtime-build-sha256",self.pins["runtime-build.json"],"--observer-build-sha256",self.pins["observer-build.json"]]
        for flags in (("-B",),("-B","-O")):
            completed=subprocess.run([sys.executable,*flags,*args],capture_output=True,text=True,timeout=10)
            self.assertEqual(completed.returncode,1,completed.stderr)
            self.assertIs(json.loads(completed.stdout)["passed"],False)

    def checkpoints(self):
        """Separate immutable synthetic build checkpoints from their stage."""
        import shutil
        owned=self.root/"project"; (owned/"build").mkdir(parents=True)
        builds=copy.deepcopy(self.builds); paths={}; pins={}
        for name,build in builds.items():
            role=name.removesuffix("-build.json"); base=owned/"build"/role; base.mkdir()
            for relative in build["source_sha256"]:
                for target in (owned/relative,base/"source"/relative):
                    target.parent.mkdir(parents=True,exist_ok=True)
                    shutil.copyfile(self.stage/"source"/relative,target)
            for artifact in build["artifacts"]: shutil.copyfile(self.stage/artifact,base/artifact)
            original=build["steps"][0]["log"]
            path=base/Path(original).name
            shutil.copyfile(self.stage/"build-logs"/role/path.name,path)
            build["steps"][0]["log"]=str(path)
            if role=="runtime":
                shutil.copytree(self.stage/"runtime-prepared",base/"prepared")
                shutil.copytree(self.stage/"runtime-original",base/"original")
                shutil.copyfile(self.stage/"runtime-selected.h",base/"selected.h")
                build["prepared_sha256"]={str(base/"prepared"/key.split("/prepared/")[1]):value
                                           for key,value in build["prepared_sha256"].items()}
            path=base/"result.json"; write(path,build); paths[role]=path; pins[role]=digest(path)
        return owned,paths,pins

    def test_stager_synthetic_success_binds_three_inputs_and_leaves_vm_pending(self):
        owned,paths,pins=self.checkpoints(); destination=owned/"build"/"new-stage"
        with mock.patch.multiple(S,ROOT=owned,BOOT_BUILD=owned/"build"):
            result=S.freeze(paths["runtime"],pins["runtime"],paths["observer"],pins["observer"],destination)
        self.assertIs(result["native_execution"],False)
        manifest,inputs,_,sources,_,_,_=M.approved_stage(destination/"guest-files.json",result["sha256"],
            {"runtime-build.json":pins["runtime"],"observer-build.json":pins["observer"]})
        self.assertEqual(set(inputs),M.INPUTS)
        self.assertEqual(len(sources),23)
        self.assertEqual(manifest["nonce"],self.nonce)

    def test_stager_current_source_drift_rejected_before_final_directory_creation(self):
        owned,paths,pins=self.checkpoints(); destination=owned/"build"/"new-stage"
        (owned/"src/m98_trident_script.h").write_bytes(b"changed ABI")
        with mock.patch.multiple(S,ROOT=owned,BOOT_BUILD=owned/"build"):
            with self.assertRaises(ValueError): S.freeze(paths["runtime"],pins["runtime"],paths["observer"],pins["observer"],destination)
        self.assertFalse(destination.exists())

    def test_stager_invalid_probe_gate_rejected_before_final_directory_creation(self):
        owned,paths,pins=self.checkpoints(); destination=owned/"build"/"new-stage"
        build=json.loads(paths["runtime"].read_bytes()); build["artifacts"]["QJS13PR.EXE"]["i486_instructions"]["post_i486_families"]="fcomi"
        write(paths["runtime"],build); pins["runtime"]=digest(paths["runtime"])
        with mock.patch.multiple(S,ROOT=owned,BOOT_BUILD=owned/"build"):
            with self.assertRaises(ValueError): S.freeze(paths["runtime"],pins["runtime"],paths["observer"],pins["observer"],destination)
        self.assertFalse(destination.exists())

    def test_stager_never_overwrites_existing_or_symlink_stage(self):
        owned,paths,pins=self.checkpoints(); destination=owned/"build"/"new-stage"; destination.mkdir()
        marker=destination/"marker"; marker.write_bytes(b"preserved")
        with mock.patch.multiple(S,ROOT=owned,BOOT_BUILD=owned/"build"):
            with self.assertRaises(ValueError): S.freeze(paths["runtime"],pins["runtime"],paths["observer"],pins["observer"],destination)
        self.assertEqual(marker.read_bytes(),b"preserved")
        marker.unlink(); destination.rmdir(); destination.symlink_to(self.stage,target_is_directory=True)
        with mock.patch.multiple(S,ROOT=owned,BOOT_BUILD=owned/"build"):
            with self.assertRaises(ValueError): S.freeze(paths["runtime"],pins["runtime"],paths["observer"],pins["observer"],destination)

    def test_stager_rejects_worktree_receipts_outside_canonical_native_scope(self):
        owned,paths,pins=self.checkpoints()
        boot=self.root/"boot"/"build"; boot.mkdir(parents=True)
        destination=owned/"build"/"host-only-stage"
        with mock.patch.multiple(S,ROOT=owned,BOOT_BUILD=boot):
            with self.assertRaisesRegex(ValueError,"canonical boot build receipt scope"):
                S.freeze(paths["runtime"],pins["runtime"],paths["observer"],pins["observer"],destination)
        self.assertFalse(destination.exists())

    def test_stager_boot_stage_keeps_all_receipts_inside_native_harness_scope(self):
        owned,paths,pins=self.checkpoints()
        boot=self.root/"boot"/"build"; boot.mkdir(parents=True)
        destination=boot/"native-stage"
        with mock.patch.multiple(S,ROOT=owned,BOOT_BUILD=boot):
            result=S.freeze(paths["runtime"],pins["runtime"],paths["observer"],pins["observer"],destination)
        manifest=json.loads((destination/"guest-files.json").read_text())
        self.assertTrue(all(Path(row["path"]).is_relative_to(boot) for row in manifest["source_receipts"]))
        self.assertTrue(all(Path(row["source"]).is_relative_to(destination) for row in manifest["inputs"]))
        self.assertEqual({Path(row["path"]).name:row["sha256"] for row in manifest["source_receipts"]},
                         {"runtime-build.json":pins["runtime"],"observer-build.json":pins["observer"]})
        self.assertFalse(result["native_execution"])


if __name__=="__main__":
    unittest.main()
