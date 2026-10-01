#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Strict read-only acceptance of a frozen runtime-only Win98 trial.

Trusted source/build/harness hashes are supplied independently by the caller.
No VM, network, installation or inference from QEMU/requested supervisor exits.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types

HELPER_SHA256 = "955be0f0d70a91fa22dbeab27074eeef223699414476d80b8b749dca22252a65"
HELPER_PATH = Path(__file__).resolve().with_name("verify_trident_automation_native.py")

def helper():
    """Compile exactly the pinned bytes; no second pathname import/TOCTOU."""
    path = HELPER_PATH.absolute()
    if path.resolve(strict=True) != path:
        raise ValueError("noncanonical/symlink verifier helper")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 65536:
            raise ValueError("nonregular/unbounded verifier helper")
        data = os.read(fd, 65537)
        after = os.fstat(fd)
        if len(data) != before.st_size or any(getattr(before,k) != getattr(after,k) for k in
                ("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns")):
            raise ValueError("verifier helper changed during read")
    finally:
        os.close(fd)
    if hashlib.sha256(data).hexdigest() != HELPER_SHA256:
        raise ValueError("frozen verifier helper hash differs")
    module = types.ModuleType("pinned_trident_evidence_helpers")
    exec(compile(data,str(path),"exec"),module.__dict__)
    return module

H = helper()
EvidenceError = H.EvidenceError
PREFIX = H.PREFIX
INPUTS = {"QJS13PR.EXE","M98QJS.DLL","M98JSRUN.EXE"}
OUTPUTS = {"QJS13.LOG","JSRUN.LOG","JSOUT.LOG"}
RECEIPTS = {"runtime-build.json","observer-build.json"}
SEMANTIC_JSON = '{"scope":"selected ES2026 semantic checks","checks":34,"full_conformance_verified":false,"browser_dom_verified":false}'
NUMERIC_JSON = '{"scope":"selected numeric semantics","checks":24,"full_conformance_verified":false,"native_math_verified":false}'

def check_catalog():
    """Acceptance catalog reviewed against the frozen v10 native fixture.

    Every eval/result-release/byte check remains observable; no skipped loops
    or isolated PASS substring can stand in for the complete ordered run.
    """
    result = ["win98se_4_10_2222","probe_exact_path","runtime_exact_path",
        "m98_script_open","m98_script_bind_root","m98_script_eval","m98_script_invoke",
        "m98_script_invoke_this","m98_script_jobs","m98_script_release_result","m98_script_info","m98_script_close",
        "caller_x87_test_environment","runtime_open","explicit_platform_observer_root",
        "eval","actual_internal_x87_pc64_nearest_masks","release_result","caller_full_x87_environment_restored"]
    for label in ("single_thread_shared_memory_policy","modern_syntax_private_optional_nullish",
                  "bigint_set_typedarray","modern_math"):
        result += ["eval",label,"release_result"]
    result += ["eval","selected_es2026_json"] + ["selected_es2026_json_bytes"]*len(SEMANTIC_JSON) + ["release_result"]
    result += ["eval","selected_numeric_json"] + ["selected_numeric_json_bytes"]*len(NUMERIC_JSON) + ["release_result"]
    result += ["caller_x87_restored_after_numeric_math","eval","actual_utc_localtimezone","release_result",
        "eval","utf16_length"] + ["utf16_nul_surrogates"]*6 + ["release_result",
        "eval","promise_pending","release_result","promise_jobs","eval","promise_result","release_result",
        "eval","function_cookie","release_result","safe_function_invoke","release_result",
        "eval","explicit_receiver_function","release_result","native_explicit_this_receiver","release_result",
        "interpreter_interrupt","interrupt_diagnostics","eval","runtime_isolation","release_result",
        "runtime_close","stale_context_rejected","new_context_generation","stale_function_rejected"]
    return result

CHECKS = check_catalog()

def component(raw,nonce,dll_sha):
    header=b"M98QJS runtime-only native probe v1\r\n"
    H.need(raw.startswith(header),"different native runtime fixture generation")
    fields,_=H.pairs(raw[len(header):])
    expected={"nonce":nonce,"expected_runtime_sha256":dll_sha,"observed_internal_x87_control_word":"895",
        "selected_es2026_checks":"34","selected_numeric_checks":"24","checks":str(len(CHECKS)),
        "component_result":"PASS","mshtml_automation_verified":"0","html5_verified":"0","wasm_verified":"0",
        "es2026_conformance":"0","applications_verified":"0","actual_child_exit":"externally_observed_only"}
    keys=set(expected)|{"original_x87_control_word"}|{f"check_{i}" for i in range(1,len(CHECKS)+1)}
    H.need(set(fields)==keys,"native runtime checks/metadata are missing, duplicated, extra or stale")
    H.need([k for k in fields if k.startswith("check_")]==
           [f"check_{i}" for i in range(1,len(CHECKS)+1)],"native runtime check order differs")
    H.need(all(fields[k]==v for k,v in expected.items()),"native runtime semantic/x87/nonce/scope summary differs")
    for i,label in enumerate(CHECKS,1):
        H.need(fields[f"check_{i}"]==label+":PASS",f"native runtime check {i} ({label}) did not complete")
    original=H.uint(fields["original_x87_control_word"],"original x87 control word")
    H.need(original<=65535,"original x87 word exceeds actual hardware width")
    return {"checks":len(CHECKS),"selected_es2026_checks":34,"selected_numeric_checks":24,
        "original_x87_control_word":original,"observed_internal_x87_control_word":895,
        "caller_x87_state_restoration_verified":True,"actual_utc_and_current_timezone_check_verified":True,
        "scope":"frozen selected semantics/runtime lifetime; not full language, historical timezone or DOM certification"}

def observer(raw,nonce):
    fields,_=H.pairs(raw)
    expected={"scope":"actual-win98-trident-owned-child-observer","nonce":nonce,"profile":"runtime-only",
        "WIN98_IDENTIFIED":"1","os.major":"4","os.minor":"10","os.build-low":"2222","os.platform":"1",
        "child.path":PREFIX+"QJS13PR.EXE","child.stdout":PREFIX+"JSOUT.LOG","child.created":"1",
        "child.create-error":"0","child.wait":"0","child.exit-query":"1","child.exit-query-error":"0",
        "child.exit-code":"0","child.stdout-flushed":"1","child.handles-closed":"1","child.success":"1",
        "supervisor.requested-exit-code":"0"}
    H.need(set(fields)==set(expected)|{"child.pid"} and all(fields[k]==v for k,v in expected.items()),
           "observer lacks actual owned child exit zero and complete flush/close")
    return H.uint(fields["child.pid"],"actual owned child PID",True)

def original_sources(runtime,stage,directory="runtime-original"):
    dependency=runtime.get("dependency")
    H.need(isinstance(dependency,dict) and dependency.get("quickjs_version")=="2026-06-04" and
           dependency.get("musl_revision")=="c4e1bb3994c14ed5112c894d15a451bf00f0d501","approved source dependency generation differs")
    result={}
    for role,key in (("quickjs","quickjs_original_sha256"),("math","musl_original_sha256")):
        hashes=dependency.get(key)
        H.need(isinstance(hashes,dict) and 1<=len(hashes)<=128,"original source pin set missing/unbounded")
        for name,digest in hashes.items():
            H.need(isinstance(name,str) and re.fullmatch(r"[A-Za-z0-9_./-]{1,200}",name) and
                   all(p not in {"",".",".."} for p in name.split("/")),"original source path escapes snapshot")
            H.need(H.sha(H.read(stage/directory/role/name,8<<20))==H.pin(digest,"original dependency source"),
                   "original source/licence snapshot changed")
            result[role+"/"+name]=digest
    H.need("quickjs/LICENSE" in result and "math/COPYRIGHT" in result and "math/src/math/round.c" in result,
           "original licences/required actual helper source missing")
    return result

def instructions(item):
    record=item.get("i486_instructions")
    H.need(isinstance(record,dict) and set(record)=={"instructions_decoded","post_i486_families"} and
           type(record["instructions_decoded"]) is int and 0<record["instructions_decoded"]<=1048576 and
           record["post_i486_families"]=="absent","approved linked i486 instruction evidence differs")

def approved_stage(manifest_path,manifest_sha,build_pins):
    manifest_path=Path(manifest_path).absolute();stage=manifest_path.parent
    manifest=H.receipt(manifest_path,manifest_sha,65536)
    H.need(type(manifest.get("schema")) is int and manifest["schema"]==1 and
           manifest.get("kind")=="isolated-guest-file-inputs","unsupported frozen manifest schema/kind")
    nonce=manifest.get("nonce")
    H.need(isinstance(nonce,str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}",nonce),"bounded trial nonce required")
    H.need(manifest.get("command")==PREFIX+"M98JSRUN.EXE" and manifest.get("network_required") is False,
           "manifest is not the offline runtime-only observer")
    H.need(isinstance(manifest.get("outputs"),list) and len(manifest["outputs"])==3 and
           set(manifest["outputs"])=={PREFIX+n for n in OUTPUTS},"different runtime output plan")
    inputs_by_guest=H.records(manifest.get("inputs"),{PREFIX+n for n in INPUTS})
    inputs={}
    for guest,row in inputs_by_guest.items():
        name=guest[len(PREFIX):];path=H.local(row.get("source"),stage)
        H.need(path.name==name,"different guest/source input filename")
        data=H.read(path,1048576)
        H.need(type(row.get("bytes")) is int and row["bytes"]==len(data) and 0<len(data)<=1048576 and
               H.sha(data)==H.pin(row.get("sha256"),"guest input"),"changed staged input")
        inputs[name]=row
    H.need(isinstance(build_pins,dict) and set(build_pins)==RECEIPTS,"exact two caller-approved build pins required")
    receipts=H.records(manifest.get("source_receipts"),{str(stage/n) for n in RECEIPTS},"path")
    builds={};logs={};merged={}
    for name in sorted(RECEIPTS):
        row=receipts[str(stage/name)]
        H.need(row.get("sha256")==H.pin(build_pins[name],name),"unapproved staged build receipt")
        builds[name]=H.receipt(H.local(row["path"],stage),build_pins[name])
        H.need(builds[name].get("passed") is True,"approved build did not pass")
        logs[name]=H.build_logs(builds[name],stage/"build-logs"/name.removesuffix("-build.json"))
    runtime,observed=builds["runtime-build.json"],builds["observer-build.json"]
    H.need(runtime.get("profile")=="bounded-local-trident-quickjs-v1" and runtime.get("nonce")==nonce and
           observed.get("kind")=="win98-trident-owned-child-observer-build" and
           type(observed.get("schema")) is int and observed["schema"]==1 and observed.get("nonce")==nonce,
           "runtime/probe/observer generations differ")
    H.sources(runtime,H.RUNTIME_SOURCES,stage/"source",merged)
    H.sources(observed,H.OBSERVER_SOURCES,stage/"source",merged)
    prepared=H.prepared_sources(runtime,stage/"runtime-prepared")
    originals=original_sources(runtime,stage)
    H.need(H.sha(H.read(stage/"runtime-selected.h",65536))==
           H.pin(runtime.get("embedded_fixture_header_sha256"),"selected fixture header"),"changed embedded selected semantic input")
    dll=H.artifact(runtime,"M98QJS.DLL",inputs["M98QJS.DLL"],524288)
    probe=H.artifact(runtime,"QJS13PR.EXE",inputs["QJS13PR.EXE"],524288)
    supervisor=H.artifact(observed,"M98JSRUN.EXE",inputs["M98JSRUN.EXE"],65536)
    H.need(dll.get("stack_commit")==524288 and probe.get("stack_commit")==524288 and supervisor.get("stack_commit")==65536,
           "different runtime/probe/observer explicit stack profiles")
    H.need(isinstance(dll.get("exports"),list) and len(dll["exports"])==9 and set(dll["exports"])==H.RUNTIME_EXPORTS and
           probe.get("exports")==[],"different exact runtime/probe exports")
    instructions(dll);instructions(probe)
    H.need(supervisor.get("i486_instruction_gate")=="pass","observer lacks linked i486 gate")
    H.need(runtime.get("selected_es2026_checks")==34 and type(runtime["selected_es2026_checks"]) is int and
           runtime.get("selected_numeric_checks")==24 and type(runtime["selected_numeric_checks"]) is int,
           "approved selected semantic fixture counts differ")
    for key in ("native_guest_execution_verified","native_math_verified","mshtml_dom_verified","html5_verified",
                "wasm_verified","full_es2026_conformance_verified","applications_verified","user_objective_complete"):
        H.need(runtime.get(key) is False,"build receipt improperly claims native or whole-objective success")
    profile=observed.get("profiles",{}).get("script")
    H.need(isinstance(profile,dict) and all(profile.get(k)==v for k,v in {
        "self":PREFIX+"M98JSRUN.EXE","supervisor_log":PREFIX+"JSRUN.LOG","child_stdout":PREFIX+"JSOUT.LOG",
        "child":PREFIX+"QJS13PR.EXE","child_log":PREFIX+"QJS13.LOG","child_timeout_ms":60000,"reap_timeout_ms":5000}.items()),
        "different observer runtime child/path/deadline profile")
    return manifest,inputs,receipts,merged,prepared,originals,logs

def verify(run_path,run_sha,manifest_path,manifest_sha,harness_sha,build_pins):
    run_path,manifest_path=Path(run_path).absolute(),Path(manifest_path).absolute()
    run_dir=run_path.parent
    manifest,inputs,receipts,merged,prepared,originals,pinned_logs=approved_stage(manifest_path,manifest_sha,build_pins)
    run=H.receipt(run_path,run_sha,16<<20)
    H.need(run.get("profile")=="actual-win98-uefi-csmwrap" and run.get("status") in {"PASS","NEEDS-VISUAL-REVIEW"} and
           not run.get("runtime_failure") and not run.get("error"),"native harness failed")
    H.need(run.get("originals_unchanged") is True and run.get("prepared_source_unchanged") is True and
           type(run.get("qemu_exit_code")) is int and run["qemu_exit_code"]==0 and run.get("manual_finish_requested") is True,
           "owned native run is not normally stopped/preserved")
    source=H.local(run.get("source_snapshot"),run_dir)
    H.need(source.name=="runner-source.py" and H.sha(H.read(source))==H.pin(harness_sha,"harness")==run.get("source_sha256"),
           "approved native harness source differs")
    hardware=run.get("hardware",{})
    H.need(hardware.get("run_name")==run_dir.name and hardware.get("network")=="none" and hardware.get("accel")=="kvm" and
           type(hardware.get("memory")) is int and hardware["memory"]==128 and type(hardware.get("smp")) is int and hardware["smp"]==2 and
           type(hardware.get("reserve_gib")) is int and hardware["reserve_gib"]==20 and hardware.get("manual_gui") is True and
           hardware.get("firmware_gop") is True and run.get("firmware_gop_opt_in") is True,"different cold GOP/offline hardware profile")
    H.need(run.get("prepared_reuse",{}).get("method","").startswith("verified private sparse post-run disk copy; cold hardware"),
           "verified private cold-clone profile missing")
    files=run.get("guest_files",{})
    H.need(files.get("manifest")==str(manifest_path) and files.get("manifest_sha256")==manifest_sha and
           files.get("immutable_sources_unchanged") is True and files.get("output_baseline")=="all absent before private injection",
           "native staging differs or is stale")
    immutable={str(manifest_path):manifest_sha}|{r["source"]:r["sha256"] for r in inputs.values()}|{r["path"]:r["sha256"] for r in receipts.values()}
    H.need(files.get("immutable_sources")==immutable and files.get("outputs")==manifest["outputs"],"different immutable scope")
    copied=H.records(files.get("inputs"),{PREFIX+n for n in INPUTS})
    for guest,row in copied.items():
        original=inputs[guest[len(PREFIX):]]
        H.need(all(row.get(k)==original[k] for k in ("source","guest","bytes","sha256")) and
               row.get("private_copy_sha256")==original["sha256"] and
               H.sha(H.read(run_dir/("prepared-guest-"+guest[len(PREFIX):]),1048576))==original["sha256"],
               "different private prepared guest input")
    readback=H.records(files.get("readback"),{PREFIX+n for n in OUTPUTS});logs={}
    for guest,row in readback.items():
        name=guest[len(PREFIX):];path=H.local(row.get("path"),run_dir)
        H.need(path.name=="guest-output-"+name,"different stopped collector output path")
        data=H.read(path,65536)
        H.need(row.get("status")=="captured" and row.get("freshness")=="new-in-owned-run" and
               type(row.get("bytes")) is int and row["bytes"]==len(data) and row.get("sha256")==H.sha(data),"missing/stale native readback")
        logs[name]=data
    H.need(logs["JSOUT.LOG"]==b"","unexpected inherited runtime diagnostics")
    nonce=manifest["nonce"]
    pid=observer(logs["JSRUN.LOG"],nonce)
    observations=component(logs["QJS13.LOG"],nonce,inputs["M98QJS.DLL"]["sha256"])
    return {"schema":"win98modern.trident-script-native-component.v1","passed":True,
        "scope":"actual Win98 selected JS/numeric/runtime/x87/UTC component and owned child completion",
        "nonce":nonce,"harness_result_sha256":run_sha,"manifest_sha256":manifest_sha,"harness_source_sha256":harness_sha,
        "verifier_helper_sha256":HELPER_SHA256,"approved_build_sha256":build_pins,"source_sha256":merged,
        "runtime_prepared_sha256":prepared,"runtime_original_sha256":originals,"build_log_sha256":pinned_logs,
        "input_sha256":{n:r["sha256"] for n,r in inputs.items()},"log_sha256":{n:H.sha(data) for n,data in logs.items()},
        "actual_owned_child":{"pid":pid,"exit_code":0,"stdout_flushed":True,"handles_closed":True},
        "supervisor_requested_exit_code":0,"actual_supervisor_exit_verified":False,
        "native_component_execution_verified":True,"native_observations":observations,
        "source_semantics_trust":"caller-approved source/build/harness hashes; bounded byte binding, not independent source-correctness proof",
        "native_mshtml_dom_verified":False,"standard_browser_navigation_verified":False,"full_javascript_verified":False,
        "es2026_conformance_verified":False,"modern_css_verified":False,"webassembly_verified":False,
        "webgpu_verified":False,"webgl_verified":False,"modern_apps_verified":False,"user_objective_complete":False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("run-result","manifest"):
        parser.add_argument("--"+name,type=Path,required=True)
        parser.add_argument("--"+name+"-sha256",required=True)
    parser.add_argument("--harness-sha256",required=True)
    for role in ("runtime","observer"):
        parser.add_argument("--"+role+"-build-sha256",required=True)
    args=parser.parse_args()
    try:
        result=verify(args.run_result,args.run_result_sha256,args.manifest,args.manifest_sha256,args.harness_sha256,
                      {"runtime-build.json":args.runtime_build_sha256,"observer-build.json":args.observer_build_sha256})
    except (EvidenceError,OSError,ValueError,TypeError,KeyError,AttributeError) as error:
        print(json.dumps({"passed":False,"native_component_execution_verified":False,"error":str(error)}));return 1
    print(json.dumps(result,indent=2));return 0

if __name__=="__main__":
    raise SystemExit(main())
