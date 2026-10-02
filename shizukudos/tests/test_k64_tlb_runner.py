#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual evaluator gate and persistent loaded-helper replacement controls.

Private prepared receipts model build admission only; QEMU is stopped at its
boundary. These are not compiled-artifact origin or native execution receipts.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
RUNNER=ROOT/"shizukudos/tests/run_k64_tlb_ap.py"
CHANGE=b"\n# private persistent successor helper\n"
def load(path):
    spec=importlib.util.spec_from_file_location("private_tlb_runner",path);module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module
class VMStopped(Exception): pass

def identity_trial(target,built,captured):
    with tempfile.TemporaryDirectory(prefix="smp-tlb-helper-") as temporary:
        root=Path(temporary)
        for name,data in captured.items():
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
        runner_path=root/RUNNER.relative_to(ROOT);runner_path.parent.mkdir(parents=True,exist_ok=True);runner_path.write_bytes(RUNNER.read_bytes())
        runner=load(runner_path);expected=copy.deepcopy(built)
        expected["sources_sha256"]={name:hashlib.sha256(data).hexdigest() for name,data in captured.items()}
        if target:
            expected["sources_sha256"][target]=hashlib.sha256((root/target).read_bytes()+CHANGE).hexdigest()
        receipt=root/"prepared.json";receipt.write_text(json.dumps(expected));replaced=False
        trigger="shizukudos/kbuild.py" if target=="shizukudos/win64/pe_parse.h" else target
        def after_load(frame,event,arg):
            nonlocal replaced
            if target and not replaced and event=="return" and frame.f_code.co_name=="<module>" and Path(frame.f_code.co_filename)==root/trigger:
                p=root/target;p.write_bytes(p.read_bytes()+CHANGE);replaced=True
        actual_run=runner.subprocess.run
        def stop_guest(command,*args,**kwargs):
            if str(command[0])==built["tools"]["qemu"]["path"]:raise VMStopped("QEMU boundary reached")
            return actual_run(command,*args,**kwargs)
        old_profile=sys.getprofile()
        try:
            sys.setprofile(after_load)
            with patch.object(sys,"argv",[str(runner_path),"--receipt",str(receipt),"--out",str(root/"proof")]),patch.object(runner.subprocess,"run",side_effect=stop_guest):
                try:runner.main();outcome="unexpected return"
                except VMStopped:outcome="QEMU boundary reached"
                except SystemExit as exc:outcome=str(exc)
        finally:sys.setprofile(old_profile)
        valid=outcome=="QEMU boundary reached" if not target else replaced and ("closure changed" in outcome or "producer bytes changed" in outcome)
        return {"target":target,"replaced":replaced,"actual":outcome,"expected_behavior":valid}

def evaluator_trials(runner):
    whole="K64 PMA summary: failures=0 ticks=42\nSHZ-EXIT:0\n"
    rows="".join(f"SMP-TLB CPU: cpu={i} actual={i} warm=16 reads=48 ack=16 inv=16 bad=0 value=544c420000000010\n" for i in range(2))
    summary="SMP-TLB summary: cpus=2 ready=2 request=16 completed=16 retirements=16 poisoned=0 retained=1 pages=100/100 bad=0 scheduler_cpus=1\n"
    ap="SMP-AP summary: discovered=2 arch_online=2 completed=1 bad=0 scheduler_cpus=1\n"
    text=rows+summary+ap+whole
    fixtures=[("positive",text,True,True),("stale-payload",text.replace("value=544c420000000010","value=544c420000000000"),False,True),
              ("future-ack",text.replace("ack=16","ack=17"),False,True),("missing-instruction",text.replace("inv=16","inv=0"),False,True),
              ("premature-reuse",text.replace("completed=16 retirements=16","completed=0 retirements=16"),False,True),
              ("lost-resource",text.replace("retained=1","retained=0"),False,True),
              ("conservation",text.replace("pages=100/100","pages=100/99"),False,True),
              ("duplicate-cpu",text.replace("cpu=1 actual=1","cpu=0 actual=0"),False,True),
              ("whole-failure",text+"K64 PMA FAIL: preserved existing failure\n",True,False),
              ("missing-exit",text.replace("SHZ-EXIT:0\n",""),True,False)]
    results=[]
    for name,serial,component,whole_expected in fixtures:
        observed=runner.evaluate(serial,1,2,"positive")[:2]
        results.append({"case":name,"observed":observed,"expected_behavior":observed==(component,whole_expected)})
    return results
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--receipt",type=Path,required=True);parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False);runner=load(RUNNER)
    producer,builder,captured,before=runner.bound_builder();built=json.loads(args.receipt.read_text())
    # Bind current evaluator and source maps in a prepared non-origin fixture.
    built["status"]="BUILT";built["sources_unchanged"]=True;built["evaluator_sha256"]=runner.digest(RUNNER)
    cases=[identity_trial(target,built,captured) for target in (None,"shizukudos/tests/run_k64_native_firmware.py","shizukudos/kbuild.py","shizukudos/tools/shzlib.py","shizukudos/win64/pe_parse.h")]
    gates=evaluator_trials(runner);okay=all(row["expected_behavior"] for row in cases+gates)
    result={"status":"PASS" if okay else "FAIL","scope":__doc__,"test_sha256":runner.digest(__file__),"evaluator_sha256":runner.digest(RUNNER),"cases":cases,"gates":gates,"guest_executed":False}
    (args.out/"result.json").write_text(json.dumps(result,indent=2)+"\n");print(json.dumps(result,indent=2));return 0 if okay else 1
if __name__=="__main__":raise SystemExit(main())
