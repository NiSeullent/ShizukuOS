#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real AP evaluator/helper race controls; modeled receipt/VM boundary only.

Disposable copies use the actual archived 219 source bytes and exact validated
machine inputs. A prepared successor receipt expects the replacement helper
comment bytes. Loading the older bytes and later recording those newer bytes
must not reach the VM boundary. No guest is launched and originals are intact.
"""
import argparse
import hashlib
import importlib.util
import json
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
EVALUATOR=ROOT/"shizukudos/tests/run_k64_ap_bringup.py"
PRIOR=ROOT/"build/smp-normal-firmware-bound-3"
CHANGE=b"\n# private successor helper identity\n"


class VMBoundaryReached(Exception):
    pass


def trial(target):
    with tempfile.TemporaryDirectory(prefix="smp-ap-evaluator-identity-") as temporary:
        root=Path(temporary)
        with zipfile.ZipFile(PRIOR/"source-snapshot-219.zip") as archive:
            for name in archive.namelist():
                if name.startswith("sources/"):
                    destination=root/name[len("sources/"):]
                    destination.parent.mkdir(parents=True,exist_ok=True)
                    destination.write_bytes(archive.read(name))
        evaluator=root/EVALUATOR.relative_to(ROOT)
        evaluator.parent.mkdir(parents=True,exist_ok=True)
        evaluator.write_bytes(EVALUATOR.read_bytes())
        receipt=json.loads((PRIOR/"result.json").read_bytes())
        mutation=root/target if target else None
        if mutation:
            receipt["sources_sha256"][target]=hashlib.sha256(mutation.read_bytes()+CHANGE).hexdigest()
        receipt_path=root/"prepared-successor.json"
        receipt_path.write_text(json.dumps(receipt))
        spec=importlib.util.spec_from_file_location("smp_private_ap_evaluator",evaluator)
        runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
        replaced=False
        def after_load(frame,event,arg):
            nonlocal replaced
            if event=="return" and frame.f_code.co_name=="<module>" and mutation and \
               Path(frame.f_code.co_filename)==mutation and not replaced:
                mutation.write_bytes(mutation.read_bytes()+CHANGE);replaced=True
        def stop_vm(*args,**kwargs):
            raise VMBoundaryReached("VM boundary reached")
        saved_profile,saved_path=sys.getprofile(),list(sys.path)
        saved_shzlib=sys.modules.pop("shzlib",None)
        try:
            sys.setprofile(after_load)
            with patch.object(sys,"argv",[str(evaluator),"--receipt",str(receipt_path),"--out",str(root/"proof")]), \
                 patch.object(runner.subprocess,"run",side_effect=stop_vm):
                try:
                    runner.main();outcome="unexpected return"
                except VMBoundaryReached:
                    outcome="VM boundary reached"
                except SystemExit as exc:
                    outcome=str(exc)
        finally:
            sys.setprofile(saved_profile);sys.path[:]=saved_path
            sys.modules.pop("shzlib",None)
            if saved_shzlib is not None:sys.modules["shzlib"]=saved_shzlib
        valid=outcome=="VM boundary reached" if not mutation else replaced and "closure changed" in outcome
        return {"target":target,"replacement_performed":replaced,"actual":outcome,"expected_behavior":bool(valid)}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    cases=[trial(None),trial("shizukudos/kbuild.py"),trial("shizukudos/tools/shzlib.py")]
    okay=all(row["expected_behavior"] for row in cases)
    result={"status":"PASS" if okay else "FAIL","scope":"actual evaluator/copied helpers; prepared successor receipt and stopped VM boundary; no guest/source-origin acceptance claim",
            "evaluator_sha256":hashlib.sha256(EVALUATOR.read_bytes()).hexdigest(),
            "test_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),"cases":cases}
    (args.out/"result.json").write_text(json.dumps(result,indent=2)+"\n");print(json.dumps(result,indent=2))
    return 0 if okay else 1


if __name__=="__main__":raise SystemExit(main())
