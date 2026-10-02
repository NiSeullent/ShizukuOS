#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Source-bound normal-main physical AP TLB proof; no generic MM/SMP acceptance."""
import argparse
import hashlib
import json
import re
import subprocess
import time
import types
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
PRODUCER=ROOT/"shizukudos/tests/run_k64_native_firmware.py"
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def bound_builder():
    raw=PRODUCER.read_bytes();module=types.ModuleType("tlb_bound_producer");module.__file__=str(PRODUCER)
    exec(compile(raw,str(PRODUCER),"exec"),module.__dict__)
    captured=module.capture_sources()
    # The canonical builder now also binds the PE declaration header. Capture
    # its bytes before executing the builder; do not infer inputs after import.
    captured["shizukudos/win64/pe_parse.h"]=(ROOT/"shizukudos/win64/pe_parse.h").read_bytes()
    before={name:hashlib.sha256(data).hexdigest() for name,data in captured.items()}
    if before[str(PRODUCER.relative_to(ROOT))]!=hashlib.sha256(raw).hexdigest():
        raise SystemExit("producer bytes changed during capture; no compiler/guest")
    builder=module.load_builder(captured)
    if {**builder.source_hashes(),str(PRODUCER.relative_to(ROOT)):digest(PRODUCER)}!=before:
        raise SystemExit("captured helper/source closure changed; no compiler/guest")
    return module,builder,captured,before

def evaluate(text,rc,cpus,mode):
    rows=re.findall(r"^SMP-TLB CPU: cpu=(\d+) actual=(\d+) warm=(\d+) reads=(\d+) ack=(\d+) inv=(\d+) bad=(\d+) value=([0-9a-f]+)$",text,re.M)
    total=re.findall(r"^SMP-TLB summary: cpus=(\d+) ready=(\d+) request=(\d+) completed=(\d+) retirements=(\d+) poisoned=(\d+) retained=(\d+) pages=(\d+)/(\d+) bad=(\d+) scheduler_cpus=1$",text,re.M)
    ap=re.findall(r"^SMP-AP summary: discovered=(\d+) arch_online=(\d+) completed=(\d+) bad=(\d+) scheduler_cpus=1$",text,re.M)
    whole=rc==1 and len(re.findall(r"^SHZ-EXIT:0$",text,re.M))==1 and "K64 PMA FAIL:" not in text and "K64 EXCEPTION" not in text and "K64 PMA summary: failures=0 " in text
    component=len(rows)==cpus and {int(r[0]) for r in rows}==set(range(cpus)) and len(total)==1
    if component and mode=="positive":
        t=tuple(map(int,total[0]));component=t[:7]==(cpus,cpus,16,16,16,0,1) and t[7]==t[8] and t[9]==0
        component=component and all(tuple(map(int,r[:7]))==(int(r[0]),int(r[0]),16,48,16,16,0) and int(r[7],16)==0x544c420000000010 for r in rows)
        component=component and ap==[(str(cpus),str(cpus),str(cpus-1),"0")]
    elif component:
        t=tuple(map(int,total[0]));component=t[0:2]==(cpus,cpus) and t[2:7]==(1,0,0,1,1) and t[7]==t[8] and t[9]>0
        victim=next((r for r in rows if r[0]=="1"),None)
        if mode=="no-invalidate":
            component=component and victim is not None and victim[2:7]==("1","3","0","0","2") and int(victim[7],16)==0x544c420000000000
        else:
            component=component and victim is not None and victim[2:7]==("1","3","0","1","0") and int(victim[7],16)==0x544c420000000001
    return bool(component),bool(whole),{"cpu_rows":rows,"summary":total,"ap_summary":ap}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--build-only",action="store_true");parser.add_argument("--receipt",type=Path)
    parser.add_argument("--cpus",type=int,choices=(2,4),default=4)
    parser.add_argument("--mode",choices=("positive","no-invalidate","withhold-completion"),default="positive")
    parser.add_argument("--accel",choices=("kvm","tcg"),default="kvm")
    parser.add_argument("--qemu",default="/usr/libexec/qemu-kvm");parser.add_argument("--bios",default="/usr/share/seabios/bios-256k.bin")
    args=parser.parse_args();out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    evaluator=digest(__file__);producer,kbuild,captured,before=bound_builder();tools=producer.identities(args.qemu,args.bios)
    def sources(): return {**kbuild.source_hashes(),str(PRODUCER.relative_to(ROOT)):digest(PRODUCER)}
    if args.build_only:
        if args.receipt:parser.error("build-only cannot reuse an unreviewed receipt")
        for name,data in captured.items():
            path=out/"source"/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        kbuild.BUILD=out/"compiled"
        with (out/"build.log").open("w") as log:
            previous=kbuild.run
            def logged(command,**kw):
                if kw.get("capture"):return previous(command,**kw)
                result=subprocess.run([str(v) for v in command],stdout=log,stderr=subprocess.STDOUT);result.check_returncode();return result
            kbuild.run=logged
            extra=[ROOT/"shizukudos/win64/pe_parse.c",kbuild.STUB_DIR/"standalone64.c",ROOT/"drivers/ahci_native/ahci.c",*sorted((ROOT/"shizukufs/v1/libsfs").glob("*.c")),*kbuild.dead_screen_sources()]
            kernel=kbuild.build_kernel("kernel64s","kernel64",kbuild.K64_FLAGS+["-DSHZ_STANDALONE"],"elf64","elf_x86_64","KERNEL64S.BIN",extra_c=extra)
            stub=kbuild.build_standalone_stub()
        inputs={str(kernel["bin"]):digest(kernel["bin"]),str(kernel["elf"]):digest(kernel["elf"]),str(stub["elf"]):digest(stub["elf"])}
        stable=sources()==before and producer.identities(args.qemu,args.bios)==tools and digest(__file__)==evaluator
        result={"status":"BUILT" if stable else "FAIL","scope":"captured-source normal production build; no guest executed or whole acceptance","whole_acceptance":False,"sources_sha256":before,"sources_unchanged":stable,"compiled_inputs_sha256":inputs,"tools":tools,"executed_helpers_sha256":{n:before[n] for n in ("shizukudos/kbuild.py","shizukudos/tools/shzlib.py")},"executed_producer_sha256":before[str(PRODUCER.relative_to(ROOT))],"evaluator_sha256":evaluator}
        (out/"result.json").write_text(json.dumps(result,indent=2)+"\n");print(json.dumps({k:v for k,v in result.items() if k!="sources_sha256"},indent=2));return 0 if stable else 1
    if not args.receipt:parser.error("captured-source BUILT receipt required")
    receipt_bytes=args.receipt.read_bytes();receipt_sha=hashlib.sha256(receipt_bytes).hexdigest();built=json.loads(receipt_bytes)
    if built.get("status")!="BUILT" or built.get("sources_unchanged") is not True or built.get("sources_sha256")!=before or built.get("evaluator_sha256")!=evaluator or built.get("tools")!=tools:
        raise SystemExit("compiled source/helper/evaluator/tool closure does not match")
    inputs=built["compiled_inputs_sha256"]
    if len(inputs)!=3 or {Path(p).name for p in inputs}!={"KERNEL64S.BIN","kernel64s.elf","boot.elf"}:raise SystemExit("incomplete compiled artifact set")
    def stable():return sources()==before and digest(__file__)==evaluator and digest(args.receipt)==receipt_sha and producer.identities(args.qemu,args.bios)==tools and all(digest(p)==h for p,h in inputs.items())
    if not stable():raise SystemExit("compiled inputs changed before guest")
    kernel=next(p for p in inputs if p.endswith("KERNEL64S.BIN"));stub=next(p for p in inputs if p.endswith("boot.elf"));serial=out/"serial.log"
    flag={"positive":"","no-invalidate":" shz.tlb=no-invalidate","withhold-completion":" shz.tlb=withhold-completion"}[args.mode]
    command=[tools["qemu"]["path"],"-machine","pc","-bios",tools["bios"]["path"],"-accel",args.accel,"-cpu","max","-m","256","-smp",str(args.cpus),"-kernel",stub,"-initrd",kernel,"-append","shz.pma=test shz.smp=bringup shz.tlb=test"+flag,"-display","none","-monitor","none","-serial",f"file:{serial}","-no-reboot","-device","isa-debug-exit,iobase=0xf4,iosize=0x04"]
    start=time.monotonic()
    try:
        run=subprocess.run(command,capture_output=True,text=True,timeout=60);rc,timed_out,error=run.returncode,False,run.stderr
    except subprocess.TimeoutExpired as exc:rc,timed_out,error=None,True,str(exc.stderr)
    (out/"qemu.log").write_text(error or "");text=serial.read_text(errors="replace") if serial.exists() else ""
    component,whole,evidence=evaluate(text,rc,args.cpus,args.mode);unchanged=stable();valid=component and whole and unchanged and not timed_out
    result={"status":"PASS" if valid else "FAIL","scope":"actual shared-kernel aperture invalidation only; AP scheduler/process unsupported","whole_acceptance":False,"mode":args.mode,"cpus":args.cpus,"tlb_component_pass":component,"whole_native_gate_pass":whole,"expected_behavior":valid,"command":command,"qemu_returncode":rc,"timed_out":timed_out,"elapsed_seconds":time.monotonic()-start,"actual_evidence":evidence,"sources_sha256":before,"compiled_inputs_sha256":inputs,"tools":tools,"producer_receipt_sha256":receipt_sha,"evaluator_sha256":evaluator,"inputs_sources_tools_unchanged":unchanged,"serial_sha256":digest(serial) if serial.exists() else None}
    (out/"result.json").write_text(json.dumps(result,indent=2)+"\n");print(json.dumps({k:v for k,v in result.items() if k!="sources_sha256"},indent=2));return 0 if valid else 1
if __name__=="__main__":raise SystemExit(main())
