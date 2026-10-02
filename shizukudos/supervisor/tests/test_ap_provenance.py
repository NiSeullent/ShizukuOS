#!/usr/bin/env python3
"""Controlled helper/include identity counterexamples and successor controls."""
if '__shz_driver_capture__' not in globals():
    from pathlib import Path as _EntryPath
    import hashlib as _EntryHash
    _entry_path=_EntryPath(__file__).resolve();_entry_bytes=_entry_path.read_bytes()
    _capture={'path':str(_entry_path),'sha256':_EntryHash.sha256(_entry_bytes).hexdigest()}
    exec(compile(_entry_bytes,str(_entry_path),'exec'),{'__name__':__name__,'__file__':str(_entry_path),'__shz_driver_capture__':_capture})
    raise SystemExit(0)
import argparse,ast,hashlib,json,subprocess,sys,types
from pathlib import Path
REPO=Path(__file__).resolve().parents[3]
OUT=REPO/'build/shizukudos/supervisor-ap/provenance-host'
OUT.mkdir(exist_ok=True)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def extract(path,name,namespace):
    tree=ast.parse(path.read_text())
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name)
    exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),namespace)
    return namespace[name]
def main():
    p=argparse.ArgumentParser();p.add_argument('--legacy-red',choices=('helper','dependency'));args=p.parse_args()
    old=REPO/'build/shizukudos/supervisor-ap/r4-retained/source/shizukudos/supervisor/build_ap_component.py'
    helper=OUT/'mutating-helper.py'
    helper.write_text('from pathlib import Path\nvalue=1\nPath(__file__).write_text("value=2\\n")\n')
    original=helper.read_bytes();oldsha=sha(helper)
    if args.legacy_red=='helper':
        fresh=extract(old,'fresh',{'types':types,'sys':sys})
        module=fresh('ap_legacy_counterexample',helper)
        recorded=sha(helper)
        assert module.value==1
        assert recorded==oldsha,'r4 recorded current helper bytes differ from bytes actually executed'
    header=OUT/'generated.h';unit=OUT/'unit.c';binary=OUT/'unit'
    unit.write_text('#include <stdio.h>\n#include "generated.h"\nint main(void){printf("%d\\n",VALUE);}\n')
    header.write_text('#define VALUE 1\n');header_sha=sha(header)
    command=['gcc','-std=c11','-I',str(OUT),str(unit),'-o',str(binary)]
    if args.legacy_red=='dependency':
        subprocess.run(command,check=True);header.write_text('#define VALUE 2\n')
        closure=extract(old,'dependency_closure',{'Path':Path,'shlex':__import__('shlex'),
                      'subprocess':subprocess,'build':types.SimpleNamespace(sha256_file=sha)})
        groups,pins=closure([command],['true'])
        assert subprocess.check_output([binary],text=True).strip()=='1'
        assert pins[str(header.resolve())]==header_sha,'r4 post-build include pin differs from the compiled header'
    fresh=extract(REPO/'shizukudos/supervisor/build_ap_component.py','fresh',
                  {'types':types,'sys':sys,'hashlib':hashlib})
    module=fresh('ap_successor_counterexample',helper,original)
    assert module.value==1 and module.__shz_loaded_sha256__==oldsha and sha(helper)!=oldsha
    path=REPO/'shizukudos/supervisor/ap_provenance.py';data=path.read_bytes()
    provenance=fresh('ap_provenance_host',path,data)
    guard=provenance.CommandGuard(OUT/'positive')
    guard.run(command,check=True)
    assert subprocess.check_output([binary],text=True).strip()=='1'
    event=guard.events[-1]
    assert event['inputs_pre'][str(header.resolve())]==header_sha and event['inputs_post_equal']
    assert event['executed_subprograms'] and event['tools_post_equal'] and event['pass']
    assert all(p in event['tools_pre'] for p in event['executed_subprograms'])
    negative=provenance.CommandGuard(OUT/'mutated-include')
    invoke=negative._execute
    def mutate(cmd,**kwargs):
        # Runs after the pre-consumption receipt is retained. Validate its
        # first-consumer pin, then exercise the post-consumption mismatch gate.
        pre=json.loads(next((OUT/'mutated-include').glob('*-pre.json')).read_text())
        assert pre['inputs_pre'][str(header.resolve())]==header_sha
        header.write_text('#define VALUE 2\n')
        return invoke(cmd,**kwargs)
    negative._execute=mutate
    try:negative.run(command,check=True)
    except AssertionError:pass
    else:raise AssertionError('changed consumed generated include was approved')
    assert not negative.events[-1]['pass'] and not negative.events[-1]['inputs_post_equal']
    print('AP helper byte binding + generated first-consumer/tool closure: PASS')
    (OUT/'result.json').write_text(json.dumps({'pass':True,'helper_loaded_sha256':oldsha,
        'driver_capture':__shz_driver_capture__,
        'helper_disk_successor_sha256':sha(helper),'production_provenance_sha256':sha(path),
        'positive_event':event,'controlled_mutated_include_event':negative.events[-1]},indent=2)+'\n')
if __name__=='__main__':main()
