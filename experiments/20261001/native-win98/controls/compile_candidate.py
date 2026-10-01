import sys
sys.dont_write_bytecode=True
from pathlib import Path
import hashlib,json,importlib.util
BASE=Path(__file__).resolve().parent
OUT=BASE/'win98-compile-v1'
SOURCE=OUT/'source'
sys.path.insert(0,str(SOURCE/'shizukudos/tools'))
spec=importlib.util.spec_from_file_location('w98_compile',SOURCE/'shizukudos/supervisor/build.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
pins=json.loads((OUT/'consumed-source-pins.json').read_text())
result={'status':'FAIL_COMPILE_PRESERVED','VM_executed':False,'source_pins':pins}
try:
 b.OUT.mkdir(parents=True);b.build_vbios()
 b.PAYLOAD_C += ['../native_win98/ata_pio.c','../native_win98/string_pio.c','../native_win98/win98.c']
 (b.OUT/'native_win98').mkdir()
 payload,commands=b.build_payload();loader,loader_command=b.build_loader(payload)
 if any(hashlib.sha256((SOURCE/name).read_bytes()).hexdigest()!=digest for name,digest in pins.items()):raise RuntimeError('source drift')
 result.update(status='PASS_ORDINARY_NATIVE_PAYLOAD_EFI_BUILD_NOT_RUN',commands=[[str(x) for x in c] for c in commands]+[[str(x) for x in loader_command]],artifacts={str(p.relative_to(OUT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [b.OUT/'payload.bin',b.OUT/'payload.elf',loader]},source_before_after_match=True)
except BaseException as exc:
 result['error']=str(exc);raise
finally:
 (OUT/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(result['status'])
