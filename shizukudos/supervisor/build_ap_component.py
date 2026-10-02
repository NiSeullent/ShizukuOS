#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Fresh Supervisor-only AP component build using a captured qualified DOS disk."""
# The producer body is executed from this exact captured byte array. The small
# first entry only loads this array; no project helper/tool executes before it.
if '__shz_driver_capture__' not in globals():
    from pathlib import Path as _EntryPath
    import hashlib as _EntryHash
    _entry_path=_EntryPath(__file__).resolve();_entry_bytes=_entry_path.read_bytes()
    _entry_capture={'path':str(_entry_path),'sha256':_EntryHash.sha256(_entry_bytes).hexdigest()}
    exec(compile(_entry_bytes,str(_entry_path),'exec'),{'__name__':__name__,'__file__':str(_entry_path),'__shz_driver_capture__':_entry_capture})
    raise SystemExit(0)
import argparse
import json
import struct
import sys
import types
import hashlib
import shlex
import shutil
import subprocess
from pathlib import Path
def fresh(name,path,data):
    module=types.ModuleType(name); module.__file__=str(path); sys.modules[name]=module
    module.__shz_loaded_sha256__=hashlib.sha256(data).hexdigest()
    exec(compile(data,str(path),'exec'),module.__dict__)
    return module
here=Path(__file__).resolve().parent
module_paths={'ap_provenance':here/'ap_provenance.py','shzlib':here.parents[0]/'tools/shzlib.py','build':here/'build.py'}
module_bytes={name:path.read_bytes() for name,path in module_paths.items()}
loaded_modules={name:fresh(name,module_paths[name],data) for name,data in module_bytes.items()}
loaded_sha={str(module_paths[name]):module.__shz_loaded_sha256__ for name,module in loaded_modules.items()}
loaded_sha[__shz_driver_capture__['path']]=__shz_driver_capture__['sha256']
build=loaded_modules['build'];provenance=loaded_modules['ap_provenance']

def source_paths():
    paths = sorted(p for p in build.SRC.rglob("*") if p.is_file() and p.suffix in (".c", ".h", ".asm", ".ld", ".py"))
    paths += [build.SHZ / "kernel64" / n for n in ("smp_acpi.c", "smp_acpi.h", "standalone/memholes.h")]
    paths += [build.SHZ / "uefi" / n for n in ("boot.c", "boot.h", "efi.h")]
    paths += [build.SHZ / "abi" / n for n in ("shz_abi.h", "shz_ipc.h")]
    paths += [build.SHZ / "csmwrap/video" / n for n in ("cp437.c", "cp437.h", "font8x8_basic.h")]
    paths += [build.SHZ / "tools" / n for n in ("qemu.py", "shzlib.py", "shzinfo.py")]
    return paths

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--disk", type=Path, required=True)
    p.add_argument("--origin", type=Path, required=True)
    p.add_argument("--label", default="final")
    args = p.parse_args()
    original = json.loads(args.origin.read_text())["artifacts"]["hd32.img"]
    origin_before=build.sha256_file(args.origin)
    digest = build.sha256_file(args.disk)
    assert digest == original["sha256"] == "aa40e4f0dd81fb6d611aa4425c69782214f59cf78de75e716a9f41407446e0e2"
    assert args.disk.stat().st_size == original["bytes"] == 33546240
    assert not build.guest_kernel_files(), "DOS-only AP QA must not acquire optional kernel/media artifacts"
    build.OUT.mkdir(parents=True, exist_ok=True)
    assert not (build.OUT/f'ap-build-result-{args.label}.json').exists(), 'immutable component receipt already exists'
    source_before={str(p.relative_to(build.REPO)):build.sha256_file(p) for p in source_paths()}
    assert all(build.sha256_file(Path(path))==h for path,h in loaded_sha.items()), 'loaded helper identity changed'
    assert all(source_before[str(Path(path).relative_to(build.REPO))]==h for path,h in loaded_sha.items())
    tools={n:shutil.which(n) for n in ('nasm','gcc','ld','nm','readelf','objcopy','strace',
        'x86_64-w64-mingw32-gcc','mkfs.vfat','mcopy','mmd','mtype')}
    tools['python']=sys.executable
    tool_before={p:build.sha256_file(Path(p)) for p in tools.values()}
    roots=(build.OUT,build.BUILD/'supervisor-ap')
    existing=sum(p.stat().st_size for root in roots for p in root.rglob('*') if p.is_file())
    target=build.OUT/f'ap-component-base-{args.label}.img'
    replacement=target.stat().st_size if target.exists() else 0
    forecast=existing-replacement+(34<<20)+(8<<20)
    assert forecast<=384<<20, 'bounded AP component aggregate forecast exceeds 384 MiB'
    free=shutil.disk_usage(build.OUT).free
    assert free>64<<20, 'new 34 MiB component and bounded receipts require 64 MiB free'
    preflight={'existing_file_bytes':existing,'unsealed_replacement_bytes':replacement,
               'forecast_peak_bytes':forecast,'aggregate_limit_bytes':384<<20,'rootfs_free_before':free}
    build.shzlib.write_json(build.OUT/f'ap-build-intent-{args.label}.json',
        {'resource_preflight':preflight,'sources_sha256':source_before,'build_tools_sha256':tool_before,
         'loaded_exact_bytes_sha256':loaded_sha,'driver_capture':__shz_driver_capture__})
    guard=provenance.CommandGuard(build.OUT/f'ap-command-inputs-{args.label}')
    def checked_run(command,cwd=None,env=None,timeout=300,capture=False,check=True):
        return guard.run(command,cwd=cwd,env=env,timeout=timeout,check=check,
                         stdout=subprocess.PIPE if capture else None,
                         stderr=subprocess.STDOUT if capture else None,text=capture)
    build.run=checked_run
    vbios = build.build_vbios()
    ap, ap_command = build.build_ap_trampoline()
    payload, payload_commands = build.build_payload()
    loader, loader_command = build.build_loader(payload)
    assert args.label.isalnum()
    build.ESP_MIB=34  # Dedicated DOS component: verified DOS, EFI and free clusters.
    esp = build.build_esp(loader, args.disk, f"ap-component-base-{args.label}.img")
    policy = build.OUT / "ap-component-BOOT.INI"
    policy.write_text("mode=supervisor\nmenu_timeout=0\n")
    build.run(["mmd", "-i", esp, "::/EFI/SHIZUKU"])
    build.run(["mcopy", "-i", esp, policy, "::/EFI/SHIZUKU/BOOT.INI"])
    config = build.OUT / "ap-component-APCFG.BIN"
    config.write_bytes(struct.pack("<IIII", 0x31435041, 1, 4, 0))
    build.run(["mcopy", "-i", esp, config, "::/SHZDOS/APCFG.BIN"])
    sources=source_paths()
    embedded=guard.run([tools['mtype'],'-i',str(esp),'::/SHZDOS/DISK.IMG'],check=True,capture_output=True,timeout=30).stdout
    assert len(embedded)==original['bytes'] and hashlib.sha256(embedded).hexdigest()==digest
    with esp.open('rb') as f: bpb=f.read(512)
    assert struct.unpack_from('<I',bpb,32)[0]*struct.unpack_from('<H',bpb,11)[0]==34<<20
    embedded_efi=guard.run([tools['mtype'],'-i',str(esp),'::/EFI/BOOT/BOOTX64.EFI'],
        check=True,capture_output=True,timeout=30).stdout
    assert len(embedded_efi)==loader.stat().st_size and hashlib.sha256(embedded_efi).hexdigest()==build.sha256_file(loader)
    sector=struct.unpack_from('<H',bpb,11)[0]; fats=bpb[16]; reserved=struct.unpack_from('<H',bpb,14)[0]
    fat_sectors=struct.unpack_from('<I',bpb,36)[0]; spc=bpb[13]
    total_sectors=struct.unpack_from('<I',bpb,32)[0]
    clusters=(total_sectors-reserved-fats*fat_sectors)//spc
    with esp.open('rb') as f: f.seek(reserved*sector); fat=f.read(fat_sectors*sector)
    free_clusters=sum(struct.unpack_from('<I',fat,c*4)[0]&0x0fffffff==0 for c in range(2,clusters+2))
    assert clusters>=65525 and free_clusters>=1024, 'FAT32 geometry or formatter headroom inadequate'
    guard.verify()
    groups,dependencies=guard.dependency_groups,guard.dependency_pins
    assert all(build.sha256_file(Path(p))==h for p,h in dependencies.items())
    source_after={str(p.relative_to(build.REPO)):build.sha256_file(p) for p in sources}
    assert source_before==source_after, 'source changed during fresh component build'
    assert all(build.sha256_file(Path(p))==h for p,h in tool_before.items()), 'build tool changed'
    tool_before.update(guard.tool_pins)
    assert build.sha256_file(args.disk)==digest and build.sha256_file(args.origin)==origin_before
    artifacts = {p.name: {"sha256": build.sha256_file(p), "bytes": p.stat().st_size}
                 for p in (loader, build.OUT / "payload.elf", build.OUT / "payload.bin",
                           build.OUT / "ap-trampoline.bin", build.OUT / "vbios.bin", esp)}
    receipt = {"profile": "physical-ap-vmx-DOS-component-only", "git": build.shzlib.git_state(),
               "built_utc": build.shzlib.utc_now(), "historical_input": {"disk": str(args.disk), "sha256": digest,
               "bytes": args.disk.stat().st_size, "origin_sha256": origin_before},
               "sources_sha256": source_after, "sources_pre_post_equal":True,
               "build_tools_sha256":tool_before,"build_tools_pre_post_equal":True,
               "loaded_exact_bytes_sha256":loaded_sha,"driver_capture":__shz_driver_capture__,
               "commands_pre_post":guard.events,"actual_compiler_subtools_pinned_pre":True,
               "dependency_groups":groups,"compiler_dependency_sha256":dependencies,
               "embedded_disk":{"bytes":len(embedded),"sha256":hashlib.sha256(embedded).hexdigest()},
               "embedded_efi":{"bytes":len(embedded_efi),"sha256":hashlib.sha256(embedded_efi).hexdigest()},
               "fat32":{"clusters":clusters,"free_clusters":free_clusters,"bytes_per_cluster":sector*spc},
               "resource_preflight":preflight,
               "commands": {"payload": [[str(x) for x in c] for c in payload_commands],
                            "loader": [str(x) for x in loader_command], "ap": [str(x) for x in ap_command]},
               "artifacts": artifacts, "claims": "No actual Windows desktop or new ordinary DOS producer acceptance"}
    build.shzlib.write_json(build.OUT / f"ap-build-result-{args.label}.json", receipt)
    print(json.dumps(artifacts, indent=2))


if __name__ == "__main__":
    main()
