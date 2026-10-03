#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded check for SHZWALL.EXE: host core test (gcc, clang ASan/UBSan when
available), i486 Win98 PE32 cross-build, and import check against the actual
Win98 SE native export inventory. Does not run Windows 98; see lane report."""
import hashlib, importlib.util, json, subprocess, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
ALLOWED = ('KERNEL32.DLL', 'USER32.DLL', 'GDI32.DLL', 'ADVAPI32.DLL')
CORE = [HERE / 'desktop_agent_core.c', HERE / 'core.c']
def run(argv, label):
    r = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=60)
    if r.returncode:
        sys.stderr.write(r.stdout.decode(errors='replace') + r.stderr.decode(errors='replace'))
        raise SystemExit(label + ' failed: ' + str(r.returncode))
    return r.stdout
def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / 'build/shell-wallpaper').resolve()
    out.mkdir(parents=True, exist_ok=True)
    for cc, extra in (('gcc', ['-O2']), ('clang', ['-O1', '-fsanitize=address,undefined', '-fno-sanitize-recover=all'])):
        exe = out / ('test-agent-' + cc)
        run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror', *extra, '-I', str(HERE),
             str(HERE / 'test_desktop_agent.c'), *map(str, CORE), '-o', str(exe)], 'host-build-' + cc)
        print(run([str(exe)], 'host-test-' + cc).decode().strip())
    cc = 'i686-w64-mingw32-gcc'
    flags = ['-std=c11', '-Os', '-Wall', '-Wextra', '-Werror', '-march=i486', '-mno-sse', '-mno-mmx', '-msoft-float',
             '-fno-stack-protector', '-fno-builtin', '-ffreestanding', '-nostdlib', '-Intwddm/include']
    exe = out / 'SHZWALL.EXE'
    run([cc, *flags, '-Wl,--subsystem,windows:4.10', '-Wl,--major-os-version,4', '-Wl,--minor-os-version,10',
         '-Wl,--entry,_WinMainCRTStartup@0', '-Wl,--disable-dynamicbase', '-Wl,--disable-nxcompat',
         '-Wl,--no-insert-timestamp', str(HERE / 'desktop_agent.c'), str(HERE / 'agent_ctl.c'), *map(str, CORE),
         str(ROOT / 'platform/freestanding/memory.c'),
         '-lkernel32', '-luser32', '-lgdi32', '-ladvapi32', '-lgcc', '-o', str(exe)], 'win98-link')
    spec = importlib.util.spec_from_file_location('pe', ROOT / 'ntwin32/prepare.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    pe = mod.PE(exe.read_bytes())
    exports = json.loads((ROOT / 'benchmarks/win98se-ko-oem-native-exports-v1.json').read_bytes())['dlls']
    imports = {}
    for entry in pe.imports():
        dll = entry['dll'].upper(); names = [e[1] for e in entry['entries']]
        missing = [n for n in names if n not in exports.get(dll, ())]
        if dll not in ALLOWED or missing:
            raise SystemExit('import outside Win98 SE inventory: %s %s' % (dll, missing or names))
        imports[dll] = sorted(names)
    if set(imports) != set(ALLOWED):
        raise SystemExit('unexpected import set: %s' % sorted(imports))
    print('SHZWALL.EXE sha256=%s imports=%d dlls=%s (Win98 SE inventory: all present)' % (
        hashlib.sha256(exe.read_bytes()).hexdigest(), sum(map(len, imports.values())), ','.join(sorted(imports))))
if __name__ == '__main__':
    main()
