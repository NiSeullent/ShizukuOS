#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build/audit NTW64GUI.EXE (native Win98 presenter for the W64 GUI frame pull) without running it.

The PE32 links the NTW32 W64 client (ntw64.c + ntw64_gui.c) statically because it uses the internal
ntw64_gui_poll_exit; the same six GUI APIs are exported by NTW32.DLL (ntwin32/exports.def). The import audit
admits only functions present in the original Windows 98 SE KERNEL32/USER32/GDI32. Compile/import evidence only:
running it needs a Win98 guest, NTWRAP9X.VXD built with NTWV_W64_DERIVED_OWNER and a K64 built with
SHZ_W64_GUI_DERIVED_OWNER whose display is a real scanout or the w64-hosted private buffer."""
import hashlib, json, re, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = HERE/'build'
SOURCES = ('ntwddm/win98/w64_presenter/w64_presenter.c', 'ntwddm/win98/w64_presenter/build.py',
           'ntwddm/win98/adapter.c', 'ntwddm/win98/adapter.h', 'ntwddm/src/ntwddm.c', 'ntwddm/include/ntwddm.h',
           'platform/freestanding/memory.c', 'platform/freestanding/memory.h',
           'shizukudos/win64/native_window/szwin.c', 'shizukudos/win64/native_window/szwin.h',
           'shizukudos/win64/native_window/szwin_session.c',
           'ntwin32/win64/ntw64.c', 'ntwin32/win64/ntw64.h', 'ntwin32/win64/ntw64_gui.c', 'ntwin32/win64/ntw64_gui.h',
           'shizukudos/abi/shz_w64_gui.h', 'shizukudos/abi/shz_abi.h', 'ntwrapper/vxd/bridge.h')
ALLOWED = {
    'KERNEL32.DLL': set('CloseHandle CreateFileA DeviceIoControl ExitProcess GetCommandLineA GetLastError '
                        'GetModuleHandleA GetProcessHeap GetTickCount HeapAlloc HeapFree SetLastError Sleep'.split()),
    'USER32.DLL': set('AdjustWindowRect BeginPaint CreateWindowExA DefWindowProcA DestroyWindow DispatchMessageA '
                      'EndPaint GetDC GetKeyState InvalidateRect LoadCursorA MessageBoxA PeekMessageA RegisterClassA ReleaseDC ShowWindow '
                      'TranslateMessage UnregisterClassA UpdateWindow'.split()),
    'GDI32.DLL': set('BitBlt CreateCompatibleDC CreateDIBSection DeleteDC DeleteObject GdiFlush GetDeviceCaps '
                     'SelectObject'.split()),
}
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def imports(exe):
    text = subprocess.run(['i686-w64-mingw32-objdump', '-p', str(exe)], check=True, capture_output=True, text=True).stdout
    found, dll = {}, None
    for line in text.splitlines():
        m = re.match(r'\s*DLL Name: (\S+)', line)
        if m: dll = m.group(1).upper(); found.setdefault(dll, set()); continue
        m = re.match(r'\s*[0-9a-f]{8}\s+(?:<none>|[0-9a-f]+)\s+[0-9a-f]{4}\s+([A-Za-z_][A-Za-z0-9_@]*)\s*$', line)
        if dll and m: found[dll].add(m.group(1))
    return found, text
def main():
    BUILD.mkdir(exist_ok=True)
    receipt = BUILD/'build-result.json'; receipt.unlink(missing_ok=True)
    before = {name: sha(ROOT/name) for name in SOURCES}
    output = BUILD/'NTW64GUI.EXE'; temporary = BUILD/'NTW64GUI.EXE.tmp'
    command = ['i686-w64-mingw32-gcc', '-std=c11', '-Os', '-Wall', '-Wextra', '-Werror', '-march=i486',
        '-mno-sse', '-mno-sse2', '-mno-mmx', '-msoft-float', '-ffreestanding', '-fno-builtin',
        '-fno-stack-protector', '-mno-stack-arg-probe', '-fno-ident', '-fno-asynchronous-unwind-tables', '-nostdlib',
        '-Wl,--subsystem,windows:4.10', '-Wl,--major-os-version,4', '-Wl,--minor-os-version,10',
        '-Wl,--disable-dynamicbase', '-Wl,--disable-nxcompat', '-Wl,--disable-tsaware',
        '-Wl,--no-insert-timestamp', '-Wl,--entry,_mainCRTStartup', '-Wl,--strip-all',
        '-I', str(ROOT/'ntwddm/include'),
        *[str(ROOT/s) for s in SOURCES if s.endswith('.c')],
        '-lkernel32', '-luser32', '-lgdi32', '-o', str(temporary)]
    subprocess.run(command, check=True, cwd=ROOT)
    found, text = imports(temporary)
    bad = {dll: sorted(names - ALLOWED.get(dll, set())) for dll, names in found.items() if names - ALLOWED.get(dll, set())}
    if bad or not found or not all(found.values()) or 'subsystem' not in text.lower():
        temporary.unlink(missing_ok=True)
        sys.exit(f'FAIL NTW64GUI import audit: outside Win98 SE classic set: {bad or "no imports parsed"}')
    if 'Subsystem\t\t00000002' not in text or 'MajorSubsystemVersion\t4' not in text:
        temporary.unlink(missing_ok=True)
        sys.exit('FAIL NTW64GUI: not a Windows GUI 4.x subsystem image')
    if before != {name: sha(ROOT/name) for name in SOURCES}:
        temporary.unlink(missing_ok=True)
        sys.exit('FAIL NTW64GUI: sources changed during build')
    temporary.replace(output)
    info = {'status': 'BUILT_NOT_EXECUTED', 'exe': 'NTW64GUI.EXE', 'sha256': sha(output),
            'imports': {d: sorted(n) for d, n in sorted(found.items())}, 'sources': before,
            'runtime_requires': ['Win98 SE guest', 'NTWRAP9X.VXD with NTWV_W64_DERIVED_OWNER',
                                 'K64 with SHZ_W64_GUI_DERIVED_OWNER',
                                 'display_backend SCANOUT or HOSTED_PRIVATE (no GOP/acceleration claim)']}
    receipt.write_text(json.dumps(info, indent=2, sort_keys=True) + '\n')
    print('PASS NTW64GUI build+import audit (not executed):', info['sha256'])
    for d, n in info['imports'].items(): print(' ', d, ' '.join(n))
if __name__ == '__main__':
    main()
