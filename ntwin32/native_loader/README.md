# Native Windows 98 PE32 loader stage

Explicit host parsing budgets for the original large Chromium core DLL are
described in [CHROMIUM_LARGE_IMAGE.md](../../docs/CHROMIUM_LARGE_IMAGE.md).
They leave native file-reading defaults and execution admission unchanged.

`NTWPE32.EXE` uses actual native Kernel32 file, memory, module, cache and child-process services. It is an i486 PE32 executable with subsystem 4.10 and no CRT imports. It does not use the Linux `int 0x80` backend in `../loader/`. Official target files, including their subsystem version, remain unchanged.

Build into a new private output:

```text
python3 ntwin32/native_loader/build.py --out build/shizukudos/ntwpe32-native-stage2
```

Native diagnostic examples use fresh log files (`CREATE_NEW`):

```text
NTWPE32.EXE --diagnose C:\APPLAB\chrome.exe --log C:\VXDLAB\PE32.LOG
NTWPE32.EXE --diagnose C:\APPLAB\chrome.exe --log C:\VXDLAB\PE32P.LOG --bridge C:\APPLAB\NTWPROV.DLL --providers C:\APPLAB
NTWPE32.EXE --diagnose C:\APPLAB\chrome.exe --log C:\VXDLAB\PE32N.LOG --ntw32 C:\APPLAB\NTW32.DLL
```

The diagnostic validates bounded file/section/directory ranges, relocation blocks and import/export structures; it reports ordinary and RVA-based delay imports, available real native exports, optional NTW32 routes and NTWPROV provider exports. The relocation profile accepts strictly increasing page blocks and rejects overlapping four-byte targets, including targets crossing into the next page. Private DLL dependencies are parsed from the target's directory; bounded graph cycles and missing files fail closed. Known native DLLs load by an absolute path from the actual system directory and their real handles remain owned until cleanup. A resolved import is an address-availability result, not an API semantic or application execution claim. API-set module aliases and arbitrary system DLL names are currently reported as unavailable.

Explicit `--run-classic` runs an import-closed freestanding PE32 root in a child limited to 15 seconds, with real exit-code reporting and timeout termination. Mapping copies the original headers, applies validated HIGHLOW relocations, binds imports, protects pages and flushes the instruction cache. DLL dependencies attach in graph order with the actual mapped base and `DLL_PROCESS_ATTACH`, then detach in reverse order. Failed attach rolls back successful attaches and all owned native library references. The supplied `PE32FIX.DLL` checks that its fixture export receives the same actual mapped base as DllMain:

```text
NTWPE32.EXE --run-classic C:\VXDLAB\PE32FIX.DLL --log C:\VXDLAB\PE32FIX.LOG
```

`PE32FAIL.DLL` is a separate rejection control. It records its failing process attach and its own process detach, which must occur exactly once before dependency cleanup. Its entry point must never execute. Ordinal imports are refused during classic execution, and the forbidden API check applies at the final native export after any private forwarder alias.

This initial execution profile rejects static TLS, delay imports, load configuration, CLR, bound-import runtime state, exception/architecture directories, writable executable sections, provider-backed execution, and imported module-identity, resource-loader, dynamic-loader and thread/TLS APIs. It does not register manually mapped images in the native module database, implement static FS-based TLS or arbitrary application startup identity, or claim current Chromium execution. An ordinary EXE entry is called without arguments only for the explicit freestanding classic profile; the own DLL fixture is the intended first native execution control. Parent-owned Windows VM trials supply native evidence independently from host tests and build receipts.

The preserved official Chromium 157 roots contain runtime directories outside this execution profile. Diagnostics continue to enumerate their actual import blockers, but do not call their entry points or TLS callbacks. Existing portable parser code was not reused because its bounds assumptions are too weak for these immutable inputs.

The separate `--run-runtime` profile adds a closed initial module graph with
bounded PE32 static TLS. Templates, writable indices, callback arrays and code
addresses are validated from the original file and checked again after mapping
and relocation. The Win98-only backend reserves real native TLS slots and
requires its guarded FS:0x2c vector checks; it preserves unrelated native slots.
All templates are published before TLS callbacks or DLL entry points. DLL TLS
callbacks precede DllMain for each reason, dependency attaches precede their
consumer, and target threads get DLL notifications before EXE TLS callbacks.
The supplied MS-ABI compiler fixture uses actual FS:0x2c instructions.

```text
NTWPE32.EXE --run-runtime C:\VXDLAB\PE32TLS.DLL --log C:\VXDLAB\PETLS.LOG
NTWPE32.EXE --run-runtime C:\VXDLAB\PEORDER.DLL --log C:\VXDLAB\PEORDER.LOG
```

For DLL-export execution, NULL module queries and the command line retain the
actual native NTWPE32 process executable identity. The fixture requires its own
DLL handle to differ from the real main module and checks the main `.EXE` path.
For an explicit mapped EXE root, wrappers supply that target's logical identity;
this does not add the mapped image to the native module database.
The runtime profile provides mapped module identity for GetModuleHandle,
GetModuleFileName and GetProcAddress, plus retained references to already
initialized graph members through LoadLibrary/FreeLibrary. It refuses
uninitialized members, unknown handles and new graph loads. The order fixture
requires A's initializer to reject a request for later B; replacing only the
staged `PEORDB.DLL` with the separately built `PEBFAIL.DLL` tests B's failed
attach and A's rollback. All original host files stay unchanged.

CreateThread routes through a native thread trampoline. It publishes each
thread's TLS, sends callbacks and DLL notifications, invokes a validated mapped
start routine, then performs detach before dropping the live-thread count.
Cleanup waits for workers and refuses to unmap code while any worker remains.
The first profile accepts null security attributes, a bounded stack and flags
zero or CREATE_SUSPENDED. Imported termination, fibers, provider callback
workers and unmanaged thread ingress remain unsupported. Native ExitProcess is
also refused by this profile until mapped process-exit ownership is implemented.
Provider resolution remains diagnostic only because provider-created callback
threads would bypass this trampoline. Load configuration, delay loading,
resources and current Chromium/NPP startup are still outside this candidate.

The standalone corrected TLS ABI probe has passed 27 checks on an actual
parent-owned Windows 98 4.10.2222 GOP run; its original failed v2 receipt remains
preserved. That proves only the tested native slot/compiler/thread behavior.
The stage2 mapping, identity and callback fixtures require separate actual
Windows runs; build and parser receipts do not establish their native success.
Callback sequencing also follows the primary [Wine loader implementation](https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/loader.c);
that comparison is an implementation reference, not Windows 98 runtime proof.

The additive NULL-thread-ID fixture now has a separate genuine Windows 98 GOP
receipt. Its target passes NULL to CreateThread; the adapter supplies private
native ID storage and retains the native failure error across cleanup. The
target's actual main and worker IDs differ, compiler TLS values remain isolated,
and the complete log contains 43 passing assertions, including the process
detach notifications after the fixture returns. Both its worker and the native
parent observer report actual wait zero and child OS exit zero. The frozen
independent review is
`build/native-controls-independent-20261001T0402-v2/result.json`, SHA-256
`4effe5acd8f01dba4d9da00fea216527974b0bb98d5d031b16ff59deb7f0c6f0`.
It also verifies the delay and address substrates' 28 native checks each and
their actual child exits. This proves the closed fixtures, without identifying
the cause of the earlier NULL-ID failures or admitting Chromium execution.
The observer's own OS exit requires a further independent observer.

Format and cache/protection contracts: [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect), [FlushInstructionCache](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-flushinstructioncache).
