# Actual pinned engine source continuation

This continuation builds the actual WebKit 2.54.0 sources, independently of the
dirty canonical IEWebKit checkout. Private source/dependencies/build products
belong in `build/iewebkit-core-83bd`, not Git. Upstream commit remains
`5220e80b97a253c60ed899361654142ab5021998`; upstream copyright and license files
are retained. New tooling uses MIT.

## Integration repair

The existing `JSCOnly` interpreter profile uses the generic event loop. Its
Windows WTF archive therefore does not compile `win/RunLoopWin.cpp`. Linking
a separately compiled Windows-loop object into that archive would combine
different `RunLoop` layouts. The existing `IEWEBKIT_WIN9X` CMake option also did
not expose its value as a C++ macro, so the new opt-in RunLoop backend would
not be selected by that build.

`patches/core-jsconly-windows-loop.patch` adds an explicit Windows event-loop
selection and exports the Win9x macro. Generic remains the default. The
private profile consistently selects the Windows loop for all WTF/JSC
translation units. `core_profile.json` pins its prerequisites and final source
hashes; those prerequisites are the canonical reviewed source patches, not
an unmodified upstream tree.

## Reproduce the private build

Run each phase in order, using the same private work directory:

```sh
python3 -B tools/iewebkit_port/core_build.py source \
  --work /root/Win98-Modern-boot/build/iewebkit-core-83bd \
  --iewebkit-repo /home/almalinux/workspace/iewebkit \
  --cached-webkit /srv/zuku/legacy-work/20260930-01a0f1c7-733e/engine-source-cache/webkitgtk-2.54.0.tar.xz
```

Continue with `icu`, `perl`, `memory`, `statistics`, `optional`, and `allocator`, using the same
arguments. Build the source-matched private GCC runtime next:

```sh
python3 -B tools/iewebkit_port/core_runtime_build.py \
  --output /root/Win98-Modern-boot/build/iewebkit-core-83bd/runtime-win9x-v5
```

The output directory must be new. Configure with the same three build arguments
and additionally
`--runtime /root/Win98-Modern-boot/build/iewebkit-core-83bd/runtime-win9x-v5`, then
run the `runloop`, `allocator-object`, `wtf`, and `jsc` phases. The runtime object
combines compiled ports of the installed GCC package's actual `atexit_thread.cc`
and `emutls.c` with a relocatable link. It defines their genuine GNU runtime ABI
functions. Exact upstream sources, original archive members, compiler headers,
GPL notice and GCC Runtime Library Exception are pinned in `core_runtime_pin.json`.
No installed compiler library is replaced.

Its legacy branch pins a destructor's owning DLL with `VirtualQuery`,
`GetModuleFileNameA`, and `LoadLibraryA`, then retains the upstream TLS callback
and balanced `FreeLibrary` cleanup. The process image outlives its own TLS.
The pin sequence is not atomic: the host must prevent concurrent module unload
while executing or registering that module's code. Native DLL lifetime remains
unverified. Failure of the new platform pin aborts because GCC-generated TLS
registration callers ignore the return value; upstream allocation-failure
behavior remains intact.

The source-matched POSIX runtime's original cleanup key order frees emutls cells
before saved C++ destructors use them. The Win9x port reinstalls the original
per-thread array, drains the real C++ destructor chains, refetches an array that
destructors may grow, clears the key and then frees the current cells. New chains
registered during cleanup are drained too, including the main thread's
`std::exit` path. Ordinary modern controls retain the upstream cleanup algorithm.
The private emutls build explicitly uses installed target libc and genuine
POSIX gthread headers; it does not invent GCC's generated compiler-build
configuration headers. Compile receipts pin each component, combined object,
all actual compiler dependencies and producing compiler/assembler/linker bytes.

Source restoration fetches only hash-pinned supplemental Windows files; the
ICU phase fetches ICU 78.3's exact source archive and published checksum file.
The Perl phase stages the exact signature-verified host-only `bigint` package
and the JSC phase scopes its module path to that child process.
The memory phase applies the separately pinned legacy memory-size, memory-pressure
and committed-private virtual-byte accounting source port; its modern branches
remain available when the Win9x profile is disabled. See `core_memory_README.md`.
These are private downloads, without host package installation. Builds use
one worker, no precompiled header or debugging information in the target profile, a default private
disk budget of 2 GiB and a hard host free-space floor of 20 GiB. The monitor
terminates only its own child session, including separate Ninja job groups, if
that bound is crossed. Receipts
record completed steps, exact commands, logs and artifact hashes.

The `statistics` phase also removes the direct legacy `GetProcessMemoryInfo`
dependency from the real `FastMalloc` statistics source. It reports the same
committed private virtual-byte proxy as the shared memory helper; this is not
resident memory. The `optional` phase preserves the real mimalloc NUMA-node-zero
fallback when newer CPU APIs are absent and performs optional lookup of the
stack-capture API. An absent stack-capture API yields no diagnostic frames.
Vectored exception registration is looked up only when real handlers exist and
fails explicitly if unavailable. The C_LOOP profile disables JIT and WebAssembly;
this does not implement their exception machinery on Win98. Modern branches
remain available in all these patches.

The `allocator` phase applies the real mimalloc Win9x OS-TLS and thread identity
port and the measured ANSI CryptoAPI selection in `RandomDevice.cpp`.
The explicit project hook propagates `IEWEBKIT_WIN9X=1` to the separately compiled
`mimalloc-obj` C target. Heap slots use real checked `TlsAlloc`/`TlsGetValue`/
`TlsSetValue` APIs, with zero valid and `TLS_OUT_OF_INDEXES` as the failure sentinel.
A live, page-aligned `VirtualAlloc` reservation supplies a unique thread identity
and holds the allocator's C TLS state until actual heap abandonment completes.
GNU TLS callbacks retain their early attach and late detach sections. The port
guards the NT thread-pool TEB-field read and preserves modern branches.

Completed native ICU installation and generated engine objects are retained.
Private redundant build caches may be removed only after exact archive/patch
reconstruction and installed-file hashes are verified. Each removal has its own
receipt; active JSC includes and ICU installed archives are not removed.
`core_cache_trim.py` removes only byte-verified, archive-reconstructible private
ANGLE, Skia and WebCore caches after confirming the effective JSCOnly graph and
compiler dependencies exclude them. It retains license copies and a complete
file/link hash and normalized-mode inventory. Cached feature flags may remain
ON while `OptionsJSCOnly.cmake` sets their effective normal CMake variables OFF;
the configured graph and generated flags determine the gate. Reconstruct the
full renderer source from the pinned archive before starting a WebCore build.

The `runloop` phase checks the generated configuration and compiles the real
upstream CMake target. The earlier focused check also compiles original and
patched source against actual WTF and pinned ICU headers:

```sh
python3 -B tools/iewebkit_port/core_compile_runloop.py \
  --work /root/Win98-Modern-boot/build/iewebkit-core-83bd \
  --original /root/Win98-Modern-boot/build/iewebkit-win98-engine-83bd/source/RunLoopWin.original.cpp
```

Its explicit Windows profile uses upstream configuration-header defaults,
not JSCOnly's generated Generic configuration. It compiles the genuine engine
translation unit, without replacement WTF declarations or host Linux libraries.
Both original and patched objects compile. The original object imports the
Unicode window APIs; the ported object selects their ANSI counterparts.
`focused-runloop/objects.json` records those unresolved import symbols.
`focused-runloop/objects-verified.json` preserves the verified patched receipt
when later focused controls run separately.
The `generic-layout-negative` control compiles the same genuine Windows file
against JSCOnly's original Generic layout and must fail; it checks that the
explicit Windows selection is required.

## Native comparison

`core_unicode_native.c` measures the original object's exact Unicode
registration/window/context API choices and compares the shared ANSI backend.
It requires native Win9x 4.10 and writes `C:\GOPLAB\RLCMP.LOG`; create that
directory first. It is separate from the RunLoop worker/timer fixture.

The prior native fixture created an ANSI `HWND_MESSAGE` window successfully.
That observation disproves a blanket claim that this parent handle fails on
the tested Windows 98 guest. Unicode export presence alone also does not show
that the corresponding Win9x implementation works. The comparison records
returned handles, creation/context callbacks and native last-error values.

The exact `RLCMP.EXE` SHA-256
`de2c9f41f2e00be3bda35265a7b05096e6d7b3f36cbf3346c382f7d5d969736a`
ran in Windows 98 SE 4.10.2222 with IE 5.0.2614.3500. Fresh native telemetry
reports `RegisterClassW` returning atom 0 and error 120
(`ERROR_CALL_NOT_IMPLEMENTED`). The original Unicode window creation was
therefore skipped; this does not independently establish its behavior.
The shared ANSI backend registers its class, creates its window, preserves
the exact callback/context pointer and destroys the window with exit 0.
The disposable guest's digest-bound input, version and fresh log evidence is
under `build/shizukudos/csm/run-win98-uefi-83bd-ie-unicode-compare/`.

## Real library and native caller

The complete real CMake WTF archive has compiled successfully. It is a thin
archive: its own SHA does not bind the external object members, which must also
be retained and hashed for a complete rebuild receipt. `core_link_wtf.py` links
that archive, the actual bmalloc/mimalloc object, all three genuine ICU archives,
and the source-matched GCC TLS object into a GUI Win98 caller. The allocator
object follows the real CMake interface dependency; it is not contained in
`libbmalloc.a` alone.

The `wtf-native-v3` caller passes the exact Win98 import baseline: 191 imports
resolve, PE machine is i386, and OS/subsystem version is 4.0. Its SHA is
`0554e029684dca0c43f31af30cb70adf50c3fd9f9e76931061e09f48b1fcd33c`.
Failed prior link/import receipts remain separate. This static result does not
establish that all exported Unicode functions are implemented on Win98.

That exact v3 binary failed in the original IO.SYS UEFI/GOP Win98 guest. The
definitive stopped-disk log contains its fresh nonce and exact OS, with Unicode
provider acquisition failing at error 120 and real ANSI acquisition/generation
succeeding. It reaches no `wtf.initialize` row. The native crash PC `0x005d2316`
resolves to genuine mimalloc `__mi_theap_default+6`, reading an NT-specific FS
offset with EDX `0x5e5`. The crash's CS prefix is not reliably legible and is not
part of the verified transcription. This is a native failure, not a passed
engine initialization gate.

The v4 static candidate is also preserved but never authorized for native
execution: review found allocator C TLS cells disappearing before its late
heap cleanup. The v2 allocator source port keeps those fields in the real
OS-TLS-held identity page. Independent source review then found and corrected
the separate genuine GCC C++ destructor/storage ordering defect described above.

The current `wtf-native-v5-r1` caller passes full linked imports and identical
pre/post inventories of 177 genuine WTF and 168 bmalloc thin members, plus the
actual standalone allocator and all paired-runtime inputs. Its binary SHA is
`584dc67e51dacf3856ce412998f19c628bb2286d087f3a5fefec964b0c6fe60a`.
Its frozen manifest is `build/iewebkit-core-83bd/frozen-wtf-v5-r1/guest-files.json`;
native execution remains pending. The first v5 caller compile failed on a name
collision with upstream's `mainThread` assertion; its source/error receipt is
retained separately and the successful revision uses `probeMainThread`.
The root-owned j trial stopped during preparation and k stopped at the host
free-space floor before launching this caller. Neither run supplies native
v5 initialization, worker cleanup or process-exit evidence.

The caller first checks native Win98 SE 4.10.2222 and measures real CryptoAPI
ANSI/Unicode provider acquisition before actual `WTF::initializeMainThread`.
It exercises the genuine engine RunLoop, a real worker posting 96 callbacks,
timers and memory-pressure monitor installation/teardown. Its worker owns an
actual WTF thread context. A genuine C++ destructor must still see that original
TLS cell, creates 64 compiler TLS cells to exercise array growth, and registers
a new thread-local destructor during cleanup. The four worker context/cleanup/
growth/chained flags must all equal one after joining. The fresh native log
and external process termination still require guest validation. Its success
log is emitted before final CRT/TLS process teardown and cannot alone prove
successful process teardown or DLL unloading.

`core_wtf_fixture.py` freezes the actual caller with a separate-inode COW copy
and exact source/receipt hashes. Input receipt copies live under the build
directory while original paths are retained as provenance. The roughly 47 MB
binary contains real ICU data; an isolated runner must explicitly permit that
size instead of accepting a truncated or substitute engine. No VM is started
by these build or fixture tools.

Freeze requires the complete linked provenance gate and rechecks every actual
source/runtime/compiler input, including each separate GCC component object.
It retains exact copies of paired runtime source/patch/extraction evidence,
allocator source pin/patch, runtime hook pin and all four thin-member receipts
under the private build directory. The root-owned external process observer
separately verifies actual post-CRT termination; the caller's own exit row
cannot substitute for that evidence.

The JSC builder now binds the effective generated profile at configuration and
requires the identical profile before and after the actual single-worker build.
This includes the reviewed source-port composition, feature definitions,
standalone allocator command and the genuine combined runtime in both the real
dependency graph and linker flags. Reconfiguration invalidates an earlier JSC
artifact. A completed executable records the profile digest and exact runtime
receipt so an older executable cannot inherit a later configuration's proof.

`core_link_jsc.py` additionally requires that completed upstream executable and
rechecks its profile and all genuine runtime inputs around the real C API link.
Its JSC/WTF/bmalloc pre/post thin-member receipts use the common immutable-field
comparison; the WTF receipt also includes the standalone allocator object.
Source, baseline, compile database and dependency bytes are pinned before
command selection. Failed link/provenance attempts retain a failing receipt.
The caller's exact upstream compiler flags also drive a bounded `-M` dependency
query. Every returned source and header, including the generated public JSC
headers, is pinned before compilation. The actual compile emits `-MD` evidence
which must name the identical dependency set; the source/header bytes and the
newly produced caller object are checked again before and after linking.
This dependency-query and compile wiring has not yet run a compiler.
This source wiring has not completed or executed JSC: the existing graph still
uses the older runtime and must be regenerated with the current paired runtime
after the pending native WTF gate and host resource checks permit compilation.
The seven read-only controls in `core_jsc_profile_controls.py` reject a runtime
present only as a dependency, an order-only runtime, an allocator macro override,
an incompatible loop, completed-profile drift and the preserved obsolete runtime;
the unchanged actual generated graph is the positive control. Malformed reads
are injected only in memory, leaving the actual source and graph unchanged.

Host helper modules now execute from source bytes captured and checked before
loading, including any previously cached Python module and the import auditor's
late NTW32 parser. `core_tool_snapshot_controls.py` verifies cached-source
replacement, rejects source drift and late module replacement, audits the real
189-import WTF PE with the pinned parser, and refuses incomplete JSC before
output creation. It also checks preservation of the actual caller compiler
flags and rejects malformed or incomplete source/header dependency output.
All seven controls passed without a PE, compiler or guest execution.

The future direct JSC C API link also binds the actual MinGW driver's selected
startup objects, runtime and system import archives, linker and plugin files.
Read-only WTF/JSC command expansion found 30 input files; eleven rejection
controls passed. Selection is a prediction until the real GNU input trace is
checked. The caller requests that trace, compares it with the genuine pre-link
thin inventories, and rechecks selection and file identities under the same
explicit working directory. Unknown trace syntax fails closed. This narrow
gate does not pin transitive host ELF-loader libraries. The existing frozen
WTF v5 receipts predate this extra implicit-platform archive evidence and are
preserved unchanged; no retrospective full-link-input claim is added.

These are engine source, compilation and OS-abstraction gates. They do not
produce `iewebkit-engine.dll`, implement the IE engine provider, or establish
DOM/layout/JavaScript/TLS rendering. A full renderer still requires real
WTF/JSC/WebCore linkage, complete target import closure and actual IE guest
navigation/painting/input/lifecycle tests.
