# Chromium and Legcord source port — 83bd

This lane adds source prerequisites for actual applications on **Windows 98 SE
4.10.2222 x86**. Chromium, Electron, Legcord and Discord have **no native PASS**.
Booting x64 UEFI preserves the guest's 32-bit process ABI. Source helpers,
import coverage, version checks and a software-rendering switch do not establish
browser execution.

## Current upstream pins, checked 2026-09-30

| Application | Pinned source/runtime | Native Win98 status |
| --- | --- | --- |
| Chromium active project target | `157.0.8080.0` x86, Windows snapshot `1707946`, source `73c8f84d67bfbad65ad4817d9839ffecb78b06ee` | Source port required |
| Chromium alternate upstream reference | Windows stable `155.0.8059.26`, source `16c3e55476d3564bea713314b2fff638749ce3e6` | Reference only; active 157 unchanged |
| Legcord | latest release `1.3.0`, source `c8d91f61296019bb0c45f375535de8c93cf26ee1` | Source port required |
| Legcord runtime | Electron `43.2.0`, Chromium `150.0.7871.129`, bundled Node `24.18.0` | Native port required |

The active Chromium target reuses [the project target record](TARGET_APPS.md)
and its existing read-only preflights. Its [official snapshot](https://storage.googleapis.com/chromium-browser-snapshots/Win/1707946/chrome-win.zip)
is 323,332,967 bytes, SHA-256
`af0a1a5eb80a21ff2364b4974ca254d3a3af0bf087db9f5af4232672cb3a53df`.
This lane adds no download or binary/header edit. The profile binds the existing
chrome.exe and chrome_elf.dll preflight JSON and their input SHA-256 values.
Both retain PE32 subsystem10.0, static TLS and load configuration; these are
unmodified publisher inputs requiring real loader/API work. The [official
Windows stable metadata](https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=1)
is retained only as an alternate upstream reference, and does not downgrade 157.
The [Legcord release](https://github.com/Legcord/Legcord/releases/tag/v1.3.0)
was published July 26, 2026. Its **ia32 ZIP exists**:
`Legcord-1.3.0-win-ia32.zip`, 153,902,184 bytes, SHA-256
`f348283e64cb1aaaccb7fd3a4d7851c3c95131eef38fa087dc243dbbb604341c`.
It has not been downloaded or inventoried in this lane.

The [tagged package manifest](https://raw.githubusercontent.com/Legcord/Legcord/c8d91f61296019bb0c45f375535de8c93cf26ee1/package.json)
pins Electron and requires host Node >=26 and pnpm 11.10.0 to build the source.
That host Node requirement differs from Electron's bundled runtime Node version.
[Electron 43.2.0](https://releases.electronjs.org/release/v43.2.0) records the
embedded Chromium/Node versions; its [tagged platform
documentation](https://raw.githubusercontent.com/electron/electron/v43.2.0/README.md)
supports ia32 Windows **10+**. Electron main's later architecture policy must
not be substituted for this release's ia32 availability.

The [pinned Chromium build
instructions](https://raw.githubusercontent.com/chromium/chromium/73c8f84d67bfbad65ad4817d9839ffecb78b06ee/docs/windows_build_instructions.md)
require an x64 host, at least 8GB RAM and 100GB free NTFS space, Windows10+,
Visual Studio2026 >=18.0.0 and SDK10.0.28000.2270. They allow `target_cpu="x86"`.
That documented build SDK is distinct from the project's frozen API-reference
inventory SDK10.0.28000.2705.
Those are upstream **build-host** requirements; the checked-in GN candidate
arguments do not create a Win98 runtime port. This host cannot safely accommodate
that source checkout/build while preserving its 20GiB native-trial floor.

## Implemented bounded source prerequisites

`tools/modern_apps/chromium_win9x_wait.c` implements process-local
`WaitOnAddress`, `WakeByAddressSingle` and `WakeByAddressAll` behavior using real
Win9x events and a zero-initialized interlocked queue lock. It supports
1/2/4/8-byte comparisons, immediate return when changed, timeout/error handling,
one/all wake selection and address isolation. Comparison/publication and wake
traversal share a lock; the waiter is removed before its stack/event is released.
This closes the usual compare-to-queue lost-wake race and protects against a wake
using a closed handle. It allocates one event per blocked wait; allocation
failure returns an allowed early TRUE wake without changing the predicate.
The queue lock needs no critical-section initialization allocation/exception,
and yields with Sleep(1) while contended. It does not claim the native Windows8
API's performance characteristics. Callers must recheck their predicate after any wake,
as the [API contract](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitonaddress)
allows early wakes.

The implementation is process-lifetime source intended for static linking. It
does not provide cross-process waits or safe dynamic DLL unloading. Forcibly
terminating a waiting thread can strand its stack queue record; forcible thread
termination/cancellation and DLL unload recovery are unimplemented and unverified.
Threads must exit cooperatively. Every module must route all three APIs to one
process-wide provider. Copying this source separately into chrome.exe,
chrome.dll or Electron addons would create different queues and miss wakes
across those modules. The shared-provider integration and cross-DLL lifetime
remain native-unverified. The optional
`chromium_win9x_wait_redirect.h` redirects only those three calls when explicitly
enabled with `CHROMIUM_WIN9X_ADDRESS_WAIT_REDIRECT`; it never rewrites the OS
version. Integration into the frozen Chromium/Electron source build remains
pending. Existing `src/m98wrap.c` SRW/CV/time/file-information support,
`src/m98_fls.c` and `src/m98_threadpool.c` are reused prerequisites and are not
duplicated or modified here.

`chromium_win9x_wait_probe.c` is an actual-Win98 native probe with exact OS/nonce,
all four comparison sizes, an actually enqueued nonzero timeout, injected
event-allocation failure/early wake, sixteen mutation/wake/registration races,
concurrent one/all wakes, address isolation and joined worker exit. Every
created worker is joined even after partial creation failure. Both units must
be compiled with `CHROMIUM_WIN9X_WAIT_TESTING`. Native execution remains pending.
Its eventual native PASS would establish only the
address-wait prerequisite, never Chromium/Electron/Legcord rendering.

One bounded static compile completed on 2026-09-30. The private output tree is
113,836 bytes, below the permitted 8MiB. `CWWAIT.EXE` is 104,527 bytes, SHA-256
`f3da42267d6c50857f93e0ce667da40ad9a50e08a7bdddf8800046754d63c40e`.
The canonical PE reader confirms i386 PE32, GUI subsystem4.0 and OS header4.0.
All 66 direct/delay import rows match names in
`benchmarks/win98se-ko-oem-native-exports-v1.json`, SHA-256
`3854198a9b2bf9f54fe0383330d09ed2ea3d0d510c3d7ba24eb13426e37b4f0d`.
The [build receipt](../build/modern-browser-83bd/chromium-wait-prerequisite-static-20260930/build-receipt.json)
has SHA-256 `057979dc1e799b98d5617832ff038c94c8cfb510403905482a6273be2e135e6b`
and records the exact compiler command/source hashes/imports. Its status is
`STATIC_BUILD_AND_IMPORT_AUDIT_PASS`. No probe, application, Wine or VM was
executed. The baseline is an export-name inventory from OEM CAB modules;
optional modules may be absent from a particular installed guest. Static names
and headers therefore do not verify actual loading, scheduling or API behavior.

`chromium_port_profile.py` consumes the existing `tools/app_preflight.py` JSON
schema, so this lane adds no alternative PE parser or loader. Metadata is read
with a 4MiB bound; assessment goes to stdout and creates no files. It rejects
wrong profile/schema/ABI metadata and retains `SOURCE_PORT_REQUIRED`,
`guest_executed=false` and `browser_pass=false` even for a PE32 with statically
eligible headers. An import unresolved by NTW32 is not treated as proof of a
missing native or bundled implementation.

`legcord_win9x_entry.cjs` is an opt-in entry overlay. It validates the selected
runtime's ia32 Windows platform and the three pinned runtime versions, requests
Electron software rendering **before app startup**, then imports the selected
real `ts-out/main.js`. The caller must supply its exact compiled entry SHA-256
from the build receipt; the bootstrap reads a bounded regular-file snapshot,
checks that digest before configuring/importing Electron, and records the
canonical path/hash/size. Missing or mismatched digests fail. A complete caller
source-path inventory and the future real `win98SourceLease` native binding are
required before any application import; upstream Electron has no such binding.
The C prerequisite `legcord_win9x_source_lease.c` acquires actual Win9x
CreateFileA read handles allowing only FILE_SHARE_READ, so conflicting writers
prevent acquisition and held handles deny subsequent writes/deletes. It is
bounded to 256 ASCII DOS paths. The handles must be held before hashing and
through lazy imports until synchronous process exit; cancellable Electron
will-quit events never release them. Abnormal process termination lets the OS
close its handles. A failed import retains its lease because partially executed
application code may still run. The Node/Electron binding, complete inventory,
source-tree provenance, native filesystem semantics and native lifecycle test
remain unimplemented or unverified. The bootstrap fails closed without the binding.
The entry hash alone
does not prove Legcord's source commit or its transitive dependencies, and the
complete tree must remain frozen through import. It never starts on import and creates no replacement
Discord UI. Complete application/source/lockfile/native dependency freezing and
explicit optional-feature/network scope are still required before launching it.
This bootstrap itself does not disable Legcord's updater or native modules;
those need source changes in the frozen application rather than fake success.

## Read-only usage and source checks

```text
python3 -B tools/modern_apps/chromium_port_profile.py --app chromium
python3 -B tools/modern_apps/chromium_port_profile.py --app legcord
python3 -B tools/app_preflight.py OWNED_X86_PE --format json |
  python3 -B tools/modern_apps/chromium_port_profile.py --app legcord --preflight -
python3 -B tools/modern_apps/chromium_port_profile_test.py
node tools/modern_apps/legcord_win9x_entry_test.cjs
```

Eight Python checks cover profile/input binding and rejection gates. The Node
controls reject missing native lease/digest/runtime prerequisites and verify
that cancelled will-quit retains handles, true exit releases once, and failure
before import removes the hook and releases once. These are source logic checks
and start no guest or application.
The old stored Chromium/Electron import-coverage reports (36.2%/37.6%) are
historical inventories without current-release or native-runtime bindings.
They are not a browser acceptance result.

## Remaining real operating-system work and acceptance

1. Freeze current x86 binaries, complete source/DEPS/compiler inputs and all
   load-time/delay/API-set dependencies. Bind genuine PE/CRT/TLS/SEH execution
   to the existing Win98 loader, preserving the original IO.SYS proof.
2. Implement and validate real process creation, shared memory/handle transfer,
   async completion and Mojo IPC. NTW32's Linux-host implementations and a
   standalone NTWrapper core are separate targets, not Win98 native proof.
3. Port real V8/Node/libuv reservation/protection, exceptions, thread teardown,
   asynchronous I/O and sockets. There is no fixed 128MiB sufficiency claim.
4. Produce real Skia/Blink software raster output and fonts in a native Win98
   window, with actual input/DOM/canvas readback. GPU disabling does not remove
   every DWrite/D3D/DirectComposition dependency by itself.
5. Verify authorized HTTPS/certificate/WebSocket behavior, then actual Legcord
   main/preload/renderer IPC and Discord login UI. A local browser fixture is
   an earlier engine test. Sending account messages needs separate authorization.
6. Record updater/game detection/venmic/capture feature scope and observed owned
   process/thread shutdown, with an external process-exit observer.

No engine build, package download or VM is launched by these profiles. Keep the
20GiB floor for native trials/heavy builds/cache changes. The explicit exception
for <=256KiB new source/doc/review writes and the separate <=8MiB static
prerequisite compile do not relax that runtime floor.
