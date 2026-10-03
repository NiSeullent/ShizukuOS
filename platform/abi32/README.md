# Actual PE32 execution and ABI checks

This harness executes the project's **built `NTW32.DLL` machine code** on the
host CPU in 32-bit mode. The DLL is embedded in a static Linux ELF32 process;
sixteen original, explicitly limited service mocks replace its KERNEL32 imports.
This is compiled CPU/ABI evidence. It is **not a Windows 98 guest test**, a
Windows loader, an application compatibility layer, or a replacement kernel.

All sources in this directory were originally authored for Windows 98
Shizuku's Second Edition on 2026-09-27, under GPL-2.0-only. No Wine, ReactOS,
KernelEx, Windows implementation, emulator, or third-party runtime is included.
The packer reuses this repository's original `ntwin32/prepare.py` PE reader.
Format concepts follow the public
[Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

## What runs

`build.py` reads the existing DLL, maps its headers and sections into an image,
validates its exact import/export inventory, and builds two test executables.
The first uses preferred base `0x68000000`. The second loads at `0x69000000`
after applying all `IMAGE_REL_BASED_HIGHLOW` relocations. Each image resides in
its own ELF load segment. The segment is intentionally writable and executable
to allow this bounded test's IAT patching and execution; it does not implement
Windows section protection or loader policy.

The original x86 assembly call gate pushes real stdcall arguments, calls the
DLL entry point or an export RVA, records EDX:EAX, and checks ESP restoration.
Original C mocks use the x86 stdcall convention. The only Linux services are
`int 0x80` write and process exit; no C runtime or shared library is linked.

Each variant checks:

- DllMain failed/successful attachment and detach, with native module identity.
- All seven SRW exports, shared/exclusive transitions, and BOOLEAN returns.
- Actual 64-bit tick return registers across observed 32-bit rollover.
- GetProcAddress routing for owned exports, different module handles, case
  sensitivity, ordinals, native fallbacks, and native failure preservation.
- All four InitOnce exports, failed callback retry, actual WINAPI callback
  invocation, context passing, invalid alignment/flags, CHECK_ONLY, async
  winner preservation, and LastError adapter behavior.
- Both UTF conversion exports with real six/eight-argument stdcall calls:
  embedded NUL, inclusive `-1` scanning, queries, Korean/non-BMP characters,
  strict errors and replacement, unchanged output on failure, malformed
  arguments, flags, overlap/alignment/wrapping ranges, and long strings.
- Native conversion delegation for ACP, OEM, 1252, UTF-7, and an unknown code
  page, checking every forwarded argument and both success/failure returns.
- The imported Sleep stdcall path, using a deterministic priority model that
  releases an SRW owner or completes InitOnce only when the DLL blocks with a
  finite positive delay. Three conflicting shared/exclusive SRW combinations
  are checked. Repeated zero-delay polling fails after eight calls. This is
  not an OS scheduler or a concurrency test; the separate InitOnce pthread
  suite tests real contention, and native priority behavior remains unverified.
- The routing policy (docs/NTW32_ROUTING.md), by re-running `DllMain` with
  mocked `NTW32.INI` bytes, `NTW32_ROUTING` values and a fake KernelEx API
  library (a data buffer with PE32 headers whose addresses are compared,
  never called): every mode, module and function overrides, configured
  `[routing] order=` and `[order]` entries, malformed and oversized
  configuration, KernelEx attribution, static-export forwarding to native,
  and the guard against forwarding an export into `NTW32.DLL` itself.
- The three Core clock exports, by calling the actual native PE32 adapter with
  modeled `VirtualQuery`, device I/O and handle ownership: 64-bit samples,
  four-byte alignment, optional frequency, writable and rejected protections,
  cross-page outputs, invalid/short memory-query replies, wrapping ranges,
  malformed clock replies, open/query/close failures, retained zero handles,
  cleanup retries, LastError preservation, NTSTATUS mapping and overlap policy.
  A protection change after transport prevents output publication. Detach stops
  admission without closing under the loader lock; explicit shutdown retries
  failed cleanup and is idempotent after success.

The mocks cover only `GetModuleHandleA`, `GetProcAddress`, `GetTickCount`,
`SetLastError`, `GetLastError`, `Sleep`, `MultiByteToWideChar`,
`WideCharToMultiByte`, and, for the routing policy, `GetModuleFileNameA`,
`CreateFileA`, `ReadFile`, `CloseHandle`, `GetEnvironmentVariableA` and
`OutputDebugStringA`, plus `DeviceIoControl` and `VirtualQuery` for the clock.
The two conversion mocks only record arguments and return configured values;
all `CP_UTF8` bytes are processed by the actual independent DLL code. Mock
counters and return values are test fixtures,
not implementations of those Windows services. Unrecognized imports, forwarder
exports, TLS, CLR, delay imports, load configuration, and relocation types are
rejected. The harness does not execute an arbitrary third-party DLL.

The clock memory-query model uses the explicit 28-byte
[MEMORY_BASIC_INFORMATION32 layout](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information),
with `RegionSize` at byte 12 and `Protect` at byte 20. Calls check the compiled
adapter's stdcall arguments and requested structure size. The model follows
the documented [VirtualQuery return and region contract](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery):
returned bytes are checked, and each queried region must cover the cursor.
The three-page buffer contains real writable host memory; the queried states,
protection flags and failures are injected service results. This does not test
native Windows 98 VirtualQuery behavior, real page protection or memory pinning.
Callers must keep output ranges alive throughout the call. The clock exports
remain separate from the eight WIN64 exports and from KERNEL32 routing.

## Run

First build the independent runtime using the root platform workflow. Then:

```sh
python3 platform/abi32/test_packer.py
python3 platform/abi32/build.py
```

The build command runs the packer tests against its exact DLL input, then compiles
and executes both variants, with a 30-second timeout per test process. It requires
installed Clang, `ld.lld`, `nm`, and a host kernel
that can execute static x86 ELF32 programs. It installs nothing and downloads
nothing. Unsupported ELF32 execution is a failed/unavailable check, not a pass.
`--dll /absolute/path/NTW32.DLL` selects an independently built equivalent input.
The input DLL is never modified. All binaries, mapped images, generated headers,
linker scripts, and reports remain under ignored `platform/abi32/build/`.

The 2026-09-27 UTF integration run used DLL SHA-256
`2720dcffac234202598de8498cfbf804d9d3cbfb1c6a9c796a8e5e8398055c24`.
Both preferred and relocated variants passed **379 checks and 135 actual PE
calls**, with all outer PE call returns restoring ESP. The alternate-base image
applied a 16 MiB delta at **54 HIGHLOW relocation sites**. Both static ELF32
executables had zero undefined symbols. Twelve packer tests cover inventory,
malformed images, unsupported imports/relocations, and relocation roundtrips.

The subsequent contention-backoff regression first failed against that DLL:
the deterministic higher-priority waiter made eight zero-delay yields without
allowing its owner to complete. After changing the runtime to a finite positive
Sleep, DLL SHA-256
`a55364068fe00db2637083ea96a25131deb6a40bbd04340cd9dbe4841baaa2b3`
passes **406 checks and 147 actual PE calls at each base**, including all three
conflicting SRW owner/waiter combinations and pending InitOnce completion.
Both variants still have 54 HIGHLOW sites and zero undefined symbols. This
establishes the adapter's behavior under the explicit service model; actual
Win98 priority scheduling and timer latency still need guest tests.

`build/results.json` records the input DLL hash, the harness, clock fixture,
shared ABI header and parser hashes in `sources_sha256`, the packer test PASS/count,
mock inventory, export inventory, base/delta, relocation-site count, test
stdout, and executable hashes. A source or input change during the run prevents
a completed report. Rebuild and rerun whenever the runtime changes.

## WIN64 subsystem end-to-end run

`w64_e2e.py` (also run by `build.py`) builds a second static ELF32 program,
`build/w64/w64-e2e`, that maps the actual `NTW32.DLL` at its preferred base and
the actual `NTW64RUN.EXE` at `0x00400000`, binds the EXE's imports to the DLL's
exports, and compiles in `ntwrapper/vxd/bridge.c` and `core.c` with the VxD's
own flags. It also links the production `pma_endpoint.c` required by the bridge's
PMA dispatch and acknowledgement references. This W64 conversation does not
initialize or exercise PMA, and PMA behavior is not established by resolving
those symbols. An unexpected clock `VirtualQuery` call in this conversation
fails; the clock exports are exercised separately at both DLL bases.
DeviceIoControl goes into `ntwv_dioc_ex()` as VWIN32 would deliver
it; the VMM page services are an identity model and the Supervisor hypercalls
are modeled. The channel is a real `shz_channel_init()` region. On each
doorbell the harness pops the VxD's frames with `shz_ring_pop()` and sends the
raw slots (and pool data) to `k64model.py`, a Python model of
`kernel64/subsys64.c` that decodes them with `shizukudos/abi/test_abi.py`'s
independent decoder and answers with its encoder; each answer is checked for a
C-accepted CRC and byte identity with `shz_ring_push()` before it is placed on
the ring. `w64_gate.S` runs everything on a static stack below `0x80000000`
because the VxD accepts only Win32 private-arena buffers. Time is simulated
(`Sleep` advances it and lets the model run).

The run covers the argument checks, the recorded guest failure mode (VxD not
loadable: error 2), no Supervisor (50), no channel (55), process creation with
inline and pool-carried arguments up to the 4,016-byte limit, ordered console
output larger than the 8-frame window with a slow reader, stdin relay and EOF,
kill, wait timeout, a handle closed on a running process, the four-process
limit, a corrupted slot, a lost reply, and eleven NTW64RUN.EXE command lines.
The result is `build/w64/w64-results.json` and `win64_bridge_e2e` in
`build/results.json`. It is not a Windows 98, VMM, Supervisor or Kernel64 run.

## Core clock CI regression

The public source at `27a69c36e8dca10c1a2d5420a09c70d87dcf1214` builds a DLL
with sixteen native imports and 28 exports (17 runtime, eight WIN64, three
clock). The former exact inventory rejected `VirtualQuery` before execution.
With the typed clock fixture and exact inventory updated, the original command
`python3 platform/abi32/build.py` passes without skipping any lane. An altered
`VirtualQuery` import or clock export is still rejected by the packer.

The 2026-10-03 run used freshly built DLL SHA-256
`4a2dc8fde4813c42675936e6446c0c7689aa4b6065b6a8a803cc5c6a19fc223f` and
NTW64RUN SHA-256
`c1efefdfbdb53f6c83ed1896b1140cf32b3f9ec2d8f737ab839340d057e11831`.
Fourteen packer tests passed. Each DLL base passed 1,326 checks and 254 actual
PE calls with verified ESP, applying 491 HIGHLOW relocations at the alternate
base. The W64 conversation passed 90,903 checks, 194 DLL calls and eleven actual
NTW64RUN runs, with zero undefined symbols. These are host execution results
under the documented models; Windows 98 guest execution remains unverified.

## What this does not establish

The test proves execution of the linked x86 provider code and the exercised
stdcall/register/callback paths under these mocks. It does not verify Win98
import-descriptor loading, VMM integration, Windows SEH, native error-number
equivalence, real module handles, thread-local LastError, real Sleep behavior,
GUI applications, or any driver support. Optional InitOnce callback-context
forwarding and error mapping are checked against the project policy in
`ntwin32/INITONCE.md`; they are not native Windows differential results.

`entry.S`, `harness.c`, `build.py`, `test_packer.py`, and this README are original
project source. Test execution embeds only the project's original provider.
No Microsoft files or redistributables are packaged by this harness.
