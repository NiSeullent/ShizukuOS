# Actual PE32 execution and ABI checks

This harness executes the project's **built `NTW32.DLL` machine code** on the
host CPU in 32-bit mode. The DLL is embedded in a static Linux ELF32 process;
seven original, explicitly limited service mocks replace its KERNEL32 imports.
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

The mocks cover only `GetModuleHandleA`, `GetProcAddress`, `GetTickCount`,
`SetLastError`, `Sleep`, `MultiByteToWideChar`, and `WideCharToMultiByte`.
The two conversion mocks only record arguments and return configured values;
all `CP_UTF8` bytes are processed by the actual independent DLL code. Mock
counters and return values are test fixtures,
not implementations of those Windows services. Unrecognized imports, forwarder
exports, TLS, CLR, delay imports, load configuration, and relocation types are
rejected. The harness does not execute an arbitrary third-party DLL.

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

`build/results.json` records the input DLL hash, all four harness source and parser
hashes in `sources_sha256`, the packer test PASS/count,
mock inventory, export inventory, base/delta, relocation-site count, test
stdout, and executable hashes. A source or input change during the run prevents
a completed report. Rebuild and rerun whenever the runtime changes.

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
