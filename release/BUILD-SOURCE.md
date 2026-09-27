# Windows 98 Shizuku's Second Edition — historical KernelEx builds

This document preserves the source and build instructions for the historical
0.1.x KernelEx previews. For the current independent components, follow the
[independent platform guide](../platform/README.md). The build and packaging
steps below belong to the preserved KernelEx path.

This patch ZIP includes corresponding C source, export definitions, build
scripts, PE validation scripts, and license notices for `m98wrap.dll`,
`M98USER.DLL`, `M98GDI.DLL`, `M98CTLP.DLL`, `m98shell.dll`, `m98adv.dll`, `UXTHEME.DLL`, `dbghelp.dll`, `dwmapi.dll`,
`bcrypt.dll`, and the guarded `KSWITCH.EXE` helper. It contains **three exact
KernelEx UXTHEME source files**, not the KernelEx installer or full repository.
It does not include Windows, Microsoft Unicode Layer, any target application,
installation keys, test VM images, or remote guest state.

The combined `UXTHEME.DLL` uses pinned KernelEx commit
`31cdfc3560fc116637ee8ed7be31b12f3aacf5d1`. The original `uxtheme.c`,
`metric.c`, and `uxtheme.def` are included at
`third_party/KernelEx/auxiliary/uxtheme/` with their original notices.
`KERNELEX-UXTHEME-NOTICES.md` records their hashes and licenses. The build
script **refuses a hash mismatch** before compiling them, and needs no Git
submodule when run from the extracted ZIP. `LICENSE` supplies GPL v2;
`licenses/Wine-LGPL-2.1.txt` supplies LGPL v2.1 for the upstream `metric.c`
and Wine-derived material.

The `skills/win98-modern-lab/` folder is a reusable Codex workflow for the
entire project. Copy that folder into your Codex personal skills directory to
use it across tasks; it is also maintained in the public source repository.

On a modern Windows host, install 32-bit LLVM MinGW with
`i686-w64-mingw32-gcc` on `PATH`, Python, and PowerShell 7.2 or newer. The
LLVM MinGW toolchain is required because the pinned KernelEx UXTHEME source
uses Microsoft-style assembly blocks compiled with `-fasm-blocks`. Install the PE
validation dependency with:

```powershell
python -m pip install -r tests/requirements.txt
```

Then run this from the extracted ZIP directory:

```powershell
.\build-dlls.ps1
```

The binaries are written to `build/`; `build/uxtheme-known/UXTHEME.DLL` is
the combined KnownDLL candidate, and `build/m98adv.dll` is the DOS 8.3 copy
of the ADVAPI API library. The script checks PE32/Win98 loader headers,
base relocations, original-media native imports, UXTHEME's original 48 plus
six added exports, and the guarded mapping helper. Its UXTHEME checker uses
the pinned target app's **import names only**; that app is not inside the ZIP.
At this preview snapshot `m98wrap.dll` has a 89-name KernelEx KERNEL32 table.
This is the number of registered names, not a whole-Windows-API compatibility
percentage or a claim that all 89 behaviors are complete.

The separate `M98USER.DLL` has three USER32 clipboard API entries. Its builder
also produces a direct-call fixture and independently maintained probes. Host
checks use the native APIs, fixture, shipping table and static imports without
changing the host clipboard. Data-changing tests require explicit
`--guest-mutate` and an actual Windows 98 guest with an empty starting clipboard.
That flag is never enabled by the release builder. See `docs/CLIPBOARD_PORT.md`
and `docs/CLIPBOARD_CONTRACT_TESTS.md` for the backend and evidence limits.
The entire 45-row clipboard catalogue remains outstanding as a family.

The separate `M98GDI.DLL` has three routed GDI32 aliases:
`GdiAlphaBlend`, `GdiGradientFill`, and `GdiTransparentBlt`. The release build
calls `tools/build-gdi-alpha.ps1`, which builds the shipping provider, an
independent fixture, direct and static-import pixel contracts, a three-import
probe, and a repeated DLL load/unload probe. Its PE gate checks i386 PE32,
Win98 loader version, relocations, original-media imports, export shape, and
the genuine GDI32 imports in the routed probes. The package includes their
source and explicitly allowlisted guest executables. The installed KernelEx
auxiliary `MSIMG32.DLL` is a separate dependency: the ZIP contains neither
that DLL nor the original Microsoft `MSIMG32.DLL`. The adapter accepts only
the tested auxiliary PE layout and fails closed when it is absent or differs.
`docs/GDI_ALPHA_PORT.md` describes the bounded behavior and guest evidence;
these three entries do not establish full GDI32 compatibility.

`M98CTLP.DLL` is the separate COMCTL32 ordinal 345/381 provider. The release
builder calls `tools/build-comctl-ordinals.ps1` for the genuine ordinal-only
import probe, then `tools/build-comctl-png.ps1` for the PNG-capable shipping
provider and its generated-resource direct-call probes, including a
same-size display-color-depth selection check. The provider combines
original GPL-2.0-only bridge code with pinned, unmodified LodePNG C source;
`src/vendor/lodepng/LICENSE` carries its permissive notice. The PE gate checks
PE32/Win98 headers, relocations, OEM imports and provider table shape. The
static probe imports `COMCTL32` ordinals 345 and 381; the direct probe opens
the provider from its own directory. These are distinct checks. Windows 98
guest results and the partial `TaskDialogIndirect` behavior are documented in
`docs/COMCTL_ORDINAL_PORT.md` and `docs/RELEASE_0_1_8_CHECKPOINT.md`.

For guest installation, rename a copy of the shipped `M98CTLP.DLL` to
`M98CTL3.DLL` in the existing KernelEx folder, then route the six entries in
the guest's current `CORE.INI` using the supplied patch or guarded upgrade
tool. Preserve the existing settings and an exact backup, cold-boot, and run
the ordinal import probe. Do not overwrite the OEM `COMCTL32.DLL`. The
source-package build does not install or activate this route in a guest. The
installed, directly and statically guest-tested candidate has SHA-256
`aafd97b71ff63c9f9cedffa4705713243d5708f22ff6ffaf04c732261ca0e3f8`;
the extracted ZIP rebuild must match it byte for byte before publication.

`build-dlls.ps1` also runs the included focused builds for final-path, stream,
locale information, application restart, process path, SRW condition
variables, named-locale NLS, threadpool work and callback lifetime, one-time
initialization, and sequenced singly linked lists. The first six focused
builds compile the production wrapper and must be byte-identical to the
`m98wrap.dll` shipped in this ZIP. The NLS, threadpool, InitOnce and SList builds use separate
fixture DLLs for direct API-table tests, plus static-import probes; those
fixtures are not interchangeable with the production wrapper. All four also
compile integrated probes for a direct production-wrapper test in the guest.
The integrated probes pass PE/import checks but their guest execution must be
recorded separately. All ten builds run their Win98 PE/import checks and
focused host tests. The matching source,
test files, and bounded evidence documents are in the ZIP, including
`docs/NLS_EX_PORT.md`, `docs/THREADPOOL_WORK_PORT.md`,
`docs/THREADPOOL_CALLBACK_PORT.md`, `docs/INITONCE_PORT.md` and
`docs/SLIST_PORT.md`. Host execution,
isolated guest fixture execution, production KernelEx static-import tests,
and application launch are separate verification stages. These checks are
not a claim that every table entry or modern application works.

The InitOnce batch contains `InitOnceInitialize`, `InitOnceBeginInitialize`,
`InitOnceComplete`, and `InitOnceExecuteOnce`, sharing the same state machine.
The build runs the fixture and the host's original static-import API through
their common valid-use contracts and 192 worker executions, then runs the
integrated probe against the production `build/m98wrap.dll`. This establishes
host behavior; installed Win98 KernelEx import evidence is recorded separately
in `docs/INITONCE_PORT.md`. Invalid ExecuteOnce usage has an explicit difference:
an active asynchronous object or a callback returning a misaligned context
produces FALSE / `ERROR_INVALID_PARAMETER` in this preview, whereas the native
host terminates the isolated invalid-use probes with `0xC00000F0` or `0xC00000F1`.
This preview does not claim identical invalid-use exception behavior.

The SList batch supplies seven KERNEL32 functions, including distinct x86
fastcall `InterlockedPushListSList` and stdcall `InterlockedPushListSListEx`
entries. Its production module uses locked CMPXCHG8B and scoped x86 SEH, with
zero OS imports. Tests cover a 65,537-node chain, depth wrap, 40,000 concurrent
node transfers, sequence wrap and reclaimed-page exception handling. The fixed
16-bit sequence has a documented full-wrap ABA limitation; user SEH also cannot
reproduce NT's pre-page-fault kernel dispatch. NTDLL/KERNELBASE bindings remain
separate integration work. See `docs/SLIST_PORT.md` for exact evidence boundaries.

The callback batch adds seven functions to the existing five work APIs. Tests
cover deferred critical-section/mutex/semaphore/event/library cleanup,
disassociation while the callback remains alive, simple-callback finalization
and blocked long callbacks while other work progresses. Custom pools, cleanup
groups, timers, waits and I/O remain outside this implemented subset.

The release build runs InitOnce, SList and callback integrated probes against
copies of the exact shipping wrapper placed beside the test executables. Their
hashes are checked against `build/m98wrap.dll` so an older DLL in a probe folder
cannot silently satisfy the integration test.

`guest-tests/` contains the following explicitly allowlisted test tools:

| Files | Use |
| --- | --- |
| `initonce_import_probe.exe` | Four real KERNEL32 InitOnce imports |
| `threadpool_guest_import_smoke.exe` | Existing five work APIs, including this provider's explicit unsupported-environment rejection checks |
| `threadpool_callback_static.exe` | Twelve real work/callback imports |
| `threadpool_callback_direct.exe` and `threadpool_fixture.dll` | Isolated callback provider test |
| `threadpool_callback_integrated.exe` | Direct production-wrapper callback table test |
| `TPMARK.DLL` | Companion used to verify deferred library unloading; keep beside the threadpool tests |
| `slist_smoke.exe` and `SLISTFIX.DLL` | Isolated fifteen-name KERNEL32/Rtl table test |
| `slist_import_probe.exe` | Seven real KERNEL32 SList imports |
| `slist_integrated_probe.exe` | Direct production-wrapper SList table test |
| `slist_fault_smoke.exe` | Self-contained SList module with test-only deterministic race injection and concurrent free stress |
| `gdi_alpha_import_probe.exe` and `gdi_alpha_static_contract.exe` | Three real GDI32 imports through an installed `m98gdi3` route; the latter checks bounded pixels and errors |
| `gdi_alpha_direct_contract.exe` | Directly loads the installed `C:\WINDOWS\KERNELEX\M98GDI3.DLL` and checks the same bounded contract |
| `gdi_alpha_host.exe`, `gdi_alpha_lifetime.exe`, and `GDIFIX.DLL` | Isolated table, absent-backend, and repeated load/unload checks; keep the fixture beside these executables |
| `comctl_ordinal_import_probe.exe` | Real `COMCTL32` ordinal 345/381 imports after the `m98ctl3` route is installed |
| `comctl_png_host.exe` and `M98CTLP.DLL` | Direct PNG icon contract using the provider beside the probe; this does not check the installed KernelEx route |
| `comctl_png_depth_host.exe` and `M98CTLP.DLL` | Direct same-size icon color-depth selection using the provider and a generated resource; the installed four-bit display selected the tested 16-bpp source |

Use the guest-tests directory as the test working directory. Integrated probes
also require the production `m98wrap.dll` to be installed or copied beside them.
Fixture DLLs are test providers and must not replace installed production DLLs.
The full work smoke is intended for the installed Win98 provider because its
unsupported-environment checks differ from the host's full modern threadpool.
The native SList header diagnostic is included as source and rebuilt by the
focused build; its executable is not shipped as a guest test.

All shipped probes, fixtures and the marker are covered by package checksums and
can be rebuilt from the included source. Including a test executable in the ZIP
does not assert a guest pass for a newly packaged snapshot. The FLS backend and its thirteen routed thread/fiber API subset are included.
Its direct, static-import, independent race and CRT lifecycle probes are included
as separate evidence layers; see the FLS and KernelEx lifecycle documents for
unsupported flags, raw exit paths and suspended-callback fiber limitations.

Generated file hashes can differ across compiler versions. The ZIP's
`SHA256SUMS.txt` records files actually shipped, not locally rebuilt output.

In the source checkout, create a release ZIP after building and validating:

```powershell
.\release\build-dlls.ps1
.\tools\package-release.ps1 -Version 0.1.8-preview
```

Replace `0.1.8-preview` with the chosen release version. The packaging script writes
the ZIP and its `.sha256` file under `build/releases/` and selects every ZIP
member from a fixed list.

## Shared wrapper source recipe

Every wrapper build consumes `tools/m98wrap-sources.ps1`. The list is explicit
and ordered, including the FLS module; it is reused by the checkout, focused
API builds and this release rebuild. Integration probes must use byte-identical
copies of the shipping wrapper.

Additional guest probes: `fls_static.exe` (13 installed KERNEL32 imports),
`fls_direct.exe` / `fls_integrated.exe` (explicit API tables), `fls_smoke.exe`
(slot/fiber/termination regression children), `FLSRACE.EXE` (controlled concurrent
rundown and suspended-callback deletion guard), and `THRLIFE.EXE` (EXE/MSVCRT
thread routing and callbacks). Keep `FLSFIX.DLL` and `TPMARK.DLL` beside the
fixture probes. These tests exercise defined subsets, not every native behavior.
