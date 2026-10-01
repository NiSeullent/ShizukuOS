# Legcord and LibreOffice integration — 2026-09-30

The requested targets are the current publisher Legcord release and current
open-source LibreOffice release. Acquired packages and source work below do not
establish that either application runs. Discord login and document editing remain
unverified. A standalone Kernel64 result also does not establish execution inside
the Windows 98 GUI.

## Publisher inputs

Packages reside only in ignored
`build/app-inputs/productivity-01a0f3d0cb43/`; no application binaries or runtime
redistributables belong in source control or public release packages.

| Product | Publisher target | Package size | Publisher SHA-256 |
| --- | --- | ---: | --- |
| Legcord | [v1.3.0 Windows x64 ZIP](https://github.com/Legcord/Legcord/releases/tag/v1.3.0) | 169,732,620 | `99b52c0ccfdbdb7f264dfce8cebf5343d4190f6f1b8be8a9a86369a8696f1d6a` |
| LibreOffice | [26.8.0 Windows x64 MSI](https://download.documentfoundation.org/libreoffice/stable/26.8.0/win/x86_64/LibreOffice_26.8.0_Win_x86-64.msi.mirrorlist) | 374,906,880 | `4aa6c6e1895f4055104effcb556bd3362d20c6ad707c149543304f395ef9db95` |

Both complete downloads matched publisher hashes and sizes. Legcord's digest is
the GitHub release asset digest; LibreOffice's is the Document Foundation mirror
receipt. Legcord's tagged source uses Electron 43.2.0; its executable is AMD64,
subsystem 10.0, PE version 1.3.0, SHA-256
`cc77a1aa873ff55b4d9e5a532b356c557739dc0467c3dd54bc50b1d80a0b23b0`.
The [current LibreOffice download page](https://www.libreoffice.org/download/)
and official stable directory selected 26.8.0 at acquisition.

Legcord's full tree is `legcord/`. LibreOffice's application tree is
`libreoffice-tree/`; its MSI `File → Component → Directory` tables preserve the
actual install paths, correctly interpreting `short|long` and `target:source`
names. All 19,427 cabinet members passed MSI file-size checks after successful
cabinet extraction. The application tree contains 19,271 files and
1,519,848,078 bytes. Architecture-specific system merge modules and fonts are
kept separate from that install tree.

The same verified LibreOffice MSI contains AMD64 Visual C++ 14.44.35211 DLLs.
They are separated into `libreoffice-bundled-vc-amd64/`; their names, exact MSI
file IDs, PE versions, sizes and SHA-256 hashes are in
`libreoffice-extraction.json`. Mixing those publisher-bundled libraries
app-locally can test the missing C++ iostream/locale surface without manufacturing
success exports. The initial application attempt must retain the unmodified
application tree before such a follow-up.

## Probe and evidence gates

`shizukudos/tests/run_k64_productivity.py` adapts the existing Electron guest
runner without changing its shared source. It uses a standalone Kernel64 boot,
a probe-owned AHCI FAT32 disk with snapshot writes, and no network adapter.
It never changes a shared Windows 98 VM or the read-only publisher tree.

- Legcord runs its packaged executable with a disposable profile. No fabricated
  marker exists, so this startup diagnostic cannot produce a functionality pass.
- LibreOffice runs `program\soffice.com --headless --nologo --nodefault
  --nofirststartwizard --version`. Matching version output after autorun starts
  plus normal exit 0 and no loader/runtime fault proves that command only.
- Executable, application arguments, environment and expected-output overrides
  are rejected, including abbreviated options. Every result records its actual
  command, package content fingerprint and executable hash.
- The disk cache uses names and complete file content, including same-size
  replacement. A package mutation during copying blocks guest startup.
- `app_functionality_verified`, `windows98_execution_verified`,
  `discord_login_verified` and `document_editing_verified` remain false.

Fourteen host tests pass for output scoping, fatal/loader failures, package path
boundaries, same-size cache invalidation, package mutation and forbidden scenario
overrides. The diagnostic also records first-chance exceptions separately and
detects actual nonzero GPU child exits after autorun. A first-chance exception or
failed optional DLL probe alone does not establish an application fault.

## Actual frozen-baseline guest attempts

Both verified publisher trees were attempted sequentially in isolated KVM QEMU
with a 60-second guest timeout. The runtime and kernel came from the immutable
private `build/modern-apps/baseline-full-runtime/` snapshot, not a concurrently
rebuilt runtime. Its `WIN64.IMG` SHA-256 is
`2f3a3facad9f15187ed33e37088082afa3f8c5df2a7e00f4ef42e1af503e16f0`;
`kernel64s/KERNEL64S.BIN` SHA-256 is
`22c6c09e57152208ee3bcc650e22e0a3f16a17b81a069869731aabcffe3266fe`.
The complete four-file receipt is private
`build/modern-apps/productivity-baseline-runtime-receipt.json`.

| Actual package command | Result | Observed progress and failure |
| --- | --- | --- |
| Legcord 1.3.0 startup | FAIL, guest timeout, exit `0x102`, faulted | Executes actual `resources/app.asar` JavaScript, creates the storage folder, performs first-run setup and config recovery, and sets video flags. Then first-chance breakpoint `0x80000003` at `Legcord.exe+0x5831fba`; its main process still has 19 threads at timeout. |
| LibreOffice 26.8.0 `soffice.com --version` | FAIL, process creation status `0xc0000139` | Project `MSVCP140.dll` lacks `?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@XZ`. The launcher does not reach application output. |

Legcord probes also expose missing API-set revisions/hosts and optional modules.
Immediately before the breakpoint the guest reports missing `comctl32.dll`
ordinal `0x159`. That ordering is evidence of a missing surface, not proof that
supplying this export alone resolves the breakpoint. No successful window,
renderer, Discord connection or login was established.

Full serial and result receipts are preserved under private
`build/modern-apps/legcord-baseline-full/` and
`build/modern-apps/libreoffice-baseline-full/`. These are actual application
attempts in standalone Kernel64; Windows 98 GUI execution and product
functionality remain unverified.

After the real LibreOffice import failure, a separate
`libreoffice-msi-vc14-experiment/` tree adds the same publisher MSI's ten AMD64
VC 14.44.35211 DLLs under `program/` (1,845,512 bytes). Unchanged data files are
immutable hardlinks, and each added DLL is an independent copy; no existing
program DLL was replaced. Its exact paths and hashes are in
`libreoffice-msi-vc14-experiment.json`. The original tree and baseline image/logs
remain intact. This next mixed-library experiment has not yet produced a guest
result in the baseline runtime. In the ported `app-runtime-v1` runtime, its actual
guest attempt maps publisher `msvcp140.dll`, `vcruntime140.dll` and
`vcruntime140_1.dll` from `program/`, then fails at the next eager import:
`msvcp140.dll → api-ms-win-crt-string-l1-1-0 → ucrtbase.dll!__strncnt`
(`0xc0000139`). No launcher output is reached. Private evidence is
`build/modern-apps/libreoffice-msi-vc14-v1/{serial.log,result.json}`.

The static closure against DLLs extracted from the frozen baseline identifies
26 publisher MSVCP dependencies beyond the original C++ export: a bounded string
routine, locale locks, eight locale/time formatting routines, secure randomness,
and fourteen threadpool/event/semaphore/barrier routines. The launcher also
needs `PathCchCanonicalizeEx` and `GetBinaryTypeW`. Both publisher vcruntime
DLLs' eager imports resolve in that static audit. This is a dependency work list,
not a behavior or loading pass; its complete receipt is
`libreoffice-msi-vc14-startup-chain.json` in the ignored input directory.

## PathCch prerequisite implementation

The LibreOffice launcher imports `PathCchCanonicalizeEx` through
`api-ms-win-core-path-l1-1-0`, whose existing host is the kernelbase/kernel32
alias. New `dlls/pathcch/` source supplies the full 22-entry lexical family from
pinned Wine 11.0; new `kernel32/k32_pathcch.c` exports delegate to that real module
from SYS64. No shared build script or API-set table was changed.

Source notices, exact Wine/ReactOS commits and adaptation differences are beside
the module in its README. Missing mandatory DLLs/exports return failing HRESULTs
or Boolean false with LastError; module references are balanced. There are no
success-shaped compatibility stubs.

Validation so far: 56 algorithm contract checks and 10 wrapper loader-failure
checks pass under Clang AddressSanitizer and undefined-behavior sanitizer;
the module, kernel32 wrappers and guest test compile for AMD64 with strict
`-Werror` flags. The actual guest test `win64/tests/t_pathcch.c` checks real DLL
and API-set-host exports plus contracts: 60 checks, zero failures,
`SHZ-PATHCCH-PASS`, normal exit 0 and faulted 0. Private serial evidence is
`build/modern-apps/contracts-v1/t_pathcch/serial.log`. The generic test receipt
initially missed this custom aggregate format; the guest evidence is explicit.
These checks are focused contracts, not a full Windows API percentage.

## Additional bounded runtime ports

Steam's new `WSASocketA` entry point adapts the identical protocol fields and
bounded ANSI description to the existing real Kernel64 `WSASocketW` backend.
It resolves each `FROM_PROTOCOL_INFO` field, transfers actual duplicate-handle
ownership, and sets real inheritance metadata. Invalid flags/records/groups and
unimplemented advanced modes fail explicitly. Its AMD64 guest contract compiles;
actual create/bind/duplicate/close behavior must be recorded in a guest result.

Chromium's next real five-entry OLEACC delay-import surface was investigated
using the pinned Wine11 source. A complete untouched proxy-layer build compiles
but fails to link on missing RPC stub/proxy and COM user-marshaling providers.
The separate local standard-object subset links 17 exports, including the five
required names, with real Wine client/window COM objects. Its 448-import eager
closure resolves against frozen runtime DLLs. Proxy factory/registration remains
absent, and missing optional GUI-thread/class-query/atom providers fail; full
cross-process accessibility remains unsupported. The HWND/vtable/name/role/child
guest contract compiles and awaits execution. Source lineage, exact adaptation
and isolated-build recipe are in `wineport/oleacc-subset-README.md`; no prepared
Wine tree or normal module cache was changed by the probe.

## Later Legcord graphics evidence and measured next path

The private `legcord-v7` attempt executes setup, starts real network/renderer/GPU
processes and runs the setup page. Its GPU child then dies at a mandatory
`dxgi.dll!CreateDXGIFactory1` delay import; the raw serial records the missing DLL,
the delay-hook breakpoint and the nonzero GPU exit. The complete v7 source,
runtime, kernel, publisher and raw-log hashes are retained in ignored
`tools/legcord-dxgi-boundary/absent-before.json`. No functional UI pass follows
from the existence of these processes.

The new three-export `dlls/dxgi/` experiment implements the genuine unavailable
provider failure: it clears the factory output and returns a documented failing
HRESULT. It creates no factory, adapter or D3D object. This surface is classified
as **provider unavailable/unsupported**, not supported DXGI functionality or a
compatible API score. Sixteen host sanitizer checks and strict AMD64 module/test
builds pass, with source/binary receipts under `tools/legcord-dxgi-boundary/`.
Full Wine DXGI still requires real wined3d, graphics and composition providers;
the source/dependency evidence is retained beside the experiment.

The actual private `legcord-display-v9-offline` framebuffer
`screen-095.png` shows a titled **Legcord Setup** window with a blank gray client
area. It establishes a real window, not completed product UI rendering. The
original missing-DXGI delay-hook fault is gone, but the GPU child now breaks at
`Legcord.exe+0x7f1cf9e` and exits `0x80000003`. The exact publisher binary branch
and Chromium 150.0.7871.129 source identify the
`SoftwareOutputDeviceWinSwapChain::ResizeDelegated` check after failure to create
DirectX objects. It accepts only a genuine session-zero access-denied failure;
the unavailable graphics provider does not satisfy that contract.

Chromium's default Win11 `RemoveRedirectionBitmap` feature selects a DXGI/DComp
software swapchain even with `--disable-gpu`. Its official
`--disable-direct-composition` switch disables that choice and selects existing
GDI software output. The fixed Legcord probe profile now includes that switch;
prior captures retain their original command. Its next actual run requires
real shared DIB pixels. `dlls/gdi32/` now supplies actual section-backed 32-bpp
pixels with aligned owned views, caller-handle lifetime and genuine metadata;
17 production arithmetic sanitizer checks and full native GDI/guest builds
pass. The cross-process raster and mapping-lifetime guest fixture awaits its
own actual execution receipt. No displayed Discord page, Discord login or
Windows 98 GUI execution has been established.

Exact upstream references: [swapchain failure check](https://raw.githubusercontent.com/chromium/chromium/150.0.7871.129/components/viz/service/display_embedder/software_output_device_win_swapchain.cc),
[feature gate](https://raw.githubusercontent.com/chromium/chromium/150.0.7871.129/components/viz/common/features.cc),
[GDI software canvas and output](https://raw.githubusercontent.com/chromium/chromium/150.0.7871.129/components/viz/service/display_embedder/software_output_device_win.cc).
