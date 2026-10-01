# 100% API compatibility target and required app corpus

The completion target is **100% of the Windows API surface and working execution of all eight required applications**: Chromium, Supermium, VLC, Notepad++, Visual Studio Code, Legcord/Discord, current open-source Office and Steam. Chromium is mandatory. This is an aspiration, not a current result. A count of exported names or successful imports is only a preliminary metric: an API counts as compatible only after its documented behavior is tested in the Windows 98 guest. A stub that always succeeds or always fails does not count unless that result is the correct contract for the guest state.

The September30 user extension explicitly permits source changes and combining
ports with current libraries. App startup alone is insufficient: Chromium must
render interactive HTML/JavaScript, navigate HTTPS and accept input; Legcord
must present its real Discord UI and network/authentication path; open-source
Office must create, edit, save and reopen documents; Steam must display its real
client and network/authentication/library behavior. Normal exit and persisted
state are part of each acceptance. Existing app scopes remain required. Source
ports must identify their version and changes; remote-hosted rendering must not
be described as native Windows98 application execution. Account-dependent
behavior requires the user's actual account session and cannot be fabricated.

The Office implementation target is LibreOffice. Current publisher/version,
architecture and dependent runtime metadata are being frozen separately from
the previous five-app corpus. Legcord shares the Chromium/Electron work. Steam
is a separate proprietary client compatibility target; its source availability
must not be invented. All three additions remain unverified in the guest.

Publisher metadata now identifies [Legcord1.3.0](https://github.com/Legcord/Legcord/releases/tag/v1.3.0)
with an ia32 portable build. Its release-tag package uses Electron43.2.0;
Electron44.2.0 is the development-branch dependency, not that release.
[Release package source](https://raw.githubusercontent.com/Legcord/Legcord/v1.3.0/package.json).
The current [LibreOffice download](https://www.libreoffice.org/download/)
is26.8.0, published for Windowsx86-64/ARM64. The current
[Steam win64 client manifest](https://client-update.steamstatic.com/steam_client_win64)
is1788652215, SHA256
`40ec2f2aac99fb65c62b7b60db77e8e1575e0c8b59cfeba80294eeb1c963731c`.
Its publisher-checksum-verified bootstrap ZIP is2,668,385bytes; the actual
steam.exe is AMD64 PE32+,5,775,512bytes, SHA256
`48ea0576865d2dfda26001b7b210c3f7559d46e647424cd11704eb1ea842fe5a`.
This verifies the bootstrap architecture, not full client dependency closure
or any guest execution. Latest Office/Steam need genuine64-bit execution or
documented source ports; version spoofing does not meet those requirements.

The additive [Chromium delay-import port](../ntwin32/chromium_port/README.md)
has1,806 host ASan/UBSan controls, including1,200 concurrent cached calls and
a real C++/C ABI consumer. Its static reader accepts116 original chrome.exe
delay slots and39 chrome_elf.dll slots without calling either original entry.
The new native probe and exact two-input manifest remain pending actual
Windows98 controls. This source component is not application success or a
complete replacement for the browser's linked delay helper.

## Fixed reference surface

Use the Microsoft Windows SDK **10.0.28000.2705** (released August 2026) as the initial frozen reference. Its Win32 and WinRT desktop API declarations form the inventory to classify; this includes interface methods as well as DLL exports. The locally installed 10.0.26100.0 SDK can bootstrap the inventory, but a percentage calculated against that older subset must be labeled with its version and must not be called full 28000 coverage. Driver DDIs, .NET APIs, and the independently shipped Windows App SDK are recorded separately because the original project excludes modern application drivers and those interfaces are not all Windows SDK OS APIs. [Windows SDK overview](https://learn.microsoft.com/en-us/windows/apps/windows-sdk/), [SDK release notes](https://learn.microsoft.com/en-us/windows/apps/windows-sdk/release-notes), [desktop API families](https://learn.microsoft.com/en-us/windows/apps/api-reference/).

The inventory must record stable API identity, architecture, minimum OS, interface/contract version, and feature dependencies. A numerator entry requires a guest test for success, failure, memory ownership, thread behavior, and documented edge cases as appropriate. For a native Windows 98 function, this means a guest test of the original API. New wrappers require the same behavioral tests through NTWin32Wrapper9x without KernelEx. Historical KernelEx results below remain a separate lineage. No complete denominator or 100% score has been computed yet.

## Current publisher targets — 2026-09-30

The active targets are Chromium **157.0.8080.0 x86**, Google Windows snapshot
1707946, Notepad++ **8.9.8.1 x86**, Supermium **144 R5 x86**, VLC **3.0.24 x86**
and Visual Studio Code **1.140.0 x64**. Publisher metadata is frozen in ignored
`build/latest-app-metadata-20260930/`; older functional/loader results below
apply to their exact older versions, not automatically to these new targets.

The current Chromium ZIP is 323,332,967 bytes, SHA-256
`af0a1a5eb80a21ff2364b4974ca254d3a3af0bf087db9f5af4232672cb3a53df`.
It matches Google Storage's published MD5. The publisher source revision is
`73c8f84d67bfbad65ad4817d9839ffecb78b06ee`; its VERSION and the actual
chrome.exe RT_VERSION resource both identify 157.0.8080.0. The executable
remains an i386 PE32 with subsystem10.0/static TLS/load configuration; no
header bytes were changed. [Official snapshot](https://storage.googleapis.com/chromium-browser-snapshots/Win/1707946/chrome-win.zip).

The current Notepad++ ZIP is 7,821,291 bytes, SHA-256
`65d3435b5dcbefde47c401a2666132138e76a2b62e189ad4ffe568581b6adfd2`,
matching the publisher's release digest. Its main EXE is i386 PE32, SHA-256
`986ffd50fb51e4b08737d1c47a4aca8e681adb628789228e5f538bfb954d2eb5`.
[Official release](https://github.com/notepad-plus-plus/notepad-plus-plus/releases/tag/v8.9.8.1).

The current VS Code archive is 355,156,158 bytes, SHA-256
`52f47072473375767d63ea5be9ffb96a3092124223fe5ce036834a299715014e`,
matching Microsoft's published SHA-256. The archive endpoint returned 1.140.0
at 15:06:31 UTC; the earlier setup-endpoint result 1.139.1 is retained as
historical metadata. Code.exe is x64 PE32+, SHA-256
`96851792952c34ead53462ad36d973356af2e737b5ed4e433e23c4647e0d6318`.
This downloaded target has not executed in the Windows98 guest.

Read-only preflights of current chrome.exe/chrome_elf.dll/notepad++.exe retain
exact file hashes and bounded complete PE import inventories in
`build/latest-app-preflight-20260930/`. These are not guest launches or an
application success. The native Windows98 GOP driver, native PE loading and
real COM SaveDialog implementation are separate active prerequisites.

The actual 8.9.8.1 trial now displays the native editor, accepts keyboard text,
opens the registered native Save As COM implementation, writes a new 44-byte
file and reopens that document in the same app process. Its unchanged EXE,
installed CORE and COM provider were read back after the VM stopped. The
overall result remains **FAIL**: 14 of 15 scoped checks passed, but ordinary
program exit faults on a linked CRT direct NT PEB/ProcessParameters read.
The fresh file is `Latest NPP 8.9.8.1 Windows98 Save As proof\r\n`, SHA-256
`ab32bfab872ffd7c8a0884e06b70432d7bef6c5ac463a7bfed33aca05c3ab95d`.
The full original result is retained in ignored
`build/native-npp-controls/latest-npp-trial-20260930T1714/result.json`, SHA-256
`f0ea413eaf74b72f1fd0d62c0283e357dc68dd90b66dfe7e52804a9c2b2f7003`.
This app trial uses stock VGA. A separate cold boot now opens the saved file
in the unchanged official application and independently confirms its exact
44 bytes, executable, CORE and COM provider. That six-check scoped PASS is
recorded at `build/native-npp-controls/cold-reopen-proof-20260930T1729/result.json`,
SHA-256 `1b387e4ac6091d28a7fa79c87d038b42cc5669156dd7d05ad41a0ad431b88e53`.
It preserves that earlier unassisted clean-exit failure. A subsequent genuine
GOP trial now verifies unchanged8.9.8.1 native SaveAs, fresh44-byte NPPGOP,
warm reopen and actual normal AltF4 process/helper/waiter exit0 under the
native-proven desktop-field interpreter. Its26-gate scoped receipt is
`run-win98-gop-latest-npp-environment-v3-20260930T1748/native-gop-latest-npp-review.json`,
SHA256 `4969701e15e2170caa6927bdb9cd2c40a34367d3666d7487caa00f8170e1bfa5`.
A separate25-gate cold trial reopens NPPGOP, accepts distinct keyboard text,
saves a fresh39-byte NPEDGOP and normally exits0 again. Its receipt is
`run-win98-gop-latest-npp-cold-v3-20260930T1807/native-gop-latest-npp-cold-keyboard-review.json`,
SHA256 `e945062ad535c5e2b61f7ee39be91c308d1103b29ff3d44d0f5b2e3455d40175`.
The repeat trial's mistaken SaveAll shortcut and native restoration of the
private original document are preserved; final39/44/44-byte files match
independent disk readbacks. Both scoped GOP results require the field
interpreter and retain four OS-forwarded first-chance exceptions and three
FFFFFFFF worker shutdown exits. They do not prove all-worker successful
completion or a general NT process environment. The independent native
loader/TLS fixtures and exact app scopes are documented in
[the native runtime checkpoint](NATIVE_APP_RUNTIME.md). VLC prerequisites
and their separate native API/application gates are in
[the VLC checkpoint](VLC_COMPATIBILITY.md).

## Previous Chromium priority — 2026-09-27

The previous target was official **Chromium 156.0.8076.0 x86**, snapshot
[1705698](https://storage.googleapis.com/chromium-browser-snapshots/Win/1705698/chrome-win.zip),
identified from the publisher's `Win/LAST_CHANGE` and the actual PE version data.
The entire 322,979,270-byte ZIP matched Google's MD5 metadata and has SHA-256
`2ff3b6bafda988752817b4eda7ee74e0842535bc513eb985a8194dfa08bad6c0`.
All 258 extracted files passed CRC checks. Publisher inputs, binary identities,
imports and preparation limits are in [the current target receipt](CHROMIUM_CURRENT_TARGET.json).
Chromium 150 in the historical table below is no longer the latest target.

Both `chrome.exe` and `chrome_elf.dll` are i386 PE32, declare OS/subsystem 10.0,
and contain static TLS, load configuration and delay imports. A host fixture
with that same directory shape is now validated and preserved: TLS 24 bytes,
load configuration 192 bytes, an RVA-based delay import, subsystem 10.0, and
DLL characteristics `0xC140`. The bytes are not stripped and the subsystem
version is not rewritten to 4.10. The stock Windows 98 loader still rejects
subsystem 10.0. The current 17-export provider routes only a small KERNEL32
subset, including `AddVectoredExceptionHandler` and
`RemoveVectoredExceptionHandler` as an ordered registry that is not connected
to a CPU trap. `browser_functionality_verified` remains false. Official
`browser_functionality_verified` remains false. The official zip was
checked into ignored `benchmarks/media` (SHA-256 matches the receipt). An i386
loader maps `chrome.exe` and `chrome_elf.dll` without rewriting subsystem
10.0, applies HIGHLOW relocations, copies static TLS, installs an FS TEB slot,
and the TLS `PROCESS_ATTACH` callbacks return. `chrome_elf.dll`'s entry then
stops on `InitializeCriticalSectionEx`. That is not a browser launch.

The [bounded native observer](../platform/win98lab/app_probe/README.md) records
actual process creation, loader error, owned windows and full process exit.
Its own exit 0 can report a correctly observed launch failure. Browser startup,
rendered local pages, JavaScript, keyboard/mouse input and clean shutdown need
separate evidence. The initial unchanged-package guest trial is pending.

Follow-on kernel and application work actively references pinned ReactOS source,
with per-file licenses, authorship and adaptation differences retained. Existing
independent components and historical KernelEx ports keep their own provenance.

## Historical pinned application corpus

These programs are separate integration probes. Their static PE import coverage and their actual startup/function tests are reported separately from the full-SDK percentage. Versions below are pinned as of 2026-09-23 where the publisher offered a current release.

| Program | Pinned probe | Publisher evidence | Windows 98 guest implication |
| --- | --- | --- | --- |
| Chromium 150 | Official 32-bit [snapshot revision 1639845](https://storage.googleapis.com/chromium-browser-snapshots/Win/1639845/chrome-win.zip), `chrome.exe` version 150.0.7871.0; ZIP SHA-256 `9c3601da8237f3cb22022cd222f06b92f06d88d0674c4f242d1590bec89af97a` | [Chromium download instructions](https://www.chromium.org/getting-involved/download-chromium/), [platform policy](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/supported_platforms.md), [Chrome minimum Windows 10 and SSE3](https://support.google.com/chrome/answer/95346?hl=en) | An API import audit can prioritize wrappers; startup would also require loader, CRT, sandbox, graphics, and CPU work. No guest run is claimed. |
| Supermium | [144.0.7559.256 R5, 32-bit portable package](https://github.com/win32ss/supermium/releases/tag/v144-r5); ZIP SHA-256 `17acfcdf89ea651905053b50b0fce5a28db19cb2c69ed5579c7b177806ed6d31` | [Project README](https://github.com/win32ss/supermium) targets XP, 2003, Vista, 7, and 8.x; [Win98 request](https://github.com/win32ss/supermium/issues/1488) was closed as not planned | Its own XP-era wrappers are useful research, but Windows 98 support is not established. No guest run is claimed. |
| VLC | [3.0.24, 32-bit Windows ZIP](https://get.videolan.org/vlc/3.0.24/win32/vlc-3.0.24-win32.zip); ZIP SHA-256 `8511356afd680817f3aea624c63032d0936f3d77b2175fb36c8fc16adf9744e8` | VideoLAN's [Windows requirements](https://www.videolan.org/vlc/download-windows.html) explicitly mention KernelEx for Windows 95/98/Me | Best first real application probe after KernelEx guest installation. Current version still needs a measured import/runtime test. |
| Notepad++ | [8.9.8, 32-bit portable ZIP](https://github.com/notepad-plus-plus/notepad-plus-plus/releases/tag/v8.9.8); ZIP SHA-256 `880c5c5323305154aaed3fa5238d6186cda3bcfa3a82645243c1e7999e35602a` | [Publisher support table](https://github.com/notepad-plus-plus/notepad-plus-plus/blob/master/SUPPORTED_SYSTEM.md) says v6.0 was the last release running natively on Windows 98 | Current x86 release is an import and runtime extension target; existing v6.0 support is only a baseline. |
| VS Code | [1.138.0, Windows x64 archive](https://update.code.visualstudio.com/1.138.0/win32-x64-archive/stable); downloaded ZIP SHA-256 `c0a9f12a0d8962fa4cda1959eecd5fdd3f82de9715ad4dadd5601856bb60fd21` | [Publisher requirements](https://code.visualstudio.com/Docs/supporting/requirements) require 64-bit Windows; [FAQ](https://code.visualstudio.com/docs/supporting/faq) identifies 1.83 as the last stable 32-bit release | Current x64 PE cannot load in 32-bit Windows 98. Its API inventory can be studied, but API wrappers alone cannot turn it into a guest executable. |

All five archives were downloaded into ignored `benchmarks/media/`; the Chromium snapshot matched its Google Storage MD5 metadata, while Supermium, VLC, and Notepad++ matched hashes published on their release/download pages. The VS Code hash above is a local digest of the official HTTPS download, not a separately published publisher checksum. The four x86 entry points have PE machine `0x014C`; VS Code 1.138.0 has `0x8664` (x64).

For each binary, record direct and delay-load imports, dependent DLLs, loader failure, and a reproducible guest test. Import coverage is a triage metric, not the 100% full-API goal and not evidence that the application runs. Each required app needs a separate guest launch and meaningful functionality result before completion is claimed.

## Latest 0.1.8 COMCTL32 candidate: Notepad++ 8.9.8

This checkpoint is newer than the provider19 and USER32 loader results below.
The PNG-capable `M98CTLP.DLL` was installed as the versioned KernelEx provider
`M98CTL3.DLL` (SHA-256
`aafd97b71ff63c9f9cedffa4705713243d5708f22ff6ffaf04c732261ca0e3f8`);
after a hardware-accelerated cold boot, a genuine static
`COMCTL32` ordinal 345/381 import probe returned exit 0. Separate direct
guest probes passed generated PNG icon groups at requested sizes 16, 32, 40
and 48, the pinned app's PNG-backed icon group 501 at 16 pixels, and the
same-size 16-bpp source choice on a four-bit display.
The exact binary and direct/static evidence are documented in
`docs/COMCTL_ORDINAL_PORT.md` and `docs/RELEASE_0_1_8_CHECKPOINT.md`.

With this candidate, the pinned x86 Notepad++ 8.9.8 executable moved past its
previous `WM_CREATE` access violation and icon 501 warning. A bounded
`APP_PROBE.EXE` guest run saw the editor window by 3.974 seconds and a
visible editor still present at 12.004 seconds. The tool then posted
`WM_CLOSE` and ultimately terminated the process. A close operation
displayed a Windows 98 invalid-page-fault dialog. This is a startup
milestone, **not** a clean shutdown or complete application pass.

With the same `M98CTL3.DLL`, an existing 13-byte text file was opened, edited,
and saved with `Ctrl+S`. The guest remote tester read back 34 bytes with
SHA-256 `a1853e54f7e131411c6f0787e80d8f7157f3e60ce85438ddfc427c5b82bf1c2c`;
the exact ASCII text was `Saved under M98CTL3\r\nBaseline v3\r\n`.
This is one verified existing-file save, not general Save As or clean exit.

Save As for a **new** document did not show a dialog or write a verified new
file. A read-only guest diagnostic found the Vista `CLSID_FileSaveDialog` registry entries
absent and `CoCreateInstance` for its `IFileDialog` interface returned
`0x80040154` (`REGDB_E_CLASSNOTREG`), while a Shell Link COM control passed.
The pinned Notepad++ source calls that interface on the new-document save
path; see `docs/NPP_SAVE_DIALOG_TRIAGE.md`. The successful existing-file save
does not exercise that new-document dialog path. No full Notepad++ success is
claimed. The other four required apps have not gained a new functional pass
from this COMCTL32 work; their last guest results remain the historical
provider19 checkpoint below.

## Historical Notepad++ 8.9.8 guest probes

The previous KERNEL32-only checkpoint cold-booted the installed Win98 SE guest with
`M98WRP19.DLL` (89 KERNEL32 table names), SHA-256
`ee96a7d5dfda768f21eb0098b8dafdd4080a018847329e5e145d8086b7a46cd4`.
Six static-import suites passed: InitOnce (4 APIs), threadpool work (5),
threadpool callback extensions (7), SList (7), NLS (2), and FLS/lifecycle (13).
These are **38 focused API contract subsets**, not 38 fully compatible APIs.
The ten-test lifecycle regression bundle also passed the 89-name table smoke,
FLS concurrency/termination tests, and EXE plus system MSVCRT thread-exit
callbacks. Exact source/provider/test hashes are in
`benchmarks/api-guest-evidence-v1.json` and family documents.

At that checkpoint, APP_PROBE returned exit 2 and `LAUNCH_FAIL win32_error=31`;
the dialog named `USER32.RemoveClipboardFormatListener`
(`build/guest/npp-after-fls19.png`). The previous FlsAlloc import had been passed.

The next guest checkpoint installed `M98USR1.DLL` (SHA-256
`4932584fcb7f1af493dbebfd76a38ede4f04b5543a0559cdd8fd1c33ff8b3fc7`)
and CORE.INI with nine USER32 routes (SHA-256
`2e853bcdd3a686ad8d105ee47219049efcdd9fbcfeddeac29c9d061eadd0bcc9`).
After a clean hardware-accelerated cold boot, the six-test clipboard suite
passed, including full static imports, owned data round trips, six queued
change notifications and restoration of the empty clipboard. Exact receipt:
`build/guest/suite-clipboard-user1.json`; contract and limits:
`docs/CLIPBOARD_CONTRACT_TESTS.md`.

At that historical checkpoint, Notepad++ did not start. Its next loader dialog named
`GDI32.DLL!GdiAlphaBlend`; APP_PROBE returned exit 2 / Win32 error 31.
`benchmarks/npp-clipboard-user1.json` records the screenshot and tested
provider hashes. This advanced the loader dependency but proved no editing
function. The other required application results below remain from the earlier
provider19 checkpoint; no app gained a functionality pass then.

Earlier provider16 stopped at `InitializeSListHead`. A preceding warm restart
of a combined change produced one VxD exception preserved in a separate
snapshot. Later normal shutdown/cold boots passed; repeated warm-restart
reliability remains unverified. During provider17 testing an early host pipe
request before the guest remote agent was ready required transport recovery
and another normal guest shutdown. This is not an API test pass or failure.

The first x86 portable build attempt in the Windows 98 SE + KernelEx guest stopped at a missing `DBGHELP.DLL` loader dialog (`vm/npp-first-run.png`). Its direct `DBGHELP.DLL` import is `ImageNtHeader`. The OEM Windows 98 `IMAGEHLP.DLL` already exports that function (see `benchmarks/win98se-ko-oem-native-exports-v1.json`), so `build/dbghelp.dll` provides the same export and calls the installed native implementation. This bridge passes a PE32 Windows 98 import gate and a 32-bit Windows host smoke test, including a malformed PE image returning `NULL`.

In the earlier loader sequence, with the bridge beside `notepad++.exe`, the next guest loader dialog reported missing `DWMAPI.DLL` (`vm/npp-shim-result.png`). An app-local DLL exports the two directly imported DWM functions and reports disabled composition. After initial shims the guest showed a generic invalid-format error (`vm/npp-new-alert-upper.png`); changing the executable's PE version fields in an **ignored local test copy** did not help (`vm/npp-pe410-error-revealed.png`). A clean retry with app-local BCRYPT exposed the specific issue: `DWMAPI.DLL` had no base relocation directory, so Win98 could not load it after another shim occupied the preferred base (`vm/npp-after-bcrypt.png`). The DWM build now forces a real base relocation; its PE gate, host smoke, and Win98 guest direct smoke pass (`vm/dwm-reloc-guest-smoke.png`).

The seven direct BCRYPT imports are provided by an app-local SHA-256/MD5/HMAC subset. Its PE gate, host known-answer tests, and Win98 guest direct smoke pass (`vm/bcrypt-guest-smoke.png`). MD5/SHA256 and HMAC pseudo-handle paths also passed a direct guest smoke (`vm/pseudo-guest-smoke.png`). With DBGHELP, relocatable DWMAPI, and BCRYPT present, Notepad++ next stopped at the absent `SHCreateItemFromParsingName` export in native `SHELL32.DLL` (`vm/npp-after-dwm-reloc.png`). A new KernelEx Shell API library now supplies `SHCreateItemFromParsingName`, `SHParseDisplayName`, and the focused file-system case of `SHOpenFolderAndSelectItems`; direct and static-import guest probes passed, and Explorer selected the test file (`vm/select-shell3-guest.png`). At that historical stage, the following Notepad++ loader error was `UXTHEME.DLL!DrawThemeTextEx` (`vm/npp-after-uxtheme.png`). A no-theme bridge passed direct guest testing, but KernelEx's KnownDLL redirection bypassed an app-local `UXTHEME.DLL`, so the app had **not** started then. None of the publisher binaries or test ISOs is distributed by this project.

## Historical provider19 five-application checkpoint

Exact executable hashes, PE architectures and receipts are recorded in
`benchmarks/app-guest-checkpoint-provider19.json`. App media remain ignored.

| Selected application | Result at provider19 checkpoint | Next shared prerequisite then |
| --- | --- | --- |
| Chromium 150 x86 | Loader error 31; CHROME_ELF.DLL requires KERNEL32.AddVectoredExceptionHandler | Exception dispatch and vectored-handler family |
| Supermium 144 R5 x86 | After selecting its version directory as cwd, loader error 31; P_NTD.DLL requires NTDLL.LdrGetProcedureAddress | NT loader/export-resolution backend and bundled wrapper dependency closure |
| VLC 3.0.24 x86 | Process launches but only a failure dialog appears: invalid options or no plugins found. Same result with application directory as cwd. No player UI or playback | Plugin discovery/loading and full dependent API contracts |
| Notepad++ 8.9.8 x86 | Loader error 31 at GDI32.GdiAlphaBlend after USER32 clipboard routes | GDI alpha drawing family and graphics backend |
| VSCode 1.138.0 x64 | Local PE32+ AMD64 inspection; not launched in x86 Win98 | x64 execution plus user API/loader architecture path |

VLC's APP_PROBE exit 0 means the observation tool completed and closed the
observed process. Its screenshot shows an error dialog, so it is explicitly
not an application success. Supermium's first root-cwd attempt could not find
CHROME_ELF.DLL; using the packaged version directory resolved that layout issue
and exposed the NT loader prerequisite. This does not establish installation
or application compatibility. No target version was replaced by an older one.
