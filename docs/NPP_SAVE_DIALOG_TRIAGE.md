# Native Notepad++ Save As continuation

The historical 0.1.8 checkpoint proves Notepad++ 8.9.8 displayed its editor and
saved one existing file in an installed Microsoft Windows 98 SE + KernelEx
4.5.2 guest. New-document Save As failed with `REGDB_E_CLASSNOTREG`
(`0x80040154`) for `CLSID_FileSaveDialog`, and closing the editor still raised
an invalid-page-fault dialog. Neither problem is an application PASS. See
[the preserved checkpoint](RELEASE_0_1_8_CHECKPOINT.md). The earlier referenced
SaveDialog triage document was absent from all current local worktrees and
fetched origin branches; this document records the new continuation.

The official current x86 portable target is **Notepad++ 8.9.8.1**, released
2026-09-24. Its frozen publisher-verified package is
`benchmarks/media/npp-8.9.8.1/npp.8.9.8.1.portable.zip`, 7,821,291 bytes,
SHA-256 `65d3435b5dcbefde47c401a2666132138e76a2b62e189ad4ffe568581b6adfd2`.
The main x86 executable is 7,752,688 bytes, SHA-256
`986ffd50fb51e4b08737d1c47a4aca8e681adb628789228e5f538bfb954d2eb5`.
Publisher metadata and binary preflight do not prove native execution.

The [official tagged CustomFileDialog source](https://github.com/notepad-plus-plus/notepad-plus-plus/blob/v8.9.8.1/PowerEditor/src/WinControls/OpenSaveFileDialog/CustomFileDialog.cpp)
requires COM activation, `IFileDialogCustomize` checkboxes, an `IOleWindow`
window handle, filter/folder/filename configuration, event subscription and a
filesystem `IShellItem` result. A dummy successful `CoCreateInstance` or host
file chooser would not satisfy that path.

## New native component

`src/m98_file_dialog.c` implements a COM in-process server using original
Win98 `GetSaveFileNameA` and its actual Explorer-style hook/template controls.
It registers only `CLSID_FileSaveDialog`; stock `OLE32.CoCreateInstance` loads
the server normally. It does not replace or intercept OLE32. The registration
entry point refuses to overwrite a different existing class server, and the
unregistration entry point deletes only its own matching InprocServer32 key.

The candidate supplies the common `IFileDialog`/`IFileSaveDialog` prefix,
`IFileDialogCustomize` checkbox operations and `IOleWindow`. The actual dialog
emits type, folder, selection, check-button and file-accept events. `OnFileOk`
can veto acceptance. Returned Unicode strings use `CoTaskMemAlloc`, reference
counts share one COM identity, and event sinks remain alive across reentrant
Unadvise callbacks. ACP conversion rejects replacement/best-fit loss.

`Show` returns the real common-dialog selection, cancellation or error and
restores the guest working directory. `GetResult` fails before a successful
selection or after cancellation. A selected filename is not a saved file:
the calling application performs the actual write.

The component is a bounded filesystem Save dialog. Open dialogs, multiple
selections, virtual Shell items, property stores, custom controls other than
checkboxes, pre-navigation veto, custom overwrite/share handling and full
modern Shell behavior remain unsupported. Ordinary overwrite confirmation
comes from the native Save dialog. Names are limited to native `MAX_PATH` and
the guest ACP. Unsupported calls/options return errors.

Notepad++ requests `FOS_FILEMUSTEXIST` even for new saves. The native
[OPENFILENAME contract](https://learn.microsoft.com/en-us/windows/win32/api/commdlg/ns-commdlg-openfilenamea)
defines `OFN_FILEMUSTEXIST` for Open dialogs only; this Save provider retains
the reported FOS option without passing that invalid native Save flag.
The pinned [Wine item-dialog implementation](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/comdlg32/itemdlg.c)
also applies its file-existence check in the Open path. No Wine implementation
body is copied.

## Validation and prerequisites

Build with `python3 tools/build_file_dialog.py`. Output is isolated in
`build/native-file-dialog`; no PE is executed or registered by the builder.
The source-bound receipt records compiler bytes/version, exact commands,
artifact hashes and original OEM import gates. Both provider and probe use
PE32 x86, Win98 subsystem 4.10, i486 instructions, no CRT/TLS/delay imports,
and native Win98 DLL imports. Run `python3 tools/test_file_dialog.py` for ten
host gate positive/negative checks. These are host evidence only.

`FDPROBE.EXE` checks COM identity, reference counts, invalid results/indexes,
filters, checkbox state and event lifetime by default. Its explicit guest
`--register`/`--unregister` modes change only the SaveDialog class key.
`--cancel`, `--save` and `--veto` require actual user/QMP interaction with the
native dialog. The save probe requires a real checkbox toggle, actual
`C:\FDLG\SAVEQA.TXT` selection and an exact caller write/read round trip.
It checks the actual OS is Microsoft Windows 98 and writes fresh
`C:\FDLG\PROBE.LOG`. It never auto-accepts a dialog.

The original canonical GUI disk is vanilla Win98: KernelEx and M98 providers
are absent there. A separate disposable clone and frozen original helper-id CSM
firmware are used for the direct native COM trial; this is the working VGA
OpROM path, not native GOP driver acceptance. Screenshots and fresh file
readback are required.

The first direct native execution is recorded in
`build/native-file-dialog-trial/20260930T153452/result-v2.json`: actual
Microsoft Windows 98 completed 30 COM contract checks, 5 registration checks,
20 cancellation checks and 32 Save/veto checks, all with zero failures.
Ordinary `CoCreateInstance` activated the registered server. The actual first
`OnFileOk` veto kept the window open; a real checkbox toggle and second accept
returned the selected filesystem item. Independent post-run disk readback
found the exact 36-byte `Windows98 native COM Save As proof\r\n` file, SHA256
`5aec3701a6a6e0093ba23efae3a0652e8861a04227dc133d69cbfd256160e580`.
The generic runner's `NEEDS-VISUAL-REVIEW` remains unchanged. A preceding
optical-drive attempt and the first host review's two misread screenshot
count assertions are preserved separately.

That real screen exposed overlapping custom controls. The new candidate
creates the controls during `WM_INITDIALOG`, before the common dialog's
documented arrangement step, and uses the required sibling clipping style.
The probe now checks actual live control geometry, real
`IFileDialogControlEvents` delivery and complete COM release after `Show`.
The separately frozen cold native trial
`build/native-file-dialog-trial/20260930T155609/result.json` passed all 26
independent acceptance checks. Actual native logs record 23 cancellation and
37 Save/veto/control-event checks, all with zero failures. The class activated
after a cold boot without re-registration. Live rectangles place checkbox
rows below standard controls. Actual checkbox events, first-accept veto,
second accept, caller writes/reads, post-VM exact bytes and complete COM/event
release passed. The preserved source disk was never booted or changed.
Clean Windows shutdown was not established. See the
[Microsoft hook/template lifecycle](https://learn.microsoft.com/en-us/windows/win32/dlgbox/open-and-save-as-dialog-boxes#explorer-style-custom-templates).

Full latest-NPP execution additionally requires a pinned KernelEx install,
source-built M98 API/icon/theme providers, guarded current CORE.INI changes,
app-local helper DLLs, exact guest readback and a cold boot. Historical traces
and configurations are references, not evidence those prerequisites are
installed in the new clone. The separate native NTW32 loader does not yet
supply that broad Unicode/API environment. After prerequisite closure,
acceptance must prove latest NPP startup, real new-document Save As, exact
saved bytes, reopen, and clean exit; the historical close crash remains an
independent unresolved gate.

The new isolated latest-NPP prerequisite chain is now recorded in
`build/native-npp-controls/prerequisite-proof-20260930T1653/result.json`:
28 independent checks passed. The official KernelEx 4.5.2 installer completed
in actual Win98 using the frozen official Microsoft `UNICOWS.DLL`, with no
guest download. A new cold boot displayed KernelEx's installation-success
dialog and confirmed it is disabled by default. The native mode guard reports
ordinary Win98 version `0xC0000A04` and initially absent exact NPP settings.

All six M98 API-table providers, three app-local helper DLLs and versioned
`UXTNEW.DLL` match their source-built pinned hashes on disk. Original
`UXTHEME.DLL` is preserved. The exact installed 3,613-byte `CORE.INI`
(`f9cff1953e6295c0a4310091818faab779e29c60e69c5797dfc8079e1fbb59d9`)
was backed up before the guarded WINXP-only candidate was installed.
Other configuration profiles and existing version/parser routes remain
unchanged. The native KnownDLL guard switched only the verified original
UXTHEME mapping. The exact `C:\NPPLAB\APP\NPP.EXE` mode guard stored
`WINXP` and flags zero, flushed and read them back; a repeated apply refused
to overwrite the existing values. Fresh independently read native logs
record both the successful change and rejection. System/registry backups
and every prior source disk are retained.

That quiescent preparation disk is SHA256
`37a5c39432c091413471e9c5d4b377f3b51f96430eafcffbb9ef6057d3cd19ad`.
The official NPP executable and previously cold-tested COM server remain
byte-identical. This receipt covers prerequisites, not NPP execution.
The following new cold clone loaded those updated KernelEx tables and ran
the unchanged official application.

## Latest application execution

`build/native-npp-controls/latest-npp-trial-20260930T1714/result.json` records
**FAIL**, with 14 of 15 checks passing. Original native guest screenshots
show the latest editor, typed text, the actual Save As dialog with its
application checkbox, and the saved document. Independent post-VM readback
found the exact new 44-byte `C:\NPPLAB\NPPQA.TXT`:
`Latest NPP 8.9.8.1 Windows98 Save As proof\r\n`, SHA256
`ab32bfab872ffd7c8a0884e06b70432d7bef6c5ac463a7bfed33aca05c3ab95d`.
That path was absent on the retained pre-run disk. Closing just the document
with Ctrl+W and reopening it with Ctrl+Shift+T restored the real saved path
and text.

The first unchanged 30-second observer saw the native Notepad++ window after
2,957 ms and then deliberately posted WM_CLOSE at its observation limit.
The application faulted during that close; the observer eventually killed
it with code 1460. Direct Alt+F4 after the later successful Save As/reopen
also faulted. Neither forced termination nor visible editing is a clean
process-exit PASS. The first inspection incorrectly called the initial fault
a startup failure; original screenshot 028 and the fresh observer log prove
the editor appeared before the close request. The complete original
chronology and that correction are retained in the receipt.

The native fault is in unchanged `NPP.EXE` at `0078A91F` (RVA `0038A91F`):
`mov eax,[eax+8]` executes with EAX equal to 3. The preceding instructions
read `fs:[0x18]`, then offsets `0x30` and `0x10`, matching a linked CRT's
direct NT TEB/PEB/ProcessParameters access. API export availability does not
provide that NT memory layout on Win98. A bounded compatibility bridge is
being investigated separately; the application image and native Win98
thread/process structures remain unchanged in this preserved trial.

The quiescent post-run disk is SHA256
`9382b7b71868b42c49824257cc3cf2ce474dbf8ed06409bc6480aabe99af04c9`.
Independent readback confirms the official executable, current COM server
and guarded CORE.INI retain their frozen hashes. This actual application
trial uses the working stock VGA/OpROM path and provides no GOP graphics
driver acceptance. Windows clean shutdown was not established.

The separately preserved cold read trial
`build/native-npp-controls/cold-reopen-proof-20260930T1729/result.json`
passed six bounded checks. A fresh clone booted the unchanged prepared system,
then the official executable opened `C:\NPPLAB\NPPQA.TXT` directly. Original
screenshot 021 shows its real path, exact text, two lines and length 44.
Independent post-VM readback confirms all 44 bytes and the original hashes of
the application, COM server and CORE.INI. The quiescent cold-read disk is
`eb42f1eca995b130d3d9a5d0828cdd5cad78dbcad9b22c6d09fb75ae2b141e49`.
This proves cold saved-file reopen only. The harness stopped its own VM after
capture; clean application exit was not remeasured, and overall application
acceptance remains FAIL because of the preserved exit fault.
