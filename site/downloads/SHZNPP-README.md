# Latest Notepad++ compatibility preview

This package contains the exact open-source compatibility binaries used by the
successful Windows 98 SE Korean / UEFI force-GOP Notepad++ 8.9.8.1 experiments.
The official editor displayed a real window, edited and saved text, reopened it,
and exited normally. A second cold boot reopened the prior 44-byte document and
saved a different 39-byte document. This is a developer preview, with manual
prerequisite setup; a fresh-machine installation of this ZIP is not yet tested.

The separate NTWPENV launcher is required. Ordinary unassisted editor exit
previously crashed and is not certified. The launcher interprets two exact UCRT
process-field reads using native Windows 98 debugging events. The application
file, loaded instructions, native FS selector, TIB and PDB remain unchanged.
It accepts only the hash-bound editor executable, not arbitrary future releases.
GPU 3D acceleration, other apps and clean Windows shutdown are separate goals.

## Contents and prerequisites

The ZIP contains twelve runtime binaries, one diagnostic fixture, their full
project sources, the generated launcher profile, pinned upstream KernelEx theme
source archive, build recipes, configuration route plan and license notices.
`MANIFEST.json` hashes every member except itself. `EVIDENCE.json` identifies the
native acceptance receipts without including a licensed disk or OS binaries.

Obtain your own Windows 98 SE installation and Microsoft Unicode Layer. Install
[official KernelEx 4.5.2](https://sourceforge.net/projects/kernelex/files/KernelEx/4.5.2/)
on a disposable copy, preserving its default disabled setting. The experiment
used the Korean OEM Windows 98 SE environment; other editions have not been
accepted. Install the separately supplied Shizuku GOP driver with its matching
firmware boot path if testing GOP output.

Download the **x86 portable ZIP** from the
[official Notepad++ 8.9.8.1 release](https://github.com/notepad-plus-plus/notepad-plus-plus/releases/tag/v8.9.8.1).
The publisher ZIP SHA-256 is
`65d3435b5dcbefde47c401a2666132138e76a2b62e189ad4ffe568581b6adfd2`.
The untouched editor executable must be 7,752,688 bytes with SHA-256
`986ffd50fb51e4b08737d1c47a4aca8e681adb628789228e5f538bfb954d2eb5`.
Preserve the portable configuration and support files. The trial placed the
editor at `C:\NPPLAB\APP\NPP.EXE`; the filename alone is insufficient for acceptance.

## Manual setup in the disposable installation

1. Back up the existing KernelEx directory, CORE.INI and registry before changes.
   Copy the six `native/KernelEx/M98*.DLL` providers and `UXTNEW.DLL` into the
   existing KernelEx directory. Keep its original `UXTHEME.DLL`.
2. Read the actual installed CORE.INI back to a host workspace. Use
   `source/tools/prepare_npp_core.py` and `config/npp-routes.json`, providing the
   SHA-256 of both inputs, to create a new candidate under `source/build/`.
   Review its receipt and differences before installation. The merger preserves
   unrelated profiles and refuses conflicting routes. `CORE.EXAMPLE.INI` is the
   accepted trial configuration for comparison; do not overwrite another
   installation with that example. Retain the original as a backup.
3. Copy `native/app-local/DBGHELP.DLL`, `DWMAPI.DLL` and `BCRYPT.DLL` next to the
   editor. Put `native/FDLG/M98FDLG.DLL` at `C:\FDLG\M98FDLG.DLL` and register
   it with the installation's own `regsvr32`. Its registration refuses a
   different existing FileSaveDialog server. The backend uses the real Windows
   98 Save As dialog; filesystem paths must round-trip through the native codepage.
4. In `HKEY_LOCAL_MACHINE\Software\KernelEx\KnownDLLs`, preserve the existing
   `UXTHEME` value, require it to be exactly `UXTHEME.DLL`, and change only that
   value to `UXTNEW.DLL`. The corresponding guarded helper source is included.
   If the original value differs, stop this preview setup without overwriting it.
5. Enable KernelEx's Windows XP profile only for the exact editor path. The
   trial's `AppSettings\Configs` value was `WINXP` and its corresponding
   `AppSettings\Flags` DWORD was zero. Preserve existing settings and avoid
   default-profile or wildcard changes. The exact-path guarded helper source is
   provided for review and rebuilding; setup helper executables are not included.
6. Put the launcher and diagnostic fixture from `native/VXDLAB/` into
   `C:\VXDLAB\`. Cold boot, then run the fixture with a fresh log path:

   ```text
   C:\VXDLAB\NTWPENV.EXE --fixture --log C:\VXDLAB\ENVDBG.LOG C:\VXDLAB\ENVFIX.EXE
   ```

   Require the actual twenty fixture controls, main/worker hardware-breakpoint
   events and child exit zero. A timeout or termination is a failed test.
7. Start the unchanged editor through the launcher, again using a fresh log:

   ```text
   C:\VXDLAB\NTWPENV.EXE --npp --log C:\VXDLAB\ENVNPP.LOG C:\NPPLAB\APP\NPP.EXE
   ```

   Confirm editing, native Save As, exact saved bytes, reopening and normal
   editor exit. In this editor, **Save As is Ctrl+Alt+S**; Ctrl+Shift+S is Save All.
   The launcher has a five-minute experiment deadline, not a production session
   policy. An existing debugger/breakpoint or unknown executable profile is refused.

## Corresponding source and rebuilding

`source/` preserves the project file layout. The original provider and COM
builders, freestanding support, all included project headers and OEM public
export-name inventory are included. `upstream/KernelEx-31cdfc3560fc.tar.gz`
is the full corresponding upstream theme source archive, SHA-256
`6f9823e41bf9f48442f5926fd59a0246d4a1865783c6feed01b082980ee8cbbf`.
Place the archive and its extracted tree under a private provider input directory
as described by `source/tools/build_npp_prerequisites.py`; that builder does not
install or execute a guest component. GCC 15.1.1, Clang 21.1.8, MinGW headers and
Python pefile were used. These tools are not bundled.

`BUILD-RECIPES.json` records the actual compile/link arguments with workspace
paths replaced by `$SOURCE_ROOT`. The generated `profiles.h` is included next to
the frozen native-environment source. It permits rebuilding the launcher without
redistributing the Microsoft DLL used to establish its DebugBreak profile. The
original profile generator requires your licensed matching DLL and official
editor input. Rebuilding can change linker-selected image bases and file hashes;
deterministic ZIP assembly is not a claim of identical compiler output.

Project changes are GPL-2.0-only; Wine/KernelEx derived components retain their
individual notices and LGPL/GPL terms. LodePNG uses its included license. GCC
runtime exception and MinGW notices are included. The ZIP contains no Windows
files, UNICOWS installer, editor binary, application archive or VM disk.
