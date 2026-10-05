# Windows98 original-shell startup adapter (offline)

SPDX-License-Identifier: GPL-2.0-or-later

`shell_startup.py` prepares a **private candidate copy** of an installed
Windows98 FAT disk. Explorer stays the shell, and the original
USER/GDI/KERNEL userland stays as it is. The adapter never boots Windows, starts
a VM, writes the source media or touches a host registry.

## What it does

- **Inputs.** It takes explicit pinned local paths, all held under the existing
  `prepare_replacement.leased_inputs` read leases:
  - `--disk`: the private source disk, or the `replacement.img` from the
    default `shz.foundation=win98` route.
  - `--selector`: the `SHZTHEME.EXE` built by
    `ntwddm/win98/theme_selector/build.py` from `selector_win98.c` and
    `selector_core.c`.
  - Optionally, `--selector-build-receipt`: that build run's `result.json`.
  - Optionally, both `--appearance` (SHZAPPEAR.EXE) and `--theme-dll`
    (M98THEME.DLL).
- **Refusals.** It refuses the disk when any of these hold:
  - SYSTEM.INI `[boot] shell=` is not the original `Explorer.exe`.
  - `user.exe`, `gdi.exe` or `krnl386.exe` is overridden.
  - An original userland member is missing or has the wrong PE/NE/MZ header.
  - `C:\SHIZUKU` already exists.
  - WIN.INI `load=` or `run=` already names SHZDESK, SHZAPPR/SHZAPPEAR or
    SHZTHEME.
- **Writes to the candidate only.** It creates `C:\SHIZUKU\SHZTHEME.EXE`. When
  given, it also stages `SHZAPPR.EXE` and `M98THEME.DLL` with **no startup
  entry**.
- **Never changed.** WIN.INI, SYSTEM.INI, SYSTEM.DAT and USER.DAT. The readback
  check requires every original member to be byte-identical.
- **Never created.** No theme profile, no Run value and no palette change.

## Startup hook

The exact restore command is `C:\SHIZUKU\SHZTHEME.EXE /restore`.

- **Missing or invalid profile.** `shz_theme_restore()` fails before any palette
  write, writes no registry value, and exits 1 with an `OutputDebugStringA`
  diagnostic.
- **First selection.** This is a separate explicit action: run
  `C:\SHIZUKU\SHZTHEME.EXE` with no arguments. Only after a successful selection
  does the selector itself register its transactional, readback-checked Run
  value:
  - key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - value name: `ShizukuOSTheme` (`REG_SZ`)
  - data: `"C:\SHIZUKU\SHZTHEME.EXE" /restore`

  Its parser treats this quoted form and the unquoted form identically, as
  `/restore`.
- **Why WIN.INI `run=` is not used.** On the verified project route
  (`tools/theme_startup_trial.py`, SHZGBOOT), `run=` is an argument-free list of
  executables. Inserting the command there would start the first token without
  arguments, which opens the selector UI as a logon popup. It would also try to
  run `/restore` as a file. The adapter therefore leaves WIN.INI unchanged.
- **Pre-registering before first selection is root's job.** It needs a
  root-owned offline Windows98 USER.DAT writer that does readback, using the
  same key and value name with data `C:\SHIZUKU\SHZTHEME.EXE /restore`. No such
  writer exists in this tree. The receipt records this hook as
  `root_offline_hook.applied=false`.

## What counts as evidence

- **Executable hash.** Identity only.
- **`--selector-build-receipt`.** Binds the hash to a host build run. That run
  covers host tests, sanitizers and the OEM PE32 import gate. The receipt still
  says `native_win98_execution=not_tested`.
- **Static gate.** The adapter re-runs the selector owner's `native_gate()` on
  the staged bytes. This is a static check, not execution.

None of the following is established here:

- Windows98 boot, Explorer, selector or appearance execution
- palette persistence
- installation security
- ISO contents

M98THEME.DLL is an app-local provider. It does not style Explorer.

## Example

```
python3 integration/win98-shell/shell_startup.py \
  --disk PRIVATE.img --disk-sha256 <sha> \
  --selector build/win98-global-theme-selector/<run>/SHZTHEME.EXE --selector-sha256 <sha> \
  --selector-build-receipt build/win98-global-theme-selector/<run>/result.json \
  --selector-build-receipt-sha256 <sha> \
  --out build/<private-candidate> --copy-mode reflink \
  --copy-budget-bytes <n> --capture-budget-bytes <n>
```

Outputs must be fresh, private and Git-ignored. Never publish Microsoft media,
installed disks or candidate images.
