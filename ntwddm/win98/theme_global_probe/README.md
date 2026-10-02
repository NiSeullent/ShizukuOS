# Independent native Win98 global-theme observer

`observer.c` is a source-only ANSI Win32 companion for the native selector at
`C:\VXDLAB\SHZTHEME.EXE`. It uses a no-CRT `mainCRTStartup` entry, the legacy
25-color USER32 contract, and KERNEL32, USER32, GDI32 and ADVAPI32 APIs. It does
not link selector code, change system colors, write registry values, send theme
commands, close the selector, terminate a process, or access a network.

The guest observer may create its own two log files, independent witness
window and standard buttons, and its own exact quoted no-argument selector
child. `python3 -B ntwddm/win98/theme_global_probe/build.py` performs only the
bounded compile and native import-inventory checks; it never launches a guest.
It requires the unchanged 20 GiB reserve plus its full 8 MiB output budget,
retains each unique build receipt, freezes source hashes, and uses the shared
PE gate's observer role to reject registry/color setters and dynamic resolvers.

The actual 2026-10-01 build passed with `-Werror`, i486 PE32 GUI/OS 4.10,
usable HIGHLOW relocations and 47 OEM native imports. Its immutable receipt is
`build/win98-global-theme-observer/20261001T164450Z-89a8a48a/result.json`, SHA256
`96c0b05de65224b6a0cfe82c5d350b2232a3023c4f1034295ac560a1799e7019`.
`SHZOBS.EXE` is 37,208 bytes, SHA256
`2d48d00faaddbe70e6c6f51c520e9ce49752071ac20a3f16b3fcde955e75ee35`.
The build does not establish native execution, actual observer exit, visible
output or either cold boot. The separate `tools/global_theme_trial.py` adapter
must retain those incomplete gates until independent runtime evidence exists.

The subsequent source-bound PID build passed on 2026-10-01 with 48 OEM imports
and the shared gate's 12 resource/import regression tests. The immutable receipt
is `build/win98-global-theme-observer/20261001T172441Z-8d392a9f/result.json`,
SHA256 `2a9033a089f2121975b6a80d5b40b02c48d8239dacb6bc0d789fc3293fad71b1`.
Its executable is 37,934 bytes, SHA256
`b8f79529dceb0fb8ae31d0d51bf96ce9fbc1b269a42374ea8aa02b1fd088f2a4`.
Both phase logs now record `OBSERVER_PID` immediately after `PHASE`. The native
startup parent in `../theme_global_startup/` owns this process and reports its
actual wait and full exit code. The v2 adapter correlates both PID records;
the observer's own completion line alone still cannot establish its exit.
The parent's own external exit and the automatic Run process's external exit
remain separately unobserved. New sources require new build receipts and a
fresh plan; retain both historical binaries and the failed v1 trial.

After the shared PE gate was tightened to reject duplicate import descriptors,
the current source-bound observer build passed all 13 gate/resource regressions
with the identical 37,934-byte PID executable. Receipt:
`build/win98-global-theme-observer/20261001T173344Z-0b39a3e9/result.json`, SHA256
`3dac28fe33b7ac52820b3376151ed843271befa6fe3143350498a122da7aa69f`.
The import totals here are recomputed from the actual receipt lists:
ADVAPI32 3, GDI32 1, KERNEL32 17, USER32 27. Earlier prose totals of 46/47 were
off by one; the immutable receipts and executable hashes are unchanged.

## Fixed input and freshness

The host must create `C:\VXDLAB\SHZCASE.TXT` offline. Its complete content is
exactly 60 ASCII bytes, with CRLF after each line and no BOM, trailing space,
NUL or extra bytes:

```text
SHZGCASE1
nonce=0123456789abcdef0123456789abcdef
phase=1
```

The example nonce must be replaced with a fresh 32-character lowercase hex
nonce for each new private disk trial. Phase 2 changes only `phase=1` to
`phase=2` on the same private COW disk and keeps that nonce. A fresh phase-1 disk
must have neither `Profile` at `HKCU\Software\ShizukuOS\Theme` nor
`ShizukuOSTheme` at the HKCU Run key. Both logs must initially be absent.

Phase 1 creates `C:\VXDLAB\SHZGLOB1.LOG` with `CREATE_NEW`; phase 2 similarly
creates `SHZGLOB2.LOG`. Neither can overwrite an existing file. Each log has a
32 KiB hard write limit. The case file and phase-1 log are read through fixed
paths, bounded lengths and handles that disallow concurrent write sharing.
Phase 2 requires the phase-1 nonce, original 25 colors, final 224-byte profile,
complete sequence, and observed zero child exit. The host must additionally
bind the complete phase-1 log digest and real observer exit; a self-written
completion line cannot authenticate them.
Phase 2 also requires the phase-1 post-exit final-readback fields and verifies
their actual ShizukuOS colors, complete profile metadata and exact Run bytes.

## Actual guest sequence

Launch `SHZOBS.EXE` without arguments, preferably through a bounded native
startup entry. Do not also start the selector from WIN.INI: the observer must
launch and own the GUI child it observes. The existing HKCU `/restore` entry
is permitted in the second cold epoch and is not a GUI child of the observer.

In phase 1 the observer records the native OS identity, initial 25 colors,
profile/Run absence and the independent witness background pixel. It launches
exactly `"C:\VXDLAB\SHZTHEME.EXE"`, checks the owned process window class
`ShizukuOSThemeSelector`, and checks visible, enabled control IDs 101 and 102.
The real user or host QMP input must select ShizukuOS, Classic, then ShizukuOS,
waiting for the witness title to announce the next action. The observer polls
real system colors and native HKCU values. Each accepted transition needs the
independently decoded fixed profile, unchanged original baseline, exact Run
string `"C:\VXDLAB\SHZTHEME.EXE" /restore`, a new cross-process
`WM_SYSCOLORCHANGE`, repaint of the unrelated witness, and a native `GetPixel`
background sample equal to `GetSysColor(COLOR_BTNFACE)`. The selector must then
be closed normally by user/QMP. The observer waits on its owned process handle
and records its actual exit code; zero is mandatory.
After that actual zero exit, it performs another stable full read of all
25 system colors, Profile and Run. The final state must still be ShizukuOS;
an extra Classic choice after the accepted last transition invalidates the
trial. The final profile is recorded only after this post-exit check.

Power off the first guest, change only the case phase offline, then cold-start
the same pinned private disk. Before launching any selector child or accepting
any user action, phase 2 waits up to 30 seconds for the saved ShizukuOS profile,
exact Run value and all 25 actual system colors to match the phase-1 saved
state. The Run restoration process has no observer-owned handle, so its
external exit is explicitly `NOT_OBSERVED_NO_PROCESS_HANDLE`. After this
automatic restoration check, the observer launches its own GUI child, requires
a real Classic return with broadcast and witness pixel evidence, and waits
for normal zero child exit.
It then independently repeats the full stable readback and requires Classic
with the original baseline. An extra ShizukuOS choice before close cannot
escape this final check. No additional color-change notification is required
after the child has exited.

There is a 90-second deadline for each user transition, 15 seconds for child
GUI readiness and 60 seconds for normal close. Disabled selector buttons,
unequal consecutive snapshots, palette/persistence differences and pending
broadcast/repaint share one latched two-second deadline per stage. Button
ownership, class, visibility and nonoverlap remain hard invariants; enabled
buttons are required when a transition is completed. The deadline starts with
the first observed in-progress condition, never resets on return to old
values, and is checked before accepting settled evidence. An expired stage
cannot complete. Post-exit unstable reads also have a latched two-second
deadline. These pending states never count as evidence. A
missing phase, wrong nonce, stale log, preexisting profile, invalid profile,
wrong palette, changed baseline, unexpected sequence, blocked or overlapping
witness, missing notification/pixel, timeout, early/nonzero child exit or log
failure invalidates the trial. A failed observer leaves a still-running child
alone and closes its own handles; it never kills that child.

After `CHILD_EXIT_OBSERVED=1` and `CHILD_EXIT_CODE=0`, both phases emit exactly
one final readback in this order: `FINAL_READBACK=AFTER_NORMAL_CHILD_EXIT`,
`FINAL_STYLE` (1 in phase 1; 0 in phase 2), `FINAL_COLORS` (200 lowercase hex
characters), `FINAL_PROFILE_TYPE=3`, `FINAL_PROFILE_BYTES=224`, `FINAL_PROFILE`
(448 hex characters), `FINAL_RUN_TYPE=1`, `FINAL_RUN_BYTES=34`, and
`FINAL_RUN_RAW` (68 hex characters including the terminating NUL). The
completion footer follows only when those native values match the expected
final state. A host validator must require and independently decode these
post-exit records as well as the earlier transition records.

## Host validation and rollback remain required

Neither log contains a standalone `PASS`. `EVIDENCE_COMPLETE_REQUIRES_EXTERNAL_EXIT=1`
means only the specified observations were collected before final log
flush/close. An actual observer zero exit, complete immutable logs, source and
binary hashes, native OEM import gates, two distinct cold QEMU epochs, exact
same pinned COW identity, protected base/media hashes, all resource guards and
no-network guest configuration must be independently checked by the parent
adapter. Missing evidence or any partial sequence must fail closed. GetVersionEx
4.10/Win9x checks record guest identity; they alone cannot prove that the guest
is authentic OEM Win98 or that a ShizDOS replacement booted.

The parent adapter must preserve the protected base and original installation
media, use one private COW disk for both epochs, maintain the existing 20 GiB
free-space reserve, 256 MiB exclusive COW allocation ceiling and 16 MiB
aggregate output ceiling across its exact four output roots, with only the
pinned private COW excluded. Stage/extract only fixed bounded inputs and logs.
Stop the private guest and discard that trial disk for rollback. The final
Classic choice is a witnessed return to its recorded palette, not a guarantee
that every external desktop preference was unchanged.
