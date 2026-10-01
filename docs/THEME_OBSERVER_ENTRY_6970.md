# Native observer startup diagnostics

The v7 private Windows 98 trial reached the desktop and exited QEMU normally.
Readback matched all three injected binaries, and the stopped guest's Run
history contained the complete expected command and fresh nonce. No theme
window was observed and neither `THOBS.LOG` nor `THEME.LOG` existed. This
narrows the next measurement to executable entry and the observer's pre-log
stages; it does not establish that the observer executed.

`NTTHRUN.EXE` now creates `C:\VXDLAB\THENTRY.LOG` with `CREATE_NEW` before
calling its existing strict nonce parser. The independent diagnostic records
entry reached, bounded `GetCommandLineA` and `GetModuleFileNameA` return/error
values, strict-parser and local-path decisions, fresh `THOBS.LOG` creation,
and the observer's requested return code. It explicitly says that its own
external exit has not been observed. Diagnostic stages, raw command capture,
pin validity and requested returns are not native theme acceptance.

The fourth staged input, `C:\VXDLAB\THNONCE.TXT`, contains exactly the fresh
32-byte lower-case hexadecimal trial challenge. The diagnostic reads at most
33 bytes and closes its own handle. It logs a raw command only when it names
this probe (or contains only its argument), has no additional arguments, and
matches that staged challenge. Raw input scanning stops at 384 bytes. Other
commands and module paths are redacted. The argument-only and leading-space
forms are diagnostic observations; the strict executable-token nonce parser
has not been relaxed. The pin is not used to determine logical child success.

Native `MessageBoxA` reports pre-log failures and unavailable/incomplete entry
file evidence. This is an OEM USER32 import checked against the retained
Windows 98 export corpus. The entry log uses separate handles and write/error
state, never inherits handles into a child, never overwrites a stale log, and
does not replace the original `THOBS` actual-child-exit contract. Diagnostic
failures remain separate from the original observer result and cannot turn
an original failure into success. Flush/close failures are visible through
the diagnostic message box; the log does not claim that its own close or
external process exit was observed.

The original sources were preserved under
`ntwddm/win98/theme_probe/build/observer-entry-source-before-20261001` with a
hash receipt. The source-bound new build is
`ntwddm/win98/theme_probe/build/20261001T085330Z-78489160/result.json`, SHA-256
`d59f06ee71be2d1e16163a53ee419aa26ee7a87f2d1d4ee6da1fcd385512e993`.
It passed 18,383 observer lifecycle/privacy/resource assertions normally and
under ASan/UBSan, 312 shared-core assertions in both modes, the OEM PE32 gate,
and the unchanged 19 strict-verifier tests. These are host/static results.

The private staging manifest is
`/root/Win98-Modern-boot/build/theme-entry6970-20261001T085527Z/guest-files.json`,
SHA-256 `179fc543d2e11c04af9152c71ccbef7b0a89f3f7e8aafea64ce18d9615fdfe68`.
It contains `M98THEME.DLL`, `NTTHGUI.EXE`, `NTTHRUN.EXE`, and `THNONCE.TXT`,
with `THEME.LOG`, `THOBS.LOG`, and `THENTRY.LOG` absent output requirements.
The new trial's nonce is `9c7517e6e5d687720666ae236d25ca6a`.

The canonical GUI text helper rejects `=`. Use separate, sequential owned
GUI actions: select the reviewed Run input, type
`C:\VXDLAB\NTTHRUN.EXE --nonce`, send a QMP `equal` key and the unchanged
nonce, then press Enter after the input has settled. Review actual captures;
accepted QMP input and Run history prove input delivery only. After the
observer's bounded wait, stop the owned VM, read back all four staged inputs
and the three fresh logs, and apply the existing strict child/theme verifier
only with observed child-exit evidence. Preserve all failures and maintain
the unchanged 20 GiB volume reserve and 256 MiB private COW quota.

The v8 consumer acquired the native lane but aborted before QEMU because a
peer's guarded source review held the cold-v3 source open. No GUI launch was
attempted, so this failure supplies no executable-entry evidence. Its original
staging and failure receipt remain preserved.

The v9 staging manifest reuses the identical source-bound build without
recompiling and selects a new 32-byte diagnostic challenge:
`/root/Win98-Modern-boot/build/theme-entry6970-v9-20261001T090123Z/guest-files.json`,
SHA-256 `847d315d2e530565208d2af6b0ddee47d6d9ccecbfcbedaa2f7dc35f86c783ec`.
Its nonce is `56e64a365035624734e9e4154e255d6a`; staging files are read-only.
The candidate base is the peer's successful
`run-win98-gop-theme-5abe-native-v1`, whose stopped raw post-run SHA-256 is
`828080b6bc04dfdeafaa8cded0e3e5c7c6698bb38b6c21d094b5cf38ed1e5b05`.
The consumer must repeat all source-hash, unopened-source, free-space and
private-COW guards before creating a new clone. These preparation facts are
separate from the still-required v9 guest measurement.

V9 has now passed the strict native-contract verifier. Fresh stopped-guest
readbacks match all four input hashes and all three canonical output hashes.
`THOBS.LOG` identifies actual Windows 98 SE (platform 1, 4.10, build 2222),
normal owned-child wait and actual exit 0, no termination, and closed child
handles. `THEME.LOG` records 75 Classic paints, 39 Modern paints, three
selections, a local provider, and checked cleanup. `THENTRY.LOG` confirms
the exact quoted full command, module path and original strict parser; no
parser relaxation is warranted. The original/archive/base/source guards and
final private COW guard passed. The native verifier and visual receipt are
under `build/theme-native-runs/win98-gop-theme-6970-20261001-v9/`.

Screens 076 and 082 visibly show the Modern and Classic labels/palettes.
Some frames contain incomplete repaint operations, and the C key's effect
cannot be isolated from automatic switching. The v9 visual receipt preserves
these limits; native contract success is not complete-window or OS-wide theme
acceptance. The probe's periodic 250 ms invalidation caused repeated full
clear/paint operations during capture.

For v10, only that periodic invalidation and its timestamp were removed.
Initial `UpdateWindow`, selection-triggered invalidation, C/M controls,
automatic switches at 10/20 seconds and close at 30 seconds are unchanged.
The fresh source-bound build is
`ntwddm/win98/theme_probe/build/20261001T092131Z-cb51f3e5/result.json`, SHA-256
`73e0f72c555121d96662e7f8bd345b37cb6622395f31b4ca6d309b97121c19ac`;
the required normal/sanitizer host checks and OEM PE gates passed. The v10
private manifest is
`/root/Win98-Modern-boot/build/theme-entry6970-v10-20261001T092354Z/guest-files.json`,
SHA-256 `c6d0be1e5c0c0e6056f4b538a4912a3ae60f8daa629c73358fe11e2da58e380a`.
Its fresh nonce is `5135c64f86c95b322b19494025ca8c18`. V10 still requires a
real private guest trial, stable full-window review and fresh strict readback.
