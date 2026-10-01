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
