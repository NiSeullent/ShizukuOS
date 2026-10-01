# Native Windows 98 application runtime checkpoint

The unchanged official Notepad++ 8.9.8.1 now executes on genuine Windows 98
4.10.2222 with the Shizuku GOP driver. Under the separately native-proven
ordinary-desktop field interpreter it edits, saves a fresh 44-byte document,
reopens it in the same application, and exits through normal Alt+F4 with actual
application, helper and outer waiter exit zero. Its frozen 26-gate scoped review is
`build/shizukudos/csm/run-win98-gop-latest-npp-environment-v3-20260930T1748/native-gop-latest-npp-review.json`,
SHA256 `4969701e15e2170caa6927bdb9cd2c40a34367d3666d7487caa00f8170e1bfa5`.
The earlier unassisted exit trial remains **FAIL**; this scoped result requires
the field interpreter. Four unrelated first-chance exceptions were forwarded to
the OS, and three worker shutdown exits were FFFFFFFF; zero application exit
is not a claim that each worker completed successfully. The new GOP document was reopened in a separate cold boot, followed by
distinct keyboard editing and a fresh39-byte file save. The25-gate repeat
review is `run-win98-gop-latest-npp-cold-v3-20260930T1807/native-gop-latest-npp-cold-keyboard-review.json`,
SHA256 `e945062ad535c5e2b61f7ee39be91c308d1103b29ff3d44d0f5b2e3455d40175`.
An incorrect SaveAll shortcut first saved39B over the existing private NPPGOP;
the actual menu identified SaveAs CtrlAltS. The39B text was then saved to
NPEDGOP, and native SaveAs restored NPPGOP from the preserved NPPQA. Final
disk readback confirms both44-byte originals and distinct39-byte NPEDGOP.
The original parent disk and all earlier traces remain unchanged. Actual repeat
process/helper/waiter exits are zero with146armed/retired native threads. The previous stock-VGA trial did
independently reopen its original saved file after a cold boot. This checkpoint
does not claim Chromium, Supermium, VLC or VS Code execution.

The unchanged application is bound to SHA256
`986ffd50fb51e4b08737d1c47a4aca8e681adb628789228e5f538bfb954d2eb5`.
Its newly saved `C:\NPPLAB\NPPQA.TXT` contains exactly 44 bytes:

```text
Latest NPP 8.9.8.1 Windows98 Save As proof\r\n
```

The displayed escapes above identify the final CRLF bytes. Independent disk
readback gives SHA256
`ab32bfab872ffd7c8a0884e06b70432d7bef6c5ac463a7bfed33aca05c3ab95d`.
The frozen full-trial receipt is
`build/native-npp-controls/latest-npp-trial-20260930T1714/result.json`
(`f0ea413eaf74b72f1fd0d62c0283e357dc68dd90b66dfe7e52804a9c2b2f7003`).
Its separate cold-reopen receipt is
`build/native-npp-controls/cold-reopen-proof-20260930T1729/result.json`
(`1b387e4ac6091d28a7fa79c87d038b42cc5669156dd7d05ad41a0ad431b88e53`).
The latter proves the six recorded cold-read and preservation checks; it does
not supersede the original exit failure.

The independent PE32 loader and native TLS components have also executed in
actual Windows 98 GOP guests:

| Native scope | Actual result | Frozen receipt under `build/shizukudos/csm/` |
| --- | --- | --- |
| Classic mapped fixture, actual module base, real child and worker exit, failed-attach rollback | 30 semantic controls passed | `run-win98-gop-native-classic-v5-20260930T1650/native-classic-v5-review.json` |
| Native slot publication and compiler FS-based TLS on main and worker threads | 27 controls passed | `run-win98-gop-native-tls-v3-20260930T1642/native-tls-v3-review.json` |
| Closed initial mapped module graph, TLS callbacks, owned thread trampoline, module identity and cleanup | 40 checks passed, 37 distinct | `run-win98-gop-native-runtime-v6-20260930T1708/native-runtime-v6-review.json` |
| New compiler TLS template published to an already-created admitted worker while preserving original TLS | 43 controls passed | `run-win98-gop-native-tls-remote-20260930T1714/native-remote-tls-review.json` |

The corresponding receipt SHA256 values, in table order, are
`c463f1d191cad8f4d49ee6387a29e0738e33d0d6ece7cfdb6956250b76a3a1ba`,
`5560c7a331b416fc32c07710c74822a7339165e80c16b61104e7b2424e33bf7b`,
`952a65ad23552f6d82f0b1ec6fef29c735b3bd411a55b4e827a300de150d6959`,
and `d82c92b920cf3b2652e4909be6741ca7f9d04d2ee827d65bb8214abdc2a93cae`.
Each scoped review preserves the original runner receipt and separately binds
fresh guest logs, actual exit results and source identities. Earlier failed
fixture revisions remain available.

Portable C controls separately passed 329 TLS runtime checks and 235 remote
publication checks under AddressSanitizer and UndefinedBehaviorSanitizer.
Those host results establish bounded fault handling, not guest execution.
The remote native trial explicitly gates the existing worker's first access
to the new template. General dynamic module loading still needs a loader lock,
admitted-thread lifetime management, notification ordering and complete API
ingress handling. Threads entering through providers, COM, WinMM, USER hooks
and other callback facilities cannot be assumed to use the direct CreateThread
trampoline.

The latest application's exit fault occurs in an exact UCRT instruction chain
that reads `FS:18h`, then offset `30h`, and treats the result as an NT PEB.
On this actual Windows 98 build that pointer identifies the native process
database. The two layouts cannot be exchanged. The separate
`ntwin32/native_environment/` candidate interprets only the two validated field
loads through owned debugger events and an explicit desktop model. It keeps
the original executable, code, FS selector, TIB and process database intact;
the original shift, mask, return and application cleanup still execute.
Its nonzero owned v3 fixture has now executed on genuine Windows 98 GOP:
20 semantic fixture checks, six verifier and six secure-field events across
the actual main and worker threads, unchanged FS self/PDB/TLS pointers and
code, plus actual worker, child, helper and outer waiter exit zero. The frozen
31-gate scoped review is
`build/shizukudos/csm/run-win98-gop-native-environment-v3-20260930T1734/native-environment-v3-review.json`,
SHA256 `546d8dcb5ed60b3fe7c1b89113bc6500a75f98f592ae2da23dde4144ecc31cc9`.
The actual compiler-generated operations still execute after the interpreted
loads. The subsequent original NPP GOP GUI/exit trial passed its bounded
26-gate review above, including one actual secure-field event, 120 armed and
retired native threads and native application exit zero. Neither result claims
a general NT PEB implementation or patches the application binary or FS state.

Notepad++ currently uses the separately validated KernelEx and native API
providers for startup. It is not evidence that the independent PE32 loader can
already execute this application. Hardware GPU 3D acceleration, the remaining
latest applications and general hardware coverage remain incomplete.
