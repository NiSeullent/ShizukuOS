# Separate diagnostic supervisor

`NTWDRUN.EXE` is the original `native_runner.c` compiled with
`NTWRUN_DIAGNOSTIC`. Only four fixed name arrays differ: its own absolute path,
log and three probe/log names. The unchanged supervisor runs
`NTWPROBE.EXE`, then `NTWGPROB.EXE`, then `NTWVDIAG.EXE` from `C:\NTWLAB`.
The graphics probe therefore runs before a potential VxD loader failure.

The same Windows 98 identity check, exclusive fresh log, stale-child-log
preflight, absolute CreateProcess paths, full DWORD process exit recording,
120-second child wait and 5-second termination wait apply. A failed stop does
not become a stopped proof. The diagnostic runner uses `NTWDRUN.LOG`; the log
format retains `NTWRUN_VERSION=1` because the supervisor logic is shared.
Require its separately recorded zero process exit and every expected child log.
An unresponsive kernel/API still requires the external lab watchdog.

```sh
python3 -B platform/win98lab/build_native.py --diagnostic
python3 -B platform/win98lab/test_native_runner.py --diagnostic
```

Outputs live only in `platform/win98lab/build/diagnostic_runner/`, with separate
`build-result.json` and `test-result.json`. The second command also runs the
unchanged default host tests and builds the default PE into `default-regression/`.
If an old default binary/build receipt from the same compiler is present, its
SHA-256 must match exactly. Existing default artifacts/receipts are preserved.
Both variants undergo GCC, Clang and nonrecovering ASan/UBSan fault injection.
The diagnostic host model explicitly checks all three changed process/log names
and their order. It has no dependency on a built VxD or a runnable Windows child,
so this **host-only variant command is suitable for CI**. The pinned VxD
diagnostic builder itself is currently local-only; see
[`ntwrapper/vxd/DIAGNOSTIC.md`](../../ntwrapper/vxd/DIAGNOSTIC.md).

`run_diagnostic.bat` runs `C:\NTWLAB\NTWDRUN.EXE` and immediately tests
`ERRORLEVEL` in descending order. It records runner exit 0, 1, 2 or 3 in
`NTWDEXIT.TXT`; 4 and higher produce `unexpected`. Native child DWORD exits come
from the supervisor log, never COMMAND.COM inference. The batch also records
`GUESTVER.TXT`. Independent host tests interpret the bounded batch language and
check all 256 possible DOS exit values and rejected malformed branch layouts.
This is a script contract test, not actual COMMAND.COM execution evidence.

The separate media builder must include the new runner, diagnostic, original
DLL/provider and graphics probe, convert batch text to CRLF, and preserve the
previous CD and logs. Existing probe logs must be archived before a deliberate
new run, or the runner refuses to start children. Do not count this build or
host model as a successful native VxD load; actual guest collection is separate.
