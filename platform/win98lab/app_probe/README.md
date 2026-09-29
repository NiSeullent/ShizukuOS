# Windows 98 Shizuku's Second Edition — raw Chromium launch observation

`NTWAPP.EXE` is an original diagnostic for a separately supplied application in
an isolated Windows 98 guest. It makes **no browser compatibility or page-rendering
success claim**. The source does not contain Chromium or Windows implementation
code, and the build does not download or run either product.

Fixed paths are `C:\NTWLAB\NTWAPP.EXE`, exclusive new `C:\NTWLAB\NTWAPP.LOG`,
and `C:\CHROMIUM\CHROME.EXE`. The child working directory is `C:\CHROMIUM`;
the mutable command line contains only the quoted executable path. There are no
browser feature flags, sandbox changes, app patches, inherited handles, or PATH
search. Chromium's ordinary profile inside this disposable guest is used.

`--cd-source` builds a separate fixed-path variant for `D:\CHROME\CHROME.EXE`
with working directory `D:\CHROME`. The complete application package must be
present on the hash-verified read-only CD. Copy only the observer and its batch
driver to `C:\NTWLAB`; logs and the ordinary profile remain writable in the guest.
This avoids copying the 722 MB current package through the guest's IDE stack.
The build receipt records the selected source/path; both modes have the same
observation and cleanup policy. A read-only application directory may itself
affect application behavior and must be recorded in native results.

The diagnostic requires OS-reported platform Win32Windows, version 4.10, and logs
the raw and low-word build. It requests `SetErrorMode(0x8001)` (critical/open-file
error boxes), records the previous mode, and restores it on every returning path
after the change. The child inherits the requested error mode. A zero old mode is
not an API failure. This reduces some system dialogs; it does not guarantee a
failed loader or GUI application cannot display/block on another dialog.

`CreateProcessA` is called with an explicit application path; its error is saved
immediately before any logging API. On success the original process/thread
handles, PID and TID are recorded. Up to 40 half-second waits over approximately
20 seconds sample top-level windows belonging to that PID, including ownership,
visibility, class and title. ANSI bytes are hex encoded to preserve Korean/code
page bytes and prevent newline injection. Class/title lengths are bounded; an
at-cap field explicitly records possible truncation. Empty title and failed API
returns remain distinguishable by the raw return and cleared-then-read last error,
to the extent Windows 98 defines that API's last-error behavior.

Each enumeration scans at most 256 windows and records at most eight owned ones.
Counts are observations, not counts of distinct windows. Foreign windows are
filtered before reading title/class. On cleanup an immediate PID recheck precedes
`PostMessageA(WM_CLOSE)` to owned windows, followed by a five-second grace wait.
If the original process is still not observed stopped, only its retained process
handle is passed to `TerminateProcess`, followed by a five-second confirmation
wait. Return values/errors and the full DWORD child exit code are logged. Both
owned handles are closed even after earlier failure, then the error mode is
restored. Failed log writes/flushes trigger cleanup and a nonzero runner exit;
no further log writes are attempted once logging fails.

This is process-handle ownership, not a Win9x job object. Descendant processes and
their windows are **untracked**; no whole-browser shutdown claim follows. Window
metadata and HWND ownership checks are snapshots and cannot eliminate concurrent
window destruction/reuse. Only the captured original process handle authorizes
forced termination. A synchronous native API or GUI loader can block beyond the
internal timing policy; the outer guest harness must enforce a **600-second
watchdog** and stop/discard the isolated trial if needed. Frozen/backward tick
counts cannot make the observation loop unbounded; a normal 32-bit tick wrap is
handled by unsigned subtraction.

Exit 0 means the diagnostic recorded a completed observation, including a
faithfully recorded launch failure. It never means Chromium ran successfully.
Exit 1 means OS/precondition, process-stop, child-exit query or handle cleanup was
incomplete; exit 2 is wrong tool location or log-create refusal; exit 3 is log I/O
or final log-close failure. `END=BEFORE_LOG_CLOSE` explicitly precedes the final
close, so capture the runner process exit separately. `PAGE_FUNCTIONALITY=UNTESTED`
and `BROWSER_COMPATIBILITY=UNVERIFIED` are never promoted by this tool. Complete
native evidence also requires independently bound application/tool/media hashes,
guest identity, actual logs, screenshots and stopped-guest provenance.

Host-only commands from the repository root:

```text
python3 -B platform/win98lab/app_probe/test.py
python3 -B platform/win98lab/app_probe/build.py
python3 -B platform/win98lab/app_probe/test.py --cd-source
python3 -B platform/win98lab/app_probe/build.py --cd-source
```

Generated files go only beneath the existing private-RAM-backed
`platform/win98lab/build/native_runner/app_probe/disk/` or `app_probe/cd/`
(or the explicit `--output` directory). Strict GCC/Clang and
nonrecovering ASan/UBSan run a synthetic WinAPI fault model. MinGW supplies public
interface declarations/import thunks, with no CRT or KernelEx linkage. The final
PE is i486/PE32 console Windows 4.10 with an exact KERNEL32/USER32 import allowlist.
Static imports and host models do not establish actual Windows 98 execution.

Primary API/provenance references (interface facts only, no sample copied):

* [Microsoft archived MSDN SetErrorMode](https://techshelps.github.io/MSDN/WINBASE/devdoc/live/pdwbase/errors_38px.htm): Windows 95-or-later support, flags and previous-mode return. Current [Microsoft SetErrorMode reference](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-seterrormode) documents process inheritance and flag meanings.
* [Microsoft KB Q175030, archived original article](https://www.betaarchive.com/wiki/index.php/Microsoft_KB_Archive/175030): Windows 95 top-level application enumeration with EnumWindows and title retrieval. [Microsoft's original 2002 explanation](https://learn.microsoft.com/en-us/archive/msdn-magazine/2002/july/c-q-a-get-the-main-window-get-exe-name) identifies PID-based top-level-window matching with GetWindowThreadProcessId.
* [Microsoft GetWindowTextA](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowtexta), [GetClassNameA](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getclassnamea), [IsWindowVisible](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-iswindowvisible), [PostMessageA](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postmessagea): buffer, ownership/visibility and asynchronous-post contracts. Current support tables are not retroactive Win98 execution evidence.
* [Microsoft CreateProcessA](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa), [WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject), [GetExitCodeProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess), [TerminateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess): process handles, bounded waits, full exit code and asynchronous termination. The project’s original native runner already uses these classic imports; this diagnostic still requires its own actual guest trial.
