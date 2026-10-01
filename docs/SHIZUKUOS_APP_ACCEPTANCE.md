# Latest application acceptance

All current application functionality remains unverified. The adjacent JSON
matrix preserves the audited observations and concrete workflows needed for
each acceptance decision. Its release versions were observed on 2026-10-01;
check official upstream metadata again when freezing a new trial.

The target is actual Windows 98 booting through ShizukuDOS as the MS-DOS
replacement. Kernel32, Kernel64, Supervisor and WDDM must serve that Windows 98
path. A standalone Kernel64 test or a Windows 98 control boot through Microsoft
IO.SYS has a separate evidence scope.

| Application | Retained actual evidence | Next functional acceptance |
| --- | --- | --- |
| Legcord 1.3.0 | Standalone Kernel64 displays setup step 2 of 5; timeout, no normal app exit | Finish setup, interactive Discord workflows, saved profile, normal exit/relaunch and cold boot |
| Signal 8.28.0 | No actual trial input or execution in the inspected application roots | Current package/native dependencies, installation, database and UI; an authorized isolated linked-device fixture for messaging/calls |
| LibreOffice 26.8.0 | Older standalone image fails loading `SetSearchPathMode`; latest source contains the API | Freeze the updated image; Writer/Calc/Impress editing, ODF and Microsoft-format saves, PDF readback, relaunch and cold boot |
| Firefox 157.0 | Older standalone image fails loading `OpenProcessToken`; latest source contains the API | Freeze the updated image; interactive navigation, current web tests, downloads, profile and restart |
| Chromium | Standalone headless local JavaScript/DOM result and normal exit; GUI still fails | Correctly identified current input, actual Windows 98 interactive browser and graphics/consumer TLS tests |
| Notepad++ 8.9.8.1 | Actual Microsoft-DOS Windows 98 control edits/saves; older 44-byte file cold-reopens | New 39-byte file cold-reopen, unassisted exit, then repeat on the replacement target |
| Code, VLC, Steam and other claimed apps | Individual static or partial observations; no broad compatibility pass | Current official inputs, real editing/playback/game workflows, saved output and restart per claimed function |

Each new run must bind the official input, source commit, runtime image, boot
path and raw outputs. Verify installation or the explicit portable layout,
interactive UI, meaningful functions, normal app/descendant exit, independent
flushed-file readback, reopen and cold boot. Report every tested function and
failure; avoid deriving a compatibility percentage from imports or a window.

For browser and network claims, exercise TLS 1.3 through the actual consuming
application stack, including trusted-host success and wrong-host, expired and
untrusted-certificate rejection. WebGL/WebGPU claims require actual backend
creation and rendered/readback output. A diagnostic GPU-disabled launch cannot
establish those functions.

Keep test files isolated and preserve historical failures. External messaging,
calls and account actions require an explicitly authorized test fixture; this
audit sends nothing. Offline Office, browser, editor and media fixtures can
proceed independently. No private credentials, original Windows media,
application packages or generated runtime binaries are included in this source
handoff. Final ISO distribution remains at `https://m98.nyase.kr`.
