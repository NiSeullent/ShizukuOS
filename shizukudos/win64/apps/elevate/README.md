# elevate and account commands

Managed Kernel64 account/elevation companion. `elevate ADMIN IMAGE [COMMAND]` authenticates in a masked dialog and starts a fresh elevated child through the kernel. `--login USER IMAGE` starts a normal account session, `--sandbox IMAGE` creates a low-integrity child, and `--status` shows the actual subject and backend status. Passwords are never command arguments. Each launch authenticates separately; there is no reusable elevation ticket.

Before accepting credentials, the dialog displays the selected account, operation,
executable and complete command line. The executable is the separate `IMAGE`
argument used by the loader; the first word of `COMMAND` does not identify that
executable. Ampersands display literally. ASCII/C1 controls, Unicode directional
controls and line/paragraph separators that could forge field labels or reorder
arguments are refused; normal Korean and Unicode text remains literal. Invalid
UTF-8, clipped account/command text or unavailable rendering
refuse the request. Authentication stays disabled until the full consent text has
been painted. Cancel, close and failed display issue no authentication request.
The entry buffer and retired display labels are cleared on every prompt exit;
the client clears its request after the kernel call.

Consent expires: the displayed request is valid for `SHZ_ELEVATE_CONSENT_MS`
(120 s, `flow.h`) measured with GetTickCount. A one-second USER timer and a
second check at acceptance enforce it, so a delayed timer cannot extend consent;
if the timer cannot be created the prompt refuses. Outcomes are distinct exit
codes: 0 started, 1 kernel refusal (wrong credential, lockout, non-admin or
image denied are one kernel status and are not distinguished), 2 usage,
3 cancelled, 4 expired, 5 not displayable, 6 inconsistent reply. Cancelled,
expired and undisplayable requests never reach the kernel. After a reported
launch the client re-queries its own subject from the kernel and requires that
the child holds a fresh session (elevation: high integrity administrator) that
the caller does not; otherwise it reports the child as untrusted (exit 6). The
child is already running at that point; this is a detection, not a rollback.

`sh shizukudos/win64/apps/elevate/host/run_host.sh` compiles the actual
main/prompt/consent/secret bodies (gcc, clang+ASan/UBSan) against host USER/GDI,
clock and IPC adapters and checks success, refusal, cancel, expiry (timer,
acceptance-time, tick wraparound), timer failure and inconsistent replies.

`python3 shizukudos/tests/run_elevate_consent_host.py` runs the literal client,
prompt, consent builder and secret-buffer code with GCC and Clang sanitizers.
USER/GDI, events and ASCII conversion are explicit host adapters; the IPC adapter
always refuses authentication. `--baseline-commit` pins old entry/UI sources to
demonstrate runtime assertion failures with the same fixture. These controls
verify client consent and cleanup, not credential validity or native GUI behavior.

Initial `--enroll USER` is only granted to the fixed kernel-launched enrollment program selected by the explicit development boot option `shz.accounts=setup`. Ordinary programs, including a manually launched copy of elevate.exe, cannot bootstrap enrollment. Only a high-integrity administrator may `--register USER`. The initial store is volatile and requires enrollment again after reboot; no persistent security guarantee is made.

This PE64 companion requires the updated Kernel64 runtime. It cannot execute directly under native Windows98. Native Windows98 authentication needs the NTW64 bridge plus protected credential UI and secret-storage integration. The masked dialog is not a verified secure desktop. Shared native Windows98 memory, firmware and device DMA remain outside this backend's process/profile gates. Do not describe this as full Windows UAC or NT account isolation.
