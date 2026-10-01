# Native Winsock prerequisite for the current Windows Steam lane

`steam_win9x_socket_probe.c` is an independent GPL-2.0-only x86 diagnostic using
the actual Win98 SE `WSOCK32.DLL` TCP implementation. It supplies a diagnostic
baseline for a future Win98-hosted current 64-bit Windows Steam runtime. It
contains no Steam executable, authentication, update transport, TLS, socket
provider, AcceptEx replacement or remote endpoint. Passing this prerequisite
cannot establish Steam functionality or equivalence with a 64-bit provider.

The existing `ntwin32/steam_socket/` directory remains owned by another session.
Its completed parser reads explicitly identified Wine AcceptEx buffer layout;
it does not supply actual socket operations. This probe uses ordinary genuine
Winsock calls and does not modify or integrate that parser. AcceptEx, ConnectEx,
overlapped I/O, IOCP, cancellation and TLS remain separate runtime requirements.
The current Windows client and helper dependency closure also remain unverified.

## Native operations

The executable requires the exact path `C:\GOPLAB\SPROB.EXE`, one fresh ASCII
nonce of 16 to 80 letters/digits/hyphens/underscores, and a previously absent
`C:\GOPLAB\SPROB.LOG`. It reads the real operating-system version and refuses
anything except platform 1 / version 4.10 / low build 2222. This readback is one
process observation, requiring independently established Win98 IO.SYS/GOP boot
and module provenance; it is not proof against a spoofing compatibility layer.
Each checkpoint opens, flushes and closes its native file handle so a stopped
FAT guest does not retain an empty open-stream length. CREATE_NEW refuses an
old log; the parent must additionally bind a never-reused nonce to the trial.

The program requests Winsock 1.1 and checks the negotiated version. It then:

- Creates a nonblocking listener bound exclusively to IPv4 `127.0.0.1` with an
  ephemeral port, checking the returned bound address and native port.
- Requires empty `accept` to report `WSAEWOULDBLOCK` and zero-time `select` to
  report no readable listener.
- Connects a nonblocking local client, records whether connection completed
  immediately or initially reported `WSAEWOULDBLOCK`, and checks write readiness
  plus `SO_ERROR=0` before accepting.
- Checks the accepted peer and client peer against the actual local sockets,
  explicitly makes the accepted socket nonblocking, closes the listener, and
  checks empty `recv`/read readiness.
- Sends nonce-bearing payload with embedded zero, 0xff and 0x7f bytes in both
  directions, handling real partial send/receive and would-block readiness.
- Checks client send shutdown, `WSAESHUTDOWN`, readable server EOF (`recv=0`),
  continued server-to-client data after that half-close, then opposite EOF.
- Closes both sockets, checks `WSAENOTSOCK` for a saved closed handle, balances
  `WSACleanup`, and requires an unmatched cleanup to report `WSANOTINITIALISED`.

Every readiness wait shares one wrap-safe native 30-second deadline, which also
includes checkpoint time. The source creates no thread or child process. Every
error path releases only sockets and Winsock startup owned by this invocation;
the final checkpoint reports both cleanup and prerequisite completion. Actual
process exit after CRT teardown must be established by the parent, separately
from the program's last `exit=0` checkpoint. Log text alone cannot establish an
authentic executable, guest, or socket implementation.

`steam_win9x_socket_probe_verify.py --log STOPPED_SPROB.LOG --nonce FRESH_TRIAL_NONCE`
checks a bounded stopped log's complete checkpoints, unique keys, real error
transition values and nonce-bearing payload length. Its result always leaves
native execution, independent OS/executable provenance, post-CRT process exit
and Steam false. Six host rejection controls in `steam_win9x_socket_probe_test.py`
use authored synthetic text to exercise these refusal boundaries; they never
call Winsock or supply a native success receipt.

## Bounded build and integration

From `/root/Win98-Modern-boot`, choose a new private directory for each build:

```text
python3 -B tools/modern_apps/steam_win9x_socket_probe_build.py --syntax-only --output build/steam-socket-prerequisite-83bd/syntax-v1
python3 -B tools/modern_apps/steam_win9x_socket_probe_build.py --output build/steam-socket-prerequisite-83bd/pe-v1
```

The actual MinGW source check treats warnings as errors. The PE build requires
20 GiB + 256 MiB + 8 MiB free at admission and continuously samples the unchanged
20 GiB floor and private 8 MiB output limit. Compiler children receive 45-second
CPU / 2 MiB file / zero core limits; a 45-second wall bound also applies.
No source check, dependency inventory or PE compilation runs the executable or
contacts a socket endpoint. A source-only check can run below the PE floor.

Each receipt binds the original source/build instructions, compiler binary and
version, actual transitive MinGW header hashes, native-media export baseline,
build command/log, input stability and resource samples. A completed PE receipt
also binds PE32/i386 GUI, OS/subsystem 4.0, actual import inventory and exports.
Those are static admission observations, not native dependency-load or behavior
proof. No provider is injected and no imports are replaced.

For a future parent-owned native trial, stage the receipt-bound `SPROB.EXE` to
`C:\GOPLAB\SPROB.EXE` in a new bounded owned guest copy, pin its SHA-256 and
source receipt in the existing guest-file manifest, and record a fresh nonce.
Run exactly `C:\GOPLAB\SPROB.EXE FRESH_TRIAL_NONCE` only after independently
confirming the actual Win98 SE IO.SYS/GOP path. The parent must capture the real
window/process lifecycle and complete process exit, then read the stopped guest
log and require that nonce, all `check.*=1` lines, `resources.cleaned=1`,
`prerequisite.checks-completed=1`, and `exit=0`. Failure, missing phase, timeout,
or stale nonce remains failure. No VM, provider or Steam action is started by
this lane. A loopback prerequisite pass must still leave full Steam false.
