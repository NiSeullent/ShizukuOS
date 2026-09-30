# WIN64 subsystem: 64-bit programs for Windows 98 through ShizukuDOS

Requirement: *"ShizukuDOS must support 64-bit, as a subsystem or in whatever form, so that 64-bit becomes
possible on Windows 98."*

Windows 98 cannot enter Long Mode, and patching its kernel to do so is not the approach taken here. Instead,
the Shizuku Supervisor (Intel VMX) runs **two domains side by side**: the Windows 98 installation, and the
Long Mode **Kernel64** domain, which already loads and runs Win64 PE32+ programs (its own `ntdll`/`kernel32`,
`WIN64.IMG`). The *WIN64 subsystem* is the bridge between them. A 32-bit Windows 98 program asks Kernel64 to
start a Win64 program, feeds its standard input, receives its console output in order and under flow control,
waits for it, kills it, and gets its exit code. The only shared state is the inter-domain IPC channel of the
ShizukuDOS ABI (`shizukudos/abi/shz_abi.h`, `shz_ipc.h`); nothing in a message is a pointer or a handle.

This document separates what has been **executed** from what is **BLOCKED**. Section 5 is the evidence.

## 1. Architecture

```
 Windows 98 domain (ring 3)            Windows 98 domain (ring 0)          Supervisor (VMX root)       Kernel64 domain (Long Mode)
 ---------------------------           --------------------------          ---------------------       ---------------------------
 NTW64RUN.EXE (PE32 console)
   | NtwCreateProcess64W ...
 NTW32.DLL  ntwin32/win64/ntw64.c
   | DeviceIoControl(W64_*)  ------->  NTWRAP9X.VXD  ntwrapper/vxd/bridge.c
                                         owns src/dst/generation,
                                         pool blocks, pinned copies
                                         |  ring push/pop (shz_ipc.h)
                                         |  VMCALL NOTIFY / DOORBELL_ACK  ---> hypercalls, EPT-mapped
                                         |  VMCALL ABI_VERSION/CHANNEL_INFO     channel 2 (K64 <-> WIN98) ---> kernel64/subsys64.c
                                                                                                             ldr_create_process(),
                                                                                                             per-process console sink,
                                                                                                             Win64 PE32+ processes
```

| Layer | File(s) | Role |
| --- | --- | --- |
| Wire ABI 1.1 | `shizukudos/abi/shz_ipc.h`, `shz_abi.h` | Opcodes `0x200..0x208`, fixed-width payloads, receiver validators `shz_w64_create_check` / `shz_w64_console_check`, `SHZ_HC_CHANNEL_INFO` |
| Host model | `shizukudos/abi/test_abi.c`, `test_abi.py` | C round trips, hostile headers, pool ownership, fuzz; independent Python encoder/decoder and C/Python cross-verification |
| Kernel64 service | `shizukudos/kernel64/subsys64.c` (+ `sysfile.c`, `ldr.c`, `ipc64.c`, one `subsys64_start()` call in `main.c`) | Serves the channel: creates processes with `ldr_create_process`, relays console I/O, reports exits; standalone loopback self-test through the same wire frames |
| Win98 ring 0 | `ntwrapper/vxd/bridge.c`, `native.c`, `control.asm` | Guarded `CPUID`/`VMCALL` (ABI register convention), `_MapPhysToLinear` of the channel, four DeviceIoControl codes |
| Win98 ring 3 | `ntwin32/win64/ntw64.c`, `ntw64.h` (in `NTW32.DLL`) | `NtwQuerySubsystem64`, `NtwCreateProcess64W`, `NtwWaitProcess64`, `NtwReadConsole64`, `NtwWriteConsole64`, `NtwCloseConsole64`, `NtwKillProcess64`, `NtwCloseProcess64` |
| Console tool | `ntwin32/win64/ntw64run.c` -> `NTW64RUN.EXE` | `NTW64RUN [/i] [/d:<dir>] <image> [args]`, `NTW64RUN /q` |
| End-to-end host test | `platform/abi32/w64_e2e.py`, `w64_harness.c`, `w64_gate.S`, `k64model.py` | Executes the real DLL/EXE code and the VxD bridge logic against a Python Kernel64 model |

## 2. Message family (ABI 1.1, `SHZ_ABI_MINOR` 0 -> 1)

The 64-byte header, CRC-32 and 256-byte ring slot of ABI 1.0 are unchanged; a 1.0 receiver still accepts every
1.1 frame. Kernel64 is the server. Every reply echoes its request's opcode with `SHZ_MSGF_REPLY`.

| Requested name | Opcode (wire name) | Direction | Payload | Answer / semantics |
| --- | --- | --- | --- | --- |
| QUERY_SUBSYSTEM64 | `0x200` `SHZ_OP_W64_QUERY` | Win98 -> K64 request | none | reply `shz_w64_info_t` (40 B): ABI, subsystem 1.0, capabilities `0x1f`, 4 processes, window 8, chunk 176, active count, uptime |
| CREATE_PROCESS64 | `0x201` `SHZ_OP_W64_CREATE_PROCESS` | Win98 -> K64 request | `shz_w64_create_t` (16 B) + UTF-16 block: path (1..260), command line, cwd; no terminators | block <= 176 B travels inline; otherwise `SHZ_MSGF_BUFFER` and the block lives in a **pool buffer** owned by the Win98 domain until the reply (the "chunked through the shared buffer" path; 4,096 B wire limit, 4,016 B per VxD SEND) |
| PROCESS64_STARTED | reply to `0x201` | K64 -> Win98 | `shz_w64_event_t` (32 B) | state `STARTED` with the pid, or `FAILED` with the creation NTSTATUS (for example `0xC0000034`); `E_NOMEM` when all 4 slots are used |
| PROCESS64_EXITED | `0x202` `SHZ_OP_W64_PROCESS_EXITED` | K64 -> Win98 one-way | `shz_w64_event_t` | sent **after the last** CONSOLE_OUTPUT of that process; state `EXITED`/`KILLED`, exit code, fault status, last sequence number, dropped bytes |
| CONSOLE64_OUTPUT | `0x203` `SHZ_OP_W64_CONSOLE_OUTPUT` | K64 -> Win98 one-way | `shz_w64_console_t` (16 B) + <= 176 B | ordered per process by `seq` (1, 2, ...), stream 1 = stdout, 2 = stderr |
| (flow control) | `0x204` `SHZ_OP_W64_CONSOLE_ACK` | Win98 -> K64 one-way | `shz_w64_console_t`, `seq` = highest consumed | Kernel64 never has more than `SHZ_W64_CONSOLE_WINDOW` = 8 unacknowledged OUTPUT frames per process |
| CONSOLE64_INPUT | `0x205` `SHZ_OP_W64_CONSOLE_INPUT` | Win98 -> K64 request | `shz_w64_console_t` + <= 176 B; flag `EOF` closes stdin | reply status: `E_QUEUE_FULL` when the 1,024-byte stdin queue is full (the client retries), `E_NOENT` when the process is gone |
| KILL_PROCESS64 | `0x206` `SHZ_OP_W64_KILL_PROCESS` | Win98 -> K64 request | `shz_w64_kill_t` (pid, exit code) | reply status; idempotent for an exited process; EXITED follows with state `KILLED` |
| (slot release) | `0x207` `SHZ_OP_W64_RELEASE` | Win98 -> K64 request | `shz_w64_kill_t` (pid) | frees the Kernel64 slot after EXITED was delivered; `E_BUSY` before |
| (service stop) | `0x208` `SHZ_OP_W64_SHUTDOWN` | Win98 -> K64 request | none | the service stops (the DLL does not export it) |

"PROCESS64_STARTED" is deliberately the CREATE reply rather than a separate one-way message: the client learns
the pid in the same round trip, and no output of the new process can overtake it, because Kernel64 sends the
reply before its first pump of that process.

Rules both ends enforce (and the tests exercise): a receiver never trusts lengths (`block_bytes` must equal
2 x the three counts, no embedded NUL, inline/pool exclusive, pool block owned by the sender, `payload_length`
exact); the VxD, not the application, writes `src_domain`, `dst_domain`, `generation` and every buffer reference;
a pool block is freed only by the reply carrying the same request id; malformed slots are consumed and counted,
never answered or delivered.

## 3. Windows 98 side

**NTWRAP9X.VXD** (see `ntwrapper/vxd/README.md`): `W64_OPEN` (`0x4e540010`) checks the CPUID hypervisor bit and
the Supervisor signature before any `VMCALL`, asks `SHZ_HC_ABI_VERSION` and `SHZ_HC_CHANNEL_INFO`, maps the
channel with `_MapPhysToLinear` and validates it; `W64_SEND` (`0x4e540011`) copies header + payload [+ pool
data] through pinned, PTE-validated aliases, rewrites the endpoints and rings the Kernel64 doorbell;
`W64_RECV` (`0x4e540012`) returns one 256-byte slot or 259; `W64_WAIT` (`0x4e540013`) acknowledges the doorbell
and does not block in this revision. Errors: 50 without the Supervisor, 55 without a Kernel64 channel, 1306 on
an ABI major mismatch, 170 when the ring or the four pool blocks are busy.

**NTW32.DLL** (`ntwin32/win64/ntw64.h`): all calls return `BOOL` with a Win32 error. Handles are
generation-tagged records inside the DLL (not kernel handles). Console output is buffered per process (16 KiB)
and acknowledged as the application reads, so Kernel64's 8-frame window never overflows the DLL. A handle
closed on a running process keeps the process running; the DLL releases its Kernel64 slot after EXITED.
`ERROR_BUSY` from the VxD is retried while incoming frames are drained; `E_QUEUE_FULL` on stdin is retried for
up to 5 s. Native imports used: `CreateFileA`, `DeviceIoControl`, `GetLastError` (all present on Windows 98;
`DeviceIoControl` is the only one the NTW32 routing runtime does not already import).
Calls are not thread-safe; serialize them.

**NTW64RUN.EXE** (i486 PE32 console, subsystem 4.10, no CRT, imports only `KERNEL32` and `NTW32.DLL`):

```
NTW64RUN [/i] [/d:<dir>] <image> [arguments...]
NTW64RUN /q
```

`<image>` is a Kernel64 path such as `\SHZ\TESTS\T_HELLO.EXE`. The Win64 command line is the text from `<image>`
to the end. `/i` forwards stdin until end of file before showing output; without it the process sees EOF at
once. stdout and stderr arrive merged on stdout. The exit code is the Win64 exit code; 255 means NTW64RUN itself
failed and stderr names the Win32 error (2 = VxD or image not found, 50 = no Supervisor, 55 = no channel).

## 4. Kernel64 side

`subsys64_start()` (one call in `kernel64/main.c`) binds the channel whose peer is `SHZ_DOM_WIN98` from the
boot information and serves it until SHUTDOWN. A created process gets a per-process console sink (inherited by
its children, guarded by a generation) that `sysfile.c` consults for `NtWriteFile`/`NtReadFile` on the console
objects; output is queued per stream (2 KiB each), sent in 176-byte ordered frames under the 8-frame credit
window, and a writer blocked for 10 s drops (counted in EXITED). In the standalone profile (no Supervisor, no
peer) the same service runs on a kernel thread over a loopback channel, driven by a client that sends
byte-identical frames.

## 5. What is verified where

Evidence kinds follow `BASELINE.md`: `HOST_TESTED`, `GUEST_RUN` (QEMU, here TCG), `BLOCKED`.

| # | Path | Evidence | Result (this session, after merging the lead branch at `44e485f`) |
| --- | --- | --- | --- |
| 1 | Wire rules, C library vs independent Python model (`python3 shizukudos/abi/test_abi.py`) | HOST_TESTED | PASS: 3,665,461 C checks (GCC), 3,665,447 under ASan/UBSan and under TSan; Python decodes the four C-produced WIN64 frames; 6,000 generated frames cross-verified (1,234 CREATE accepted, 303 console accepted, 4,463 rejected) |
| 2 | Kernel64 service + real Win64 processes over the loopback channel (`python3 shizukudos/tests/run_k64_standalone.py`) | GUEST_RUN (QEMU TCG, no Supervisor) | PASS 16/16 harness checks; 30 `K64 subsys64 PASS` lines, 0 FAIL (evidence slot 31 = `0x57341e00`): T_HELLO.EXE relay and exit code 7, T_W64CON.EXE window/stderr/stdin echo/EOF, 263-char command line through the pool, kill, four-process capacity, hostile frames, shutdown |
| 3 | VxD bridge logic against the Kernel64 wire library (`python3 -B ntwrapper/vxd/build.py && python3 -B ntwrapper/vxd/test.py`) | HOST_TESTED | PASS 11 test groups; WIN64 bridge 2,504 assertions under ASan/UBSan including 19-step VMM-call fault injection |
| 4 | **End to end on the Win98 side**: real `NTW64RUN.EXE` and `NTW32.DLL` machine code -> DeviceIoControl -> the VxD's `bridge.c`/`core.c` (compiled for i386 bare metal) -> real `shz_channel_init()` rings -> Python Kernel64 model using `test_abi.py`'s decoder (`python3 platform/abi32/build.py`, or `w64_e2e.py` alone) | HOST_TESTED (static ELF32, KERNEL32/VMM/Supervisor/Kernel64 modeled) | PASS: 90,903 checks, 194 DLL export calls and 11 NTW64RUN.EXE runs with verified ESP, 88 VxD frames decoded identically by C and Python (2 pool-carried, largest 4,016 B), 216 model slots of which 215 are byte-identical to `shz_ring_push()` output and 1 was corrupted on purpose (dropped and counted by the VxD), the 8-frame window was full with output pending in 78 pump passes and never exceeded, 6 kills, 19 starts and 19 releases, 0 model violations. A deliberately broken DLL (ACK one past what was sent) is caught |
| 5 | Provider inventory and the rest of the runtime (`python3 platform/build.py && python3 platform/test.py`) | HOST_TESTED | PASS: 76 platform unittests incl. exact export/import inventories and the NTW64RUN.EXE import/subsystem check, 7 `routes.json` schema tests (the WIN64 API is kept out of the routing table), routing_test 1,422 checks; the routing-aware ABI harness passes 907 checks / 204 PE calls at both bases |
| 6 | Supervisor image builds with `SHZ_HC_CHANNEL_INFO` (`python3 shizukudos/supervisor/build.py`) | BUILT | PASS |
| 7 | Win98 domain <-> Kernel64 over the Supervisor (VMX, EPT-mapped channel 2, real `VMCALL`s) | — | **BLOCKED.** This container has no `/dev/kvm`, so VMX cannot be exercised (TCG does not emulate VMX). Independently of the host, the Supervisor does **not yet create a Windows 98 domain**: channel 2 (`SHZ_DOM_KERNEL64` <-> `SHZ_DOM_WIN98`) is in `kdom.c`'s channel plan but is only created when both domains are alive, so `subsys64_start()` currently finds no peer and returns. `domain.c` serves `SHZ_HC_CHANNEL_INFO`, but no VMX run has executed it |
| 8 | NTWRAP9X.VXD, NTW32.DLL WIN64 exports and NTW64RUN.EXE inside Windows 98 | — | **BLOCKED / not verified.** No Windows 98 guest ran in this session (no installed-guest checkpoint here). The last real-guest evidence for this VxD is a **failure**: loading it by absolute path failed at `CreateFile` with Win32 error 2, and the V86 diagnostic got native VXDLDR error 6 (`BAD_DEVICE_FILE`) — see [`docs/VXD_LOADER_TRIAGE.md`](../VXD_LOADER_TRIAGE.md) and [`docs/VXD_V86_LOADER_TRIAL.md`](../VXD_V86_LOADER_TRIAL.md). Until that is fixed the VxD does not load, and every NTW32 WIN64 call fails with that error (the e2e test reproduces this path: error 2 is reported, not hidden) |
| 9 | Real VMM services (`_LinPageLock`, `_CopyPageTable`, `_MapPhysToLinear`), VWIN32 dispatch, the guarded `VMCALL` inside Windows 98 | — | **BLOCKED** (needs rows 7 and 8). The e2e test models them; they are not evidence of native behavior |

In short: the protocol, the Kernel64 service with real Win64 processes, and the complete Windows 98 client
stack as compiled code are executed and cross-checked; the two joins that need hardware and a guest — the
Supervisor carrying frames between a live Win98 domain and Kernel64, and the VxD running inside Windows 98 —
have not run, and the second one has a recorded loader failure that must be solved first.

## 6. Limits and next steps

- The Supervisor needs a Windows 98 domain (VMX guest with the installed system) before channel 2 exists;
  then `supervisor/test_qemu.py` on a VMX host is the place for a Win98 -> Kernel64 run.
- The VxD loader failure (`BAD_DEVICE_FILE`) blocks every Win98-side run; `W64_WAIT` is non-blocking until the
  doorbell vector is hooked through VPICD, so the DLL polls with `Sleep(1)`.
- `_MapPhysToLinear` mappings are never released; the VxD trusts the Supervisor's channel header for the
  domain identities.
- One synchronous request at a time in NTW32.DLL; NTW64RUN forwards stdin before it shows output, so an
  interactive prompt appears only after input ends. Output streams are merged in Kernel64's pump order.
- At most 4 bridged processes in Kernel64, 8 open handles per Win98 process, 4,016 argument bytes per creation.
- GUI Win64 programs are out of scope: only console streams are relayed.

## 7. Reproduce

```sh
python3 shizukudos/abi/test_abi.py                       # row 1
python3 shizukudos/kbuild.py && python3 shizukudos/win64/build.py
python3 shizukudos/tests/run_k64_standalone.py           # row 2 (one QEMU, TCG ok)
python3 -B ntwrapper/vxd/build.py && python3 -B ntwrapper/vxd/test.py   # row 3
python3 platform/build.py && python3 platform/test.py    # row 5 (builds NTW32.DLL and NTW64RUN.EXE)
python3 platform/abi32/build.py                          # row 4 (+ the original ABI harness)
python3 shizukudos/dos16/build.py && python3 shizukudos/supervisor/build.py   # row 6
```

## 8. User-mode system DLL surface for Chromium 64-bit (agent K5, branch `wip/k5-chromium-dlls`)

The Win64 runtime's system DLLs live under `shizukudos/win64/dlls/<name>/` (own GPL-2.0-only code, one directory per
DLL, exports = the `DLLAPI` definitions, `module.json` for imports/forwarders/pinned ordinals/FileDescription) and
`shizukudos/win64/wineport/` (Wine ports, pinned commit). What K5 added for the Chromium start-up path, each with its
`tests/t_u_<dll>.c` self-check run by the standalone and GUI gates (details, evidence and the remaining gaps in
`reports/K5.md`):

| DLL | what | why Chromium needs it |
| --- | --- | --- |
| every DLL/EXE | a VS_VERSIONINFO resource (`tools/verres.py`, 10.0.22631.1 = the PEB OS version) | crashpad records module versions; `base::win::OSInfo` reads kernel32.dll's file version |
| version.dll | DLL search order for bare names, `GetFileVersionInfo{Size}ExW` | `GetFileVersionInfoSizeW(L"kernel32.dll")` |
| iphlpapi.dll (new) | adapters/interfaces/addresses/routes/statistics over the Kernel64 stack, change notifications (polled) | first delay-load Chromium reaches (`net::NetworkChangeNotifierWin`); a failed delay-load is fatal |
| dbghelp.dll (new) | Sym* over export tables, StackWalk64, SymSrvGetFileIndexInfo, in-process MiniDumpWriteDump | `base::debug::StackTrace`, crash reporting |
| advapi32.dll | SCM/event log/LSA/logon entry points (absent-server codes), Crypt* forwarders to cryptsp, LUIDs, file security | chrome.dll delay-loads |
| shcore.dll (new) | api-ms-win-shcore-* host: per-monitor DPI API, CommandLineToArgvW forwarder | `SetProcessDpiAwareness`, the shcore contracts |
| ole32.dll | in-process class table (CoCreateInstance, REGDB_E_CLASSNOTREG otherwise), IStream/ILockBytes on HGLOBAL, in-process marshalling, FTM, agile references, drop targets | `CoCreateInstance(CLSID_NetworkListManager)` and the other 18 delay-loads |
| combase.dll | RoGetActivationFactory/RoActivateInstance (REGDB_E_CLASSNOTREG), RoOriginateError | the api-ms-win-core-winrt contract |
| wtsapi32.dll (new) | the single console session; notification registration | `base::win::SessionChangeObserver` |

Rules kept: nothing is silently stubbed - a function either does the documented work over what the kernel provides or
fails with the code Windows gives when the underlying server/feature is absent, and its test asserts that code.

