# Explicit native TLS transport adapter

`M98NET.DLL` is an opt-in C API over the existing, unchanged Mbed TLS 4.2.0 / TF-PSA-Crypto 1.2.0 `M98TLS13.DLL`. It supplies actual original Winsock 1.1 nonblocking TCP, CryptoAPI entropy and UTC FILETIME conversion. It does not install a replacement standard DLL, implement DNS, select trust roots, or integrate SChannel, WinHTTP, WinINet, Trident or an application.

Build a fresh checkpoint with:

```text
python3 -B tools/build_tls13_native.py --output build/tls13-native-net-v1 --nonce m98net-5abe-20261001-v1
```

The builder runs both production-controller and production-Win32-platform fault models normally and with ASan/UBSan, a real host-only TCP/TLS integration, then builds `M98NET.DLL` and the no-CRT GUI `NET13PR.EXE`. It checks PE32/i486 flags, GUI/OS/subsystem 4.10, original OEM KERNEL32 imports, dynamic system exports, relocations, zero timestamps, exact adapter/backend exports and 2 MiB reserve / 64 KiB committed stack. Model tests do not execute Windows APIs. The real loopback fixture uses a separate POSIX platform and the same controller/backend; it does not prove Win98 networking.

## Ownership and operation

The caller supplies the IPv4 endpoint as four wire-order bytes, port, separate ASCII DNS hostname for certificate validation/SNI, a terminal-NUL PEM CA bundle and finite connect/handshake/I/O deadlines of 1–300000 ms. There is no hostname-to-address lookup, ambient trust, deterministic entropy or guessed time. Options, hostname and CA may be released after `open` returns. A read/write call accepts at most 1 MiB. One live generation handle is allowed; stale handles fail, exhausted generations never wrap, and concurrent/reentrant calls return BUSY.

The adapter loads the backend beside itself and checks the actual loaded path. Original WSOCK32/ADVAPI32 load by the system directory and all required exports are gated; the backend's MSVCRT must also come from that directory. CSPRNG succeeds only after native CryptGenRandom succeeds. UTC must be 1–253402300799 Unix seconds. The platform owns precisely one socket, WSA reference, provider and module references. It frees the backend before releasing platform ownership. Partial failures close owned resources; failed release quarantines the handle, preserves original diagnostics plus cleanup error, blocks further opens and permits explicit `close` retry. DLL unload is allowed only after successful close.

Each blocking facade operation uses a finite nonblocking select deadline and a 20000-step ceiling. Deadlines are checked before/after calls and within BIO callbacks. Loader, CSP and individual TLS CPU calls are synchronous and cannot be preempted. Successful plaintext writes completed at an expired deadline are counted in the returned prefix; previously transmitted partial ciphertext cannot safely be replayed. A failing or late read returns no plaintext count. Raw TCP EOF fails closed unless the backend has authenticated close_notify.

`shutdown` sends local authenticated close_notify, half-closes TCP output and drains bounded raw ciphertext to TCP EOF before cleanup. The frozen backend is terminal after sending its alert, so this drain does **not** authenticate the peer's TLS alert. The host server independently confirms the client's close_notify. Immediate `close` releases resources without a wire shutdown wait.

## Native acceptance remains pending

Nothing here launches a VM, stages guest files, enables a NIC or starts a remotely accessible peer. The probe has no endpoint/CA defaults. A future controlled trial must explicitly pin the endpoint, hostname, CA, nonce, executable/DLL/source hashes and peer transcript before the VM owner runs:

```text
C:\GOPLAB\NET13PR.EXE
```

Place the frozen probe, adapter and backend in `C:\GOPLAB`, an explicit root PEM in `NETCA.PEM`, and six strict ASCII CRLF lines in `NET13.CFG`, in this order: `ipv4=`, `port=`, `hostname=`, `connect_ms=`, `handshake_ms=`, `io_ms=`. No blank lines or trailing data. The selected controlled TLS 1.3 peer must validate the 3072-byte request `(i*17+3)&255`, return 1021 bytes `(i*31+9)&255`, observe the client's authenticated close_notify and then close TCP. Remove an old `NET13.LOG` as part of separately reviewed staging; the probe uses CREATE_NEW to reject stale output.

Acceptance needs fresh source-bound `NET13.LOG`, Win98 SE 4.10.2222, exact adjacent loaded paths, explicit CA/config pins, full bidirectional payload, shutdown and owned-resource cleanup success, flushed/closed log and independently observed actual child exit DWORD 0. Printed expected SHA values are compiled expectations, **not** runtime file hashing. A requested supervisor exit or textual PASS cannot replace actual exit/readback verification. Positive networking alone does not prove every negative case: repeat wrong hostname/untrusted CA/TLS 1.2/truncated TCP/deadline controls against the same frozen native artifacts before claiming broad native transport validation.

## Consumer handoff

For the requested Trident extension route, integrate this API into an explicit network consumer only after native transport proof. The consumer must own DNS resolution, CA policy, HTTP framing, redirects, proxy/authentication, concurrency and application lifecycle. Trident HTML5/WASM/current JavaScript work is a separate engine task; a full WebKit port is not an acceptance requirement. TLS transport success does not establish modern JavaScript/WASM, Legcord, Signal or Office operation, and the user objective remains incomplete until those named native applications and theme behavior are verified independently.
