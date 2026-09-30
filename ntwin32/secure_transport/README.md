# TLS 1.3 secure transport

This directory provides a real, externally serialized TLS 1.3 engine with
caller-owned byte transport and cryptographic randomness. It is separate from
`ntwin32/tls`, which implements PE thread-local storage.

The Mbed TLS 3.6.7 maintained LTS source remains unmodified and is built from
the exact publisher archive. Both protocol bounds are TLS 1.3. Clients require
an explicit CA bundle and expected hostname; certificate chain, hostname and
date verification remain enabled. There is no unauthenticated mode, TLS 1.2
fallback, early data, session persistence, or timer-derived entropy fallback.

The caller must serialize every API call, prevent callback reentry, keep the
RNG callback/context alive until runtime shutdown, and exclusively own the
linked PSA instance. Pending writes require the same unchanged buffer on retry.
Transport EOF is a fatal truncation, distinct from an authenticated TLS close.
Destroy all connections before runtime shutdown.

`M98TLS.dll` supplies the same engine plus `ntwst_native_runtime_init/fini`,
which use Windows 98's ANSI CryptoAPI. The native target reads UTC through
GetSystemTime/FileTime APIs with a 64-bit epoch and correct Gregorian calendar;
modern CRT date functions are not required. Its C-only entry points avoid the
compiler's NT static-TLS startup. This startup applies only to these authored
C artifacts; no target application or third-party binary is stripped or patched.

## Verified checkpoint

On 2026-10-01 KST, `build/secure-transport/host-v3` passed eleven actual protocol
checks: TLS 1.3 handshake/bidirectional payload/clean close, wrong hostname,
untrusted CA, expired certificate, partial I/O with retry and truncation,
TLS 1.2-only peer rejection, RNG failure during handshake, ciphertext tampering,
EOF at a record boundary, failed RNG initialization, and zero-length randomness.
The probe is executed on Linux, over bounded memory queues, using OS getrandom.
It is not a socket or Windows guest result.

`build/secure-transport/native-v3` built `TLS13PROB.exe`, `TIMEPROB.exe` and
`M98TLS.dll`. All three passed PE32/i386, subsystem 4.10, original Win98 OEM
import and forbidden-directory checks. The DLL SHA-256 is
`905afad1554867693375bc18b58cb07522965ec351f81b5d604ddf6054ea98bb`.
An independent libc-backed Windows-clock model passed 61 calendar/failure
checks, including 2038, leap centuries, overflow and invalid clock handling.
That model is explicitly identified as a Linux host, not Windows.

Native guest execution remains **NOT VERIFIED**. The filesystem is below the
existing 20 GiB guest reserve; no VM or reserve guard was overridden. Earlier
failed source-change/build/test receipts remain retained under v1/v2 directories.
The final v3 receipts identify exact compiled source snapshots and artifacts.

This backend does not yet implement Windows Schannel/SSPI, WinHTTP, WinINet,
socket/DNS integration, the OS certificate store, or a modern application's
network path. Those require separate integration and actual guest tests.

## Reproduce the build

Obtain the version-pinned archive from the [official 3.6.7 release](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-3.6.7).
The builder accepts only its exact size and publisher SHA-256. It does not fetch
dependencies, start a service/guest, install a DLL, or change configuration.
Run from the repository root with fresh output directories:

```sh
python3 -B ntwin32/secure_transport/build.py \
  --archive build/secure-transport/upstream/mbedtls-3.6.7.tar.bz2 \
  --output build/secure-transport/host-new --target host --run-probe
python3 -B ntwin32/secure_transport/build.py \
  --archive build/secure-transport/upstream/mbedtls-3.6.7.tar.bz2 \
  --output build/secure-transport/native-new --target win98-x86
```

Dependencies are CMake, Ninja, a C compiler, the installed x86 MinGW toolchain,
Python cryptography (test certificates only) and pefile (PE audit only).
Production trust anchors are supplied by the embedder. Generated private test
certificates/keys stay in ignored build directories and are never installed as
OS trust or shipped as production credentials.

## Native guest handoff

`stage_guest.py` freezes the static probe, its six private certificate fixtures
and a short COMMAND.COM-compatible launcher into eight bounded inputs. It
copies the build receipt, binds every file digest and requests fresh output
paths. Every guest input has an explicit DOS 8.3 name; the executable is staged
as `TLS13PRB.EXE`. Execute the short `C:\GOPLAB\TLSRUN.BAT` path rather than
pasting the longer probe arguments at an interactive COMMAND.COM prompt.
It performs no guest operation. The established guest owner must use a
new clone, an absent output baseline, fresh nonce, image/boot identity and exact
source/artifact/readback receipts. Capture the actual application exit after
CRT cleanup with an outer observer; the batch only distinguishes zero/nonzero.

The shared CSM runner accepts source receipts only within its own build root,
so the prepared handoff is placed in a new uniquely owned directory beneath
that root. Networking remains disabled: this fixture exchanges real TLS records
in memory. A separate socket test must use an explicitly isolated network.
Do not count this fixture as system-wide TLS or as Legcord/Signal/Office support.

The final handoff is
`/root/Win98-Modern-boot/build/secure-transport-7707/tls13-v3-dos/guest-files.json`,
SHA-256 `9b88a8ef866dab8c80349afe754d3d3ff838b5438debbb7184ecc9b72858c13f`.
The earlier `tls13-v3` staging is superseded because its executable name exceeded
DOS 8.3. Neither staging has been executed in a guest.

`verify_checkpoint.py` independently rechecks frozen receipt/source/artifact
hashes, the eleven distinct host results, original Win98 imports, DLL exports
and relocations, and the staged paths/launcher. For the retained checkpoint:

```sh
python3 -B ntwin32/secure_transport/verify_checkpoint.py \
  --host-build build/secure-transport/host-v3 \
  --host-sha256 6851a064ed6a168a72840023bc38d458cbef48464fafa5613c05a52ec6be710a \
  --native-build build/secure-transport/native-v3 \
  --native-sha256 e80ac28e5ea1ac5c719c4f2223a0f1017d3f27ae03d5972d625d560b6f688494 \
  --staged /root/Win98-Modern-boot/build/secure-transport-7707/tls13-v3-dos/guest-files.json
```

The [application requirements](../../docs/MODERN_APP_REQUIREMENTS_7707.md)
retain the complete user goal and separately require app-level TLS behavior.
Source and license details are in [PROVENANCE.md](PROVENANCE.md).
