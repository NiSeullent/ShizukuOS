# Explicit-loading SSPI native GUI probe

This prepares a project-owned Win98 SE GUI executable that explicitly loads
`C:\GOPLAB\M98SSPI.DLL` and calls its actual ANSI SSPI table. It is an isolated
component test with a separately linked real TLS server and bounded memory BIOs.
No sockets, operating-system provider registration, system DLL replacement,
application compatibility or Trident/WinINet acceptance is established here.
The executable has not run in Windows. Native default ROOT certificate
validation and actual process-exit observation remain false.

## Owned files and immutable dependencies

The four new source files are `sspi_guest_probe.c`, `sspi_guest_probe_build.py`,
`sspi_guest_probe_host_test.py` and this handoff. The existing observer, fixtures,
production engine, committed native adapter and guest images are unchanged.
Build outputs live in new `build/secure-transport/sspi-guest-probe-*` directories;
every attempt is preserved. The builder never starts, stages or changes a VM.

The accepted adapter is the corrected read-only ROOT build at
`build/secure-transport/sspi-native-v1/native-root-readonly/M98SSPI.dll`:

- SHA-256: `ac3392d878f1e35a107d14111166401d3efb8f7507df3e7e19d61d59b4d2d2b2`.
- Size: 1,638,356 bytes; its receipt binds the corrected adapter, core and
  explicitly retained library/object/configuration inputs.
- The old native-complete adapter is superseded for ROOT-opening behavior and
  must not be used for this probe.

The new builder validates every source and explicit retained input in the
corrected adapter receipt before copying that DLL. It reuses the reviewed native
v5 runtime/time objects and Mbed TLS 3.6.7 static server/crypto archives, without
rebuilding or replacing them. Headers come from retained native-v3 upstream.
It binds their header tree, actual compiler include dependencies, compiler
binary and selected compiler support archives. These recorded inputs are not
a claim of complete SDK/toolchain provenance closure.

## Child and observer contract

The exact child command is `C:\GOPLAB\TLS13PRB.EXE --nonce <nonce>`.
The child accepts only 16–64 ASCII letters, digits or hyphens. Its executable
path must match the fixed path, ignoring ASCII case. A quoted executable path
is accepted, but quoted nonce values or additional arguments are rejected.
The GUI entry is `M98SspiProbeEntry`; it uses Win32 logging and `ExitProcess`
directly, without the legacy CRT command-line startup.

The child creates **SSPI13.LOG** with CREATE_NEW and no sharing. A pre-existing
log fails before any protocol execution. Each JSON line contains the fresh
nonce, unsigned full DWORD status, event, counter and fixed false acceptance
flags. The child handles partial writes, flushes every record, latches errors,
then flushes and closes the log before exiting. Log creation/writes/flush/close
failures cannot produce a zero exit code. `terminal_candidate_only` reports the
candidate code; it does not establish that the process exited.

**The existing TLSWATCH.EXE is incompatible** because it appends legacy server,
CA and output arguments that this child rejects. A separate SSPWATCH.EXE outer
observer is required. Its independent log is SSPIOBS.LOG. It must launch the
fixed command with the matching nonce, observe the actual full DWORD exit,
require both fresh logs and completion ordering, and reject timeouts, stale
logs, missing records or partial logs. The independent stopped verifier must
bind the exact EXE, DLL, fixtures, observer and logs to a new isolated clone.
Do not stage this executable into the existing v5 fixture or use its old
observer/manifest to claim acceptance.

The cooperative child budget is 70,000 ms. Each of seven TLS pairs shares an
8,000 ms / 50,000-step budget across its handshake and subsequent traffic;
the cumulative pair budget is at most 56,000 ms. Hashing, fixture reads and
runtime/logging overhead have the remaining 14,000 ms. Wrap-safe DWORD elapsed
checks run between calls; an individual blocking native API/crypto call cannot
self-interrupt. The outer observer's 90,000 ms deadline remains authoritative.
No successful run or process-exit observation is inferred from either budget.

The child verifies original Win98 SE version 4.10, platform 1, build low-word
2222, hashes the entire exact-size DLL before loading, and holds a read-only
share-read handle until after FreeLibrary. It checks the resolved module path,
table version and the table pointers against all required named exports.
It never calls the operating-system SSPI provider or imports socket APIs.

## Trust and actual protocol cases

`native_ROOT_acquire_only` invokes the DLL's default credential acquisition and
records its native API status. Empty/unavailable ROOT stores produce a false
event, never a private protocol PASS. Even successful acquisition does not
prove Windows chain policy or default ROOT TLS validation. This observation
is excluded from the private protocol case count and all validation flags
remain false.

The private cases use the explicit project credential configuration. CA.PEM,
BADCA.PEM, SRV.PEM, SRV.KEY, EXP.PEM and EXP.KEY are copied unchanged from the
retained native-v5 private fixtures. FUT.PEM is generated separately with the
retained server key, explicit DNS identity `tls13.win98.test`, and validity
2038-01-01 through 2039-01-01. Every generated/copied byte is SHA-bound in the
new receipt and staging plan. The future-date case depends on the guest clock
being earlier than 2038; it fails if that precondition no longer holds.

The unchanged production probe body exercises these 13 intended cases:

1. Fragmented real TLS 1.3 handshake, retaining MISSING and EXTRA input tails.
2. One-byte initial/final output token buffers and retained-token empty retry.
3. Actual stream sizes: header 5, trailer 32, maximum message 16,383,
   four buffers and block size 1.
4. SSPI encryption to the separate server and authenticated echo decryption.
5. Two complete TLS application records supplied together, forcing EXTRA.
6. Actual bidirectional close_notify, close-token buffer retry and authenticated
   EndInput after peer closure.
7. Rejected stale/wrong-kind context handles.
8. Rejected wrong DNS identity.
9. Rejected unrelated private CA.
10. Rejected expired certificate.
11. Rejected future certificate.
12. Rejected altered encrypted record.
13. Rejected unauthenticated memory-transport EOF after consuming all records.

The executable's statically linked server has its own PSA/runtime globals;
the DLL owns a separate runtime and serializes all its calls. There is no
shared OS-provider context or socket. All pairs are destroyed before runtime
shutdown. The child logs cleanup errors and FreeLibrary/handle-close errors
as nonzero candidates.

## Evidence domains and commands

Native build and PE audit are preparation only:

```text
python3 ntwin32/secure_transport/sspi_guest_probe_build.py --output <new-directory>
```

This strict i486 GUI build uses the custom entry, OS/subsystem version 4.10,
zero timestamp, relocations and original OEM import inventory. It rejects NT
static TLS, load config, delay imports, CLR, unexpected export directory,
socket imports and OS SSPI provider imports. `guest-files` and `staging-plan.json`
are prepared inputs; `staged` is false.

Host fault-model tests execute the actual parser, logger, entry, DLL SHA check,
table binding and input/retry helper code with mock Win32/SSPI APIs. Only the
protocol case body is substituted. They read the actual retained native DLL
bytes for SHA validation, without loading or executing its PE code. These
tests cannot prove cryptographic protocol success or Windows behavior.

```text
python3 -B ntwin32/secure_transport/sspi_guest_probe_host_test.py --output <new-directory>
python3 -B ntwin32/secure_transport/sspi_guest_probe_host_test.py --real-protocol --output <new-directory>
```

For a bounded repeat, add `--reuse-pic` with the successful producer receipt
`build/secure-transport/sspi-guest-probe-real-host-v1-attempt2/receipt.json`.
The script checks the exact cached archive hashes, upstream and configuration
against that producer before reusing them read-only. Its full compile remains
preserved; generated adapter/core DSO and production-body driver are relinked.

The separate Linux real-protocol harness runs the production probe body against
the actual adapter/core and PIC Mbed TLS 3.6.7 in a locally bound shared ELF
library, with separate retained server PSA globals. The Linux build overrides
the expected module size/hash with the same ELF bytes it hashes and executes
through dlopen. This establishes bounded Linux protocol behavior only. It
cannot prove native Windows DLL loading, native RNG/time/certificate-store
calls, sockets, installed OS SSPI, Trident, applications or actual Windows
process exit. It has a separate receipt from the PE build and mock fault model.

Current native preparation receipt:
`build/secure-transport/sspi-guest-probe-native-v3/receipt.json`, SHA-256
`8eed2de02918d05da8ad5e7fab3f0fde6ce4c1933768b19792094c70053b0a40`, PASS.
The GUI EXE is 974,821 bytes, SHA-256
`0515a7175ad241134cb35bfba10c7d24597750ff45bbd2b175a36462b2288301`.
Its custom entry RVA is 30,176, with 6,659 HIGHLOW relocations, 54 imports all
present in the original OEM inventory, and all forbidden directories empty.
The prepared nine guest files and staging plan are SHA-bound; 337 recorded
source/header/support/retained/guest bindings were independently re-read.

The initial v1 output preserves only the strict object compilation. Native v2
linked and passed its PE audit but its overall receipt correctly failed because
the builder source was edited during that run. V2 is not acceptance evidence;
v3 repeated the gate against stable sources without overwriting prior results.
The first complete Linux actual-protocol receipt is
`build/secure-transport/sspi-guest-probe-real-host-v1-attempt2/receipt.json`,
SHA-256 `0c95ef10a111430a92fc3da667b0681cee2c9899bbfe37f5b687d1e4e6bf093b`,
PASS. All 13 ordered protocol cases succeeded, with 18 log records and a zero
private protocol candidate. ROOT acquisition was unavailable and recorded as
false without default ROOT validation or an extra protocol PASS. Client DSO
and server runtime/PSA function addresses differed; the ELF SYMBOLIC audit
passed. Client runtime init/fini counts were 7/7 with 42 real entropy calls;
the independent server counts were 1/1 with 36 real entropy calls. The initial
Linux attempt failed at CMake config-macro quoting before protocol execution
and remains preserved.

Final accepted host fault receipt:
`build/secure-transport/sspi-guest-probe-host-v1-final/receipt.json`, SHA-256
`3cf3f90a47e7454ec6deb1eac0e853a7a45ce9991aed6c2cc9d4af4d264a2294`, PASS.
Both GCC and Clang ASan/UBSan passed all 113 distinct cases, with no sanitizer
diagnostics. Protocol success remains false for this fault model.

Final accepted Linux actual-protocol receipt:
`build/secure-transport/sspi-guest-probe-real-host-v1-final/receipt.json`, SHA-256
`5ba7449363b178475f3df283dae027964853baaac7ff215a51ef656fb64011ba`, PASS.
The 13 cases and 18 records passed again using the SHA-bound PIC cache. The
actual server reported TLSv1.3 on all three positive handshake version calls,
with zero bad versions. Independent namespace and runtime/entropy checks
passed again. Both final host receipts bind unchanged probe C SHA-256
`d625b04d07d38693429ff7319394e207e08133baff1c495e414890db52f6bd7b`
and final host script SHA-256
`c8ca332a2fb3dd56547e3680722de4643b2451d043f16a427249b606e3fc0b88`.

The four-file aggregate is
`build/secure-transport/sspi-guest-probe-acceptance-v1/HANDOFF-RECEIPT.json`.
It binds the current four new sources, three final evidence receipts, prepared
guest inputs and separate observer preparation receipt. The prepared observer
is `build/secure-transport/sspi-observer-v1/native-v2/SSPWATCH.EXE`, SHA-256
`f593a6211e0a75b1c9a904a5f883936483a3e647cf954dffded3b7e7f241e84b`,
14,152 bytes. Observer preparation is separate from the probe and has no guest
execution proof. No source was committed by this worker; parent review/commit
and future isolated guest execution remain separate steps. Windows execution,
sockets, installed OS provider and native default ROOT validation remain false.

## Failure DWORDs

| DWORD | Meaning |
| --- | --- |
| 0x50000001 | Invalid command/nonce/self path; no log created |
| 0x50000002 | New log creation failed |
| 0x50000003 | Log write, flush or close failed |
| 0x50000004 | OS identity, DLL hash/path/table or default credential cleanup failed |
| 0x50000005 | Separate server runtime finalization failed |
| 0x50000006 | FreeLibrary failed |
| 0x50000007 | Retained DLL file handle close failed |
| 0x50000101 | Private fixture read/load failed |
| 0x50000102 | Separate server runtime initialization failed |
| 0x50000103 | At least one intended private protocol/cleanup case failed |

Later cleanup errors can replace a prior candidate; log failure overrides the
final code. These are full DWORD values, never an 8-bit shell success test.
