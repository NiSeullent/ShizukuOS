# Native TLS DLL interoperability handoff

This fixture loads the frozen latest `M98TLS13.DLL` client (Mbed TLS 4.2.0,
TF-PSA-Crypto 1.2.0) and the peer's independent `M98TLS.DLL` server (Mbed TLS
3.6.7 LTS). Each DLL owns its own PSA state. The probe exchanges real TLS 1.3
records through bounded memory queues in native Windows 98; it uses no sockets.
Guest execution remains unverified until an actual run passes the readback
verifier. Host controller/supervisor doubles and static PE gates cannot supply
that acceptance.

## Frozen v7 inputs and preserved v4 failure

- Staging directory:
  `/root/Win98-Modern-boot/build/tls13-native-5abe-20261001-v7`
- Manifest `guest-files.json` SHA256:
  `1f3601ec2cdff904340a5e7fc34371d1c36b4c6cfe728e894ad2ddb40828ddb0`
- Manifest-bound build receipt SHA256:
  `dbc1e147d18b033497dc0bb403522798d186acd54a255a01566f7c61432ca7ca`
- Nonce: `m98tls5abe-interop-20261001-v7`
- Client DLL SHA256:
  `8691fa74eeb9dbf02d53f7dc45a5c15c8f9d3c9960f222112621ef6351d621b9`
- Independent server DLL SHA256:
  `905afad1554867693375bc18b58cb07522965ec351f81b5d604ddf6054ea98bb`

All eight inputs fit the native harness's 1 MiB per-file limit. Both native
executables are PE32 Windows GUI/OS 4.10, built for i486 without SSE/MMX or
static TLS, delayed imports, CLR startup, CRT entry or stack probing. Each
reserves 2 MiB and commits **64 KiB** of stack: the controller's nested queue
and payload frames exceed the old default 4 KiB commitment. Their imports were
checked against the pinned Windows 98 SE OEM export inventory. Do not reduce
these stack bounds or alter frozen inputs in place; a change needs a new build,
nonce, staging directory and approved manifest hash.

The actual v4 child exited 1, with 20 checks and one combined positive-handshake
failure. Its original inputs, source snapshot, logs and result remain retained;
result SHA256 is
`89b8b33afa48b63ec7de2ab66dd59bbb5c878f53f87c92cc78f105714851447c`.
Both libraries, CryptoAPI randomness, UTC and negative cases ran, but the
positive fixture incorrectly required server certificate-verification flags to
be zero although the server does not request client certificates. The corrected
fixture requires both handshakes, server identity authenticated by the client, client
verify-flags zero and TLS1.3, while recording server flags as informational.
Client certificate authentication is explicitly **not requested**. A separate
real host latest/LTS exchange observes informational server flags128 and completes
encrypted HTTP and shutdown. This supports the fixture correction; it cannot
retroactively turn v4 into a native pass. v7 also logs both endpoint statuses
and backend errors. Its build has 15 controller assertions and 42 synthetic
evidence-parser regression cases. v5/v6 intermediate builds were never launched.

## Native execution and exit evidence

Use the established native Win98 harness to inject the frozen manifest into a
new owned cold clone of the verified installed Windows 98 SE disk. Retain its
20 GiB reserve guard, immutable originals and fresh output checks. Keep guest
networking disabled. Do not reuse another session's writable disk or logs.

Launch this exact command through the real guest's Run dialog:

```text
C:\GOPLAB\T13RUN.EXE
```

`T13RUN.EXE` requires Win32 Windows platform 1, version 4.10, build-low 2222,
its exact executable path, and absent child logs. It launches only its own
`TLSDLL.EXE`, waits at most 120 seconds, and records the child's **actual full
DWORD exit code** after `WaitForSingleObject` and `GetExitCodeProcess`. A timeout
terminates only that owned child and allows a 5-second reap. Timeout, creation,
exit-query, flush or handle-close failures cannot become successful child
acceptance.

`TLSDLL.LOG` records 24 checks, final status and `REQUESTED_EXIT`. The supervisor
must independently observe `child.exit-code=0`; the child's requested exit
alone cannot prove successful final log flush/close. Similarly,
`supervisor.requested-exit-code=0` precedes the supervisor's own final
flush/close/ExitProcess. Its **actual outer exit remains unobserved** by this
fixture and is explicitly false in the verifier's verdict. It does not negate
the separately observed successful child result.

After the owned VM has stopped and the harness has finished `result.json`, its
three outputs must be fresh captured files: `TLSDLL.LOG`, `T13RUN.LOG`, and the
empty redirected `TLSOUT.LOG`. Preserve the final harness result and its SHA256.

## Exact readback acceptance command

Run from `/root/Win98-Modern-theme-tls-5abe`. Replace `TLS13_OWNED_RUN` with the
completed run directory name, then freeze that final result's digest:

```bash
TLS13_GUEST_RESULT='/root/Win98-Modern-boot/build/shizukudos/csm/TLS13_OWNED_RUN/result.json'
TLS13_RESULT_SHA256=$(python3 -c 'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$TLS13_GUEST_RESULT")
python3 tools/verify_tls13_guest_evidence.py \
  --run-result "$TLS13_GUEST_RESULT" \
  --run-result-sha256 "$TLS13_RESULT_SHA256" \
  --manifest /root/Win98-Modern-boot/build/tls13-native-5abe-20261001-v7/guest-files.json \
  --manifest-sha256 1f3601ec2cdff904340a5e7fc34371d1c36b4c6cfe728e894ad2ddb40828ddb0
```

Acceptance requires exit 0 and structured `status=PASS`, all 24 successful
checks, exact nonce and client/server identities, native CryptoAPI/UTC,
TLS 1.3 negotiation, authenticated 3072/1021-byte bidirectional payloads,
bounded partial I/O and retries, close-notify and denied writes after close,
wrong-host/untrusted-CA rejection without plaintext, entropy return 0/-1/2
and later entropy failure rejection, tampered-ciphertext rejection without
plaintext, and provider/DLL teardown. The verifier also requires fresh output
readbacks, unchanged originals/prepared source, the complete frozen staging
scope, captured harness source, and the original current build-source hashes.

`NEEDS-VISUAL-REVIEW` is the harness's boot/GUI status; it cannot substitute for
this protocol verdict. Native DLL interoperability does not establish Winsock,
Schannel, WinHTTP, WinINet, network certificate provisioning, system-wide TLS,
Legcord, Signal or Office functionality. Those verdicts remain false. Preserve
private Windows media and screenshots in ignored build storage, not git.

Parser regressions use synthetic transcripts only:

```bash
python3 -m unittest discover -s tests -p test_m98_tls13_guest_evidence.py -q
```
