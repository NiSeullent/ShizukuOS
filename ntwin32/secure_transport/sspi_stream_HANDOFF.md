# Portable SSPI stream core — integration handoff

`sspi_stream.c/.h` implement an outbound TLS 1.3 stream-token client over the
real `ntwst` 3.6.7 engine. `sspi_stream_test.c` executes actual encrypted records
and certificates. This is **not a Windows SSPI export DLL, a registered security
package, an OS certificate-store adapter, a network client, or an application
compatibility result**. Native guest and OS-provider acceptance remain pending.

The owned files are these three new C/header files and this handoff. No existing
engine, builder, native startup, Kernel64/Wine provider, Winsock, VM or global
configuration is changed by this slice.

## Runtime and ownership

Initialize `ntwst_runtime_init` (or the native runtime adapter) before creating
pools; destroy all pool contexts and any other real engine connections before
runtime shutdown. The runtime exclusively owns its linked PSA state. All calls
across every pool, `ntwst` connection and runtime must be externally serialized;
the future Windows provider needs its own lock and callback/reentry policy.
No mutex, native credential handle or Windows pointer-validation policy is
implemented here. A pool pointer itself is an owned C object with caller-managed
lifetime, not an untrusted public handle.

Each pool has at most eight contexts. Contexts expose a kind, slot and globally
unique 32-bit generation; deletion/reuse and cross-pool handles are checked.
Generation exhaustion fails instead of wrapping. Every context has bounded
64-KiB outgoing token storage and 16-KiB private plaintext storage. The caller
owns input buffers and socket operations. `ntwst_create` copies/parses the
explicit CA and DNS hostname at creation; these are caller policy, **not an
interpretation of `SCHANNEL_CRED.hRootStore`**. Hostname validation restricts
this core to ASCII DNS labels, excluding IP literals and implicit IDNA handling.

## Input, continuation and output retries

`ntwssp_handshake` and `ntwssp_decrypt` borrow input without modifying it.
`input.consumed` counts only bytes passed to the real engine. Retain the tail at
`data + consumed` with length `size - consumed`, append new transport bytes, then
submit that tail. Do not replay an already consumed prefix. A partial TLS header
or body is not submitted to the engine; `missing` reports the additional bytes
needed, and the incomplete tail stays untouched in caller storage.

Handshake input may contain multiple complete records; the engine decides how
many it consumes before producing a continuation or final result. Decrypt
processes at most one complete record per call, preserving subsequent records
as extra input. A completed handshake leaves malformed or incomplete extra
bytes untouched for the next operation and does not report MISSING for them.
Input tokens are bounded to 64 KiB, record wire length to
16,645 bytes. Record framing does not bypass backend authentication or its
protocol/certificate checks.

`BUFFER_TOO_SMALL` on a handshake token retains exact outgoing bytes and the
operation's original status. Retry with empty input and a sufficiently large
token buffer; a nonempty token during the pending retry is `BUSY` and is not
consumed. A final successful handshake can still produce an outgoing token:
send it before treating peer establishment as complete.

Decrypt privately retains authenticated plaintext if the destination is too
small. Its first call reports the consumed ciphertext prefix and required
plaintext capacity, without copying a partial plaintext result. Retry with empty
input; a retry never decrypts the same record twice. Further input and EOF are
refused while plaintext is pending. Input and plaintext destination ranges must
not overlap in this portable API; a native in-place `DecryptMessage` wrapper
must use separate staging and copy/relabel the verified result into its caller
buffer, preserving the original extra-record tail.

Control records can return `CONTINUE` without plaintext. If they generate an
outgoing token, drain it with `ntwssp_take_token` before new record processing.
Tokens are opaque and belong to the caller's transport; the core sends no bytes
to a network itself.

## Encryption and closure

The supported layout is one nonempty DATA region plus distinct HEADER and
TRAILER buffers. Encryption overwrites the DATA bytes with real ciphertext,
puts the TLS wire header in HEADER and the remaining authenticated record bytes
in TRAILER. Contiguous adjacent buffers work; overlapping regions are rejected.

The reported stream sizes are header 5, trailer maximum 32, message maximum
**16,383**, four SSPI buffers including EMPTY, and AEAD block size 1. The pinned
Mbed TLS 3.6.7 `mbedtls_ssl_get_max_out_record_payload` reserves an inner type
byte and rounds the TLSInnerPlaintext limit to its 16-byte padding granularity;
advertising 16,384 would silently allow a backend partial write. The actual
trailer length is returned after encryption. Insufficient capacities are
detected before calling the backend, preserving plaintext and record sequence.

Compile-time guards bind the 16-KiB input/output limits, padding granularity 16
and disabled negotiated `record_size_limit` extension. Changing the effective
backend configuration requires a reviewed size accessor and updated tests;
merely compiling this header against an unrelated prebuilt library is invalid.
The core checks that successful writes produce one complete record containing
the entire requested message. An unexpected partial write fails the context
instead of returning an incomplete message as encryption success.

`ntwssp_shutdown` produces authenticated close_notify, stages it across small
output-buffer retries and rejects application writes once shutdown begins.
Reads remain available after the token is drained, allowing authenticated peer
closure. Repeated shutdown produces no duplicate alert. `ntwssp_end_input` must
be called when the real transport reports EOF; without a previously verified
peer close_notify it returns fatal `TRUNCATED`, including at record boundaries.
Certificate and record-authentication failures permanently fail the context.

## Host verification and reproduction

Private output is `build/secure-transport/sspi-stream-host-v1/`. Existing frozen
host-v4-gui libraries/configuration, native-v3 upstream headers and host-v4-gui
private certificates are read-only inputs. There is no download or extraction.
The first retained run exposed the incorrect 16,384-byte send limit; the final
normal run passes 14 groups / 38,188 checks. Groups cover typed/stale/cross-pool handles,
initial and final handshake token retries, fragmented records, wrong DNS name,
untrusted root, expired/future certificates, real TLS 1.2-only server rejection,
completed-handshake extra tails, maximum message encryption and peer readback,
extra records, plaintext retries,
tampering, orderly closure, both truncation forms, multiple live sessions and
failed handshake randomness. A self-signed future certificate is generated
only in test memory using the retained test key; no trust material is installed.

Build the normal fixture from the worktree root:

```sh
gcc -std=c11 -O2 -g -Wall -Wextra -Werror -Wpedantic \
  -DMBEDTLS_USER_CONFIG_FILE='"user_config.h"' \
  -Ibuild/secure-transport/host-v4-gui/project \
  -Ibuild/secure-transport/native-v3/upstream/mbedtls-3.6.7/include \
  -Intwin32/secure_transport \
  ntwin32/secure_transport/sspi_stream.c \
  ntwin32/secure_transport/sspi_stream_test.c \
  build/secure-transport/host-v4-gui/cmake/libntwst.a \
  build/secure-transport/host-v4-gui/cmake/upstream/library/libmbedtls.a \
  build/secure-transport/host-v4-gui/cmake/upstream/library/libmbedx509.a \
  build/secure-transport/host-v4-gui/cmake/upstream/library/libmbedcrypto.a \
  -o build/secure-transport/sspi-stream-host-v1/sspi_stream_test
build/secure-transport/sspi-stream-host-v1/sspi_stream_test \
  build/secure-transport/host-v4-gui/fixtures
```

For ASan/UBSan, use the installed Clang 21 compiler with
`-O1 -fno-omit-frame-pointer -fsanitize=address,undefined` and compile the
unchanged `transport.c` instead of linking `libntwst.a`. Enable
`ASAN_OPTIONS=detect_leaks=1:abort_on_error=1` and `UBSAN_OPTIONS=halt_on_error=1`
when executing the fixture. GCC sanitizer runtime libraries are absent locally;
no package was installed to perform this check.
The core, fixture and engine adapter are instrumented; the reused upstream
static crypto/TLS libraries are not sanitizer-instrumented. The final sanitizer
run passes all 14 groups / 38,191 checks with no diagnostics or detected leaks.
Check counts can
vary slightly with randomized handshake lengths; contract groups and failures
are stable. `build/secure-transport/sspi-stream-host-v1/receipt.json` binds exact
sources, configuration, libraries, fixture inputs, outputs and logs, retaining
the failed run separately.

## Next native integration

Provide genuine A/W SSPI exports and function tables, credential/context lifetime
rules, standard buffer descriptors, native trusted ROOT enumeration and explicit
unsupported-option behavior. Reconcile this core's consumed-input/output-retry
contract with the documented native `SECBUFFER_EXTRA` and `SECBUFFER_MISSING`
behavior. Native credentials v4/v5, package discovery, context attributes,
certificate-context allocation, revocation policy, ALPN, client authentication,
server/inbound contexts and QOP alerts require their own implementation/review.
Do not advertise unsupported package capabilities or infer OS-provider success
from this test binary. The 4.2 client still requires its separate multi-context
PSA/runtime adaptation; never cast its callbacks or merge two static PSA copies.

The native owner must run independently linked standard API callers on genuine
Windows 98, including real socket traffic to a controlled independent server,
the positive and negative certificate cases, fragmentation/retries, clean close
and actual observed process exit. Kernel64 execution, native offline protocol
tests and this Linux fixture remain separate evidence domains.

Trident/WinINet can consume a genuine native provider without replacing the
browser engine. HTML, CSS, DOM, JavaScript and WASM improvements have separate
functional acceptance; a complete WebKit port is not a prerequisite for TLS.

Primary contract references: Microsoft
[InitializeSecurityContext](https://learn.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--schannel),
[EncryptMessage](https://learn.microsoft.com/en-us/windows/win32/secauthn/encryptmessage--schannel),
[DecryptMessage](https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--schannel),
and [SCHANNEL_CRED](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-schannel_cred).
