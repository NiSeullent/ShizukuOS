# Isolated original-source TLS i486 corrective port

The preserved original latest-client DLL contains actual conditional-move
instructions in both upstream X509 code and precompiled MinGW formatting code.
The original native stage is not accepted for an i486 baseline. No existing
stage, peer project, original source archive, guest or OS configuration is
modified by this corrective work.

The new builder uses the previously pinned official Mbed TLS 4.2.0 archive
(bundled TF-PSA Crypto 1.2.0), the official 3.6.7 LTS archive and the receipt-bound
original LTS adapter snapshot. It extends documented platform configuration
hooks and rebuilds every original translation unit for i486 without ASM/AESNI/PadLock,
SSE/MMX, MinGW ANSI-format redirection or compiler CRT startup. Original client
and server public ABIs remain the intended contract.

The official archives and every regular extracted byte retain exact hashes.
Relative symbolic links are preserved with their original target metadata only
when they stay inside the single archive root and resolve to declared members.
Alias collisions, escaped or missing targets, alias-parent members and all other
nonregular types are rejected. Extraction and member counts remain bounded.

The bounded integer/string formatter supplies C99 count and truncation
semantics for supported forms. It supports signed/unsigned integer lengths
hh/h/l/ll/j/z/t and legacy I/I32/I64, decimal/octal/hex, ordinary byte strings
and characters, flags, width and precision, and an explicit 0x pointer form.
Formats and widths/precisions are bounded to 4096. Byte strings may contain
exactly 1 MiB of data plus a readable NUL terminator, and total output data is
bounded to 1 MiB. A longer string or an additional byte beyond the total limit
fails before output changes. Floating/wide-character forms, %n, unknown directives and bounds
violations return -1 before changing caller output. This is not a complete CRT.
Independent literal tests and the host C library's C99 integer/string oracle
cover extrema, null termination, zero-size output, small buffers, precision,
flags and failure immutability. Old OEM _vsnprintf truncation is not treated as
C99 success.

Every actual configured translation unit gets compiler-flag, its own full
preprocessed macro dump and format-use evidence. Separate header-context dumps
also bind each distinct configured flag group. All original upstream C/header files
also have a separate raw inventory, including excluded programs/tests and
unsupported forms. Only calls resolved to the new formatter receive its bounded
runtime parser guarantee; other format-related families are retained explicitly
without inferred routing or C99 behavior. Dynamic values in resolved calls still
can return -1, and an inventory cannot prove all runtime values supported.
The original latest `library/mbedtls_config.c` assertion-only TU deliberately
undefines then restores format-option presence macros with empty values. That
exact original file is separately required to contain no format calls, and its
terminal presence-only values are recorded; ordinary library TUs still require
the exact new function values. Original latest adapter/config bytes and private
fixture files also bind to fixed frozen receipt hashes before any output is made.
The corrected common instruction scanner binds raw bytes and addresses over
all declared executable sections, checks an explicit i486/x87 allowlist and
rejects modern mnemonics/register operands and incomplete decode.

The preserved fifth corrective trial rejected seven real UD2 instructions in
LTS cold error paths. The original LTS CMake selects -O2; GCC's null-dereference
isolation pass then emits traps even with -march=i486. Five exact original
affected TUs were independently recompiled with only
-fno-isolate-erroneous-paths-dereference added, producing no UD2 instructions.
The fresh native recipe requires that flag in every actual TU; the unchanged
full-byte allowlist still rejects any unsupported instruction in the linked DLL.
This compiler setting does not make invalid pointers or upstream precondition
violations supported API inputs. GCC documents the pass in its
[optimization options](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html#index-fisolate-erroneous-paths-dereference).
Failed linked scans retain the full artifact, PE metadata and actual disassembly.

The host latest-client probe uses a receipt-bound prepared copy of the original
test, strengthening its status-line check to an independent exact 60-byte HTTP
response. Its source remains unchanged. Latest client and LTS server run in
separate owned processes on an ephemeral loopback port with bounded deadlines.
Startup reads at most 64 bytes through a nonblocking descriptor under one
absolute five-second deadline. Partial lines do not restart that deadline;
EOF, overlong lines and malformed/out-of-range ports fail, and the finally
block terminates/reaps only the owned child and closes its pipes. Independent
pipe-only tests cover complete/fragmented lines, stalled partial lines, EOF,
oversized input, malformed ports and a continuing slow writer without networking.
Certificate/hostname, ciphertext tampering and caller-entropy/clock failures
are distinct cases. This does not execute the Windows DLLs or test WinSock.
The receipt-bound server certificate has DNS SAN tls13.win98.test, which is the
positive verification name even though the socket connects only to loopback.
The sixth historical trial completed both native DLL's strict linked gates but
failed its positive host test because the original corrective test recipe used
localhost. That failed receipt remains unchanged. A separate exact-name Linux
diagnostic passed all twelve encrypted cases with both endpoint logs and actual
exit codes retained; a fresh complete build must pass those same cases before
publishing its handoff receipts.

Current work is a corrective build candidate. Host cryptographic integration,
exact linked PE/import/export gates, a fresh native stage/nonce and genuine
owned-child Win98 trial remain separate acceptance requirements. Host results,
offline memory-BIO interop and static code are not WinSock, OS TLS, browser or
application acceptance.

The frozen v1 build remains a historical complete source/host result. The fresh
v2 generation adds the bounded startup and exact string-limit regressions and
must rebuild all four profiles and twelve encrypted cases before native staging.
