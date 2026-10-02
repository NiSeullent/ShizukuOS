# WinHTTP URL omission checkpoint — 6970

This scoped utility repair serves the Windows98 backend compatibility work;
it does not implement an HTTP engine, TLS provider or application support.
Windows98 remains the real OS, and ShizukuDOS replaces its MS-DOS foundation.

## Contract and frozen preparation

When ExtraInfo is unrequested (pointer NULL and length0), requested UrlPath
must retain the URL query/fragment. NULL plus nonzero component length requests
a borrowed pointer and must remain a separate case. [Microsoft API contract](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpcrackurl).

Production winhttp.c SHA0036c09a67593ca10bff5a0cbfbe7d458d9dcc21ea99bd8d69191815a4a7f33b
always splits at ?/# and loses that suffix for a path-only caller. Own and
canonical master source were identical. No production edit is in this prepared
checkpoint. The narrow lane was shared with canonical NT/cb43 owners;
peer worktrees and indexes were not changed.

The frozen fixture includes the complete production TU with test-only UTF16/
Win64 declarations; it never extracts or copies the parser. Only last-error
access is implemented.110 assertions cover copied/borrowed omitted paths,
requested ExtraInfo, exact pointers, explicit non-NUL input prefixes, insufficient
and exact buffer capacities, preserved input/guards and ordinary controls.
Unchanged source should fail exactly25 omission assertions; actual execution
is pending. Compiler/harness/resource failures cannot establish RED.

The new source runner derives its guard from unchanged K32 runner8b7d3c6d...
and separately records full actual compiler -M/-MD include closures, with source
and header hashes before/after. All output/temp/captures/receipt share a new
8 MiB root, admitted above20 GiB. Receipt cap is128 KiB. This does not establish
full compiler/linker/runtime provenance or execute networking/Windows.

No local compiler or runner was started. AST/static source checks passed;
hosted RED must precede any small production change, followed by the identical
fixture's HOST/ASan/UBSan GREEN. Results will be recorded here when obtained.

## Actual unchanged-production RED

[Run36921050473](https://github.com/NiSeullent/Win98-Modern/actions/runs/36921050473)
atb6901b4d510248a9b226b47bbe4513c1d086a010 actually compiled the complete
unchanged production TU with GCC13.3. The fixture exited1 after110 checks with
exactly25 expected omission failures; passing controls were retained. The four
actual commands exited0,0,0,1 and were reaped. Six project inputs matched
before/after;40 actual GCC include files and compile dependency paths matched.

Full46,373-byte receipt SHA256:
8823c3547fd9934ac3f8cb260d5206c7c9616c3e144ca047c41a0e44f3112a1b.
Root reconstructed/hashed the actual logged receipt and compared project pins
against the exact tested source. Minimum observed free92,387,663,872B,
final output81,428B, peak observed113,435B, no resource failure and accounting
verified. Neither compilation nor failure involved a Windows/network call.

The proposed small production fix chooses the full path end only when
ExtraInfo is unrequested; explicitly borrowed/requested ExtraInfo keeps its
separate suffix. No exported ABI or other request/provider path changes.
The fixture, guarded runner and shims remain unchanged for hosted GREEN.
Actual GREEN, canonical import and native Windows execution remain pending.

## Actual identical-fixture GREEN and scoped import

The reviewed production repair is committed and pushed in
7c174d9184c719fea0b1b8024ee69a4ce3d0bdd4. It changes only the path-end
decision: omitted ExtraInfo keeps the query/fragment in UrlPath; requested
copied or borrowed ExtraInfo remains separate. Production SHA256 is
a4e92796e9f6d6a8f4423e65b6197555320625e0245adb1d651290afbd8bd990.
The fixture, runner and two declaration shims are unchanged from actual RED.

[Run36921574928](https://github.com/NiSeullent/Win98-Modern/actions/runs/36921574928)
at that exact commit passed110 HOST checks and110 Clang ASan/UBSan checks.
Both test error captures were empty. All eight actual commands exited0 and
were reaped, without an abort. Six project inputs matched before/after;
40 GCC and45 Clang actual include files matched their recorded dependency
paths and before/after hashes.

Full88,231-byte receipt SHA256:
cd61f021c19fe4c26162998168383b29144c711c181b19a45cb40afe4cb2e043.
Root and an independent agent reconstructed the complete receipt from actual
job output and computed the same digest. Minimum observed free92,386,070,528B,
final output1,712,697B, peak1,712,698B; no resource failure, accounting verified.

Canonical master163f and the main publisher can import prepared fixture/runner/
workflow commitb6901b4 and narrow production repair7c174d9. Preserve any later
independent WinHTTP changes with a scoped merge and source-bound validation.
Canonical adoption and main integration have not been observed.

These results verify this parser repair through the actual production C
translation unit on the host. No native Windows DLL, networking, HTTP engine,
OS TLS provider or modern application acceptance is established. The bounded
raw receipts remain in RAM; shared-host disk reserve does not currently admit
local compiler/VM work or physical proof persistence.
