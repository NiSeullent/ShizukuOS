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
