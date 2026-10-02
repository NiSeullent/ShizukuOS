# FD5C2 token authorization

Assigned baseline: `5e2f125ad1de9f5e2d47fae432e5c0d97c49f359` in
`/root/Win98-Modern-laptop-security-fd5c-20261002`. Root owns integration and
all Git/index changes. Scope: actual Kernel64 token and stored-descriptor
entry points, ntdll token duplication transport, a new shared operation
header, actual-production host regressions and this report.

Owned files: `shizukudos/kernel64/sysk32_sec.c`,
`shizukudos/win64/ntdll/ntobj.c`, `shizukudos/abi/shz_token_ops.h`,
`shizukudos/tests/test_token_rights.c`,
`shizukudos/tests/test_token_rights.py`, and this file. No c957 settings,
driver, account authority, native Windows or ISO files are owned here.

Design: enforce actual granted handle rights before allocation, output copies
or state mutation. Token query requires QUERY; integrity and privilege changes
require ADJUST_DEFAULT and ADJUST_PRIVILEGES; session metadata requires
ADJUST_SESSIONID and still cannot change without SeTcbPrivilege. Token
duplication requires DUPLICATE. Impersonation requires token IMPERSONATE and
an explicit thread's SET_THREAD_TOKEN right. Opening process/thread tokens
requires the process/thread query rights. Stored-descriptor queries and writes
require READ_CONTROL and WRITE_DAC respectively. These are admission checks;
they do not establish full owner/SACL or token-aware DACL evaluation.

The new duplicate operation is explicitly separate from legacy operation5:
opcode0x100, one64-bit value containing desired-access32, type8 at bit32,
impersonation-level8 at bit40, reserved upper16 zero. Requested rights must
be a subset of source grants; desired0 and MAXIMUM_ALLOWED use source grants.
Legacy operation5 retains its old type/level packing and cannot amplify
grants. A new frontend against an old backend receives the existing unknown
operation failure, without fallback to broader rights. No ABI version/layout
or reserved peer header is repurposed.

Root owns the separate advapi32 helper updates: ImpersonateSelf and named-pipe
client helpers must open their required DUPLICATE/QUERY/IMPERSONATE rights;
their duplicate requests use QUERY|IMPERSONATE rather than ALL. Account
binding/inheritance uses the kernel-only `shz_token_bind_subject` helper. It
requires a live fresh child with a NULL primary token, creates flags0, and
rechecks process object/PID/lifetime before installing the token. It cannot
replace an existing identity. Trusted binding at integrity0x3000 marks elevation
type2; other fresh bindings retain default type1. Public integrity lowering
still limits root's authority and frontend elevation report.
`shz_token_integrity` reads the minimum of an
existing primary token RID and the authority fallback without creating a lazy
token. Private operations0x200..0x20f dispatch to root's account authority.
Process/thread token opening and explicit-thread impersonation also require
root's boolean subject admission policy. The host fixture stubs that policy
with explicit allow/deny controls; root separately owns its real authority.

Tests: baseline actual production source RED:20 cases,190 reached assertions,
13 failures (`build/fd5c2-token/baseline-red`). Token-only GREEN:24 cases,369
assertions,0 failures with GCC and independently Clang ASan/UBSan
(`build/fd5c2-token/elevation-green/result.json`, matching compile/run logs).
The preceding final-green receipt retains366 assertions before the explicit
elevation metadata follow-up. That follow-up's actual source RED fails the
trusted bind assertion (24 cases,356 reached assertions,1 failure) in
`build/fd5c2-token/elevation-red`; the final source passes the added high/medium
binding checks with both compilers.
Root subsequently added centralized `shz_auth_handle_allowed` admission to real
object lookup/reference functions. The fixture supplies an explicit policy
boundary and tests denial before reference increments or caller output/access
writes, then allowed lookup/ref behavior and balanced release. Immutable
baseline `5e2f125` object functions combined with the current token dispatcher
fail the new actual lookup assertion:25 cases,370 reached assertions,1 failure
(`build/fd5c2-token/handle-original-red-final`). Complete current object
functions pass:25 cases,377 assertions,0 failures with GCC and Clang ASan/UBSan
(`build/fd5c2-token/handle-final-green/result.json`). Baseline receipts record
the actual extracted object-source hash separately from the live checkout;
production token changes were already frozen before this test-only follow-up.
The fixture compiles the complete production token dispatcher and ntdll object
translation unit, and actual object/handle lifecycle functions extracted
unchanged from `objects.c`. It adapts hardware IRQ, current-thread/process
layout, heap/user-memory, Windows types, and explicit auth-policy boundaries.
Production sources/fixtures are SHA256-pinned before and after execution.
Cases cover allowed and denied rights, generic mappings, malformed packing,
legacy no-amplification, impersonation level ceilings, copyout failure/ref
cleanup, descriptor admission, fresh-child binding, auth dispatch, frontend
desired access, and old-backend refusal with no fallback. The old-backend
case is an explicitly modeled unsupported-op boundary, not a native test.
Existing `test_token_query_host.py` also passes. Actual freestanding GCC64
`sysk32_sec.c`, MinGW AMD64 `ntobj.c`, and i486 shared-header translation-unit
object compilations pass under `-Wall -Wextra -Werror`; outputs are under
`build/fd5c2-token/compile`. No whole runtime build or guest test was run here.

Remaining: root owns general NtDuplicateObject and cross-subject authority
routes outside these owned entry points. Their enforcement must pass separate
integration checks before treating this token lane as part of an isolation
boundary.
Full file/registry ACL enforcement, identity-specific token/DACL authorization,
accounts/authentication/elevation, SMP qualification and actual Windows98
VMM enforcement remain separate work. Windows98 remains the product OS;
host/backend evidence is component evidence only.

Commit SHA: pending root coordinator commit.
