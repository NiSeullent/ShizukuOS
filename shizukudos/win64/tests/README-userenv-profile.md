# Managed profile API contract

`LoadUserProfileW/A` validate the full public `PROFILEINFO` size and required
user-name pointer. A correctly sized structure has `hProfile` cleared before
further validation. No string is converted or passed to a nonexistent backend.

The caller's handle is duplicated with `DUPLICATE_SAME_ACCESS`. Real
`NtQueryObject` queries on this private duplicate confirm the `Token` object
type and the original granted access. Load requires `TOKEN_QUERY`,
`TOKEN_IMPERSONATE` and `TOKEN_DUPLICATE`; unload requires only the latter two.
The duplicate prevents handle close/reuse from mixing object type and rights
between the two queries. Only the private duplicate is closed.

Kernel64 registry.c explicitly supplies a volatile registry, with no hive file
load/unload. A valid load therefore fails with `ERROR_CALL_NOT_IMPLEMENTED`
and `hProfile == NULL`. This export closure permits consumers to load these
optional imports; it does not implement profile loading. No profile directory,
registry key, HKCU handle, backup/restore privilege or successful load is
invented. Administrative/privilege validation for a working hive backend remains
unimplemented along with that backend.

There are no handles issued by a successful profile load. Unload rejects every
unmatched supplied profile with `ERROR_INVALID_HANDLE` after token validation,
including actual keys, events and predefined HKCU. It never closes or unloads
a caller's unrelated handle. A missing profile argument also fails with
`ERROR_INVALID_HANDLE`.

The host runner compiles the exact production block with GCC and Clang
ASan/UBSan. Its handle/query adapters cover parameter errors, rights, wrong
object types, bounded native query records, injected failures and a handle
reuse at the snapshot boundary. These adapters do not represent actual guest
tokens. The native fixture instead creates genuine tokens with three access
masks, an event and a read-only existing registry key. It checks their lifetime
through each failure path. Native compilation and actual guest execution must
be reported separately; no Office functionality is proven by import closure.

Primary contracts: [LoadUserProfileW](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-loaduserprofilew),
[UnloadUserProfile](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-unloaduserprofile),
[PROFILEINFOW](https://learn.microsoft.com/en-us/windows/win32/api/profinfo/ns-profinfo-profileinfow),
[NtQueryObject](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject).
No upstream implementation body was copied. Wine's fabricated HKCU success is
not used as this provider has no managed hive backend.
