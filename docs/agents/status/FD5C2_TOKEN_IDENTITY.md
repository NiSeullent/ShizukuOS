# FD5C2 token identity rendering

Ownership: `shizukudos/win64/dlls/advapi32/token.c`, new
`shizukudos/tests/test_token_identity.c`/`.py`, and this report. Root alone owns
Git/index/integration. Existing root changes to token elevation and helper rights
are preserved. No account/kernel authority, reserved peer headers or existing
test fixtures were edited in this follow-up.

Problem: fixed legacy user RID1001 collides with newly registered account UID1001.
Target token user/owner rendering partly used account authentication IDs, but
default DACL and membership/AccessCheck still used the fixed caller SID. Actual
production RED:7 cases,23 reached checks,7 failures, recorded in
`build/fd5c2-token-identity/baseline-red/result.json` with original working-source
SHA256 `74dc0d4e0804a68191ea9243108b926407b770a3e581251240c58e34386cbc0c`.
`initial-red` contains preliminary host-adapter compile errors and is not credited
as a behavioral regression.

Implementation: per-token local SIDs use `auth_id >> 32`. Exact anonymous ID
`0x4e7` retains legacy RID1001 only after a valid version1 authority query explicitly
reports zero accounts; enrollment, failed queries or invalid versions use RID0.
Bootstrap authentication ID `UINT64_MAX` renders RID `0xffffffff`. User, owner,
default DACL and membership/AccessCheck all use the requested token. Current-user
helper opens/queries/closes the current primary token on each call and returns an
immutable SID record, preserving its existing static-storage API without mutable
shared identities or a stale caller cache. Current account UID1000..1015 storage
is compile-time checked against the real16-account bound. Unrecognized current
UIDs fail closed to anonymous. Machine-domain SID prefix and group RID513 stay
consistent with the established registry identity.

Related false-success finding: `CreateProcessAsUserW` accepted a foreign token
based only on medium integrity/session1, then launched as its caller. Root
authorized the same-file correction. Actual old gate RED:8 cases,50 reached
checks,1 failure (`caller-launch-red`). The corrected gate queries the actual
caller primary token and requires matching authentication ID, primary type,
integrity, session and privilege flags. Opening/query failures propagate errors;
foreign or mismatched metadata is denied. Modified privilege flags are explicitly
unsupported because the fresh-child binder creates flags0. Nondefault anonymous
metadata is also unsupported. Matching authenticated callers can use their actual
session and label; this route forwards creation as that caller and cannot adopt
another supplied identity.

Final validation:
`python3 -B shizukudos/tests/test_token_identity.py --label final-green --compiler all --mingw`
passes GCC and Clang ASan/UBSan:8 cases,59 checks,0 failures per compiler. The
installed MinGW compiler also compiles the complete unmodified captured
production `token.c` to a PE/COFF object under freestanding warning-as-error flags.
Receipt `build/fd5c2-token-identity/final-green/result.json` SHA256:
`95263ff34f923d514822a43d50e32918634ff04335452497152b0c084ddfb246`.
Production source SHA256:
`f1885fbe8fec21d282db29558ed884a44e6f86e385dfdfa05ca2380760b9aa65`.
Receipt reports stable inputs; source closure still matched the checkout at
handoff. Generated host unit and resulting binaries/object are separately pinned.
Timeouts are bounded/configurable and failures preserve elapsed time/logs/receipt.

The host fixture extracts unchanged actual token rendering, membership,
AccessCheck and caller-launch functions, plus actual SID/ACL/security-descriptor
helpers. Windows public types and native transport/creation are explicit host
adapters. It checks different caller/target UIDs, guest versus account UID1001,
legacy/activated identity changes, previously returned immutable SID pointers,
bootstrap/default DACL identity, ACL allow/owner denial, caller-query cleanup and
foreign/modified-token launch refusal. It does not execute the real loader or a
Windows98 guest and does not establish full NT DACL enforcement.

Limits: account display/lookup names and the historical group set remain a
compatibility model. In particular, the generic set still includes Authenticated
Users for anonymous tokens; group-based AccessCheck is not an authentication or
kernel isolation guarantee. No administrator groups or new privileges are added.
Kernel account policy stays authoritative on its supported routes. Native
Windows98/VMM login, persistent credentials and protected credential UI remain
separate gates.

Commit SHA: pending root coordinator commit.
