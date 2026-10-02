# Kernel-owned account foundation

This is the managed Kernel64 component of the actual Windows98 project.
It does not replace Windows98 VMM, USER, GDI or Explorer. The account store
is volatile kernel memory; it is not a persistent Windows98 login system.

Registration uses a kernel-only first-enrollment grant or an authenticated
high-integrity administrator. Passwords are8..128 UTF-8 bytes, with independently
generated32-byte salts and PBKDF2-HMAC-SHA256 at600000 rounds. Five failed
attempts lock the named account for30 seconds. The finite store holds16 users;
usernames are case-insensitive ASCII letters, digits, underscore and hyphen.
Session IDs do not wrap. No default password, plaintext-password file or
reusable elevation credential exists.

The explicit development boot option `shz.accounts=setup` starts only the
fixed, trusted enrollment image `C:\SHZ\SYS64\ELEVATE.EXE` from a readonly
RAM initrd, before other live processes. A manually started copy cannot obtain
the bootstrap grant. The enrollment program uses `--enroll admin`. Normal
login and elevation authenticate each new child. Existing processes keep
their identity and privileges. Authenticated children receive a fresh primary
token, no inherited handles or impersonation token, a private
`C:\Users\<uid>` current directory and kernel-generated USERPROFILE/TEMP/TMP.
Failure before reply publication does not start the authenticated child.

The companion commands are documented in
`../win64/apps/elevate/README.md`. Password entry uses private UTF-16 storage
and a custom masked control because this runtime's ordinary EDIT control does
not implement ES_PASSWORD. Both the frontend and the kernel clear request
storage, including partially copied failed requests. The ordinary dialog is
not a protected secure desktop: another process in the same trusted identity
realm may access its memory. Authenticated cross-account GUI queries/input
require the kernel subject gates; they do not establish a secure native Win98
credential surface.

Process/thread handles and remote access follow UID, logon session and current
primary integrity. Administrator access requires a genuine immutable role and
high integrity. Opening or duplicating handles cannot manufacture rights.
Named object namespaces are separated by UID/session/integrity; reserved
internal names cannot be pre-seeded. Activated raw-device, driver, registry
mutation, file/profile and file-backed section operations have admission
checks. Shared named pipes and clipboard currently fail closed after account
activation. These limits may prevent applications that depend on those APIs.
Fresh sandbox policy also applies before first enrollment: writes, privileged
devices, mutable registry, shared pipes/clipboard and all network operations
are denied. Its named objects use a separate namespace and no handles are
inherited. Public files and its own account's files may be read; it is not a
filesystem containing only explicitly selected application inputs.

Native Windows98 login and the NTW64 authentication bridge, protected persistent
credential storage, full NT DACL semantics, secure desktop, revocation of
existing mapped memory after integrity lowering, native driver DMA/IOMMU
isolation, and physical hardware qualification remain integration gates.
The same UID/session/integrity is one trusted realm. This implementation is
not full Windows UAC, VBS, AppContainer, or a hardened multi-user Windows98
distribution. The separate persistent AP service accepts fixed copied jobs;
it does not provide general AP scheduling or hardware security isolation.

Validation uses actual production code with declared IRQ/loader/filesystem
boundary adapters, GCC, Clang ASan/UBSan, independent OpenSSL KDF comparisons,
actual token/object functions and freestanding compilation. Original receipts
state their scope; none prove Windows98 guest execution.

```sh
python3 -B shizukudos/tests/run_accounts_host.py --out build/accounts-check
python3 -B shizukudos/tests/test_auth_admission.py --label accounts-check
python3 -B shizukudos/tests/test_auth_creation.py --help
python3 -B shizukudos/tests/test_token_rights.py --label accounts-check
python3 -B shizukudos/tests/test_token_identity.py --help
python3 -B shizukudos/tests/test_kdf_reference.py --out build/kdf-check
```
