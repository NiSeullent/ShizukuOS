# Laptop security and ISO implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. User already selected parallel execution with full authority and no questions.

**Goal:** Implement laptop adapters, account/elevation authority, privilege enforcement and native personalization; produce an honestly labelled ISO with verifiable public contents.

**Architecture:** Disjoint agents implement production driver, token and personalization modules. Root implements account authority and process integration, reviews all contributions and coordinates existing native boot/installer and publication owners.

**Tech Stack:** Freestanding C, Windows98 USER32/GDI32/OLE32, GCC/Clang sanitizers, MinGW, Python and xorriso.

**Spec:** docs/superpowers/specs/2026-10-02-laptop-security-iso.md

## Global constraints

- Actual Windows98 remains the product and Explorer remains its visible shell.
- No private Microsoft image, credentials, VM image or peer evidence may enter public content.
- Existing17GiB native resource reserve is preserved.
- Token duplication cannot amplify granted access.
- Registration requires a kernel-only bootstrap grant or an authenticated administrator.

## Review focus

- Process-slot reuse must never inherit old identity or bootstrap authority.
- Failed authentication, copyout and launch must not expose a credential or grant elevation.
- Duplicate handles must not bypass the token access restrictions.
- EC/I2C timeout, malformed descriptors and resource revocation must preserve device ownership.
- Failed wallpaper application and battery transitions must not report success or keep animation active.

### Task1: Token enforcement (compat_audit)

Files: kernel64/sysk32_sec.c, win64/ntdll/ntobj.c, new abi/shz_token_ops.h and actual production tests.
Interfaces: NtShzToken newduplicateop0x100 desired32/type8/level8; existing operations retain wire meaning. Kernel-only shz_token_bind_subject(process_t*,uint64_t,uint32_t,uint32_t).
- [ ] Run actual missing-right/malformed-op/copyout/refcount RED cases.
- [ ] Implement rights-first token and descriptor gates and conservative duplication.
- [ ] Run host sanitizers and freestanding/MinGW compilation.

### Task2: Laptop adapters (driver agent)

Files: new drivers/common/ and drivers/shz_laptop/ only.
Interfaces: explicit transport callbacks and generation-bound ownership; tests inject actual transport errors.
- [ ] Add RED lifecycle/ACPI EC/I2C HID/power/sensor inputs.
- [ ] Implement bounded protocols and resource-safe teardown.
- [ ] Verify host/i486 objects and document missing native bindings.

### Task3: Account authority and elevate (root)

Files: new shizukudos/accounts/, abi/shz_auth.h, kernel64/sysk32_auth.c, auth_policy.h; controlled hooks in proc.c, ldr.c, sysx.c, ipc_proc.c, autorun.c; new win64/apps/elevate/.
Interfaces: private NtShzToken0x200..0x20f request structures; subject snapshots; kernel-only enrollment grant; child prepare callback installs subject before startup.
- [ ] Add RED authentication, unauthorized registration, session binding, throttling, stale identity, cross-account and command-elevation cases.
- [ ] Implement KDF using existing SHA256; authority stores only salted digests.
- [ ] Connect trusted enrollment, fresh login/elevated child launch and cross-account process checks.
- [ ] Build elevate with password input excluded from command line and verify import dependencies.

### Task4: Native personalization (display_audit)

Files: new ntwddm/win98/personalization/ only.
Interfaces: real native GDI adapter plus ActiveDesktop/SPI apply, explicit persistent preferences.
- [ ] Run production scene/preferences/HTML RED cases.
- [ ] Implement bounded scenes, settings, power pause and wallpaper apply.
- [ ] Verify sanitizer suite and i486 PE32 imports.

### Task5: Integration, core isolation and ISO (root with peers)

Files: source integration/status plus new tools/build_laptop_security_iso.py and tests.
- [ ] Read and acknowledge reciprocal owner handoffs; review restricted AP service independently before importing exact17files.
- [ ] Review delegated production paths and rerun meaningful combined checks.
- [ ] Build deterministic public add-on ISO and verify content digests/exclusions; share concrete artifact with canonical boot and publisher owners.
- [ ] Retain native boot/private installer/full hardware gaps explicitly until owner evidence closes them.
- [ ] Commit only reviewed exact source paths; preserve shared native evidence and other worktrees.
