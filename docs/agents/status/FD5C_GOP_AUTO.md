# FD5C — stop AUTO after an unvalidated GOP selection

## Scope and ownership

Worktree: /root/Win98-Modern-pma-integration-fd5c-20261002.
The reviewed firmware selection implementation is peer commit
305448b0c90a52f7c777e7049382fedf1757daa5, imported by root as
47831011c8c4f522edd8ec01648f08463cf82517.
The shared coordination message reserves this narrow caller repair for fd5c.

Owned files:

- shizukudos/supervisor/loader/loader.c: private state and AUTO guard only.
- shizukudos/supervisor/native_win98/tests/gop_auto_host.c.
- shizukudos/supervisor/native_win98/tests/test_gop_auto_host.py.
- This status document.

No firmware selector, peer worktree, public ABI, Git index or commit was changed.
Root owns integration, independent review and the final loader/payload build.
Windows 98 on ShizukuDOS remains the product target; these host tests establish
a component failure-path contract only.

## Problem and implementation

AUTO with auto_kernel64=yes and no usable Supervisor backend tried direct
Kernel64, then chain-loaded CSMWrap after every returned error. If a GOP
SetMode attempt partially changed hardware and restoration failed, the selector
correctly returned EFI_DEVICE_ERROR, but this caller still entered CSM from an
unvalidated physical display state.

The existing private k64_state_t now records display_selection_failed when an
available GOP is rejected by sd_gop_select. k64_prepare's existing full state
reset clears it for each attempt. k64_release frees pages and preserves this
failure outcome. AUTO returns the original error before its CSM call when this
flag is set. All selector errors fail closed here, including an initially
invalid or unsupported available GOP.

Ordinary missing-backend, missing-image, unreadable-image, unplaceable-Kernel64
and pre-exit launch failures retain CSM fallback. A validated selector success,
including its safe original-mode fallback, also retains that ordinary policy.
Explicit Kernel64/installer failures and explicit CSM policy retain their
existing behavior.

## Actual-code regression and source binding

The host runner extracts and compiles the complete, verbatim production
efi_main body plus the real k64_boot, k64_refuse, k64_release and zero functions.
It also executes the original k64_prepare reset statement and its entire GOP
selection block, including the new state assignment. Braces are parsed while
respecting C strings, characters and comments; absent or ambiguous extraction
points reject the fixture. No fallback decision is copied into a test helper,
and no test hooks are added to production.

The EFI services, selector, CPU/backend discovery, physical boot preparation
and launch boundaries are doubles using the real local UEFI headers and ABI.
Physical allocation/setup, memory-map planning, ExitBootServices, actual GOP
SetMode hardware and CSM execution are outside this host fixture. Unexpected
untested firmware/physical boundaries fail the fixture immediately.

Each run records the whole loader source, fixture, runner, transitive project
headers, generated verbatim inputs, resolved compiler and executable hashes.
Source contents and compiler identity are checked before/after the run;
executable bytes are checked across execution. Sanitized execution uses
nonrecovering ASan/UBSan and any stderr rejects a successful test result.
This is bounded host provenance, not a full toolchain attestation or protection
against transient concurrent edits that are reverted between observations.

Before changing loader.c, the compiled original EFI entry reproduced the
failure:

    AUTO refuses CSM after failed GOP restoration:
    returned 8000000000000015 (wanted 8000000000000007),
    CSM calls 1 (wanted 0)
    FAIL line 205: test.csm_calls == csm

The preserved RED receipt reports compile_returncode=0, test_returncode=1,
pass=false and unchanged sources/compiler/binary. The initial fixture compile
setup omission of GUEST_RAM_MIB was corrected by extracting its production
definition; its distinct setup-failure receipt remains separate.

## Fresh verification

Commands executed from the owned worktree:

    python3 -B shizukudos/supervisor/native_win98/tests/test_gop_auto_host.py --out build/pma-fd5c-gop-auto/red
    python3 -B shizukudos/supervisor/native_win98/tests/test_gop_auto_host.py --out build/pma-fd5c-gop-auto/green-gcc
    python3 -B shizukudos/supervisor/native_win98/tests/test_gop_auto_host.py --cc clang --out build/pma-fd5c-gop-auto/green-clang
    python3 -B shizukudos/supervisor/native_win98/tests/test_gop_auto_host.py --cc clang --sanitize --out build/pma-fd5c-gop-auto/green-clang-sanitized
    git diff --check -- shizukudos/supervisor/loader/loader.c shizukudos/supervisor/native_win98/tests/gop_auto_host.c shizukudos/supervisor/native_win98/tests/test_gop_auto_host.py

RED failed for the intended unexpected CSM invocation. Each GREEN command
exited zero with 15 scenarios and 180 checks, no stderr or sanitizer diagnostics,
and unchanged-source/compiler/binary fields all true. Whitespace checks passed.
The scenarios cover restoration errors, invalid/unsupported available GOP,
Intel without VMX, AMD with usable SVM, an earlier fatal outcome followed by an
unplaceable attempt, normal fallback cases and explicit profile behavior.

Local evidence remains in build/pma-fd5c-gop-auto/{red,green-gcc,green-clang,
green-clang-sanitized}/{host.log,result.json}, with generated inputs and binaries
beside each receipt. Earlier setup and initial RED evidence remain in their
separate red-compile-setup and red-initial directories.

| Frozen source/evidence | SHA256 |
|---|---|
| loader.c | 5db9d0b7dbd1734d0c8450e4ac4e374eb2b38c014f26cbeec5d472e661fbe745 |
| gop_auto_host.c | e3f43f3b09e5d0a451fc483244c582865a9dc7f2e818a044d8f1e29de23e73a9 |
| test_gop_auto_host.py | a5d120095e7cbb6f4dd3a3223dd36b7bdf606991c292cf815e7f138dd69ad3e1 |
| RED host.log | 1ee47d285e53ef4cbf2365e7512ee0b8a8819349a0b84a6e569807a56ad0b001 |

## Dependencies, remaining work and commit status

No remaining implementation blocker in this narrow caller repair.
Production sources and tests are frozen; root was sent READY with loader hash.
Independent core review approved the exact loader hash. Root's actual
source-bound freestanding Supervisor payload/EFI loader compile passed after
this repair. Physical firmware recovery, live EDID and actual
Windows 98 DOS-to-VMM/USER/GDI acceptance are not established here.
The separately reported Kernel64 reserved-mapping issue remains c957-owned;
this lane does not duplicate that repair. Code commit: `402f2cb`; the separate
reserved-mapping repair was reviewed/imported as `be337fb`.
