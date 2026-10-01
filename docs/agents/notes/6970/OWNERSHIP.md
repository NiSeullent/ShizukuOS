> Local 6970 audit/planning draft preserved after cross-chat ownership discovery. Canonical docs/agents master files are owned by session163f in /root/Win98-Modern-pma-20261002. This draft does not reserve another session's files. See ../../status/6970-master.md for current scope.

# PMA integration ownership

Observed orchestration date: 2026-10-01. 6970 isolated worktree: /root/Win98-Modern-theme-6970, branch codex/theme-integration-6970. Main publisher worktree: /root/Win98-Modern-main-integration-20261001. Audit findings must name the revision or file hashes read.

| Active role | Agent | Assigned scope | Writable source |
| --- | --- | --- | --- |
| Master/integration | root | User architecture, firmware/display/runtime-wrapper source audit, final review and own source commits | docs/agents/notes/6970 and status/6970-master.md; Kernel32 deadline tests only while production ownership is coordinated |
| Core Kernel Lead | main_publish_inventory | Completed source audit; actual Kernel32 deadline fixture/runner preparation | tests/test_sched_deadlines_k32.c and .py; accepted subsequent deadline-only sched.c/k32.h/helper hunks after actual RED |
| Windows 98/Validation Lead | coordination_audit | Completed storage/Windows bridge audit; independent Kernel32 plan/fixture review | Read-only after frozen repair handoff |
| Disk resource lead | disk_optimizer_phase2 | Exact approved inactive-copy allocation sharing and read-only candidate proposals | Approved allocation metadata only; no source, logical media, historical receipt or peer VM writes |
| Main/site/ISO publisher | existing integration session | Three-way source integration, merged-source validation and official distribution | Its own main/index/site/artifact activation; other agents do not write those paths |

Concurrency currently permits four active agents including the master. Hierarchical scheduler/SMP/sync, GOP/console/VGA, VMM/ABI/bridge, wrapper/runtime and validation children are assigned as slots become available. The role list is not evidence that inactive or uncreated agents executed work.

## Frozen storage handoff

Exactly seven public files belong to the completed root storage lane:

- shizukudos/kernel64/fat32.c
- shizukudos/kernel64/fat32.h
- shizukudos/kernel64/disk.c
- shizukudos/tests/test_fat32_rename_failures.c
- shizukudos/tests/test_disk_rename_quarantine.c
- shizukudos/tests/test_fat32_rename_failures.py
- docs/FAT32_RENAME_CHECKPOINT_6970.md

Apply the repair diff through a three-way merge. Preserve main's four-sector read_many/read_batch API, block max-sector binding, VFS volume registration/common flush and interactive raw-target no-mount guard. Keep both read_batch and undo/recovery members. Whole-file replacement from the historical lane would remove independent main work.

## Required agent status

Each assigned agent records scope, exact owned paths, decisions, dependencies, blockers, actual commands/tests and exit results, remaining work and commit SHA. A read-only auditor records no test execution rather than adopting historical passes. The master keeps public summaries; private media, raw evidence and attachment files remain outside public commits.

Do not edit another agent's source, index, live VM or historical evidence. After a child completes its task, a separate reviewer checks cross-subsystem effects before integration.

## Current peer ownership correction

Canonical master documents belong to session163f. That session owns Kernel64 scheduling, UEFI/GOP selection and existing VxD transport. Fada owns the new event/completion payload and its dispatch hunks. Fd5c owns shared channel/layout/doorbell/video validation and independently confirmed the separate Kernel32 process-owner publication race; session163f retains its user.c-only repair. C957 owns common atomics, NT spin-lock operations, framebuffer validation/clipping and the capability manifest; DOS_GATE and arbitrary GOP BitMask support remain unimplemented/unclaimed.

Canonical session163f acknowledged our Kernel32 deadline helper/arithmetic and storage lane in its ownership document on2026-10-01. Our deadline expressions/wake-width change is separate from its user.c process-owner publication repair. Production deadline edits await actual unchanged-production RED and resource admission. Never overwrite a peer scheduler file during integration.
# Native bridge linker-data correction checkpoint

The 6970 root owns the native build plan, workflow and actual-evidence
handoff. The modern-app agent owns the new `pe_link_script_6970.py` and
the ordinary bridge `build.py` integration. The disk agent owns
`build_native_pe32_guarded_6970.py`. The coordination agent independently
reviews the shared helper, effective scripts and final PE placement.
These assignments preserve production native/table/SDK and other-chat
DOS/VMM/current Kernel32 SMP/main/site/ISO ownership.

Actual third attempt at dc4a0c9 completed four object compiles, including
the SDK fixture, both links and 22 COFF controls. Its overall instruction
gate remains FAIL because linker-generated CTOR/DTOR data occupies `.text`.
The successor moves only those blocks through the actual selected linker
script; no scanner waiver, PE rewrite or native/TLS acceptance is assigned.

The next handoff step preserves that completed build's original scope. Root
owns workflow/plan edits; modern-app owns only new
`ntwin32/legacy_provider_bridge/seal_native_handoff_6970.py`; coordination and
disk agents independently review exact envelope/resource boundaries. Existing
14 build sources, guard, native/table/probe and SDK fixture stay frozen. A
selected fresh hosted run may retain only source-bound project artifacts and
explicit source/licence files. The private NAS evidence lane receives no
compiler binary, and no peer loader/DOS/VMM/main/site/ISO file is assigned here.
