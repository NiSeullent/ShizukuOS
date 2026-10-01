> Local 6970 audit/planning draft preserved after cross-chat ownership discovery. Canonical docs/agents master files are owned by session163f in /root/Win98-Modern-pma-20261002. This draft does not reserve another session's files. See ../../status/6970-master.md for current scope.

# PMA integration status

Snapshot: 2026-10-01. This document separates source inspection, component execution and final Windows acceptance.

| Area | Current evidence | Remaining acceptance |
| --- | --- | --- |
| User architecture | PMA specification and later Windows-first principles read in full and sent to all three active child agents | Apply the principles to every new implementation and merged-source review |
| Main source | Read-only main snapshot a648e9baa1c57289d50e58d3380827bd9239bc52; native device/startup changes came from 6d860bf | Source snapshots do not establish native Windows boot or PMA integration |
| Existing schedulers/SMP/sync | Core Kernel Lead actual-source audit completed; finite-deadline overflow/truncation identified | Reuse boundary, failing tests, real native preemption and CPU-local acceptance |
| DOS/VMM/VxD/channel | Windows 98/Validation Lead actual-source audit completed; replacement boot and reply lifetime gaps identified | Actual replacement boot, bridge lifecycle and wait/completion evidence |
| GOP/display/wrapper infrastructure | Existing validated RGB/BGR handoff, Kernel64 GOP backend, DOS text-to-GOP and wrapper interfaces inspected | Safe high-resolution mode/EDID policy, bitmask support, dynamic recovery console, on-demand video and actual Windows display path |
| FAT32 rename/disk repair | Actual unchanged-production RED; final HOST/SAN PASS, 1378 trials and38 bridge checks per mode | Three-way main merge retaining independent changes, exact merged closure regression, full VFS/NT/native paths |
| Global Windows theme source | Own source30057289 pushed; actual native global two-boot proof remains pending | Actual ShizukuDOS-backed Windows global theme/cold-boot/visual/lifecycle acceptance |
| Disk optimization | Separate exact allocation-only sharing; historical logical contents and failures preserved | Volatile shared-host free space is sampled at each build/VM admission; potential savings are not credited |
| Whole product | Incomplete | Actual Windows98 desktop and service return path, required modern apps/drivers/APIs, stress and final official ISO |

The final storage receipt SHA-256 is
6d88ef2a5267446a0fb140f7101a294ba9e73df601d1d6944c10f1a927abd1dc.
All ten actual commands exited zero, source closure matched, aggregate4,141,873B,
minimum observed free21,514,727,424B, resource failure absent, native execution false.
[Full repair checkpoint](../../../FAT32_RENAME_CHECKPOINT_6970.md) preserves the actual failed and passing attempts.

Main source changes, standalone component execution, an original-Microsoft-DOS Windows control and complete product acceptance are different evidence boundaries. Final integrated acceptance is pending. No ISO or modern-app completion is inferred here.

Kernel32 deadline source is repaired in6dfc4b574a023c4e4277bbc357b876cfbd82f70d.
Actual hosted unchanged-production RED reproduced22 failures across76 checks.
The identical frozen production-C fixture then passed76 HOST and76 ASan/UBSan
checks; all6 actual GREEN commands exited0, eight-file closure matched and no
resource failure occurred. This does not establish native i486 linking, context
switch assembly or Windows/VMM execution. [Evidence](K32_DEADLINE_PLAN.md#actual-hosted-red-and-green).
Canonical master163f acknowledged this lane separately from its user.c
process-owner publication repair. Combined source/build acceptance is pending.

[DOS executor boundary audit](DOS_GATE_BOUNDARY_AUDIT.md) confirms audited main
lacks an actual backend-worker→DOS executor. Canonical master163f acknowledged
the audit and assigned its Windows/NT lead that boundary; replacement boot
stays with master. Implementation/acceptance remains unverified; independent
common locks do not establish DOS replacement.
