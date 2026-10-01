> Local 6970 audit/planning draft preserved after cross-chat ownership discovery. Canonical docs/agents master files are owned by session163f in /root/Win98-Modern-pma-20261002. This draft does not reserve another session's files. See ../../status/6970-master.md for current scope.

# PMA integration status

Snapshot: 2026-10-01. This document separates source inspection, component execution and final Windows acceptance.

| Area | Current evidence | Remaining acceptance |
| --- | --- | --- |
| User architecture | PMA specification and later Windows-first principles read in full and sent to all three active child agents | Apply the principles to every new implementation and merged-source review |
| Main source | Read-only main snapshot a648e9baa1c57289d50e58d3380827bd9239bc52; native device/startup changes came from 6d860bf | Source snapshots do not establish native Windows boot or PMA integration |
| Existing schedulers/SMP/sync | Core Kernel Lead actual-source audit completed; finite-deadline overflow/truncation identified | Reuse boundary, failing tests, real native preemption and CPU-local acceptance |
| Kernel32 IPC receive integration | Committed canonical receive budget imported6cceb118; own-header HOST365/SAN365 and i486 object PASS atf5e58113; fresh combined K32 compile/link PASS | Native scheduler/VMM/DOS and actual cross-domain request/return acceptance |
| DOS/VMM/VxD/channel | Windows 98/Validation Lead actual-source audit completed; replacement boot and reply lifetime gaps identified | Actual replacement boot, bridge lifecycle and wait/completion evidence |
| GOP/display/wrapper infrastructure | Existing validated RGB/BGR handoff, Kernel64 GOP backend, DOS text-to-GOP and wrapper interfaces inspected | Safe high-resolution mode/EDID policy, bitmask support, dynamic recovery console, on-demand video and actual Windows display path |
| FAT32 rename/disk repair | Actual unchanged-production RED; final HOST/SAN PASS, 1378 trials and38 bridge checks per mode | Three-way main merge retaining independent changes, exact merged closure regression, full VFS/NT/native paths |
| Global Windows theme source | Own source30057289 pushed; actual native global two-boot proof remains pending | Actual ShizukuDOS-backed Windows global theme/cold-boot/visual/lifecycle acceptance |
| Native ANSI SSPI provider binding | New explicit private M98SSPI profile137b146; actual RED423/651 then identical HOST651/SAN651 PASS | Native x86 DLL/ROOT, real credential/TLS, OS/K64/VMM routing and required application execution |
| Required modern app versions | Official metadata rechecked at2026-10-01T21:34UTC: current own Legcord1.3.0, Signal8.28.0 and LibreOffice26.8.0 pins match latest stable versions and artifact metadata | Actual required Windows98 application functionality remains unverified |
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
process-owner publication repair. The bilateral publication/deadline source now passes an actual hosted K32/standalone K32/stub compile/link proof at65f5c7e; canonical main and Windows/VMM runtime acceptance remain pending. See the linked evidence below.

[DOS executor boundary audit](DOS_GATE_BOUNDARY_AUDIT.md) confirms audited main
lacks an actual backend-worker→DOS executor. Canonical master163f acknowledged
the audit and assigned its Windows/NT lead that boundary; replacement boot
stays with master. Implementation/acceptance remains unverified; independent
common locks do not establish DOS replacement.

The scoped WinHTTP URL parser repair7c174d9 has actual unchanged-production
RED (25 failures across110 checks), followed by the identical fixture passing
110 HOST and110 ASan/UBSan checks. Root and an independent agent verified the
actual logged receipt and source bindings. [Checkpoint](WINHTTP_URL_CHECKPOINT.md#actual-identical-fixture-green-and-scoped-import).
Native Windows, HTTP/TLS-provider execution, modern applications and canonical
main import remain separate acceptance work.

The existing native provider module was restored exactly from canonical source,
then extended with a narrow SECUR32→M98SSPI ANSI binding. Actual unchanged-source
prospective RED423/651 was followed by identical HOST651 and Clang ASan/UBSan651
PASS at137b146. Full table/export validation and cached module lifetime retain
the original five get_api_table paths. [Source and actual proof](NATIVE_SSPI_PROVIDER_PLAN.md#actual-identical-fixture-green-and-scoped-integration-handoff).
The fixture never invokes credentials or TLS and does not establish native DLL,
Windows98, Kernel64, OS registration, application or final ISO acceptance.

Canonical's tested receive-budget fix was imported from its exact committed
three-file scope, retaining the different own IPC header. A first own fixture
compile warning was preserved and fixed without disabling warnings or changing
production. Fresh own-header HOST365/SAN365 and an ELF32 compile-only object
passed; the same source also passed deadline76/76 and refreshed43-command
combined compile/link. [Exact source, failure and fresh receipts](K32_IPC_CLOSURE_IMPORT.md#actual-own-header-green-and-refreshed-combined-build).
These host/compiler results do not establish actual PMA/VMM/cross-domain
execution. Historical peer receipts and current own proof stay separate.

An independent read-only freshness check matched the existing manifest's
Legcord1.3.0, Signal8.28.0 and LibreOffice26.8.0 to their official latest stable
metadata, including artifact size and digest. Sources: [Legcord official release](https://api.github.com/repos/Legcord/Legcord/releases/latest),
[Signal release](https://api.github.com/repos/signalapp/Signal-Desktop/releases/latest)
and [Windows update metadata](https://updates.signal.org/desktop/latest.yml),
[TDF announcement](https://blog.documentfoundation.org/blog/2026/08/26/libreoffice-26-8/)
and [official artifact metadata](https://download.documentfoundation.org/libreoffice/stable/26.8.0/win/x86_64/LibreOffice_26.8.0_Win_x86-64.msi.mirrorlist).
Manifest SHA30fbbdd7d484f17a03cbe54923dade512efa6074ad82a90d15f05a80d30c3a54
keeps all three functional_pass_claimed flags false. Saved Signal timeout,
limited Legcord interaction and LibreOffice CreateDirectoryExW failure do not
establish application success. No binary was downloaded or app executed by
this metadata check.

Fresh outside check36919558655 at maina648 observed the official homepage,
without active VNC or a challenge, in all four normal-Chrome-identity browser
routes. All four direct HTTP requests returned403, so the check correctly
retains overallFAIL and external acceptancefalse. No ISO was supplied to or
verified by that run. Browser observation alone does not certify distribution.

The separate disk agent froze a complete RAM evidence gate at
2026-10-01T21:44:03.873734 UTC. Root independently checked all 139 source
files twice, their immutable identities, 39 frozen directory identities,
the exact current 43-entry/140-file listing and the gate itself. Current
pending evidence is 9,654,228 B. Conservative persistence admission requires
21,485,541,804 B; observed disk availability was 13,040,803,840 B, leaving
8,444,737,964 B insufficient. The 12,807 B command is already in the source
inventory; the 50,209 B gate plus command fits the reserved 64 KiB budget.
Gate SHA256:
34c062b67e7f954504b9ddf64648d0466d1ccb4f03bce2989194c2bb2a5db270.
The gate remains BLOCKED. No local compiler, VM, physical evidence copy,
deletion or new cleanup credit follows from this check. Older gates and
proofs retain their original scope and bytes.
