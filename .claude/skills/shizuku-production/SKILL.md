---
name: shizuku-production
description: Implement the ShizukuOS root platform and ShizukuOS Core, native desktop, execution environments, boot, installation, drivers and application compatibility under actual-system acceptance.
---

# ShizukuOS production implementation

Read the workspace AGENTS.md and docs/SHIZUKUOS_ARCHITECTURE_CONTRACT.md first.
The latter contains the user's authoritative Absolute Architecture Definition.
ShizukuOS is the root platform; ShizukuOS Core contains ShizukuDOS, the kernel
and driver layers, VM services, Linux subsystem and native runtime. Historical
implementation origins do not define system boundaries. Consult
INTEGRATED_ARCHITECTURE.md, SHIZUKU_HYBRID_TRANSITION.md and
SHIZUKUOS_FULL_GOAL_ACCEPTANCE.md for source relationships and actual acceptance.

Before coding, inspect existing production paths and classify each feature as
EXISTS, PARTIAL, MISSING, BROKEN, REUSABLE or REQUIRES REFACTOR. Extend an
appropriate implementation. The existing win64/apps/shizuku_shell executable
is the native shell; conceptual shell filenames are not a request for duplicate
programs. Slade (default), Flute and Jade require theme data and live shell
propagation, not only fixed palettes. ShizukuVM owns its ShizukuOS API. chkrnl
linux/msdos modes, SHZLB.sys/Linux sandbox/POSIX/ShizukuLB, Nix-backed pkgs and
managed X windows are Core execution paths. Terrasphere uses WebKit; reuse
media/image services for Muzik/Sapphire and a suitable existing Folio engine.
Inspect the available volume1/shizukuossound NAS source before replacement assets.

Implement actual callers, providers, exports and build wiring. Validate
pointer/length arithmetic, owner/generation lifetime and teardown. Deny absent
or revoked authority truthfully; never infer it from saved receipts or JSON
booleans. Preserve existing strict installation profiles and optional legacy
compatibility contracts. Windows x64 and System V differ; kernel code has no
red zone. Preserve external provenance and licenses. Do not repeat side effects
with another backend after denial or partial failure.

Use useful parallel coding agents, disjoint source writers and serialized
shared-index commits. Route difficult kernel/install/authenticated protocol
and app ports to Opus5.5; bounded adapters/docs can use Sonnet5.5. Adjust effort
to complexity and record actual execution. Implement code, compile affected
production units and run small meaningful controls before coordinating one
current integrated VM cohort. Avoid repeated full suites without new cause.
Preserve other sessions' changes, VMs, media and actual failures.

Prioritize bootable installable64-bit ShizukuOS with recognized working drivers.
All existing account/security/filesystem/modern app goals and the full desktop,
Linux, VM, native app, sound and game requirements remain active. Only features
with an executable production path tested inside actual ShizukuOS are complete.
Host checks, screenshots, mock transports and built images have narrower scopes.
Keep private .codex/task-state.md for long work. Never publish private Windows
media, guest disks, machine paths or credentials. Final permitted ISO distribution
uses nginx m98.nyase.kr after applicable release gates, with external access checks.
