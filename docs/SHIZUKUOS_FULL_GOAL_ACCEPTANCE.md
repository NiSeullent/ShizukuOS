# Windows98 modernization: full acceptance requirements

The active user objective has fifteen requirements. They supplement the
[original integrated architecture](INTEGRATED_ARCHITECTURE.md) and the
[installation contract](SHIZUKUOS_ARCHITECTURE_CONTRACT.md); component milestones
do not replace the complete objective. Windows98 VMM, VxD, Win16/Win32, USER/GDI
and Explorer remain the product OS. ShizukuDOS replaces MS-DOS and supplies
shared modern hardware services through auxiliary Kernel32/Kernel64 domains.

The following are acceptance gates, not a statement that they have passed.
Source paths identify existing implementation starting points. Tests must
execute the production code and evidence must bind the tested artifact, source
revision, machine, input disk, result and cleanup to the same run.

| User requirement | Existing implementation and next authoritative evidence |
| --- | --- |
| 1. Common modern driver framework and basic drivers | `drivers/common/`, `shizukudos/kernel64/ntdrv*` and `ntwddm/`: real resource ownership, discovery, PnP/power transitions, requests/completions and teardown. Qualify a declared supported driver/device matrix with actual Windows98 frontend calls and real backend transfers. Unsupported contracts must return errors. |
| 2. Laptop sensors, trackpad, power and ACPI | `drivers/shz_laptop/`: enumerate actual firmware/device resources; observe keyboard/pointer delivery in native Windows98, sensor readings, battery/AC state, suspend/resume and resource revocation on qualified devices. Parser or mocked transport success alone does not qualify a laptop. |
| 3. Cooperate with other running sessions | Use the existing private coordination mailbox and separate worktrees. Respect the current main/VM/private-media owners; hand over exact reviewed source commits and original verification records. Never commit private mailbox contents. |
| 4. User accounts | `shizukudos/accounts/`, `kernel64/sysk32_auth.c`: persistent protected enrollment, real native Windows98 login integration, distinct subjects/profiles and sessions. Test restart, account switching, failed authentication and cross-account access. Volatile Kernel64 accounts remain an intermediate foundation. |
| 5. elevate command | `win64/apps/elevate/`: authenticate one exact executable/command and create a fresh elevated child; parent authority and existing handles remain unchanged. Verify failed, canceled, expired and successful requests through the Windows98 bridge. A PE64 command cannot be described as directly executable by Win98. |
| 6. Access separation and sandboxing | Enforce process, token, object and file-handle rights in the service authority, including duplicated reduced-right handles, mapped files and asynchronous requests. Test both authorized work and denied attempts. Verify a sandbox cannot regain privileged handles, alter shared state or access forbidden devices/network. |
| 7. Improved shell and animated wallpaper | `ntwddm/win98/personalization/` and existing native theme components: real Explorer desktop, usable settings, procedural animation and static fallback. Observe pause, battery, suspend, minimize, close, bounded animation and API failure behavior in Windows98. Independent framebuffer shells remain recovery/development tools. |
| 8. Settings, elevation authentication and enrollment | Connect persistent per-user settings to authenticated subject selection and the native Windows UI. Verify registration authority, failure throttling, secret clearing, reboot persistence and authentication failure without unintended state changes. A masking control alone does not provide a secure desktop. |
| 9. Security level | State the actual threat boundary. Test unauthorized user/service requests, malformed structures, stale identities, handle reuse and failures during publication. Legacy Windows98 shared-address-space processes are not automatically isolated by Kernel64 policy. Qualify additional protection where it is implemented. |
| 10. Core isolation | Existing AP/backend worker code: verify separation of worker address spaces, memory ownership, interrupt/resource access and request completion under faults. CPU affinity, a separate core or a fixed-job AP service alone does not prove hardware memory or DMA isolation. |
| 11. Multi-agent operation | Preserve disjoint implementation ownership and reproducible integration. Native independent workers require actual simultaneous progress and completion evidence; development subagents and runtime workers are separate capabilities. |
| 12. 64-bit applications | Execute real x64 code through Kernel64 services from a Windows98-visible process/window; observe input, rendering, file/network work and normal process completion. Meaningful Chromium, Legcord/Discord, current open-source Office and Steam functions remain explicit earlier requirements. Import presence or a toolbar is insufficient. |
| 13. ShizukuFS | `shizukufs/` and `kernel64/sfs_mount.c`: keep versioned formats, real Windows98 filesystem integration, durable write ordering, crash recovery, ownership/access checks and large-file behavior. Current v1 uses ext4's on-disk format; v0 is a separate deprecated experiment. A new independent format must be explicitly implemented and migrated, not silently asserted. Any superiority to NTFS requires named comparable workloads, identical hardware/caching/durability settings and measured results. |
| 14. Modern and classic Windows shell | Preserve Explorer, USER/GDI windows, icons and taskbar; verify both styles repaint real unrelated applications, persist per user and restore after cold boot. System-palette changes are distinct from complete non-client visual styles or application functionality. |
| 15. ISO | Produce the actual installer from coherent source/artifact receipts; boot its shipped configuration in a VM, install onto an owned target, independently verify written files and cold-boot Windows98 on ShizukuDOS with the default GOP driver. Publish permitted public media/checksums through nginx at `m98.nyase.kr` and verify the homepage and full download externally. Microsoft media, product keys and installed private disks remain private. |

The earlier acceleration/driver/application, default GOP graphics, Dead Screen
and Korean/English official website requirements remain active. Genuine
Windows98 replacement boot is the prerequisite for final native integration
claims. Original Microsoft DOS control boots, host tests, static import audits,
standalone Kernel64 app tests and source/add-on ISOs retain their exact scope.

Each implementation handoff records what changed, what actually ran, failures
retained, the proof's scope and the next native acceptance gate. Historical
resource thresholds belong to their recorded experiment. New work follows the
current owner's explicit capacity admission without retroactively weakening
old evidence or changing another session's running inputs.
