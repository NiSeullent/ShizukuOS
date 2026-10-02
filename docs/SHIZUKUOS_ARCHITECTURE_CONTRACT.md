# ShizukuOS: Windows 98 on ShizukuDOS

The user reaffirmed this original architecture on 2026-10-01:
**ShizukuDOS replaces MS-DOS beneath genuine Windows 98.** The public product
name is ShizukuOS. Kernel32 and Kernel64 are ShizukuDOS components for that
Windows 98 system. The Supervisor, NT/VxD wrappers and graphics components
support the same system.

ShizukuDOS supplies the DOS-compatible boot and resident services that Windows
98 needs. The target boot chain reaches the genuine Windows 98 `WIN.COM`, VMM,
drivers and desktop with those services supplied by ShizukuDOS. Kernel32 and
Kernel64 extend the system's application execution; their channels, graphics
and normal process completion must be demonstrated from that same Windows 98
boot. Preserve DOS compatibility, BIOS/CSM support and the approved firmware
bridge while implementing this chain.

## Required evidence for the final installation

1. A fresh installation from the user's protected original Windows 98 media
   using the supplied USB combination or integrated installer ISO. Verify the
   unchanged original copy and each extension's source, version and checksum.
2. A recorded ShizukuDOS volume boot, with no original MS-DOS `IO.SYS` execution,
   reaching `WIN.COM`, VMM and a usable Windows 98 desktop. Observe the required
   INT 2Fh/DOSMGR, resident memory and MCB behavior along this boot chain.
3. A real Windows 98 VxD request, Supervisor channel transfer, Kernel32/Kernel64
   execution and reply on this boot, including the parent-owned application's
   actual normal exit. Bind the request, reply, process and visible result to
   the same private disk, fresh nonce and source revision.
4. Working Classic and ShizukuOS system themes, actual repaint of unrelated
   native windows, saved settings and restoration across cold boots.
5. Meaningful native functionality checks for the selected current
   Legcord/Discord, Signal and open-source Office applications, with actual
   DirectX, Direct2D, DirectWrite and OS TLS 1.3 behavior.
6. The resulting installation ISO and checksum available through
   <https://m98.nyase.kr>, and independent outside-host HTTPS verification of
   the official homepage and download. GitHub contains public development
   sources and permitted patches; private media and binaries stay outside it.

## How to interpret development results

Keep OEM Windows 98 control boots, host tests, static PE/import checks,
standalone domain boots and channel discovery as separately scoped results.
Each can validate a prerequisite. Final acceptance requires the positive
replacement boot and integration chain above. A VMCS initialized at the
SeaBIOS reset vector over an existing installed raw disk establishes a native
domain entry. Channel metadata or a successful VxD open/query/close establishes
the observed protocol boundary. Record separately whether the replacement
boot, positive application execution and actual GUI reply occurred.

The global-theme selector and observer in `ntwddm/win98/` currently provide an
OEM control lane. Their compiler, host, registry, palette and process evidence
must retain that scope until they run successfully on the replacement boot.
An unobserved process exit, missing raw framebuffer, failed Korean text result
or missing modern application function remains an incomplete acceptance gate.

Use a new plan and nonce after a failure or source change. Preserve original
media, base disks and both successful and failed evidence; keep the unchanged
20 GiB free reserve, 256 MiB cumulative private COW limit and 16 MiB aggregate
host-output limit. A different machine rebuilds the pinned public sources and
creates new evidence rather than editing historical hashes.
