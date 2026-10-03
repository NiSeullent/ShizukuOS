# Source-built first-load route (native execution pending)

This increment connects actual guardian admission to Windows98's dynamic VxD
load contract. It does not change SYSTEM.INI, a registry key, a display mode or
the default Display class. A baseline boot on original DOS/stdVGA without the
native guardian and GOP descriptor is refused before SHZGOP.VXD is loaded.

Supervisor hypercall14 accepts RBX=word index0..39 and RCX=version1. It returns
RAX=status, RBX=word and RCX=40 only for the current paused CPL0 Win98 domain,
its actual current VMCS, frozen generation/owner binding, active admitted native
VGA and retained successful guardian grant. Neither CPUID nor guest evidence
booleans admit this capability. Other/absent/stale domains fail. The forty words
are GPE1 magic, version1, count40, domain5, generation, ownerCPU, flags3, BDF,
vendor/device, class, six raw BARs, nonce32B, configuration SHA256 and ROM SHA256.
The native physical VMCS address is never exposed to the guest.

SHZGUARD.VXD is a nongraphics bootstrap. Initialization only locks its own image;
its query checks the actual HC14 words twice, unique F000 SHZLOC1 slot and actual
96-byte GOP descriptor. The descriptor owner/base must match the guardian's
VGA identity/BAR. It retains at most two readonly physical aliases and never
maps the framebuffer or programs PCI/VGA/mode registers. Output aliases are
validated, pinned and compared to their original PTEs before copying under
interrupt exclusion. Failed alias release blocks further queries and unloading. Physical aliases
also forbid dynamic unloading: both bootstrap and target use no delete-on-close
flag and remain resident for the current boot. The bootstrap cannot forget or
recycle its at most68KiB of physical mappings; no VMM automatic cleanup is assumed.
The raw descriptor has no synthetic Supervisor nonce field: binding is to the
current actual domain's admission, matched owner/BAR, and stable live snapshots.

GOPLOAD.EXE holds byte-exact source-built SHZGUARD.VXD and SHZGOP.VXD inputs open
without write sharing. It loads the nongraphics guard using the existing
Win9x CreateFile dynamic-VxD contract, checks its source identity, current
snapshot and the independently staged guardian nonce, then requests loading
SHZGOP.VXD and rechecks the same snapshot. Target uses no delete-on-close flag,
so the next Win16 GOPINST fresh PM16 probe can observe it. A successful CreateFile
handle is load-request evidence; it is not actual GPU, HDA, GDI rendering or
Display default evidence. On any failure after the target load request the tool
leaves the loaded provider retained and reports failure; it never tries an
unproven rollback or unload against an unknown provider lifetime.

The guardian owner must stage the current actual owned-process nonce as the
exact32B file C:\SHZGOP\GPEPOCH.NON on an owned clone after source/hash checks.
Do not manufacture this file or use a saved nonce to claim a native boot. This
utility has no authority to mint a guardian grant. Stage the two VxDs and
GOPLOAD.EXE under C:\SHZGOP; FIRSTLOAD.LOG must not already exist. Guest execution
belongs to the active VM owner. No first-load utility execution occurred here.
Existing Win16 SetupX installation still needs its separate observed Enum path,
actual SETUPX/driver byte pins, backups/readback and fresh loaded-backend query.

Build with first_load/build.py --out <fresh workspace build component> --gop-build
<actual source-built GOP producer directory>. Microsoft SDK files are unnecessary
for this bootstrap; public original ABI thunks and LE packager are reused with
recorded source and tool hashes. Builder records the GOP producer receipt and
exact target VxD bytes. It does not certify unreviewed upstream producer history.
Host tests: first_load/test_guard.py and native_win98/tests/gop_epoch_host.c;
ordinary Supervisor compile.py builds the actual additive HC path. These checks
are component evidence only; actual Windows98 on ShizukuDOS remains unproved.

Interface facts reuse ntwrapper/vxd/REFERENCES.md, its source-built loader control
and original Win98 DDK VMM/DIOC definitions (private SDK is not copied here).
Original Microsoft page-service calling convention reference:
https://www.pcjs.org/documents/books/mspl13/win/w3ddkvxd/ (chapter19).
