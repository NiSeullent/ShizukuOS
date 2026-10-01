# Opt-in original Windows 98 DOS control capture

This isolated helper measures original Windows 98 on its existing IO.SYS/MS-DOS
path. It creates a new owned raw clone, prepends a source-built passive DOSVMM
TSR to the clone's AUTOEXEC, and observes a bounded QEMU instance. It does not
replace MS-DOS and is not ShizukuOS or modern-application acceptance.

Every input is explicit. The existing 2 GiB installed disk must match its own
receipt's SHA, active FAT32 geometry and MBR/VBR pins. Original boot files are
hashed before injection and after the VM, and the original disk and receipt are
checked before/after. Original images, boot files and running VMs are untouched.
Only the disposable clone receives DOSVMM.COM and an AUTOEXEC prefix. Its prior
AUTOEXEC is preserved verbatim. Original SYSTEM.INI and drivers are not edited.

`--reflink` is an explicit Linux FICLONE requirement. The current implementation
acquires an actual source read lease during clone preparation, refuses existing
writers and lease breaks, verifies distinct inodes and reads the complete target
SHA. Unsupported clone filesystems fail without a dense fallback. The default
sparse helper retains its existing source-stability/full-SHA behavior; it does
not assert an exclusive source read lease.

The controller uses one QMP connection to its own child, disables network and
VNC, uses fresh firmware variables, and captures CPU state and PNGs. It retains
20 GiB free space, a 1 MiB trace cap and a maximum 300-second run. In the current
source, fresh-QEMU `query-blockstats` device `win98` total `wr_bytes` is checked
monotonically against a sampled 256 MiB write budget, including early startup
writes. File allocation growth is recorded separately; shared COW extents cannot
attest actual writes. This is a sampled fail-closed gate, not an I/O timing or
hard instantaneous write-rate guarantee.

A controller input request is limited to Enter, a contiguous sequence 1..8, the
purpose `continue-known-optional-device-warning`, and the SHA of a screenshot
captured by that same owned run. An operator must inspect the actual warning
first. No general monitor-command interface or automatic success input exists.

Frozen earlier actual control evidence is retained privately. Its older runner
reached the Korean Explorer desktop/Start taskbar/Welcome page and captured four
complete pairs: startup 1605 and DOSMGR 1607 requests CX=0, CX=4, CX=1. Original
before/after disk, receipt and five boot-file hashes matched. That older runner's
COW allocation counter did **not** validate the sampled write budget, and its
source lock was advisory; those limitations are preserved in a separate visual
review. Later source corrections are host-test results, not a replacement of
that frozen VM evidence and not a new VM result.

The current focused host checks cover actual COW isolation, an incompatible
source writer, an actual Linux lease break, incorrect pins, existing targets,
clone failure without fallback, qualified Enter requests and strict write-counter
validation. The DOSVMM parser/COM machine controls remain independently frozen.
No original Windows media, guest images, COM/object binaries or private raw
register captures belong in a GitHub source handoff. ISO artifacts remain on
m98.nyase.kr only. Actual ShizukuDOS Windows 98 startup/GUI, native drivers,
acceleration and all required modern applications remain unfinished gates.

Run the focused host checks from the repository root:

```sh
python3 -B -W error::ResourceWarning -m unittest tools.tests.test_control_input tools.tests.test_control_reflink tools.tests.test_control_budget
```

Use `tools/run_original_dos_control.py --help` for the explicit private input,
source-helper, firmware, QEMU, checksum and fresh-output requirements. The helper
must be an opt-in control, never a default Windows 98 or ShizukuOS startup hook.
