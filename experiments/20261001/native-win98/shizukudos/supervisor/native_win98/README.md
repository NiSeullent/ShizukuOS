# Opt-in installed Windows 98 domain

This candidate boots an installed, privately copied 2 GiB Windows 98 disk inside
the Supervisor. The existing DOS/default boot path remains the default. Opt-in
requires `mode=supervisor` and an exact 16-byte `WIN98CFG.BIN` containing the
versioned magic, 128 MiB RAM profile and zero reserved field. An actual 256 KiB
SeaBIOS ROM supplies the reset vector, IVT, BIOS data area and boot flow.

The constructor creates an actual VMCS and EPT mapping for RAM and the real ROM,
then initializes a primary ATA PIO device backed by the owned disk bytes. ATA
read/write/identify/status and IRQ14 use the same device model as the host
fixtures. Sector writes publish only after all 512 bytes arrive. Unsupported
commands return an ATA error. REP IN/OUT emulates bounded real elements,
segment access, 386 non-PAE page translation, page faults and A/D updates before
port side effects. PIC cascade support is enabled by actual external IRQ
raises; the original timer-only path stays unchanged.

`build_candidate.py --out <fresh-owned-directory>` validates inputs only.
Adding `--build` constructs a separate 2304 MiB ESP, exact owned disk copy,
SeaBIOS/config files, native K64 and genuine tiny Win64 runtime. Every installed
payload is read back in full, and the original cold disk is read-leased and
hashed before/after. The command never executes a VM. It preserves the 17 GiB
disk floor plus its bounded preparation budget and preserves failed output.

The ordinary native foundation has already run successfully under root-owned
VM execution. This opt-in Win98 candidate has compiled and passed host device,
paging, constructor and lease fixtures. Those results do not establish that
Windows 98 boots, maps a VMM channel, renders a desktop or runs current apps.
The next gate is a root-owned, offline 4096 MiB L1 with fresh ESP/VARS clones.
Display currently renders actual B8000 text. VGA graphics, input and installed
Win98 VMM integration still require actual boot evidence and further generic
device work. The shared ABI and Kernel64 sources are unchanged by this stage.

The system SeaBIOS binary is pinned independently of the peer's source checkout.
Original and compiled-source SHA receipts identify all consumed bytes. The
constructor host fixture uses explicit VMCS/EPT callbacks; it never executes
VMX. Device/paging fixtures execute the actual production C bodies on host
memory. They provide semantic checks, not a native Win98 boot claim.
