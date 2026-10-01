# Native Windows 98 firmware MMIO candidate

This development component supports the goal of actual Windows 98 on ShizukuDOS.
It is not a completed Windows 98 boot or a replacement for its DOS foundation.
The installed Windows control still uses original Microsoft DOS. Modern apps,
full acceleration and drivers remain unverified in this native domain.

The preceding actual capture passed the former MTRR MSR failure and stopped on
an EPT read violation at GPA `FEE00030`. The paused instruction was
`A1 30 00 E0 FE` (`MOV EAX,[FEE00030]`). SeaBIOS 1.17's
[mptable_setup](https://github.com/coreboot/seabios/blob/rel-1.17.0/src/fw/mptable.c)
unconditionally reads the LAPIC version there. Its
[smp_scan](https://github.com/coreboot/seabios/blob/rel-1.17.0/src/fw/smp.c)
separately checks CPUID APIC and keeps a single CPU when APIC is absent.

This candidate defines only the exact `FEE00000–FEE00FFF` bus window as absent
hardware returning all ones. A private aligned page supplies those bytes under
an actual 4 KiB EPT mapping with read permission and UC memory type. Writes and
instruction fetches have no EPT permission. The software memory reader applies
the same span and write restrictions; all other unknown GPAs remain unmapped.
This profile has no LAPIC registers, interrupt delivery or active APIC claim.
CPUID APIC stays hidden and APICBASE stays zero. No PCI host bridge is fabricated.

An 8-bit input at configured SeaBIOS debug port `0402` now returns the `E9`
presence signature, matching the configured
[QEMU debugcon device](https://github.com/qemu/qemu/blob/v10.0.0/hw/char/debugcon.c).
Its existing output path already writes actual guest diagnostic bytes to serial.
Other input widths and ports retain their existing behavior.

Host controls compile and execute the production domain constructor and EPT
mapper under strict GCC and Clang ASan/UBSan. They cover full shadow-ROM bytes,
MMIO boundaries, read-only UC leaf flags, adjacent unknown addresses, unchanged
RAM/high-ROM permissions, overlap/alignment rejection, pool exhaustion, debug
signature width and unchanged ATA/generic-port routing. VMX is modeled in these
host controls. Real Windows 98 acceptance requires a fresh owned VM capture;
host compilation alone does not establish it.

The earlier observer, whole 256 KiB ROM shadow and native MTRR-absent CPUID
correction are preserved. Previous failed captures remain immutable. Private
media, installed disk bytes and firmware dumps are excluded from this document
and from the public source handoff.
