/* SPDX-License-Identifier: GPL-2.0-only */
OUTPUT_FORMAT(elf32-i386)
OUTPUT_ARCH(i386)
ENTRY(kernel_main)
PHDRS { code PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
SECTIONS {
    . = 0x02010000;
    .text : { KEEP(*(.text.entry)) *(.text .text.*) } :code
    .rodata : { *(.rodata .rodata.*) } :code
    . = ALIGN(4096);
    .data : { *(.data .data.*) } :data
    .bss : { *(.bss .bss.*) *(COMMON) } :data
    __payload_end = .;
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
    ASSERT(__payload_end <= 0x020ff000, "Payload overlaps before-output guard")
    ASSERT(0x02180000 + 4096 <= 0x021f0000, "Output/guards overlap 64KiB stack")
    ASSERT(0x02200000 - 0x02000000 == 2097152, "EFI reservation must be 2MiB")
}
