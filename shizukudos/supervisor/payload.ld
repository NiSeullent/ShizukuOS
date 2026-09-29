/* SPDX-License-Identifier: GPL-2.0-only
 * Fixed-address Supervisor payload: SHZ_PAYLOAD_ENTRY = region base + 0x1000.
 * Only file-backed sections are copied by the loader; entry.asm clears .bss. */
ENTRY(_start)
SECTIONS
{
    . = 0x04002000;
    .text : {
        *(.text.entry)
        *(.text .text.*)
    }
    . = ALIGN(16);
    .rodata : { *(.rodata .rodata.*) }
    . = ALIGN(16);
    .data : { *(.data .data.*) }
    . = ALIGN(4096);
    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss.stack)
        sup_stack_top = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4096);
        __bss_end = .;
    }
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
