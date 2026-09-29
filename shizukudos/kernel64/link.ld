/* Kernel64: linked in the higher half, loaded by the Supervisor at guest-physical 1 MiB. */
ENTRY(_start)
SECTIONS
{
    . = 0xFFFFFFFF80100000;
    .text : AT(0x100000) { *(.text.entry) *(.text .text.*) }
    . = ALIGN(4096);
    .rodata : AT(ADDR(.rodata) - 0xFFFFFFFF80000000) { *(.rodata .rodata.*) }
    . = ALIGN(4096);
    .data : AT(ADDR(.data) - 0xFFFFFFFF80000000) { *(.data .data.*) }
    . = ALIGN(4096);
    .bss (NOLOAD) : { __bss_start = .; *(.bss .bss.*) *(COMMON) __bss_end = .; }
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
