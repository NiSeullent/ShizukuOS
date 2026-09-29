/* Kernel32: flat image loaded by the Supervisor at guest-physical 1 MiB. */
ENTRY(_start)
SECTIONS
{
    . = 0x100000;
    .text : { *(.text.entry) *(.text .text.*) }
    . = ALIGN(16);
    .rodata : { *(.rodata .rodata.*) }
    . = ALIGN(16);
    .data : { *(.data .data.*) }
    . = ALIGN(16);
    .bss (NOLOAD) : { __bss_start = .; *(.bss .bss.*) *(COMMON) __bss_end = .; }
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
