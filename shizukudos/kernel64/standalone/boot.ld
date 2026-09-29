/* Standalone Kernel64 boot stub: loaded by QEMU's Multiboot loader at 4 MiB (above the kernel's 1-3 MiB window). */
ENTRY(_start)
SECTIONS
{
    . = 0x400000;
    .text : { *(.multiboot) *(.text .text.*) }
    . = ALIGN(16);
    .rodata : { *(.rodata .rodata.*) }
    .data : { *(.data .data.*) }
    .bss : { *(.bss .bss.*) *(COMMON) }
    stub_end = .;
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
