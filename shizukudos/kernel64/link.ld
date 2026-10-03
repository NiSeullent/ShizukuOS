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
/* The loaders (Supervisor kdom.c, UEFI boot manager loader.c, Multiboot stub boot32.c) zero guest-physical [1 MiB, 4 MiB)
 * for the image and its bss and accept at most 3 MiB of file; mem.c puts the kernel heap at 4 MiB. 0x400000 is
 * standalone/memholes.h SHZ_K64_KERNEL_END == SHZ_K64_HEAP_GPA (test_memplan.py checks the literal): an image whose bss
 * ran past it would overlap the heap. Never relax this without moving the heap and every loader with it. */
ASSERT(__bss_end - 0xFFFFFFFF80000000 <= 0x400000, "Kernel64 image + bss must end below 4 MiB (heap starts at 4 MiB)")
