/* Standalone Kernel64/Kernel32 boot stub: loaded by QEMU's Multiboot loader at 4 MiB, at or above the end of the kernel
 * window it zeroes (Kernel64 [1 MiB, 4 MiB) = memholes.h SHZ_K64_KERNEL_END; Kernel32 [1 MiB, 3 MiB)). The Kernel64 heap
 * later reuses this range; the stub hands everything over in low memory before the jump. */
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
ASSERT(ADDR(.text) >= 0x400000, "stub image must start at or above the Kernel64 window end (4 MiB)")
ASSERT(stub_end <= 0x2000000, "stub image must end below the initial RAM image at 32 MiB")
