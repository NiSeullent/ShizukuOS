/* SPDX-License-Identifier: GPL-2.0-only */
OUTPUT_FORMAT(elf32-i386)
ENTRY(ntwv_control)
SECTIONS
{
  . = 0x10000;
  .text : { *(.text .text.*) }
  . = ALIGN(4096);
  .data : {
    KEEP(*(.ddb))
    *(.rodata .rodata.*)
    *(.data .data.*)
    *(.bss .bss.* COMMON)
    BYTE(0)
  }
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
