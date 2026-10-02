/* SPDX-License-Identifier: GPL-2.0-only */
OUTPUT_FORMAT(elf32-i386)
ENTRY(ntwv_control)
SECTIONS
{
  . = 0x10000;
  .text : { ntwv_text_begin = .; *(.text .text.*) ntwv_text_last = . - 1; }
  . = ALIGN(4096);
  .data : {
    ntwv_data_begin = .;
    KEEP(*(.ddb))
    *(.rodata .rodata.*)
    *(.data .data.*)
    *(.bss .bss.* COMMON)
    BYTE(0)
    ntwv_data_last = . - 1;
  }
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
