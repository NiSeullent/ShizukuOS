/* SPDX-License-Identifier: GPL-2.0-only
 * AMD64 PE32+ image parsing and validation, independent of any kernel: the same source is
 * compiled into Kernel64 (freestanding) and into host tests that fuzz it with corrupted
 * images. Every offset and size is checked with overflow-safe arithmetic before use.
 *
 * Scope: Machine == AMD64 (0x8664), PE32+ optional header (0x20b). ARM64/ARM64EC and PE32
 * (x86) images are rejected here on purpose; x86 processes belong to a separate WOW64-style
 * profile.
 */
#ifndef PE_PARSE_H
#define PE_PARSE_H
#include <stddef.h>
#include <stdint.h>

enum pe_error {
    PE_OK = 0, PE_E_TRUNCATED = -1, PE_E_DOS = -2, PE_E_NT_SIG = -3, PE_E_MACHINE = -4, PE_E_MAGIC = -5,
    PE_E_OPT_SIZE = -6, PE_E_ALIGN = -7, PE_E_SECTIONS = -8, PE_E_SECTION_RANGE = -9, PE_E_OVERLAP = -10,
    PE_E_IMAGE_SIZE = -11, PE_E_HEADERS = -12, PE_E_DIR = -13, PE_E_RVA = -14, PE_E_IMPORT = -15,
    PE_E_RELOC = -16, PE_E_EXPORT = -17, PE_E_ENTRY = -18, PE_E_TLS = -19, PE_E_NOT_FOUND = -20,
    PE_E_FORWARD = -21, PE_E_STRING = -22, PE_E_CLR = -23, PE_E_SIGNED_ONLY = -24
};

#define PE_CHAR_DLL 0x2000
#define PE_CHAR_EXECUTABLE 0x0002
#define PE_DLLCHAR_DYNAMIC_BASE 0x0040
#define PE_DLLCHAR_NX_COMPAT 0x0100
#define PE_DLLCHAR_HIGH_ENTROPY_VA 0x0020
#define PE_SCN_MEM_EXECUTE 0x20000000u
#define PE_SCN_MEM_READ 0x40000000u
#define PE_SCN_MEM_WRITE 0x80000000u
#define PE_SCN_CNT_UNINIT 0x00000080u
#define PE_SCN_CNT_CODE 0x00000020u
#define PE_MAX_SECTIONS 96

typedef struct {
    char name[9];
    uint32_t vsize, rva, raw_size, raw_off, characteristics;
} pe_section_t;

typedef struct {
    uint64_t image_base, stack_reserve, stack_commit, heap_reserve, heap_commit;
    uint32_t size_of_image, size_of_headers, section_alignment, file_alignment, entry_rva, checksum;
    uint16_t characteristics, dll_characteristics, subsystem, nsections, major_os, minor_os;
    uint32_t dir_rva[16], dir_size[16];         /* data directories: 0 export, 1 import, 3 exception, 5 reloc, 9 tls, 13 delay */
    uint32_t nt_offset, section_table_offset;
} pe_info_t;

int pe_parse(const uint8_t *file, uint64_t size, pe_info_t *info);
int pe_get_section(const uint8_t *file, const pe_info_t *info, unsigned index, pe_section_t *out);
/* Translates an RVA to a file offset when it is backed by file data (headers or raw section
 * data). RVAs inside a section's zero-filled tail return PE_E_RVA. *avail is the number of
 * contiguous file bytes from that offset. */
int pe_rva_to_offset(const uint8_t *file, uint64_t size, const pe_info_t *info, uint32_t rva, uint64_t *off, uint64_t *avail);
/* Reads a NUL-terminated ASCII string at an RVA (bounded by `cap`). */
int pe_read_string(const uint8_t *file, uint64_t size, const pe_info_t *info, uint32_t rva, char *out, unsigned cap);

/* Export lookup by name (ordinal < 0) or ordinal. On success *rva is the function RVA; if it
 * points inside the export directory it is a forwarder and *forward receives "DLL.Name". */
int pe_find_export(const uint8_t *file, uint64_t size, const pe_info_t *info, const char *name, int ordinal,
                   uint32_t *rva, char *forward, unsigned forward_cap);

/* Iteration helpers for imports and relocations (callback style keeps this allocation-free). */
typedef int (*pe_import_fn)(void *ctx, const char *dll, const char *name, uint16_t ordinal_or_hint, int by_ordinal,
                            uint32_t iat_rva);
int pe_walk_imports(const uint8_t *file, uint64_t size, const pe_info_t *info, pe_import_fn fn, void *ctx);
typedef int (*pe_reloc_fn)(void *ctx, uint32_t rva, unsigned type);
int pe_walk_relocs(const uint8_t *file, uint64_t size, const pe_info_t *info, pe_reloc_fn fn, void *ctx);
#endif
