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
    PE_E_FORWARD = -21, PE_E_STRING = -22, PE_E_CLR = -23, PE_E_SIGNED_ONLY = -24, PE_E_LOADCFG = -25, PE_E_DELAY = -26
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
    /* SectionAlignment == FileAlignment < 4096 ("low alignment"): every section's RVA equals its file offset and
     * the image is mapped as one flat copy of the file (one protection for all pages). */
    int low_alignment;
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

/* Iteration helpers for imports and relocations (callback style keeps this allocation-free).
 * Named symbols are validated NUL-terminated views into the caller-owned raw file, valid for
 * that file's lifetime. No fixed-size symbol copy truncates decorated C++ names. */
typedef int (*pe_import_fn)(void *ctx, const char *dll, const char *name, uint16_t ordinal_or_hint, int by_ordinal,
                            uint32_t iat_rva);
int pe_walk_imports(const uint8_t *file, uint64_t size, const pe_info_t *info, pe_import_fn fn, void *ctx);
/* Base relocations: `type` is the IMAGE_REL_BASED_* value in its low 4 bits (ABSOLUTE entries are skipped). Accepted:
 * HIGH (1), LOW (2), HIGHLOW (3), HIGHADJ (4, bits 16..31 of `type` carry the low half from the following entry) and
 * DIR64 (10); any other type rejects the image (PE_E_RELOC). */
typedef int (*pe_reloc_fn)(void *ctx, uint32_t rva, unsigned type);
int pe_walk_relocs(const uint8_t *file, uint64_t size, const pe_info_t *info, pe_reloc_fn fn, void *ctx);

/* Applies the base relocations for a load at image_base + delta. `page(ctx, rva)` returns a writable pointer to the
 * mapped 4 KiB page containing `rva` (page aligned) or NULL; the page pointer is looked up once per relocation block
 * and fixups that straddle a page boundary are written through both pages. Returns PE_OK or PE_E_RELOC. */
typedef uint8_t *(*pe_page_fn)(void *ctx, uint32_t page_rva);
int pe_apply_relocs(const uint8_t *file, uint64_t size, const pe_info_t *info, uint64_t delta, pe_page_fn page, void *ctx,
                    uint64_t *applied);

/* ---- IMAGE_DELAYLOAD_DESCRIPTOR walking (the loader does not resolve these; ntdll does on first call). */
typedef struct {
    uint32_t attributes;                /* bit 0: RvaBased (VA-based legacy descriptors are converted to RVAs) */
    uint32_t name_rva, module_handle_rva, iat_rva, int_rva, bound_iat_rva, unload_iat_rva, timestamp;
    char dll[128];
} pe_delay_desc_t;
typedef int (*pe_delay_fn)(void *ctx, const pe_delay_desc_t *desc, const char *name, uint16_t ordinal_or_hint, int by_ordinal,
                           uint32_t iat_slot_rva);
int pe_walk_delay_imports(const uint8_t *file, uint64_t size, const pe_info_t *info, pe_delay_fn fn, void *ctx);

/* ---- IMAGE_LOAD_CONFIG_DIRECTORY64: every field the loader reads. Fields beyond the structure's own Size are 0.
 * Pointer-valued fields are virtual addresses at the preferred image base; the ones the loader writes through
 * (security cookie, CFG/XFG function pointers) are validated to lie inside the image. */
#define PE_GUARD_CF_INSTRUMENTED 0x00000100u
#define PE_GUARD_CFW_INSTRUMENTED 0x00000200u
#define PE_GUARD_CF_FUNCTION_TABLE_PRESENT 0x00000400u
#define PE_GUARD_SECURITY_COOKIE_UNUSED 0x00000800u
#define PE_GUARD_PROTECT_DELAYLOAD_IAT 0x00001000u
#define PE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION 0x00002000u
#define PE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT 0x00004000u
#define PE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION 0x00008000u
#define PE_GUARD_CF_LONGJUMP_TABLE_PRESENT 0x00010000u
#define PE_GUARD_RF_INSTRUMENTED 0x00020000u
#define PE_GUARD_EH_CONTINUATION_TABLE_PRESENT 0x00400000u
#define PE_GUARD_XFG_ENABLED 0x00800000u
#define PE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK 0xF0000000u
#define PE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT 28
#define PE_DEFAULT_SECURITY_COOKIE_64 0x00002B992DDFA232ull

typedef struct {
    uint32_t size;                      /* the structure's Size field (0: no load configuration) */
    uint16_t dependent_load_flags;
    uint64_t security_cookie;           /* VA of __security_cookie, 0 if none */
    uint64_t se_handler_table, se_handler_count;            /* x86 only: must be 0 on x64 (ignored otherwise) */
    uint64_t guard_cf_check_fptr, guard_cf_dispatch_fptr;   /* VAs of the function pointers the loader fills */
    uint64_t guard_cf_function_table, guard_cf_function_count;
    uint32_t guard_flags;
    uint64_t guard_iat_table, guard_iat_count, guard_longjump_table, guard_longjump_count;
    uint64_t dynamic_value_reloc_table;
    uint32_t dynamic_value_reloc_offset;
    uint16_t dynamic_value_reloc_section;
    uint64_t guard_rf_failure_fptr, guard_rf_verify_sp_fptr;
    uint64_t guard_ehcont_table, guard_ehcont_count;
    uint64_t guard_xfg_check_fptr, guard_xfg_dispatch_fptr, guard_xfg_table_dispatch_fptr;
    uint64_t guard_memcpy_fptr;
} pe_load_config_t;
/* PE_OK with *out filled (out->size == 0 when the image has no load configuration), or PE_E_LOADCFG. */
int pe_load_config(const uint8_t *file, uint64_t size, const pe_info_t *info, pe_load_config_t *out);
#endif
