/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_LOAD_CONFIG_H
#define NTW_LOAD_CONFIG_H

#include "../native_loader/pe.h"

#define NP_LC_DIRECTORY_LIMIT 4096u
#define NP_LC_TABLE_LIMIT 262144u
#define NP_LC_LARGE_TABLE_LIMIT 8388608u
#define NP_LC_DEFAULT_COOKIE 0xbb40e64eu

/* Explicit structural work budget. Image limits are also enforced by this
 * reader; callers must first use np_parse_limited with matching limits.
 * total_table_entries includes all five metadata tables and lock-prefix entries.
 * No allocation, execution admission, or mitigation implementation is implied.
 * Limits must remain immutable, naturally aligned and disjoint from writable
 * outputs/mapped cookie storage. Both table ceilings are capped at8388608.
 * Default APIs retain32MiB file/64MiB image/262144 records per-table ceilings.
 */
typedef struct np_load_config_limits {
    np_parse_limits image;
    uint32_t table_entries, total_table_entries;
} np_load_config_limits;

/* IMAGE_GUARD_* values from the public Windows PE32 contract. */
#define NP_LC_CF_INSTRUMENTED                 0x00000100u
#define NP_LC_CFW_INSTRUMENTED                0x00000200u
#define NP_LC_CF_FUNCTION_TABLE_PRESENT      0x00000400u
#define NP_LC_SECURITY_COOKIE_UNUSED         0x00000800u
#define NP_LC_PROTECT_DELAYLOAD_IAT           0x00001000u
#define NP_LC_DELAYLOAD_IAT_IN_OWN_SECTION    0x00002000u
#define NP_LC_CF_EXPORT_SUPPRESSION_INFO     0x00004000u
#define NP_LC_CF_ENABLE_EXPORT_SUPPRESSION   0x00008000u
#define NP_LC_CF_LONGJUMP_TABLE_PRESENT      0x00010000u
#define NP_LC_RF_INSTRUMENTED                0x00020000u
#define NP_LC_RF_ENABLE                      0x00040000u
#define NP_LC_RF_STRICT                      0x00080000u
#define NP_LC_RETPOLINE_PRESENT              0x00100000u
#define NP_LC_EH_CONTINUATION_TABLE_PRESENT  0x00400000u
#define NP_LC_XFG_ENABLED                    0x00800000u
#define NP_LC_CASTGUARD_PRESENT              0x01000000u
#define NP_LC_MEMCPY_PRESENT                 0x02000000u
#define NP_LC_CF_TABLE_SIZE_MASK             0xf0000000u
#define NP_LC_CF_TABLE_SIZE_SHIFT            28u

/* These are outstanding runtime work, never implemented-mitigation flags. */
#define NP_LC_PREREQ_SAFESEH          0x00000001u
#define NP_LC_PREREQ_CFG              0x00000002u
#define NP_LC_PREREQ_CFW              0x00000004u
#define NP_LC_PREREQ_DELAY_IAT        0x00000008u
#define NP_LC_PREREQ_XFG              0x00000010u
#define NP_LC_PREREQ_EHCONT           0x00000020u
#define NP_LC_PREREQ_RF               0x00000040u
#define NP_LC_PREREQ_CODE_INTEGRITY   0x00000080u
#define NP_LC_PREREQ_LEGACY_CONFIG    0x00000100u
#define NP_LC_PREREQ_DYNAMIC_RELOC    0x00000200u
#define NP_LC_PREREQ_CHPE             0x00000400u
#define NP_LC_PREREQ_HOTPATCH         0x00000800u
#define NP_LC_PREREQ_ENCLAVE          0x00001000u
#define NP_LC_PREREQ_VOLATILE         0x00002000u
#define NP_LC_PREREQ_CASTGUARD        0x00004000u
#define NP_LC_PREREQ_MEMCPY           0x00008000u
#define NP_LC_PREREQ_COOKIE_CRT_REINIT 0x00010000u
#define NP_LC_PREREQ_COOKIE           0x00020000u
#define NP_LC_PREREQ_RETPOLINE        0x00040000u

#define NP_LC_PROTECT_CF_CHECK       0x00000001u
#define NP_LC_PROTECT_CF_DISPATCH    0x00000002u
#define NP_LC_PROTECT_XFG_CHECK      0x00000004u
#define NP_LC_PROTECT_XFG_DISPATCH   0x00000008u
#define NP_LC_PROTECT_XFG_TABLE      0x00000010u
#define NP_LC_PROTECT_RF_FAILURE    0x00000020u
#define NP_LC_PROTECT_RF_VERIFY     0x00000040u
#define NP_LC_PROTECT_MEMCPY        0x00000080u
#define NP_LC_PROTECT_CASTGUARD     0x00000100u

typedef struct np_load_config_table {
    uint32_t rva, count, stride;
} np_load_config_table;

typedef struct np_load_config_info {
    uint32_t present, directory_rva, directory_bytes, declared_size;
    uint32_t timestamp;
    uint16_t major_version, minor_version;
    uint32_t global_flags_clear, global_flags_set, critical_section_timeout;
    uint32_t decommit_free, decommit_total, maximum_allocation;
    uint32_t virtual_memory_threshold, process_heap_flags, affinity_mask;
    uint16_t csd_version, dependent_load_flags;
    uint32_t lock_prefix_rva, lock_prefix_count;
    uint32_t cookie_rva, cookie_raw_backed, cookie_initial;
    uint32_t cf_check_rva, cf_dispatch_rva, guard_flags;
    uint32_t rf_failure_rva, rf_failure_slot_rva, rf_verify_slot_rva;
    uint32_t xfg_check_rva, xfg_dispatch_rva, xfg_table_rva;
    uint32_t castguard_rva, memcpy_rva;
    np_load_config_table seh, cfg, address_taken_iat, long_jump, eh_continuation;
    uint32_t protection_needed, prerequisites;
} np_load_config_info;

typedef struct np_load_config_cookie_result {
    uint32_t present, rva, previous, value, initialized, needs_crt_reinit;
    uint32_t remaining_prerequisites;
} np_load_config_cookie_result;

/* p must be the successful np_parse result for a still-immutable original file.
 * p/info/error must be live C objects with their natural ABI alignment; caller
 * exclusively owns writable output objects and keeps inputs unchanged in-call.
 * All VA fields use its preferred ImageBase. Missing versioned fields are zero.
 * Tables and metadata require raw backing; writable cookie may be zero-fill.
 * Output is zero on failure except illegal output/input aliases, which are
 * rejected before any output write. error, when supplied, must be writable and
 * disjoint from inputs and info; a detected alias returns 0 without writing it.
 * Success validates metadata, never executable code.
 */
int np_load_config(const np_image *p, np_load_config_info *info,
                   const char **error);
int np_load_config_limited(const np_image *p, np_load_config_info *info,
                           const np_load_config_limits *limits,
                           const char **error);

/* Before ANY TLS callback/CRT entry or protected code: caller exclusively owns
 * mapped[0..p->size), separately mapped and relocated from immutable p->file.
 * Caller must provide entropy from its reviewed runtime entropy source; this
 * routine gathers none and makes no randomness-quality claim. A zero entropy
 * sample is legal. Only a zero/default cookie is changed; no adjacent guessed
 * complement, guard slot, table, protection, or original-file byte is written.
 * result/error must be writable and disjoint from the mapping and inputs; an
 * illegal output alias is rejected before clearing it, preserving all inputs.
 * They must be live, naturally aligned C output objects exclusively owned by
 * caller; the actual mapped cookie address must also have 4-byte alignment.
 * A nondefault highword-zero cookie is preserved and explicitly requires CRT
 * reinitialization. Result flags do not assert mitigation enforcement.
 */
int np_load_config_cookie(const np_image *p, void *mapped, uint32_t mapped_bytes,
                          uint32_t entropy, np_load_config_cookie_result *result,
                          const char **error);
int np_load_config_cookie_limited(const np_image *p, void *mapped,
                                  uint32_t mapped_bytes, uint32_t entropy,
                                  np_load_config_cookie_result *result,
                                  const np_load_config_limits *limits,
                                  const char **error);

/* Conservative gate for this unintegrated module: parse then refuse every
 * outstanding prerequisite, including cookie preparation and legacy options.
 * The native loader's own profile still independently blocks Load Config.
 */
int np_load_config_execution_profile(const np_image *p, const char **error);
int np_load_config_execution_profile_limited(const np_image *p,
                                             const np_load_config_limits *limits,
                                             const char **error);

#endif
