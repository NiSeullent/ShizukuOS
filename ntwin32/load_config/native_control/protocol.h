/* SPDX-License-Identifier: GPL-2.0-only -- own native API observation protocol */
#ifndef LC_NATIVE_CONTROL_PROTOCOL_H
#define LC_NATIVE_CONTROL_PROTOCOL_H
#include <stdint.h>
typedef struct lc_row { const char *name; uint32_t count; } lc_row;
static const char *const lc_exports[] = {
    "np_parse", "np_parse_limited", "np_load_config", "np_load_config_limited",
    "np_load_config_cookie", "np_load_config_cookie_limited",
    "np_load_config_execution_profile", "np_load_config_execution_profile_limited"
};
static const lc_row lc_rows[] = {
    {"DLL_FILE_READ",1}, {"DLL_FILE_PIN",1}, {"LOAD_LIBRARY_NATIVE",1},
    {"LOADED_MODULE_EXACT_PATH",1},
    {"EXPORT_np_parse",1}, {"EXPORT_np_parse_limited",1},
    {"EXPORT_np_load_config",1}, {"EXPORT_np_load_config_limited",1},
    {"EXPORT_np_load_config_cookie",1}, {"EXPORT_np_load_config_cookie_limited",1},
    {"EXPORT_np_load_config_execution_profile",1},
    {"EXPORT_np_load_config_execution_profile_limited",1},
    {"ORIGINAL_DLL_PARSE_CDECL",1}, {"ORIGINAL_DLL_PARSE_LIMITED_CDECL",1},
    {"ORIGINAL_EXPORT_RVAS_MATCH_NATIVE_POINTERS",1},
    {"ORIGINAL_DLL_LC_ABSENT",1}, {"ORIGINAL_DLL_LC_LIMITED_ABSENT",1},
    {"ORIGINAL_DLL_GATE_CDECL",1}, {"ORIGINAL_DLL_GATE_LIMITED_CDECL",1},
    {"ORIGINAL_DLL_MAPPED_COPY",1}, {"ORIGINAL_DLL_COOKIE_ABSENT",1},
    {"ORIGINAL_DLL_COOKIE_LIMITED_ABSENT",1}, {"ABSENT_COOKIE_MAPPING_UNCHANGED",1},
    {"ORIGINAL_DLL_MAPPING_RELEASED",1},
    {"SYNTHETIC_PARSE_CDECL",1}, {"SYNTHETIC_PARSE_LIMITED_CDECL",1},
    {"SYNTHETIC_COOKIE_METADATA",1}, {"SYNTHETIC_LIMITED_METADATA",1},
    {"SYNTHETIC_COOKIE_GATE_REFUSED",1}, {"SYNTHETIC_COOKIE_LIMITED_GATE_REFUSED",1},
    {"SYNTHETIC_MAPPED_COPY",1}, {"NATIVE_COOKIE_DEFAULT_INITIALIZED",1},
    {"COOKIE_ONLY_FOUR_BYTES_CHANGED",1}, {"NATIVE_COOKIE_NONDEFAULT_PRESERVED",1},
    {"NATIVE_COOKIE_LOW_HIGHWORD_CRT_PREREQUISITE",1},
    {"NATIVE_LIMITED_COOKIE_ZERO_NORMALIZED",1},
    {"LIMITED_COOKIE_ONLY_FOUR_BYTES_CHANGED",1},
    {"LIMITED_COOKIE_SHORT_MAPPING_REFUSED",1}, {"FAILED_COOKIE_MAPPING_UNCHANGED",1},
    {"SYNTHETIC_MAPPING_RELEASED",1}, {"SYNTHETIC_FILE_UNCHANGED",1},
    {"LIMITED_PARSE_COMBINED_BUDGET_REFUSED",1},
    {"SAFESEH_REPARSE_CDECL",1},
    {"SAFESEH_METADATA_PRESERVED",1}, {"SAFESEH_EXECUTION_REFUSED",1},
    {"SAFESEH_LIMITED_EXECUTION_REFUSED",1}, {"TABLE_BUDGET_REFUSED",1},
    {"AGGREGATE_TABLE_BUDGET_REFUSED",1}, {"BUDGET_FAILURE_FILE_UNCHANGED",1},
    {"ORIGINAL_DLL_FILE_UNCHANGED",1}, {"FREE_LIBRARY_NATIVE",1},
    {"DLL_FILE_STORAGE_RELEASED",1}
};
#define LC_ARRAY_COUNT(a) ((uint32_t)(sizeof(a)/sizeof((a)[0])))
#endif
