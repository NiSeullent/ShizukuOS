/* SPDX-License-Identifier: GPL-2.0-only
 * API-set contract resolution for the Kernel64 PE32+ loader. Freestanding (no kernel headers): the same source is
 * compiled into Kernel64 and into the host tests (win64/tests/test_apiset.c) and the host load simulator.
 *
 * Name rules (see kernel64/apiset_contracts.txt for the table itself):
 *   - a DLL name is an API-set name when it starts with "api-" or "ext-" (ASCII case-insensitive); ".dll" is optional;
 *   - it must end in "-l<level>-<major>-<minor>"; <contract>-l<level> selects the contract, versions are cumulative;
 *   - the request resolves through the table row of that contract with the highest version, and only when that
 *     version is >= the requested one (l1-1-0 is served by an l1-2-1 row, l1-3-0 is not, l2-* is another contract).
 */
#ifndef K64_APISET_H
#define K64_APISET_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *contract;               /* lowercase, including the level: "api-ms-win-core-synch-l1" */
    uint16_t major, minor;              /* highest version this row provides */
    const char *windows_host;           /* host DLL in the Windows 10/11 schema */
    const char *host;                   /* the Shizuku DLL that implements it */
} apiset_entry_t;

enum apiset_result {
    APISET_NOT_APISET = 0,              /* an ordinary DLL name */
    APISET_OK = 1,                      /* *entry is the row to use */
    APISET_UNKNOWN = -1,                /* well-formed API-set name, but no such contract (or level) in the table */
    APISET_VERSION = -2,                /* contract known, requested version newer than any row: *entry = best row */
    APISET_BAD_NAME = -3                /* "api-"/"ext-" prefix without a -lL-M-m suffix, or too long */
};

/* Classifies `name` and, for API-set names, finds the row that serves it. `entry` may be NULL. */
int apiset_lookup(const char *name, const apiset_entry_t **entry);

/* Parses "<contract>-l<L>-<M>-<m>[.dll]" (any case) into a lowercase contract (with level) and version.
 * Returns 0 on success, -1 when the name is not of that form or longer than `cap` - 1. */
int apiset_parse_name(const char *name, char *contract, size_t cap, unsigned *major, unsigned *minor);

/* Table access for diagnostics and host tools. */
unsigned apiset_count(void);
const apiset_entry_t *apiset_entry(unsigned index);
#endif
