/* SPDX-License-Identifier: GPL-2.0-only
 * Original routing policy for NTWin32Wrapper9x: modes, provider order, the
 * known-stub list and the bounded NTW32.INI / NTW32_ROUTING parser.
 * Freestanding: no C runtime, no allocation, no undefined behaviour on any
 * input. See docs/NTW32_ROUTING.md for the exact semantics. */
#ifndef NTW_ROUTING_H
#define NTW_ROUTING_H
#include <stddef.h>
#include <stdint.h>

/* Providers. Zero terminates a packed order. */
enum {
    NTW_PROVIDER_NONE = 0,
    NTW_PROVIDER_NATIVE = 1,   /* the export the native loader returns, attributed to Windows */
    NTW_PROVIDER_OWN = 2,      /* an implementation linked into NTW32.DLL */
    NTW_PROVIDER_KERNELEX = 3  /* a native-loader result attributed to a detected KernelEx API library */
};
/* Process modes. Auto is the default in every fallback path. */
enum {
    NTW_MODE_AUTO = 0,
    NTW_MODE_OWN = 1,
    NTW_MODE_KERNELEX = 2,
    NTW_MODE_NATIVE = 3
};
/* KernelEx detection state, recorded for diagnostics. */
enum {
    NTW_KERNELEX_NOT_DETECTED = 0,  /* no KernelEx module is mapped in this process */
    NTW_KERNELEX_CORE_ONLY = 1,     /* KERNELEX.DLL is mapped, no API library exports get_api_table */
    NTW_KERNELEX_ACTIVE = 2         /* at least one API library exporting get_api_table is mapped */
};

/* Packed provider order: two bits per slot, first provider in the low bits. */
#define NTW_ORDER1(a) ((unsigned)(a))
#define NTW_ORDER2(a, b) ((unsigned)(a) | ((unsigned)(b) << 2))
#define NTW_ORDER3(a, b, c) ((unsigned)(a) | ((unsigned)(b) << 2) | ((unsigned)(c) << 4))
#define NTW_ORDER_SLOTS 3u
#define NTW_ORDER_AT(order, index) (((order) >> (2u * (index))) & 3u)
#define NTW_ORDER_DEFAULT NTW_ORDER3(NTW_PROVIDER_NATIVE, NTW_PROVIDER_OWN, NTW_PROVIDER_KERNELEX)

struct ntw_route_entry { const char *name; unsigned order; };
struct ntw_stub_entry { const char *module; const char *name; unsigned provider; };
struct ntw_route_table {
    const struct ntw_route_entry *routes;
    unsigned route_count;
    const struct ntw_stub_entry *stubs;
    unsigned stub_count;
    unsigned default_order;  /* used in Auto for names without a route entry; 0 selects NTW_ORDER_DEFAULT */
};

#define NTW_ROUTE_TEXT_MAX 4096u   /* longest accepted configuration in bytes */
#define NTW_ROUTE_LINE_MAX 127u    /* longest accepted line after trimming */
#define NTW_ROUTE_NAME_MAX 64u     /* function-name storage including the terminator */
#define NTW_ROUTE_MODULE_MAX 32u   /* module-name limit including the terminator */
#define NTW_ROUTE_MAX_OVERRIDES 32u
#define NTW_ROUTE_MESSAGE_MAX 200u

/* MODULE and FUNCTION entries set a mode; an ORDER entry ([order] section)
 * sets the provider order one function uses while its effective mode is Auto. */
enum { NTW_OVERRIDE_MODULE = 1, NTW_OVERRIDE_FUNCTION = 2, NTW_OVERRIDE_ORDER = 3 };
enum { NTW_ROUTE_SOURCE_DEFAULT = 0, NTW_ROUTE_SOURCE_INI = 1, NTW_ROUTE_SOURCE_ENV = 2 };

struct ntw_route_override {
    unsigned char kind;   /* NTW_OVERRIDE_* */
    unsigned char mode;   /* NTW_MODE_* (module and function entries) */
    unsigned char order;  /* packed provider order (order entries; never 0 there) */
    char name[NTW_ROUTE_NAME_MAX];  /* modules stored upper-case; functions exact */
};
struct ntw_route_policy {
    unsigned char mode;      /* process mode */
    unsigned char log;       /* 1 traces every routing decision */
    unsigned char source;    /* NTW_ROUTE_SOURCE_* */
    unsigned char order;     /* [routing] order=: Auto order for every name; 0 keeps routes.json */
    unsigned warnings;       /* rejected lines and values, cumulative */
    unsigned override_count;
    struct ntw_route_override overrides[NTW_ROUTE_MAX_OVERRIDES];
};

/* Bounded message builder. Output is always NUL-terminated and never exceeds
 * the capacity; text beyond it is dropped rather than overflowing. */
struct ntw_text { char *buffer; size_t capacity; size_t length; };
void ntw_text_start(struct ntw_text *, char *buffer, size_t capacity);
void ntw_text_add(struct ntw_text *, const char *);
/* Up to `limit` characters of a NUL-terminated string; "..." marks a cut. */
void ntw_text_add_bounded(struct ntw_text *, const char *, size_t limit);
/* Exactly `length` characters of a slice (stopping early at a NUL). */
void ntw_text_add_slice(struct ntw_text *, const char *, size_t length);
void ntw_text_add_uint(struct ntw_text *, unsigned);

typedef void (*ntw_route_log)(void *context, const char *message);

void ntw_route_policy_init(struct ntw_route_policy *);
/* Parse INI-style text into the policy. `separator` ends a line ('\n' for a
 * file, '|' for the environment variable; '\n' always ends a line as well).
 * Anything rejected leaves the corresponding default in place and reports a
 * warning through `log` (which may be NULL). Returns the warnings added. */
unsigned ntw_route_parse(struct ntw_route_policy *, const char *text, size_t length,
                         char separator, ntw_route_log log, void *context);
/* After parsing: report entries that cannot take effect because only
 * `routed_module` is routed ([modules] naming another module) or because the
 * effective mode there is not Auto ([order] entries, [routing] order=). The
 * entries stay stored and harmless; each report counts as a warning. Returns
 * the warnings added. */
unsigned ntw_route_check(struct ntw_route_policy *, const char *routed_module, ntw_route_log log, void *context);
/* Function override, then module override (case-insensitive), then the process
 * mode. A NULL policy is mode Own. */
unsigned ntw_route_effective_mode(const struct ntw_route_policy *, const char *module, const char *name);
/* The packed provider order a mode tries for a name according to the table. */
unsigned ntw_route_order(unsigned mode, const struct ntw_route_table *, const char *name);
/* The order the resolver uses. In mode Auto: the [order] entry for the name,
 * else the [routing] order, else ntw_route_order. Own, KernelEx and Native
 * keep their fixed orders. A NULL policy means ntw_route_order. */
unsigned ntw_route_effective_order(const struct ntw_route_policy *, const struct ntw_route_table *,
                                   unsigned mode, const char *name);
/* One to three distinct provider names separated by commas, case-insensitive,
 * blanks around a name allowed ("native, own"). Returns 0 and leaves `order`
 * unchanged for anything else. */
int ntw_route_parse_order(const char *text, size_t length, unsigned *order);
/* Appends "native,own,kernelex" for a packed order ("none" when empty). */
void ntw_text_add_order(struct ntw_text *, unsigned order);
int ntw_route_is_stub(const struct ntw_route_table *, const char *module, const char *name, unsigned provider);
int ntw_route_parse_mode(const char *text, size_t length, unsigned *mode);
const char *ntw_route_mode_name(unsigned mode);
const char *ntw_route_provider_name(unsigned provider);
const char *ntw_route_kernelex_name(unsigned state);
int ntw_route_name_equal(const char *left, const char *right);
int ntw_route_name_iequal(const char *left, const char *right);
/* Read SizeOfImage from mapped PE32 headers without trusting any field. The
 * whole header chain must fit inside `available` bytes. */
int ntw_route_image_size(const unsigned char *headers, size_t available, uint32_t *size_of_image);
#endif
