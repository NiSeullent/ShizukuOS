/* SPDX-License-Identifier: GPL-2.0-only
 * shzinf: Windows driver INF engine in portable C (no OS calls, no C library beyond memcpy/memset/strlen and the
 * allocator macros below). Used by the Win64 CLI shzpnp and by a host test harness that is cross-checked against
 * shizukudos/ntdrv/inf.py (shizukudos/ntdrv/tests/test_shzpnp.py). The rules implemented are the ones documented in
 * inf.py: INF syntax and string substitution, TargetOSVersion selection (architecture required for non-x86 unless
 * legacy), DDInstall decoration search, CopyFiles / DestinationDirs / SourceDisks*, AddReg type encoding, AddService,
 * KMDF, PCI identifier generation and driver ranking (0xSSGGTHHH, identifier score with the k*0x100 term).
 * All strings are UTF-8 (UTF-16 INFs are converted on load). */
#ifndef SHZINF_H
#define SHZINF_H
#include <stddef.h>
#include <stdint.h>

#ifndef SHZINF_MALLOC
#ifdef _WIN64                          /* Shizuku Win64 program: the freestanding shzcrt heap */
#include "shzcrt.h"
#define SHZINF_MALLOC shz_malloc
#define SHZINF_REALLOC shz_realloc
#define SHZINF_FREE shz_free
#else                                  /* host build (test harness) */
#include <stdlib.h>
#define SHZINF_MALLOC malloc
#define SHZINF_REALLOC realloc
#define SHZINF_FREE free
#endif
#endif

typedef struct {
    char *key;              /* "" for value-only lines; substituted and unquoted */
    int nvals;
    char **vals;
    int lineno;
} shzinf_line_t;

typedef struct {
    char *name;
    int nlines, cap;
    shzinf_line_t *lines;
} shzinf_section_t;

typedef struct {
    int nsec, cap;
    shzinf_section_t *secs;
    int nstr, strcap;
    char **strk, **strv;    /* [Strings] after the locale override */
    int nwarn;
    char warn[16][160];
} shzinf_t;

typedef struct {
    const char *arch;       /* "amd64" */
    int major, minor, build, product_type, suite;
    int legacy;             /* accept arch-less / undecorated Models sections (ReactOS setupapi behaviour) */
} shzinf_target_t;

#define SHZINF_MAX_IDS 32
typedef struct {
    const char *description, *install, *mfg, *section;
    const char *hwid;
    int ncompat;
    const char *compat[SHZINF_MAX_IDS];
    int lineno;
} shzinf_model_t;

/* AddReg entry. Data: REG_SZ/EXPAND_SZ: str; REG_MULTI_SZ: str holds the strings separated by '\n' (count in nmulti);
 * REG_DWORD/QWORD: num; REG_BINARY/NONE: bin/binlen. */
enum { SHZ_REG_NONE = 0, SHZ_REG_SZ = 1, SHZ_REG_EXPAND_SZ = 2, SHZ_REG_BINARY = 3, SHZ_REG_DWORD = 4, SHZ_REG_MULTI_SZ = 7, SHZ_REG_QWORD = 11 };
enum { SHZ_FLG_BINVALUETYPE = 1, SHZ_FLG_NOCLOBBER = 2, SHZ_FLG_DELVAL = 4, SHZ_FLG_APPEND = 8, SHZ_FLG_KEYONLY = 0x10,
       SHZ_FLG_OVERWRITEONLY = 0x20 };
typedef struct {
    char root[8];
    const char *subkey, *name, *str;
    uint32_t flags, type;
    uint64_t num;
    unsigned char *bin;
    int binlen, nmulti, has_data;
    const char *section;
    int lineno;
} shzinf_reg_t;

typedef struct {
    const char *dest, *source, *section;
    int dirid;
    const char *subdir;
    uint32_t flags;
} shzinf_copy_t;

typedef struct {
    const char *name, *section, *eventlog;
    uint32_t flags;
    int is_delete;
    int service_type, start_type, error_control;       /* -1 when absent */
    const char *binary, *group, *display, *description, *startname;
    int ndeps;
    const char *deps[16];
    int nreg;
    shzinf_reg_t *reg;
} shzinf_service_t;

typedef struct {
    const char *base, *section;                        /* section == 0: not found */
    int ncopy, nreg, nhwreg, nsvc;
    shzinf_copy_t *copy;
    shzinf_reg_t *reg, *hwreg;
    shzinf_service_t *svc;
    int feature_score;                                 /* -1 absent */
    const char *driverver, *kmdf, *umdf, *kmdf_service;
    int nwarn;
    char warn[8][160];
} shzinf_install_t;

typedef struct {
    int nhw, ncp;
    char hw[8][96], cp[12][96];
} shzinf_device_t;

/* ranking (inf.py): rank = sig << 24 | feature << 16 | identifier score */
#define SHZINF_SIG_UNSIGNED_NT 0x80
#define SHZINF_SIG_UNSIGNED 0xC0
typedef struct {
    uint32_t rank, identifier;
    int kind;                                          /* 0x0000 / 0x1000 / 0x2000 / 0x3000 */
    const char *inf_id, *dev_id;
} shzinf_score_t;

shzinf_t *shzinf_parse(const unsigned char *data, size_t len, const char *locale);
void shzinf_free(shzinf_t *inf);
const shzinf_section_t *shzinf_section(const shzinf_t *inf, const char *name);
const char *shzinf_first(const shzinf_section_t *s, const char *key);           /* first value of key, or 0 */
const char *shzinf_version(const shzinf_t *inf, const char *key, const shzinf_target_t *t);  /* [Version] field; DriverVer joined */
int shzinf_models(const shzinf_t *inf, const shzinf_target_t *t, shzinf_model_t *out, int max);
shzinf_install_t *shzinf_install(const shzinf_t *inf, const char *base, const shzinf_target_t *t);
void shzinf_install_free(shzinf_install_t *r);
int shzinf_dest_dir(const shzinf_t *inf, const char *file_list_section, const char **subdir);
const char *shzinf_source_subdir(const shzinf_t *inf, const char *file, const shzinf_target_t *t, char *buf, size_t cap);
int shzinf_score(const shzinf_device_t *dev, const shzinf_model_t *m, shzinf_score_t *out);   /* 1 on match */
uint32_t shzinf_rank(const shzinf_install_t *inst, int identifier);
void shzinf_pci_device(shzinf_device_t *d, unsigned ven, unsigned dev, int has_subsys, uint32_t subsys, int has_rev,
                       unsigned rev, int has_class, uint32_t cls);
int shzinf_parse_device(shzinf_device_t *d, const char *spec);                  /* same syntax as inf.py Device.parse */
int shzinf_driverver_cmp(const char *a, const char *b);                          /* >0 when a is newer */
int shzinf_stricmp(const char *a, const char *b);
#endif
