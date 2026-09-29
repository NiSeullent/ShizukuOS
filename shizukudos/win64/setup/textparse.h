/* SPDX-License-Identifier: GPL-2.0-only
 * SHZSETUP: the two text formats the installer reads.
 *   INI  - the answer file (shzsetup.ini): [Section] / Key=Value, ';' or '#' comments, case-insensitive names.
 *   JSON - the payload manifest (manifest.json, RFC 8259 subset: no floating point, \uXXXX only below U+0080).
 * Both parsers work on a caller-owned text buffer and allocate one arena through the platform allocator.
 */
#ifndef SHZ_TEXTPARSE_H
#define SHZ_TEXTPARSE_H
#include <stddef.h>
#include <stdint.h>
#include "plat.h"

typedef struct ini_entry {
    const char *section, *key, *value;
    unsigned line;
} ini_entry_t;

typedef struct ini {
    ini_entry_t *e;
    unsigned count;
    char *arena;
} ini_t;

/* 0 = ok; on error *err gets "line N: ...". */
int ini_parse(const plat_t *P, const char *text, size_t len, ini_t *out, char *err, size_t errcap);
const char *ini_get(const ini_t *ini, const char *section, const char *key);
void ini_free(const plat_t *P, ini_t *ini);
int text_ieq(const char *a, const char *b);

enum { J_NULL, J_FALSE, J_TRUE, J_NUM, J_STR, J_ARR, J_OBJ };
typedef struct jnode {
    int type;
    const char *key;                /* member name inside an object */
    const char *s;                  /* J_STR */
    uint64_t n;                     /* J_NUM (non-negative integers only) */
    struct jnode *kid, *next;
} jnode_t;

typedef struct json {
    jnode_t *root;
    char *arena;
} json_t;

int json_parse(const plat_t *P, const char *text, size_t len, json_t *out, char *err, size_t errcap);
const jnode_t *json_get(const jnode_t *obj, const char *key);             /* NULL when absent or obj not an object */
const char *json_str(const jnode_t *obj, const char *key);                /* NULL unless a string */
int json_u64(const jnode_t *obj, const char *key, uint64_t *out);         /* 0 = ok */
void json_free(const plat_t *P, json_t *j);
#endif
