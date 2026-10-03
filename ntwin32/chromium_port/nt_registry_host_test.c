/* SPDX-License-Identifier: GPL-2.0-only */
/* Host controls for nt_registry.c against an in-memory model of Win98 ANSI
 * registry semantics (RegCreateKeyEx creates intermediates, RegDeleteKey is
 * recursive, DBCS trail bytes may equal '\\'). Host-only evidence. */
#include "nt_registry.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#define KEYS 256
#define VALS 8
typedef struct { char name[256]; uint32_t type, len; uint8_t data[256]; int used; } val;
typedef struct { int used; unsigned root; char path[NTR_PATH_MAX]; val v[VALS]; } key;
static key keys[KEYS];
static int opens;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static unsigned checks, failures;
static void check(int ok, const char *what) { checks++; if (!ok) { failures++; fprintf(stderr, "FAIL %s\n", what); } }
static void lk(void *p) { (void)p; pthread_mutex_lock(&mu); }
static void ulk(void *p) { (void)p; pthread_mutex_unlock(&mu); }
static int find(unsigned root, const char *path)
{ int i; for (i = 0; i < KEYS; i++) if (keys[i].used && keys[i].root == root && !strcasecmp(keys[i].path, path)) return i; return -1; }
static int add(unsigned root, const char *path)
{ int i = find(root, path); if (i >= 0) return i; for (i = 0; i < KEYS; i++) if (!keys[i].used) { memset(&keys[i], 0, sizeof keys[i]); keys[i].used = 1; keys[i].root = root; snprintf(keys[i].path, sizeof keys[i].path, "%s", path); return i; } return -1; }
static long b_open(void *p, unsigned root, const char *path, void **k)
{ int i; (void)p; if (!*path) { *k = (void *)(intptr_t)(1000 + root); opens++; return 0; } i = find(root, path); if (i < 0) return 2; *k = (void *)(intptr_t)(i + 1); opens++; return 0; }
static long b_create(void *p, unsigned root, const char *path, void **k, int *created)
{ /* Win98 behaviour: create every missing intermediate. */
  char tmp[NTR_PATH_MAX]; size_t i, n = strlen(path); int was = find(root, path) >= 0, idx = -1; (void)p;
  for (i = 0; i <= n; i++) if (i == n || path[i] == '\\') { memcpy(tmp, path, i); tmp[i] = 0; idx = add(root, tmp); if (idx < 0) return 8; }
  *created = !was; *k = (void *)(intptr_t)(idx + 1); opens++; return 0; }
static key *K(void *k) { intptr_t i = (intptr_t)k - 1; if (i < 0 || i >= KEYS || !keys[i].used) return 0; return &keys[i]; }
static long b_query(void *p, void *k, const char *name, uint32_t *type, uint8_t *data, uint32_t *bytes)
{ key *x = K(k); int i; (void)p; if (!x) return 1010; for (i = 0; i < VALS; i++) if (x->v[i].used && !strcasecmp(x->v[i].name, name)) {
    *type = x->v[i].type; if (data && *bytes < x->v[i].len) { *bytes = x->v[i].len; return 234; }
    if (data) memcpy(data, x->v[i].data, x->v[i].len); *bytes = x->v[i].len; return 0; } return 2; }
static long b_set(void *p, void *k, const char *name, uint32_t type, const uint8_t *data, uint32_t bytes)
{ key *x = K(k); int i, f = -1; (void)p; if (!x) return 1010; if (bytes > 256) return 87;
  for (i = 0; i < VALS; i++) if (x->v[i].used && !strcasecmp(x->v[i].name, name)) f = i;
  for (i = 0; f < 0 && i < VALS; i++) if (!x->v[i].used) f = i; if (f < 0) return 8;
  x->v[f].used = 1; snprintf(x->v[f].name, 256, "%s", name); x->v[f].type = type; x->v[f].len = bytes; if (bytes) memcpy(x->v[f].data, data, bytes); return 0; }
static long b_has(void *p, void *k, int *present)
{ key *x = K(k); int i; size_t n; (void)p; if (!x) return 1010; n = strlen(x->path); *present = 0;
  for (i = 0; i < KEYS; i++) if (keys[i].used && keys[i].root == x->root && strlen(keys[i].path) > n && !strncasecmp(keys[i].path, x->path, n) && keys[i].path[n] == '\\') *present = 1; return 0; }
static long b_remove(void *p, unsigned root, const char *path)
{ /* Win98 behaviour: recursive. */ int i; size_t n = strlen(path); (void)p; if (find(root, path) < 0) return 2;
  for (i = 0; i < KEYS; i++) if (keys[i].used && keys[i].root == root && !strncasecmp(keys[i].path, path, n) && (!keys[i].path[n] || keys[i].path[n] == '\\')) keys[i].used = 0; return 0; }
static long b_close(void *p, void *k) { (void)p; (void)k; opens--; return 0; }
/* Model code page: ASCII plus U+AC00 <-> {0xB0,0x5C} (DBCS trail equals '\\'). */
static int b_ansi(void *p, const uint16_t *w, uint32_t n, char *out, uint32_t cap, uint32_t *used)
{ uint32_t i, o = 0; (void)p; for (i = 0; i < n; i++) { if (w[i] < 0x80) { if (out) { if (o >= cap) return 0; out[o] = (char)w[i]; } o++; }
    else if (w[i] == 0xAC00) { if (out) { if (o + 2 > cap) return 0; out[o] = (char)0xB0; out[o + 1] = 0x5C; } o += 2; } else return 0; } *used = o; return 1; }
static int b_wide(void *p, const char *a, uint32_t n, uint16_t *out, uint32_t cap, uint32_t *used)
{ uint32_t i, o = 0; (void)p; for (i = 0; i < n; i++) { uint16_t c; unsigned char b = (unsigned char)a[i];
    if (b < 0x80) c = b; else if (b == 0xB0 && i + 1 < n) { c = 0xAC00; i++; } else return 0;
    if (out) { if (o >= cap) return 0; out[o] = c; } o++; } *used = o; return 1; }
static void *b_alloc(void *p, uint32_t n) { (void)p; return malloc(n); }
static void b_release(void *p, void *b) { (void)p; free(b); }
static ntr_state st;
static uint16_t W[64][160];
static int wi;
static ntr_unicode_string *U(const char *s)
{ static ntr_unicode_string us[64]; uint16_t *b = W[wi % 64]; ntr_unicode_string *u = &us[wi++ % 64]; size_t i, n = strlen(s);
  for (i = 0; i < n; i++) b[i] = (unsigned char)s[i] == 0x01 ? 0xAC00 : (unsigned char)s[i] == 0x02 ? 0x00E9 : (uint16_t)(unsigned char)s[i];
  u->Buffer = b; u->Length = (uint16_t)(n * 2); u->MaximumLength = (uint16_t)(n * 2 + 2); return u; }
static ntr_object_attributes OA(void *root, const char *name)
{ ntr_object_attributes o; memset(&o, 0, sizeof o); o.Length = sizeof o; o.RootDirectory = root; o.ObjectName = name ? U(name) : 0; o.Attributes = NTR_OBJ_CASE_INSENSITIVE; return o; }
static void *worker(void *arg)
{ /* Per-thread name storage: the U()/OA() helpers are single-threaded. */
  int i, id = (int)(intptr_t)arg; char name[64]; uint16_t wn[64], wv[2] = {'n', 0}; size_t k, n;
  ntr_unicode_string un, uv = {2, 4, wv}; ntr_object_attributes o;
  snprintf(name, sizeof name, "\\Registry\\Machine\\Software\\T%d", id); n = strlen(name);
  for (k = 0; k < n; k++) wn[k] = (uint16_t)(unsigned char)name[k];
  un.Buffer = wn; un.Length = (uint16_t)(n * 2); un.MaximumLength = (uint16_t)(n * 2);
  memset(&o, 0, sizeof o); o.Length = sizeof o; o.ObjectName = &un;
  for (i = 0; i < 200; i++) { void *h = 0; uint32_t d, r, v = (uint32_t)i, got; uint8_t buf[64];
    if (ntr_create_key(&st, &h, 0xF003F, &o, 0, 0, 0, &d)) { __atomic_add_fetch(&failures, 1, __ATOMIC_SEQ_CST); continue; }
    if (ntr_set_value_key(&st, h, &uv, 0, 4, &v, 4) ||
        ntr_query_value_key(&st, h, &uv, NTR_KEY_VALUE_PARTIAL, buf, sizeof buf, &r) || r != 16 ||
        (memcpy(&got, buf + 12, 4), got != v))
      __atomic_add_fetch(&failures, 1, __ATOMIC_SEQ_CST);
    if (ntr_close(&st, h)) __atomic_add_fetch(&failures, 1, __ATOMIC_SEQ_CST); } return 0; }
int main(void)
{
  ntr_backend ops = {0, lk, ulk, b_open, b_create, b_query, b_set, b_has, b_remove, b_close, b_ansi, b_wide, b_alloc, b_release};
  ntr_unicode_string cu, s; ntr_object_attributes o; void *h = 0, *a = 0, *b = 0, *b2 = 0, *ro = 0, *hs[NTR_HANDLES];
  uint32_t d = 0, r = 0, dw = 0x12345678; uint8_t buf[256]; ntr_status x; int i; pthread_t t[4];
  static const uint16_t hi[] = {'h', 'i', 0}, bad[] = {0xE9, 0};
  add(NTR_ROOT_MACHINE, "Software");
  check(ntr_init(&st, &ops), "init");
  check(sizeof(void *) != 4 || (sizeof(ntr_unicode_string) == 8 && sizeof(ntr_object_attributes) == 24), "x86 layouts");
  ntr_init_unicode_string(&s, hi); check(s.Length == 4 && s.MaximumLength == 6 && s.Buffer == hi, "RtlInitUnicodeString");
  check(ntr_format_current_user_key_path(&st, &cu) == NTR_SUCCESS && cu.Length == 2 * strlen("\\REGISTRY\\USER\\" NTR_CURRENT_USER_ALIAS), "format user");
  o = OA(0, "\\Registry\\Machine\\Software\\Nope"); check(ntr_open_key_ex(&st, &h, 0x20019, &o, 0) == NTR_OBJECT_NAME_NOT_FOUND && !h, "open missing");
  o = OA(0, "\\Registry\\Machine\\Software\\A\\B"); check(ntr_create_key(&st, &h, 0xF003F, &o, 0, 0, 0, &d) == NTR_OBJECT_NAME_NOT_FOUND, "no intermediates");
  check(find(NTR_ROOT_MACHINE, "Software\\A") < 0, "Win98 intermediate creation suppressed");
  o = OA(0, "\\REGISTRY\\MACHINE\\software"); check(ntr_create_key(&st, &h, 0xF003F, &o, 0, 0, 0, &d) == 0 && d == NTR_REG_OPENED_EXISTING_KEY, "open existing via create");
  o = OA(h, "A"); check(ntr_create_key(&st, &a, 0xF003F, &o, 0, 0, 0, &d) == 0 && d == NTR_REG_CREATED_NEW_KEY, "relative create");
  o = OA(a, "B"); check(ntr_create_key(&st, &b, 0xF003F, &o, 0, 0, 0, &d) == 0 && d == NTR_REG_CREATED_NEW_KEY && find(NTR_ROOT_MACHINE, "Software\\A\\B") >= 0, "nested relative create");
  check(ntr_set_value_key(&st, b, U("s"), 0, 1, hi, 6) == 0, "set REG_SZ");
  { int k = find(NTR_ROOT_MACHINE, "Software\\A\\B"); check(keys[k].v[0].len == 3 && !memcmp(keys[k].v[0].data, "hi", 3), "stored as ANSI"); }
  check(ntr_query_value_key(&st, b, U("s"), NTR_KEY_VALUE_FULL, buf, 0, &r) == NTR_BUFFER_TOO_SMALL && r == 30, "full too small");
  memset(buf, 0xCC, sizeof buf);
  check(ntr_query_value_key(&st, b, U("s"), NTR_KEY_VALUE_FULL, buf, 20, &r) == NTR_BUFFER_OVERFLOW && r == 30 && buf[20] == 0xCC, "full overflow header");
  check(ntr_query_value_key(&st, b, U("s"), NTR_KEY_VALUE_FULL, buf, sizeof buf, &r) == 0 && r == 30, "full ok");
  { uint32_t off, len, nl, ty; memcpy(&ty, buf + 4, 4); memcpy(&off, buf + 8, 4); memcpy(&len, buf + 12, 4); memcpy(&nl, buf + 16, 4);
    check(ty == 1 && off == 24 && len == 6 && nl == 2 && buf[20] == 's' && !memcmp(buf + off, hi, 6), "full layout and UTF-16 data"); }
  check(ntr_query_value_key(&st, b, U("s"), NTR_KEY_VALUE_PARTIAL, buf, sizeof buf, &r) == 0 && r == 18 && !memcmp(buf + 12, hi, 6), "partial");
  check(ntr_query_value_key(&st, b, U("s"), NTR_KEY_VALUE_BASIC, buf, sizeof buf, &r) == 0 && r == 14, "basic");
  check(ntr_query_value_key(&st, b, U("s"), 5, buf, sizeof buf, &r) == NTR_INVALID_INFO_CLASS, "info class");
  check(ntr_query_value_key(&st, b, U("zz"), NTR_KEY_VALUE_FULL, buf, sizeof buf, &r) == NTR_OBJECT_NAME_NOT_FOUND, "missing value");
  check(ntr_set_value_key(&st, b, U("d"), 0, 4, &dw, 4) == 0 && ntr_query_value_key(&st, b, U("d"), NTR_KEY_VALUE_PARTIAL, buf, sizeof buf, &r) == 0 && r == 16 && !memcmp(buf + 12, &dw, 4), "REG_DWORD raw");
  check(ntr_set_value_key(&st, b, U("u"), 0, 1, bad, 4) == NTR_UNMAPPABLE_CHARACTER && ntr_query_value_key(&st, b, U("u"), 2, buf, sizeof buf, &r) == NTR_OBJECT_NAME_NOT_FOUND, "unmappable not stored");
  check(ntr_set_value_key(&st, b, U("o"), 0, 1, hi, 3) == NTR_INVALID_PARAMETER, "odd REG_SZ");
  check(ntr_set_value_key(&st, b, U("x\x02"), 0, 4, &dw, 4) == NTR_UNMAPPABLE_CHARACTER, "unmappable value name");
  o = OA(0, "\\Registry\\Machine\\Software\\A\\B"); check(ntr_open_key_ex(&st, &ro, 0x20019, &o, 0) == 0, "open read-only");
  check(ntr_set_value_key(&st, ro, U("d"), 0, 4, &dw, 4) == NTR_ACCESS_DENIED && ntr_delete_key(&st, ro) == NTR_ACCESS_DENIED, "access enforced");
  o = OA(0, "\\Registry\\Machine\\Software\\A\\B"); check(ntr_open_key_ex(&st, &b2, 0xF003F, &o, 0) == 0, "second handle");
  check(ntr_delete_key(&st, a) == NTR_CANNOT_DELETE && find(NTR_ROOT_MACHINE, "Software\\A\\B") >= 0, "Win98 recursive delete suppressed");
  check(ntr_delete_key(&st, b) == 0 && find(NTR_ROOT_MACHINE, "Software\\A\\B") < 0, "delete leaf");
  check(ntr_query_value_key(&st, b2, U("s"), 2, buf, sizeof buf, &r) == NTR_KEY_DELETED && ntr_query_value_key(&st, ro, U("s"), 2, buf, sizeof buf, &r) == NTR_KEY_DELETED, "other handles deleted");
  check(ntr_delete_key(&st, a) == 0, "delete now-empty parent");
  check(ntr_close(&st, b) == 0 && ntr_close(&st, b) == NTR_INVALID_HANDLE, "stale handle after close");
  check(ntr_close(&st, b2) == 0 && ntr_close(&st, ro) == 0 && ntr_close(&st, a) == 0, "close deleted handles");
  check(ntr_close(&st, (void *)(uintptr_t)(0x4E000000u | (0x3FF0u << 10) | 4u)) == NTR_INVALID_HANDLE && ntr_close(&st, (void *)(uintptr_t)0x1234) == NTR_INVALID_HANDLE, "forged handles");
  o = OA(0, "\\Registry\\Machine\\Software\\"); check(ntr_open_key_ex(&st, &a, 0x20019, &o, 0) == NTR_OBJECT_NAME_INVALID, "trailing slash");
  o = OA(0, "\\Registry\\Machine\\Software\\\\X"); check(ntr_open_key_ex(&st, &a, 0x20019, &o, 0) == NTR_OBJECT_NAME_INVALID, "empty component");
  o = OA(0, "\\Device\\Foo"); check(ntr_open_key_ex(&st, &a, 0x20019, &o, 0) == NTR_OBJECT_NAME_NOT_FOUND, "non registry");
  o = OA(0, "Software"); check(ntr_open_key_ex(&st, &a, 0x20019, &o, 0) == NTR_OBJECT_PATH_SYNTAX_BAD, "relative without root");
  o = OA(h, "\\X"); check(ntr_open_key_ex(&st, &a, 0x20019, &o, 0) == NTR_OBJECT_PATH_SYNTAX_BAD, "absolute with root");
  o = OA(0, "\\Registry\\Machine\\Software"); o.SecurityDescriptor = &d; check(ntr_create_key(&st, &a, 0xF003F, &o, 0, 0, 0, &d) == NTR_NOT_SUPPORTED, "security descriptor");
  o = OA(0, "\\Registry\\Machine\\Software"); o.Length = 20; check(ntr_open_key_ex(&st, &a, 0x20019, &o, 0) == NTR_INVALID_PARAMETER, "OA length");
  o = OA(0, "\\Registry\\Machine\\Software\\V"); check(ntr_create_key(&st, &a, 0xF003F, &o, 0, 0, 1, &d) == NTR_NOT_SUPPORTED && find(NTR_ROOT_MACHINE, "Software\\V") < 0, "volatile refused");
  o = OA(0, "\\Registry\\Machine\\Software"); check(ntr_open_key_ex(&st, &a, 0x20319, &o, 0) == NTR_INVALID_PARAMETER, "both WOW64 views");
  o = OA(0, "\\Registry\\Machine\\Software"); check(ntr_open_key_ex(&st, &a, 0x20119, &o, 0) == 0 && ntr_close(&st, a) == 0, "WOW64 view bit accepted");
  { char name[200]; snprintf(name, sizeof name, "\\REGISTRY\\USER\\%s\\Software", NTR_CURRENT_USER_ALIAS); o = OA(0, name);
    check(ntr_create_key(&st, &a, 0xF003F, &o, 0, 0, 0, &d) == 0 && find(NTR_ROOT_CURRENT_USER, "Software") >= 0 && ntr_close(&st, a) == 0, "current user alias -> HKCU"); }
  add(NTR_ROOT_USERS, ".DEFAULT");
  o = OA(0, "\\Registry\\User\\.Default"); check(ntr_open_key_ex(&st, &a, 0x20019, &o, 0) == 0 && ntr_close(&st, a) == 0, "HKU .DEFAULT");
  o = OA(0, "\\Registry\\Machine\\Software\\K\x01"); check(ntr_create_key(&st, &a, 0xF003F, &o, 0, 0, 0, &d) == 0, "DBCS key create");
  o = OA(a, "C"); check(ntr_create_key(&st, &b, 0xF003F, &o, 0, 0, 0, &d) == 0 && find(NTR_ROOT_MACHINE, "Software\\K\xB0\x5C\\C") >= 0, "DBCS trail 0x5C path");
  check(ntr_delete_key(&st, b) == 0 && ntr_delete_key(&st, a) == 0 && ntr_close(&st, b) == 0 && ntr_close(&st, a) == 0, "DBCS delete");
  o = OA(0, "\\Registry\\Machine\\Software");
  for (i = 0; i < (int)NTR_HANDLES - 1; i++) check(ntr_open_key_ex(&st, &hs[i], 0x20019, &o, 0) == 0, "fill handles");
  check(ntr_open_key_ex(&st, &a, 0x20019, &o, 0) == NTR_INSUFFICIENT_RESOURCES && !a, "handle exhaustion");
  for (i = 0; i < (int)NTR_HANDLES - 1; i++) ntr_close(&st, hs[i]);
  check(ntr_close(&st, hs[0]) == NTR_INVALID_HANDLE, "generation rejects reused slot");
  for (i = 0; i < 4; i++) pthread_create(&t[i], 0, worker, (void *)(intptr_t)i);
  for (i = 0; i < 4; i++) pthread_join(t[i], 0);
  check(failures == 0, "concurrent create/set/query/close");
  x = ntr_close(&st, h); check(x == 0, "close root");
  ntr_free_unicode_string(&st, &cu); check(!cu.Buffer && !cu.Length, "RtlFreeUnicodeString");
  s.Buffer = (uint16_t *)hi; ntr_free_unicode_string(&st, &s); check(!s.Buffer, "foreign buffer not freed");
  o = OA(0, "\\Registry\\Machine\\Software"); check(ntr_open_key_ex(&st, &a, 0x20019, &o, 0) == 0, "open for shutdown");
  check(ntr_shutdown(&st) == 1 && opens == 0, "shutdown closes owned keys");
  check(ntr_open_key_ex(&st, &a, 0x20019, &o, 0) == NTR_UNSUCCESSFUL, "use after shutdown");
  if (failures) { printf("FAIL %u/%u\n", failures, checks); return 1; }
  printf("PASS %u checks; in-memory Win98 registry model; native_executed=false; application_executed=false\n", checks);
  return 0;
}
