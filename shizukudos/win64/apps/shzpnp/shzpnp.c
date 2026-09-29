/* SPDX-License-Identifier: GPL-2.0-only
 * shzpnp: ShizukuDOS 10 driver-package tool (Win64 console program, \SHZ\SYS64\SHZPNP.EXE).
 *
 *   shzpnp add-driver <inf> [--install] [--device <id>]... [--legacy]
 *        Stage a driver package the way `pnputil /add-driver` does: the INF and every file its applicable DDInstall
 *        sections copy go to C:\SHZ\INF\FileRepository\<inf>_amd64_<crc32>\, the INF is published as C:\SHZ\INF\oem<N>.inf
 *        and recorded under HKLM\SYSTEM\DriverDatabase. With --install, every device (from --device, else from the
 *        Enum tree) whose best-ranked model is in this INF is installed: CopyFiles to their DestinationDirs, AddService
 *        -> HKLM\SYSTEM\CurrentControlSet\Services\<name>, DDInstall AddReg -> the software key
 *        Control\Class\{ClassGUID}\<NNNN>, .HW AddReg -> Enum\<instance>\Device Parameters, and the device's Enum key
 *        (HardwareID, CompatibleIDs, Service, Driver, ClassGUID, DeviceDesc, Mfg).
 *   shzpnp enum [--log <file>]      devices under HKLM\SYSTEM\CurrentControlSet\Enum (or PCI functions from a Kernel64 boot log)
 *   shzpnp match [<device>...] [--store <dir>] [--all] [--legacy]
 *        rank the models of the media driver store (<dir>\INDEX.TXT, default C:\DRIVERS, written by
 *        shizukudos/ntdrv/store.py) against devices; without devices, against every device of `enum`.
 *   shzpnp load <service>           NtLoadDriver(\Registry\Machine\System\CurrentControlSet\Services\<service>)
 *
 * Devices: VVVV:DDDD[:SSSSSSSS[:RR[:CCSSPP]]], a PCI\VEN_... hardware ID, or a "K64 pci: ..." boot-log line.
 * INF semantics are those of shzinf.c (cross-checked against shizukudos/ntdrv/inf.py). Paths: %10% = C:\SHZ,
 * %11% = C:\SHZ\SYS64, %12% = C:\SHZ\SYS64\DRIVERS, %17% = C:\SHZ\INF (docs/shizukudos10/DRIVER_INSTALL.md).
 * Nothing here loads code into the kernel except `load`, which only calls NtLoadDriver when ntdll exports it.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winreg.h>
#include "shzcrt.h"
#include "shzinf.h"

#define SVC_ROOT L"SYSTEM\\CurrentControlSet\\Services\\"
#define ENUM_ROOT L"SYSTEM\\CurrentControlSet\\Enum"
#define CLASS_ROOT L"SYSTEM\\CurrentControlSet\\Control\\Class\\"
#define DB_ROOT L"SYSTEM\\DriverDatabase"
#define INF_DIR "C:\\SHZ\\INF"
#define REPO_DIR "C:\\SHZ\\INF\\FileRepository"
#define STATUS_INVALID_SYSTEM_SERVICE_ ((LONG)0xC000001C)
#define STATUS_NOT_IMPLEMENTED_ ((LONG)0xC0000002)

static const shzinf_target_t TARGET_STRICT = { "amd64", 10, 0, 22631, 1, 0, 0 };
static shzinf_target_t g_target;
static int g_errors;

/* ----------------------------------------------------------------------------------------------------- utilities */
static size_t slen(const char *s) { size_t n = 0; while (s[n]) ++n; return n; }
static int ieq(const char *a, const char *b) { return shzinf_stricmp(a, b) == 0; }

static void scpy(char *d, size_t cap, const char *s)
{
    size_t n = slen(s);
    if (n >= cap) n = cap - 1;
    memcpy(d, s, n);
    d[n] = 0;
}

static void scat(char *d, size_t cap, const char *s)
{
    size_t l = slen(d), n = slen(s);
    if (l + n >= cap) n = cap - 1 - l;
    memcpy(d + l, s, n);
    d[l + n] = 0;
}

static WCHAR *wide(const char *s)                      /* UTF-8 -> UTF-16, heap */
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, 0, 0);
    WCHAR *w = (WCHAR *)malloc(sizeof(WCHAR) * (size_t)(n > 0 ? n : 1));
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    else w[0] = 0;
    return w;
}

static char *narrow(const WCHAR *w)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, 0, 0, 0, 0);
    char *s = (char *)malloc((size_t)(n > 0 ? n : 1));
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, 0, 0);
    else s[0] = 0;
    return s;
}

static unsigned char *read_file(const char *path, size_t *len)
{
    WCHAR *w = wide(path);
    HANDLE h = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    LARGE_INTEGER sz;
    unsigned char *b = 0;
    DWORD got = 0;
    free(w);
    if (h == INVALID_HANDLE_VALUE) return 0;
    if (GetFileSizeEx(h, &sz) && sz.QuadPart < (1LL << 30)) {
        b = (unsigned char *)malloc((size_t)sz.QuadPart + 1);
        if (b && ReadFile(h, b, (DWORD)sz.QuadPart, &got, 0) && got == (DWORD)sz.QuadPart) {
            b[got] = 0;
            *len = got;
        } else {
            free(b);
            b = 0;
        }
    }
    CloseHandle(h);
    return b;
}

static int file_exists(const char *path)
{
    WCHAR *w = wide(path);
    DWORD a = GetFileAttributesW(w);
    free(w);
    return a != INVALID_FILE_ATTRIBUTES;
}

static int make_dirs(const char *path)                  /* mkdir -p for "C:\a\b\c" */
{
    char buf[520];
    size_t i;
    scpy(buf, sizeof buf, path);
    for (i = 3; ; ++i) {
        if (buf[i] == '\\' || buf[i] == 0) {
            char c = buf[i];
            WCHAR *w;
            buf[i] = 0;
            w = wide(buf);
            if (GetFileAttributesW(w) == INVALID_FILE_ATTRIBUTES && !CreateDirectoryW(w, 0)) {
                free(w);
                printf("error: cannot create directory %s (error %u)\n", buf, (unsigned)GetLastError());
                return 0;
            }
            free(w);
            buf[i] = c;
            if (!c) break;
        }
    }
    return 1;
}

static int copy_file(const char *src, const char *dst)
{
    WCHAR *ws = wide(src), *wd = wide(dst);
    BOOL ok = CopyFileW(ws, wd, FALSE);
    free(ws);
    free(wd);
    if (!ok) printf("error: copy %s -> %s failed (error %u)\n", src, dst, (unsigned)GetLastError());
    return ok ? 1 : 0;
}

static void dir_of(const char *path, char *out, size_t cap)
{
    size_t n = slen(path);
    scpy(out, cap, path);
    while (n && out[n - 1] != '\\' && out[n - 1] != '/') --n;
    out[n ? n - 1 : 0] = 0;
    if (!n) scpy(out, cap, ".");
}

static const char *base_name(const char *path)
{
    const char *b = path, *p;
    for (p = path; *p; ++p)
        if (*p == '\\' || *p == '/' || *p == ':') b = p + 1;
    return b;
}

/* %N% dirid -> ShizukuDOS directory (DRIVER_INSTALL.md); 0 when unknown */
static const char *dirid_path(int dirid, const char *pkgdir)
{
    switch (dirid) {
    case 10: return "C:\\SHZ";
    case 11: return "C:\\SHZ\\SYS64";
    case 12: return "C:\\SHZ\\SYS64\\DRIVERS";
    case 13: return pkgdir;
    case 17: return INF_DIR;
    case 18: return "C:\\SHZ\\HELP";
    case 20: return "C:\\SHZ\\FONTS";
    case 24: return "C:\\";
    case 25: return "C:\\SHZ\\SYSTEM";
    case 1: return pkgdir;
    default: return 0;
    }
}

/* ServiceBinary "%12%\x.sys" -> ImagePath "\SystemRoot\SYS64\DRIVERS\x.sys" (SystemRoot = C:\SHZ) */
static void image_path(const char *binary, char *out, size_t cap)
{
    int64_t id = 0;
    const char *p = binary;
    out[0] = 0;
    if (p[0] == '%') {
        const char *q = p + 1;
        while (*q >= '0' && *q <= '9') id = id * 10 + (*q++ - '0');
        if (*q == '%') {
            const char *d = dirid_path((int)id, "");
            if (d && d[0] == 'C' && d[1] == ':' && d[2] == '\\' && d[3] == 'S' && d[4] == 'H' && d[5] == 'Z') {
                scpy(out, cap, "\\SystemRoot");
                scat(out, cap, d + 6);
                scat(out, cap, q + 1);
                return;
            }
            if (d) { scpy(out, cap, d); scat(out, cap, q + 1); return; }
        }
    }
    scpy(out, cap, binary);
}

/* ---------------------------------------------------------------------------------------------------- registry */
static HKEY reg_create(HKEY root, const char *sub)
{
    HKEY k = 0;
    WCHAR *w = wide(sub);
    LONG e = RegCreateKeyExW(root, w, 0, 0, 0, KEY_ALL_ACCESS, 0, &k, 0);
    free(w);
    if (e) { printf("error: cannot create registry key %s (error %d)\n", sub, (int)e); ++g_errors; return 0; }
    return k;
}

static HKEY reg_open(HKEY root, const char *sub)
{
    HKEY k = 0;
    WCHAR *w = wide(sub);
    LONG e = RegOpenKeyExW(root, w, 0, KEY_READ, &k);
    free(w);
    return e ? 0 : k;
}

static void set_sz(HKEY k, const char *name, const char *v, DWORD type)
{
    WCHAR *wn = wide(name), *wv = wide(v);
    DWORD bytes = (DWORD)((lstrlenW(wv) + 1) * sizeof(WCHAR));
    if (RegSetValueExW(k, wn, 0, type, (const BYTE *)wv, bytes)) ++g_errors;
    free(wn);
    free(wv);
}

static void set_dword(HKEY k, const char *name, DWORD v)
{
    WCHAR *wn = wide(name);
    if (RegSetValueExW(k, wn, 0, REG_DWORD, (const BYTE *)&v, 4)) ++g_errors;
    free(wn);
}

/* REG_MULTI_SZ from strings separated by '\n' (count n) */
static void set_multi(HKEY k, const char *name, const char *joined, int n)
{
    size_t len = slen(joined), i;
    char *tmp = (char *)malloc(len + 2);
    WCHAR *wn = wide(name), *w;
    int wl;
    memcpy(tmp, joined, len + 1);
    for (i = 0; i < len; ++i) if (tmp[i] == '\n') tmp[i] = 0;
    tmp[len + 1] = 0;
    wl = MultiByteToWideChar(CP_UTF8, 0, tmp, (int)len + (n ? 2 : 1), 0, 0);
    w = (WCHAR *)malloc(sizeof(WCHAR) * (size_t)(wl + 2));
    MultiByteToWideChar(CP_UTF8, 0, tmp, (int)len + (n ? 2 : 1), w, wl);
    if (!n) { w[0] = 0; wl = 1; }                    /* empty list: a single terminating NUL */
    w[wl] = 0;
    /* wl counts every string's NUL plus the final empty string: "a\0b\0\0" */
    if (RegSetValueExW(k, wn, 0, REG_MULTI_SZ, (const BYTE *)w, (DWORD)((size_t)wl * sizeof(WCHAR)))) ++g_errors;
    free(tmp);
    free(wn);
    free(w);
}

static int value_exists(HKEY k, const char *name)
{
    WCHAR *wn = wide(name);
    DWORD type, sz = 0;
    LONG e = RegQueryValueExW(k, wn, 0, &type, 0, &sz);
    free(wn);
    return e == ERROR_SUCCESS || e == ERROR_MORE_DATA;
}

static char *query_sz(HKEY k, const char *name)          /* REG_SZ / EXPAND_SZ / MULTI_SZ ('\n' separated), heap */
{
    WCHAR *wn = wide(name), *buf;
    DWORD type = 0, sz = 0, i;
    char *out;
    if (RegQueryValueExW(k, wn, 0, &type, 0, &sz) || !(type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ)) {
        free(wn);
        return 0;
    }
    buf = (WCHAR *)malloc(sz + 4);
    if (RegQueryValueExW(k, wn, 0, &type, (BYTE *)buf, &sz)) { free(wn); free(buf); return 0; }
    buf[sz / 2] = 0;
    if (type == REG_MULTI_SZ)
        for (i = 0; i + 1 < sz / 2; ++i) if (!buf[i] && buf[i + 1]) buf[i] = '\n';
    out = narrow(buf);
    free(wn);
    free(buf);
    return out;
}

/* One AddReg entry against a key: HKR -> hkr, other roots absolute. Flags per the INF AddReg directive. */
static void apply_reg(const shzinf_reg_t *r, HKEY hkr)
{
    HKEY root = 0, k;
    WCHAR *wname;
    int exists;
    if (!strcmp(r->root, "HKR")) root = hkr;
    else if (!strcmp(r->root, "HKLM")) root = HKEY_LOCAL_MACHINE;
    else if (!strcmp(r->root, "HKCR")) root = HKEY_CLASSES_ROOT;
    else if (!strcmp(r->root, "HKCU")) root = HKEY_CURRENT_USER;
    else if (!strcmp(r->root, "HKU")) root = HKEY_USERS;
    if (!root) return;
    k = r->subkey[0] ? reg_create(root, r->subkey) : root;
    if (!k) return;
    if (!(r->flags & SHZ_FLG_KEYONLY)) {
        exists = value_exists(k, r->name);
        wname = wide(r->name);
        if (r->flags & SHZ_FLG_DELVAL) RegDeleteValueW(k, wname);
        else if ((r->flags & SHZ_FLG_NOCLOBBER) && exists) { }
        else if ((r->flags & SHZ_FLG_OVERWRITEONLY) && !exists) { }
        else if (r->type == SHZ_REG_DWORD) set_dword(k, r->name, (DWORD)r->num);
        else if (r->type == SHZ_REG_QWORD) { uint64_t q = r->num; if (RegSetValueExW(k, wname, 0, REG_QWORD, (const BYTE *)&q, 8)) ++g_errors; }
        else if (r->type == SHZ_REG_BINARY || r->type == SHZ_REG_NONE || (r->flags & SHZ_FLG_BINVALUETYPE)) {
            if (RegSetValueExW(k, wname, 0, r->type, r->bin ? r->bin : (const BYTE *)"", (DWORD)r->binlen)) ++g_errors;
        } else if (r->type == SHZ_REG_MULTI_SZ) {
            if ((r->flags & SHZ_FLG_APPEND) && exists) {                /* append the strings not already present */
                char *cur = query_sz(k, r->name), *acc;
                int n = 0;
                const char *p;
                size_t cap;
                if (!cur) cur = (char *)calloc(1, 1);
                cap = slen(cur) + slen(r->str) + 4;
                acc = (char *)malloc(cap);
                scpy(acc, cap, cur);
                for (p = cur; *p; ++p) if (*p == '\n') ++n;
                n = cur[0] ? n + 1 : 0;
                {
                    const char *s = r->str;
                    while (*s) {
                        const char *e = s;
                        char one[260];
                        size_t l;
                        while (*e && *e != '\n') ++e;
                        l = (size_t)(e - s) < sizeof one - 1 ? (size_t)(e - s) : sizeof one - 1;
                        memcpy(one, s, l);
                        one[l] = 0;
                        {
                            const char *c = cur;
                            int found = 0;
                            while (*c) {
                                const char *ce = c;
                                while (*ce && *ce != '\n') ++ce;
                                if ((size_t)(ce - c) == l && !memcmp(c, one, l)) found = 1;
                                c = *ce ? ce + 1 : ce;
                            }
                            if (!found) { if (n) scat(acc, cap, "\n"); scat(acc, cap, one); ++n; }
                        }
                        s = *e ? e + 1 : e;
                    }
                }
                set_multi(k, r->name, acc, n);
                free(cur);
                free(acc);
            } else {
                set_multi(k, r->name, r->str, r->nmulti);
            }
        } else {
            set_sz(k, r->name, r->str, r->type == SHZ_REG_EXPAND_SZ ? REG_EXPAND_SZ : REG_SZ);
        }
        free(wname);
    }
    if (k != root) RegCloseKey(k);
}

/* -------------------------------------------------------------------------------------------------------- devices */
typedef struct {
    char key[260];              /* Enum-relative instance path, e.g. PCI\VEN_8086&DEV_100E\SHZ0000 */
    shzinf_device_t ids;
    char service[64], driver[64];
    int registered;
} device_t;

static int load_enum(device_t *out, int max)
{
    HKEY e = reg_open(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum");
    int n = 0;
    DWORD i, j, l;
    WCHAR bus[128], dev[260], inst[128];
    if (!e) return 0;
    for (i = 0; ; ++i) {
        HKEY kb;
        l = 128;
        if (RegEnumKeyExW(e, i, bus, &l, 0, 0, 0, 0)) break;
        if (RegOpenKeyExW(e, bus, 0, KEY_READ, &kb)) continue;
        for (j = 0; ; ++j) {
            HKEY kd;
            DWORD m;
            l = 260;
            if (RegEnumKeyExW(kb, j, dev, &l, 0, 0, 0, 0)) break;
            if (RegOpenKeyExW(kb, dev, 0, KEY_READ, &kd)) continue;
            for (m = 0; n < max; ++m) {
                HKEY ki;
                char *b, *d, *in, *hw, *cp, *sv, *dr;
                l = 128;
                if (RegEnumKeyExW(kd, m, inst, &l, 0, 0, 0, 0)) break;
                if (RegOpenKeyExW(kd, inst, 0, KEY_READ, &ki)) continue;
                b = narrow(bus); d = narrow(dev); in = narrow(inst);
                memset(&out[n], 0, sizeof out[n]);
                scpy(out[n].key, sizeof out[n].key, b); scat(out[n].key, sizeof out[n].key, "\\");
                scat(out[n].key, sizeof out[n].key, d); scat(out[n].key, sizeof out[n].key, "\\");
                scat(out[n].key, sizeof out[n].key, in);
                hw = query_sz(ki, "HardwareID");
                cp = query_sz(ki, "CompatibleIDs");
                sv = query_sz(ki, "Service");
                dr = query_sz(ki, "Driver");
                {
                    const char *lists[2] = { hw, cp };
                    int w;
                    for (w = 0; w < 2; ++w) {
                        const char *s = lists[w];
                        while (s && *s) {
                            const char *q = s;
                            size_t len;
                            while (*q && *q != '\n') ++q;
                            len = (size_t)(q - s) < 95 ? (size_t)(q - s) : 95;
                            if (w == 0 && out[n].ids.nhw < 8) { memcpy(out[n].ids.hw[out[n].ids.nhw], s, len); out[n].ids.hw[out[n].ids.nhw++][len] = 0; }
                            if (w == 1 && out[n].ids.ncp < 12) { memcpy(out[n].ids.cp[out[n].ids.ncp], s, len); out[n].ids.cp[out[n].ids.ncp++][len] = 0; }
                            s = *q ? q + 1 : q;
                        }
                    }
                }
                if (sv) scpy(out[n].service, sizeof out[n].service, sv);
                if (dr) scpy(out[n].driver, sizeof out[n].driver, dr);
                out[n].registered = 1;
                free(b); free(d); free(in); free(hw); free(cp); free(sv); free(dr);
                RegCloseKey(ki);
                ++n;
            }
            RegCloseKey(kd);
        }
        RegCloseKey(kb);
    }
    RegCloseKey(e);
    return n;
}

static int device_from_spec(device_t *d, const char *spec, int index)
{
    char inst[16];
    memset(d, 0, sizeof *d);
    if (!shzinf_parse_device(&d->ids, spec) || !d->ids.nhw) return 0;
    /* Enum instance path: <first hardware ID>\SHZ<nnnn> (Windows uses the bus driver's instance ID; no bus driver
     * reported this device, so the instance ID is shzpnp's own) */
    scpy(d->key, sizeof d->key, d->ids.hw[0]);
    shz_snprintf(inst, sizeof inst, "\\SHZ%04u", (unsigned)index);
    scat(d->key, sizeof d->key, inst);
    return 1;
}

static void print_device(const device_t *d)
{
    int i;
    printf("%s%s\n", d->key, d->registered ? "" : "  (not registered)");
    for (i = 0; i < d->ids.nhw; ++i) printf("    HW %s\n", d->ids.hw[i]);
    for (i = 0; i < d->ids.ncp; ++i) printf("    CP %s\n", d->ids.cp[i]);
    if (d->service[0] || d->driver[0]) printf("    service=%s driver=%s\n", d->service[0] ? d->service : "-", d->driver[0] ? d->driver : "-");
}

/* -------------------------------------------------------------------------------------------- media store index */
typedef struct {
    char *pkg, *inf, *install, *ddinstall, *service, *binary, *hwid, *desc, *driverver;
    int rules_w, sig, feature;
    shzinf_model_t m;
    char *compat_buf;
} imodel_t;

static int split_tabs(char *line, char **f, int max)
{
    int n = 0;
    f[n++] = line;
    for (; *line && n < max; ++line)
        if (*line == '\t') { *line = 0; f[n++] = line + 1; }
    return n;
}

static int hexval(const char *s)
{
    int v = 0;
    for (; *s; ++s) v = v * 16 + (*s >= '0' && *s <= '9' ? *s - '0' : (*s | 32) - 'a' + 10);
    return v;
}

/* INDEX.TXT (store.py) -> models; returns count or -1 when the index is missing */
static int load_index(const char *store, imodel_t **out)
{
    char path[520];
    size_t len;
    unsigned char *data;
    char *p, *line;
    int n = 0, cap = 0;
    imodel_t *arr = 0;
    scpy(path, sizeof path, store);
    scat(path, sizeof path, "\\INDEX.TXT");
    data = read_file(path, &len);
    if (!data) return -1;
    for (p = (char *)data; *p; ) {
        char *f[16];
        int nf;
        line = p;
        while (*p && *p != '\n') ++p;
        if (*p) *p++ = 0;
        if (line[0] && line[slen(line) - 1] == '\r') line[slen(line) - 1] = 0;
        nf = split_tabs(line, f, 16);
        if (nf >= 14 && !strcmp(f[0], "MODEL")) {
            imodel_t *m;
            char *c;
            if (n == cap) {
                cap = cap ? cap * 2 : 256;
                arr = (imodel_t *)realloc(arr, sizeof(imodel_t) * (size_t)cap);
            }
            m = &arr[n++];
            memset(m, 0, sizeof *m);
            m->pkg = f[1]; m->inf = f[2]; m->rules_w = f[3][0] == 'W'; m->install = f[4]; m->ddinstall = f[5];
            m->sig = hexval(f[6]); m->feature = hexval(f[7]); m->service = f[8]; m->binary = f[9];
            m->hwid = f[11]; m->desc = f[13];
            m->m.install = m->install; m->m.hwid = m->hwid; m->m.description = m->desc;
            c = f[12];
            while (*c && m->m.ncompat < SHZINF_MAX_IDS) {
                char *e = c;
                while (*e && *e != ';') ++e;
                m->m.compat[m->m.ncompat++] = c;
                if (*e) *e++ = 0;
                c = e;
            }
        }
    }
    *out = arr;
    return n;
}

static void index_driverver(const char *store, imodel_t *arr, int n)
{
    char path[520];
    size_t len, off = 0;
    unsigned char *data;
    int i;
    scpy(path, sizeof path, store);
    scat(path, sizeof path, "\\INDEX.TXT");
    data = read_file(path, &len);
    if (!data) return;
    while (off < len) {
        char *line = (char *)data + off, *f[16];
        size_t e = off;
        int nf;
        while (e < len && data[e] != '\n') ++e;
        data[e] = 0;
        if (e > off && data[e - 1] == '\r') data[e - 1] = 0;
        off = e + 1;
        nf = split_tabs(line, f, 16);
        if (nf >= 8 && !strcmp(f[0], "INF"))
            for (i = 0; i < n; ++i)
                if (!strcmp(arr[i].pkg, f[1]) && ieq(arr[i].inf, f[2])) arr[i].driverver = f[6];
    }
}

typedef struct { imodel_t *m; uint32_t rank; shzinf_score_t sc; } hit_t;

static int hit_before(const hit_t *a, const hit_t *b)
{
    if (a->rank != b->rank) return a->rank < b->rank;
    return shzinf_driverver_cmp(a->m->driverver, b->m->driverver) > 0;     /* equal rank: newer DriverVer first */
}

static int rank_device(const device_t *d, imodel_t *arr, int n, int want_w, hit_t *hits, int max)
{
    int i, nh = 0, j;
    for (i = 0; i < n; ++i) {
        shzinf_score_t sc;
        if (arr[i].rules_w != want_w && want_w) continue;
        if (!shzinf_score(&d->ids, &arr[i].m, &sc)) continue;
        if (nh < max) {
            hit_t h;
            h.m = &arr[i];
            h.sc = sc;
            h.rank = ((uint32_t)arr[i].sig << 24) | ((uint32_t)(arr[i].feature & 0xFF) << 16) | sc.identifier;
            for (j = nh; j > 0 && hit_before(&h, &hits[j - 1]); --j) hits[j] = hits[j - 1];   /* stable insertion */
            hits[j] = h;
            ++nh;
        }
    }
    return nh;
}

static int cmd_match(int argc, char **argv)
{
    const char *store = "C:\\DRIVERS";
    static device_t devs[64];
    static hit_t hits[256];
    imodel_t *arr = 0;
    int ndev = 0, i, all = 0, legacy = 0, n;
    for (i = 0; i < argc; ++i) {
        if (!strcmp(argv[i], "--store") && i + 1 < argc) store = argv[++i];
        else if (!strcmp(argv[i], "--all")) all = 1;
        else if (!strcmp(argv[i], "--legacy")) legacy = 1;
        else if (ndev < 64) {
            if (!device_from_spec(&devs[ndev], argv[i], ndev)) { printf("error: cannot parse device %s\n", argv[i]); return 2; }
            ++ndev;
        }
    }
    if (!ndev) {
        ndev = load_enum(devs, 64);
        if (!ndev) {
            printf("no devices: the Enum tree is empty (no bus driver has reported devices; the NT driver host is not present)\n"
                   "give devices on the command line, e.g. shzpnp match 8086:100E\n");
            return 1;
        }
    }
    n = load_index(store, &arr);
    if (n < 0) { printf("error: no driver store index %s\\INDEX.TXT (shizukudos/ntdrv/store.py writes it)\n", store); return 2; }
    index_driverver(store, arr, n);
    printf("%d models in %s\\INDEX.TXT\n", n, store);
    for (i = 0; i < ndev; ++i) {
        int nh = legacy ? 0 : rank_device(&devs[i], arr, n, 1, hits, 256), k;
        const char *rules = "Windows x64 rules";
        if (!nh) {             /* as store.py: models only ReactOS-style undecorated sections provide, when nothing else matches */
            nh = rank_device(&devs[i], arr, n, 0, hits, 256);
            rules = legacy ? "all models (--legacy)" : "undecorated-models fallback";
        }
        printf("device %s (%s)\n", devs[i].key, devs[i].ids.hw[0]);
        if (!nh) { printf("  no driver in the store\n"); continue; }
        for (k = 0; k < (all ? nh : 1); ++k)
            printf("  %s rank %08x (%s) %s\\%s [%s] '%s' service=%s binary=%s matched %s\n", k ? "    " : "best",
                   (unsigned)hits[k].rank, rules, hits[k].m->pkg, hits[k].m->inf, hits[k].m->install, hits[k].m->desc,
                   hits[k].m->service[0] ? hits[k].m->service : "-", hits[k].m->binary[0] ? hits[k].m->binary : "-", hits[k].sc.inf_id);
    }
    return 0;
}

/* ------------------------------------------------------------------------------------------------------ add-driver */
static uint32_t crc32_of(const unsigned char *d, size_t n) { return shz_crc32(d, n); }

static int next_free_index(HKEY parent, const char *fmt_prefix, int width)
{
    int i;
    char name[32];
    (void)fmt_prefix;
    for (i = 0; i < 10000; ++i) {
        HKEY k;
        WCHAR *w;
        shz_snprintf(name, sizeof name, width == 4 ? "%04u" : "%u", (unsigned)i);
        w = wide(name);
        if (RegOpenKeyExW(parent, w, 0, KEY_READ, &k)) { free(w); return i; }
        RegCloseKey(k);
        free(w);
    }
    return -1;
}

static int install_on_device(shzinf_t *inf, const shzinf_model_t *m, const device_t *d, const char *pkgdir, const char *published,
                             const shzinf_target_t *t)
{
    shzinf_install_t *r = shzinf_install(inf, m->install, t);
    char path[520], src[520], sub[260], cls_key[160], guid[64], idx[16];
    HKEY hsw = 0, hdev = 0, hparams = 0, hclass;
    int i, ok = 1, assoc = -1;
    const char *clsguid = shzinf_version(inf, "ClassGuid", t);
    scpy(guid, sizeof guid, clsguid);
    if (!r->section) { printf("error: DDInstall section [%s] not found\n", m->install); shzinf_install_free(r); return 0; }
    printf("installing %s on %s: [%s]\n", m->description, d->key, r->section);
    for (i = 0; i < r->ncopy; ++i) {                       /* CopyFiles */
        const shzinf_copy_t *c = &r->copy[i];
        const char *dst = dirid_path(c->dirid, pkgdir);
        if (!dst) { printf("error: DestinationDirs dirid %d is not mapped on ShizukuDOS\n", c->dirid); ok = 0; continue; }
        scpy(path, sizeof path, dst);
        if (c->subdir[0]) { scat(path, sizeof path, "\\"); scat(path, sizeof path, c->subdir); }
        if (!make_dirs(path)) { ok = 0; continue; }
        scat(path, sizeof path, "\\");
        scat(path, sizeof path, c->dest);
        scpy(src, sizeof src, pkgdir);
        scat(src, sizeof src, "\\");
        shzinf_source_subdir(inf, c->source, t, sub, sizeof sub);
        if (sub[0]) { scat(src, sizeof src, sub); scat(src, sizeof src, "\\"); }
        scat(src, sizeof src, c->source);
        if (!file_exists(src)) {                           /* staged packages keep the files next to the INF */
            scpy(src, sizeof src, pkgdir);
            scat(src, sizeof src, "\\");
            scat(src, sizeof src, c->source);
        }
        if (copy_file(src, path)) printf("  copied %s -> %s\n", src, path);
        else ok = 0;
    }
    for (i = 0; i < r->nsvc; ++i) {                        /* AddService */
        const shzinf_service_t *s = &r->svc[i];
        HKEY hs;
        char img[300];
        int k;
        if (s->is_delete) continue;
        scpy(path, sizeof path, "SYSTEM\\CurrentControlSet\\Services\\");
        scat(path, sizeof path, s->name);
        hs = reg_create(HKEY_LOCAL_MACHINE, path);
        if (!hs) { ok = 0; continue; }
        if (s->service_type >= 0) set_dword(hs, "Type", (DWORD)s->service_type);
        if (s->start_type >= 0) set_dword(hs, "Start", (DWORD)s->start_type);
        if (s->error_control >= 0) set_dword(hs, "ErrorControl", (DWORD)s->error_control);
        if (s->binary) { image_path(s->binary, img, sizeof img); set_sz(hs, "ImagePath", img, REG_EXPAND_SZ); }
        if (s->display) set_sz(hs, "DisplayName", s->display, REG_SZ);
        if (s->description) set_sz(hs, "Description", s->description, REG_SZ);
        if (s->group) set_sz(hs, "Group", s->group, REG_SZ);
        if (s->ndeps) {
            char deps[512] = "";
            int nd = 0;
            for (k = 0; k < s->ndeps; ++k) {
                if (s->deps[k][0] == '+') continue;            /* +group dependencies go to DependOnGroup */
                if (nd++) scat(deps, sizeof deps, "\n");
                scat(deps, sizeof deps, s->deps[k]);
            }
            if (nd) set_multi(hs, "DependOnService", deps, nd);
        }
        for (k = 0; k < s->nreg; ++k) apply_reg(&s->reg[k], hs);
        printf("  service %s: Type=%d Start=%d ImagePath=%s\n", s->name, s->service_type, s->start_type, s->binary ? img : "-");
        if (s->flags & 2) assoc = i;                        /* SPSVCINST_ASSOCSERVICE: the device's function driver */
        RegCloseKey(hs);
    }
    /* software key Control\Class\{guid}\NNNN */
    scpy(cls_key, sizeof cls_key, "SYSTEM\\CurrentControlSet\\Control\\Class\\");
    scat(cls_key, sizeof cls_key, guid);
    hclass = reg_create(HKEY_LOCAL_MACHINE, cls_key);
    if (hclass) {
        int n = next_free_index(hclass, "", 4);
        shz_snprintf(idx, sizeof idx, "%04u", (unsigned)n);
        scat(cls_key, sizeof cls_key, "\\");
        scat(cls_key, sizeof cls_key, idx);
        RegCloseKey(hclass);
        hsw = reg_create(HKEY_LOCAL_MACHINE, cls_key);
    }
    if (hsw) {
        set_sz(hsw, "DriverDesc", m->description, REG_SZ);
        set_sz(hsw, "ProviderName", shzinf_version(inf, "Provider", t), REG_SZ);
        set_sz(hsw, "DriverVersion", shzinf_version(inf, "DriverVer", t), REG_SZ);
        set_sz(hsw, "InfPath", published, REG_SZ);
        set_sz(hsw, "InfSection", r->section, REG_SZ);
        set_sz(hsw, "MatchingDeviceId", m->hwid, REG_SZ);
        for (i = 0; i < r->nreg; ++i) apply_reg(&r->reg[i], hsw);
        RegCloseKey(hsw);
    }
    /* device key Enum\<instance> */
    scpy(path, sizeof path, "SYSTEM\\CurrentControlSet\\Enum\\");
    scat(path, sizeof path, d->key);
    hdev = reg_create(HKEY_LOCAL_MACHINE, path);
    if (hdev) {
        char hw[1024] = "", cp[1400] = "", drv[96];
        for (i = 0; i < d->ids.nhw; ++i) { if (i) scat(hw, sizeof hw, "\n"); scat(hw, sizeof hw, d->ids.hw[i]); }
        for (i = 0; i < d->ids.ncp; ++i) { if (i) scat(cp, sizeof cp, "\n"); scat(cp, sizeof cp, d->ids.cp[i]); }
        set_multi(hdev, "HardwareID", hw, d->ids.nhw);
        set_multi(hdev, "CompatibleIDs", cp, d->ids.ncp);
        set_sz(hdev, "DeviceDesc", m->description, REG_SZ);
        set_sz(hdev, "Mfg", m->mfg ? m->mfg : "", REG_SZ);
        set_sz(hdev, "ClassGUID", guid, REG_SZ);
        set_sz(hdev, "Class", shzinf_version(inf, "Class", t), REG_SZ);
        scpy(drv, sizeof drv, guid);
        scat(drv, sizeof drv, "\\");
        scat(drv, sizeof drv, idx);
        set_sz(hdev, "Driver", drv, REG_SZ);
        set_dword(hdev, "ConfigFlags", 0);
        if (assoc >= 0) set_sz(hdev, "Service", r->svc[assoc].name, REG_SZ);
        hparams = reg_create(hdev, "Device Parameters");
        if (hparams) {
            for (i = 0; i < r->nhwreg; ++i) apply_reg(&r->hwreg[i], hparams);
            RegCloseKey(hparams);
        }
        RegCloseKey(hdev);
        printf("  device key Enum\\%s: Service=%s Driver=%s\n", d->key, assoc >= 0 ? r->svc[assoc].name : "-", drv);
    }
    if (r->kmdf) printf("  note: KMDF %s driver: needs Wdf01000.sys/WdfLdr (the KMDF runtime) in the driver host\n", r->kmdf);
    shzinf_install_free(r);
    return ok && !g_errors;
}

static int cmd_add_driver(int argc, char **argv)
{
    const char *infpath = 0;
    static device_t devs[64];
    static shzinf_model_t models[2048];
    int ndev = 0, install = 0, i, n, used_legacy = 0;
    size_t len;
    unsigned char *data;
    shzinf_t *inf;
    char pkgdir[520], repo[520], published[520], dst[520], sub[260], id[160];
    const char *sig;
    uint32_t crc;
    g_target = TARGET_STRICT;
    for (i = 0; i < argc; ++i) {
        if (!strcmp(argv[i], "--install")) install = 1;
        else if (!strcmp(argv[i], "--legacy")) g_target.legacy = 1;
        else if (!strcmp(argv[i], "--device") && i + 1 < argc) {
            if (ndev < 64 && !device_from_spec(&devs[ndev], argv[++i], ndev)) { printf("error: cannot parse device %s\n", argv[i]); return 2; }
            ++ndev;
            install = 1;
        } else infpath = argv[i];
    }
    if (!infpath) { printf("usage: shzpnp add-driver <inf> [--install] [--device <id>]... [--legacy]\n"); return 2; }
    data = read_file(infpath, &len);
    if (!data) { printf("error: cannot read %s\n", infpath); return 2; }
    inf = shzinf_parse(data, len, "0409");
    sig = shzinf_version(inf, "Signature", &g_target);
    if (!ieq(sig, "$Windows NT$") && !ieq(sig, "$Chicago$")) {
        printf("error: %s: [Version] Signature is '%s', not $Windows NT$ or $Chicago$\n", infpath, sig);
        return 2;
    }
    n = shzinf_models(inf, &g_target, models, 2048);
    if (!n) {
        shzinf_target_t lt = g_target;
        lt.legacy = 1;
        printf("error: no Models section of %s applies to NTamd64.10.0...22631\n", base_name(infpath));
        if (!g_target.legacy && shzinf_models(inf, &lt, models, 2048))
            printf("note: its Models sections are undecorated or arch-less; Windows x64 ignores those. "
                   "--legacy accepts them (ReactOS setupapi behaviour).\n");
        return 1;
    }
    if (n > 2048) n = 2048;
    used_legacy = g_target.legacy;
    printf("%s: class=%s provider=%s DriverVer=%s, %d models for NTamd64.10.0...22631%s\n", base_name(infpath),
           shzinf_version(inf, "Class", &g_target), shzinf_version(inf, "Provider", &g_target),
           shzinf_version(inf, "DriverVer", &g_target), n, used_legacy ? " (undecorated fallback)" : "");
    /* stage: FileRepository\<inf>_amd64_<crc32> + oem<N>.inf */
    dir_of(infpath, pkgdir, sizeof pkgdir);
    crc = crc32_of(data, len);
    shz_snprintf(id, sizeof id, "%s_amd64_%08x", base_name(infpath), (unsigned)crc);
    for (i = 0; id[i]; ++i) if (id[i] >= 'A' && id[i] <= 'Z') id[i] = (char)(id[i] + 32);
    scpy(repo, sizeof repo, REPO_DIR "\\");
    scat(repo, sizeof repo, id);
    if (!make_dirs(repo)) return 2;
    scpy(dst, sizeof dst, repo);
    scat(dst, sizeof dst, "\\");
    scat(dst, sizeof dst, base_name(infpath));
    if (!copy_file(infpath, dst)) return 2;
    {
        int k, staged = 1, missing = 0;
        for (i = 0; i < n; ++i) {
            shzinf_install_t *r;
            int dup = 0;
            for (k = 0; k < i; ++k) if (ieq(models[k].install, models[i].install)) dup = 1;
            if (dup) continue;
            r = shzinf_install(inf, models[i].install, &g_target);
            for (k = 0; k < r->ncopy; ++k) {
                char src[520], out[520];
                shzinf_source_subdir(inf, r->copy[k].source, &g_target, sub, sizeof sub);
                scpy(src, sizeof src, pkgdir); scat(src, sizeof src, "\\");
                if (sub[0]) { scat(src, sizeof src, sub); scat(src, sizeof src, "\\"); }
                scat(src, sizeof src, r->copy[k].source);
                if (!file_exists(src)) {
                    scpy(src, sizeof src, pkgdir); scat(src, sizeof src, "\\"); scat(src, sizeof src, r->copy[k].source);
                }
                scpy(out, sizeof out, repo); scat(out, sizeof out, "\\"); scat(out, sizeof out, r->copy[k].source);
                if (file_exists(out)) continue;
                if (!file_exists(src)) { printf("error: %s copies %s, which is not in the package\n", r->section, r->copy[k].source); ++missing; continue; }
                if (copy_file(src, out)) ++staged;
            }
            shzinf_install_free(r);
        }
        if (missing) { printf("error: package incomplete (%d files missing)\n", missing); return 2; }
        printf("staged %d files in %s\n", staged, repo);
    }
    {   /* publish oem<N>.inf and record the package */
        HKEY db = reg_create(HKEY_LOCAL_MACHINE, "SYSTEM\\DriverDatabase\\DriverInfFiles"), pk;
        int oem = -1;
        char key[300], name[32];
        if (!db) return 2;
        for (i = 0; i < 10000 && oem < 0; ++i) {           /* the same package added again keeps its oem<N>.inf */
            HKEY k;
            char *v;
            shz_snprintf(name, sizeof name, "oem%u.inf", (unsigned)i);
            k = reg_open(db, name);
            if (!k) { oem = i; break; }
            v = query_sz(k, "");
            if (v && ieq(v, id)) oem = i;
            free(v);
            RegCloseKey(k);
        }
        shz_snprintf(name, sizeof name, "oem%u.inf", (unsigned)oem);
        pk = reg_create(db, name);
        if (pk) { set_sz(pk, "", id, REG_SZ); RegCloseKey(pk); }
        RegCloseKey(db);
        make_dirs(INF_DIR);
        scpy(published, sizeof published, INF_DIR "\\");
        scat(published, sizeof published, name);
        copy_file(infpath, published);
        scpy(key, sizeof key, "SYSTEM\\DriverDatabase\\DriverPackages\\");
        scat(key, sizeof key, id);
        pk = reg_create(HKEY_LOCAL_MACHINE, key);
        if (pk) {
            set_sz(pk, "InfName", name, REG_SZ);
            set_sz(pk, "OriginalInf", base_name(infpath), REG_SZ);
            set_sz(pk, "StorePath", repo, REG_SZ);
            set_sz(pk, "Provider", shzinf_version(inf, "Provider", &g_target), REG_SZ);
            set_sz(pk, "Class", shzinf_version(inf, "Class", &g_target), REG_SZ);
            set_sz(pk, "ClassGuid", shzinf_version(inf, "ClassGuid", &g_target), REG_SZ);
            set_sz(pk, "DriverVer", shzinf_version(inf, "DriverVer", &g_target), REG_SZ);
            set_dword(pk, "UndecoratedModels", (DWORD)used_legacy);
            RegCloseKey(pk);
        }
        printf("published as %s (package %s)\n", published, id);
    }
    if (install) {
        int installed = 0;
        if (!ndev) ndev = load_enum(devs, 64);
        for (i = 0; i < ndev; ++i) {
            int best = -1, k;
            uint32_t best_rank = 0;
            for (k = 0; k < n; ++k) {
                shzinf_score_t sc;
                if (shzinf_score(&devs[i].ids, &models[k], &sc)) {
                    shzinf_install_t *r = shzinf_install(inf, models[k].install, &g_target);
                    uint32_t rk = shzinf_rank(r, (int)sc.identifier);
                    shzinf_install_free(r);
                    if (best < 0 || rk < best_rank) { best = k; best_rank = rk; }
                }
            }
            if (best < 0) { printf("%s: no model of this INF matches\n", devs[i].key); continue; }
            printf("%s: best model rank %08x\n", devs[i].key, (unsigned)best_rank);
            if (install_on_device(inf, &models[best], &devs[i], repo, published, &g_target)) ++installed;
        }
        if (!ndev) printf("no devices to install on (Enum is empty; use --device <id>)\n");
        printf("installed on %d device(s)\n", installed);
    }
    shzinf_free(inf);
    free(data);
    return g_errors ? 1 : 0;
}

/* ------------------------------------------------------------------------------------------------------ enum, load */
static int cmd_enum(int argc, char **argv)
{
    static device_t devs[64];
    int n, i;
    if (argc >= 2 && !strcmp(argv[0], "--log")) {
        size_t len;
        unsigned char *data = read_file(argv[1], &len);
        char *p;
        if (!data) { printf("error: cannot read %s\n", argv[1]); return 2; }
        n = 0;
        for (p = (char *)data; *p && n < 64; ) {
            char *line = p, *k;
            while (*p && *p != '\n') ++p;
            if (*p) *p++ = 0;
            for (k = line; *k; ++k)
                if (k[0] == 'K' && k[1] == '6' && k[2] == '4' && k[3] == ' ' && k[4] == 'p' && k[5] == 'c' && k[6] == 'i' && k[7] == ':') {
                    if (device_from_spec(&devs[n], k, n)) print_device(&devs[n]), ++n;
                    break;
                }
        }
        printf("%d PCI functions in the boot log (not registered: no bus driver reported them)\n", n);
        return 0;
    }
    n = load_enum(devs, 64);
    for (i = 0; i < n; ++i) print_device(&devs[i]);
    if (!n) printf("Enum is empty: no bus driver has reported devices (the NT driver host / PnP manager is not present).\n"
                   "PCI functions Kernel64 saw at boot are in its log: shzpnp enum --log <file>\n");
    else printf("%d device instance(s)\n", n);
    return 0;
}

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } shz_ustr_t;
typedef LONG (NTAPI *nt_load_driver_t)(shz_ustr_t *);

static int cmd_load(int argc, char **argv)
{
    char key[300];
    WCHAR *w;
    HKEY k;
    HMODULE ntdll;
    nt_load_driver_t fn;
    shz_ustr_t us;
    LONG st;
    if (argc < 1) { printf("usage: shzpnp load <service>\n"); return 2; }
    scpy(key, sizeof key, "SYSTEM\\CurrentControlSet\\Services\\");
    scat(key, sizeof key, argv[0]);
    k = reg_open(HKEY_LOCAL_MACHINE, key);
    if (!k) { printf("error: no service key HKLM\\%s (add-driver --install creates it)\n", key); return 2; }
    RegCloseKey(k);
    ntdll = GetModuleHandleA("ntdll.dll");
    fn = ntdll ? (nt_load_driver_t)(void *)GetProcAddress(ntdll, "NtLoadDriver") : 0;
    if (!fn) { printf("driver host not present: ntdll.dll exports no NtLoadDriver\n"); return 3; }
    scpy(key, sizeof key, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
    scat(key, sizeof key, argv[0]);
    w = wide(key);
    us.Buffer = w;
    us.Length = (USHORT)(lstrlenW(w) * sizeof(WCHAR));
    us.MaximumLength = (USHORT)(us.Length + sizeof(WCHAR));
    st = fn(&us);
    free(w);
    if (st == STATUS_INVALID_SYSTEM_SERVICE_ || st == STATUS_NOT_IMPLEMENTED_) {
        printf("driver host not present: NtLoadDriver returned %08x\n", (unsigned)st);
        return 3;
    }
    printf("NtLoadDriver(%s) = %08x%s\n", argv[0], (unsigned)st, st == 0 ? " (loaded)" : "");
    return st == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc < 2 || !strcmp(argv[1], "help") || !strcmp(argv[1], "/?")) {
        printf("shzpnp add-driver <inf> [--install] [--device <id>]... [--legacy]\n"
               "shzpnp enum [--log <file>]\n"
               "shzpnp match [<device>...] [--store <dir>] [--all] [--legacy]\n"
               "shzpnp load <service>\n"
               "devices: VVVV:DDDD[:SSSSSSSS[:RR[:CCSSPP]]] | PCI\\VEN_... | \"K64 pci: b:d.f vvvv:dddd class ccsspp\"\n");
        return argc < 2 ? 2 : 0;
    }
    if (!strcmp(argv[1], "add-driver")) return cmd_add_driver(argc - 2, argv + 2);
    if (!strcmp(argv[1], "enum")) return cmd_enum(argc - 2, argv + 2);
    if (!strcmp(argv[1], "match")) return cmd_match(argc - 2, argv + 2);
    if (!strcmp(argv[1], "load")) return cmd_load(argc - 2, argv + 2);
    printf("unknown command %s (shzpnp help)\n", argv[1]);
    return 2;
}
