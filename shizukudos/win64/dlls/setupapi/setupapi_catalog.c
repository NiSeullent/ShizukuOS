/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded SetupAPI implementation over the real registered PnP
 * catalog. No device discovery, USB controller or installed driver is invented.
 * HDEVINFO and Reserved are owned generation tokens, never caller pointers.
 */
#ifndef SHZ_SETUP_HOST_TEST
#define _SETUPAPI_
#include "nt.h"
#include <windows.h>
#include <setupapi.h>
#include <winreg.h>
#include <string.h>
#endif
#include "../../../abi/shz_pnp_catalog.h"

#define CATALOG_LIMIT 1024u
#define CATALOG_MAX_BYTES (sizeof(shz_pnp_catalog_t) + CATALOG_LIMIT * sizeof(shz_pnp_row_t))
struct setup_item { struct setup_item *next; ULONG_PTR id; shz_pnp_row_t row; };
struct setup_set {
    struct setup_set *next;
    ULONG_PTR id;
    unsigned has_class;
    GUID class_guid;
    struct setup_item *items, **tail;
};
static struct setup_set *sets;
static ULONG_PTR sequence;
static volatile LONG mutex;

static void lock(void) { while (InterlockedCompareExchange(&mutex, 1, 0)) Sleep(0); }
static void unlock(void) { InterlockedExchange(&mutex, 0); }
static BOOL failure(DWORD error) { SetLastError(error); return FALSE; }
static ULONG_PTR token(unsigned kind)
{ return sequence == (~(ULONG_PTR)0 >> 2) ? 0 : (++sequence << 2) | kind; }
static struct setup_set *find_set(HDEVINFO handle)
{
    struct setup_set *set;
    for (set = sets; set; set = set->next) if (set->id == (ULONG_PTR)handle) return set;
    return NULL;
}
static void free_set(struct setup_set *set)
{
    struct setup_item *item = set->items;
    while (item) { struct setup_item *next = item->next; HeapFree(GetProcessHeap(), 0, item); item = next; }
    HeapFree(GetProcessHeap(), 0, set);
}
static struct setup_set *new_set(const GUID *guid)
{
    struct setup_set *set = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *set);
    if (!set) return NULL;
    set->id = token(1);
    if (!set->id) { HeapFree(GetProcessHeap(), 0, set); return NULL; }
    if (guid) { set->has_class = 1; set->class_guid = *guid; }
    set->tail = &set->items;
    return set;
}
static int same_guid(const GUID *a, const GUID *b) { return !memcmp(a, b, sizeof *a); }
static unsigned fold(unsigned c) { return c >= 'A' && c <= 'Z' ? c + 'a' - 'A' : c; }
static int equal(const WCHAR *a, const WCHAR *b)
{
    while (*a && *b) if (fold(*a++) != fold(*b++)) return 0;
    return !*a && !*b;
}
static unsigned length(const WCHAR *s) { unsigned n = 0; while (s[n]) ++n; return n; }
static int terminated16(const uint16_t *s, unsigned cap)
{ unsigned i; for (i = 0; i < cap; ++i) if (!s[i]) return 1; return 0; }
static int terminated8(const char *s, unsigned cap)
{ unsigned i; for (i = 0; i < cap; ++i) if (!s[i]) return 1; return 0; }
static int hex(unsigned c)
{
    if (c >= '0' && c <= '9') return (int)(c - '0');
    c = fold(c); return c >= 'a' && c <= 'f' ? (int)(c - 'a') + 10 : -1;
}
static int parse_guid(const uint16_t *text, GUID *guid)
{
    unsigned i; uint32_t value = 0;
    static const unsigned lengths[] = {8,4,4,2,2,2,2,2,2,2,2};
    if (*text++ != '{') return 0;
    memset(guid, 0, sizeof *guid);
    for (i = 0; i < 11; ++i) {
        unsigned k; value = 0;
        for (k = 0; k < lengths[i]; ++k) { int h = hex(*text++); if (h < 0) return 0; value = (value << 4) | (unsigned)h; }
        if (i == 0) guid->Data1 = value;
        else if (i == 1) guid->Data2 = (WORD)value;
        else if (i == 2) guid->Data3 = (WORD)value;
        else guid->Data4[i - 3] = (BYTE)value;
        if (i == 0 || i == 1 || i == 2 || i == 4) { if (*text++ != '-') return 0; }
    }
    return *text++ == '}' && !*text;
}
static int class_matches(const struct setup_set *set, const shz_pnp_row_t *row)
{
    GUID guid;
    return !set->has_class || (parse_guid(row->class_guid, &guid) && same_guid(&guid, &set->class_guid));
}
static struct setup_item *node_item(struct setup_set *set, uint32_t node)
{
    struct setup_item *item;
    for (item = set->items; item; item = item->next)
        if (item->row.kind == SHZ_PNP_NODE && item->row.node_id == node) return item;
    return NULL;
}
static struct setup_item *data_item(struct setup_set *set, const SP_DEVINFO_DATA *data)
{
    struct setup_item *item;
    if (!data || data->cbSize != sizeof *data) return NULL;
    for (item = set->items; item; item = item->next)
        if (item->row.kind == SHZ_PNP_NODE && item->id == data->Reserved && item->row.node_id == data->DevInst) return item;
    return NULL;
}
static struct setup_item *interface_item(struct setup_set *set, const SP_DEVICE_INTERFACE_DATA *data)
{
    struct setup_item *item; GUID guid;
    if (!data || data->cbSize != sizeof *data) return NULL;
    for (item = set->items; item; item = item->next) {
        memcpy(&guid, item->row.interface_guid, sizeof guid);
        if (item->row.kind == SHZ_PNP_INTERFACE && item->id == data->Reserved && same_guid(&guid, &data->InterfaceClassGuid)) return item;
    }
    return NULL;
}
static struct setup_item *add_item(struct setup_set *set, const shz_pnp_row_t *row)
{
    struct setup_item *item;
    for (item = set->items; item; item = item->next)
        if (item->row.kind == row->kind && item->row.node_id == row->node_id &&
            (row->kind == SHZ_PNP_NODE || equal((const WCHAR *)item->row.link, (const WCHAR *)row->link))) {
            item->row = *row; return item;
        }
    item = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *item);
    if (!item) return NULL;
    item->id = token(row->kind == SHZ_PNP_NODE ? 2 : 3);
    if (!item->id) { HeapFree(GetProcessHeap(), 0, item); return NULL; }
    item->row = *row; *set->tail = item; set->tail = &item->next;
    return item;
}
static BOOL fill_device(struct setup_item *item, SP_DEVINFO_DATA *output)
{
    GUID guid;
    if (!output) return TRUE;
    if (output->cbSize != sizeof *output) return failure(ERROR_INVALID_USER_BUFFER);
    memset(&output->ClassGuid, 0, sizeof output->ClassGuid);
    if (parse_guid(item->row.class_guid, &guid)) output->ClassGuid = guid;
    /* An absent/malformed setup class does not become a partial GUID. */
    output->DevInst = item->row.node_id; output->Reserved = item->id;
    return TRUE;
}
static BOOL fill_interface(struct setup_item *item, SP_DEVICE_INTERFACE_DATA *output)
{
    if (!output) return TRUE;
    if (output->cbSize != sizeof *output) return failure(ERROR_INVALID_USER_BUFFER);
    memcpy(&output->InterfaceClassGuid, item->row.interface_guid, sizeof output->InterfaceClassGuid);
    output->Flags = item->row.enabled ? SPINT_ACTIVE : 0; output->Reserved = item->id;
    return TRUE;
}
static DWORD snapshot(shz_pnp_catalog_t **output)
{
    unsigned attempt, i, j; ULONG required = 0, returned = 0; NTSTATUS status;
    shz_pnp_catalog_t *catalog; shz_pnp_row_t *rows;
    *output = NULL;
    for (attempt = 0; attempt < 4; ++attempt) {
        status = NtQuerySystemInformation(SHZ_PNP_CATALOG_CLASS, NULL, 0, &required);
        if (status != (NTSTATUS)0xc0000004u) return status ? RtlNtStatusToDosError(status) : ERROR_INVALID_DATA;
        if (required < sizeof *catalog || required > CATALOG_MAX_BYTES) return ERROR_INVALID_DATA;
        catalog = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, required);
        if (!catalog) return ERROR_NOT_ENOUGH_MEMORY;
        status = NtQuerySystemInformation(SHZ_PNP_CATALOG_CLASS, catalog, required, &returned);
        if (status == (NTSTATUS)0xc0000004u) { HeapFree(GetProcessHeap(), 0, catalog); continue; }
        if (status) { HeapFree(GetProcessHeap(), 0, catalog); return RtlNtStatusToDosError(status); }
        if (returned > required || returned < sizeof *catalog || catalog->version != SHZ_PNP_CATALOG_VERSION ||
            catalog->row_size != sizeof(shz_pnp_row_t) || catalog->count > CATALOG_LIMIT || catalog->reserved ||
            returned != sizeof *catalog + catalog->count * sizeof(shz_pnp_row_t)) goto malformed;
        rows = (shz_pnp_row_t *)(catalog + 1);
        for (i = 0; i < catalog->count; ++i) {
            shz_pnp_row_t *r = &rows[i];
            if ((r->kind != SHZ_PNP_NODE && r->kind != SHZ_PNP_INTERFACE) || !r->node_id || r->enabled > 1 || r->started > 1 ||
                !terminated16(r->instance,128) || !r->instance[0] || !terminated16(r->class_guid,40) ||
                !terminated16(r->driver_key,80) || !terminated16(r->description,128) || !terminated16(r->manufacturer,128) ||
                !terminated16(r->link,160) || !terminated8(r->service,64)) goto malformed;
            if (r->kind == SHZ_PNP_NODE) {
                for (j = 0; j < i; ++j) if (rows[j].kind == SHZ_PNP_NODE && rows[j].node_id == r->node_id) goto malformed;
            } else {
                if (!r->link[0]) goto malformed;
                for (j = 0; j < catalog->count; ++j)
                    if (rows[j].kind == SHZ_PNP_NODE && rows[j].node_id == r->node_id &&
                        equal((const WCHAR *)rows[j].instance,(const WCHAR *)r->instance)) break;
                if (j == catalog->count) goto malformed;
            }
        }
        *output = catalog; return ERROR_SUCCESS;
malformed:
        HeapFree(GetProcessHeap(), 0, catalog); return ERROR_INVALID_DATA;
    }
    return ERROR_RETRY;
}
static shz_pnp_row_t *catalog_node(shz_pnp_catalog_t *catalog, uint32_t node)
{
    shz_pnp_row_t *rows = (shz_pnp_row_t *)(catalog + 1); unsigned i;
    for (i = 0; i < catalog->count; ++i) if (rows[i].kind == SHZ_PNP_NODE && rows[i].node_id == node) return &rows[i];
    return NULL;
}
static int enumerator_matches(const WCHAR *filter, const shz_pnp_row_t *row)
{
    const WCHAR *instance = (const WCHAR *)row->instance; unsigned i;
    if (!filter) return 1;
    for (i = 0; filter[i]; ++i) if (filter[i] == '\\') return equal(filter, instance);
    for (i = 0; filter[i] && instance[i] && instance[i] != '\\'; ++i)
        if (fold(filter[i]) != fold(instance[i])) return 0;
    return !filter[i] && instance[i] == '\\';
}
static void win32_link(const shz_pnp_row_t *row, WCHAR *output)
{
    unsigned i;
    for (i = 0; row->link[i]; ++i) output[i] = row->link[i];
    output[i] = 0;
    /* Only the prefix changes: the actual registered symbolic link remains
     * the source. Kernel interface publication/opening is a separate gap. */
    if (i >= 4 && output[0] == '\\' && output[1] == '?' && output[2] == '?' && output[3] == '\\') {
        output[1] = '\\'; output[2] = '?';
    }
}

DLLAPI HDEVINFO WINAPI SetupDiCreateDeviceInfoList(const GUID *guid, HWND parent)
{
    struct setup_set *set; ULONG_PTR id = 0; (void)parent;
    lock(); set = new_set(guid);
    if (set) { set->next = sets; sets = set; id = set->id; }
    unlock();
    if (!set) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return INVALID_HANDLE_VALUE; }
    return (HDEVINFO)id;
}
DLLAPI BOOL WINAPI SetupDiDestroyDeviceInfoList(HDEVINFO handle)
{
    struct setup_set **link, *set;
    lock(); for (link = &sets; *link && (*link)->id != (ULONG_PTR)handle; link = &(*link)->next) { }
    set = *link;
    if (!set) { unlock(); return failure(ERROR_INVALID_HANDLE); }
    *link = set->next; free_set(set); unlock(); return TRUE;
}
DLLAPI HDEVINFO WINAPI SetupDiGetClassDevsW(const GUID *guid, PCWSTR enumerator, HWND parent, DWORD flags)
{
    struct setup_set *set; shz_pnp_catalog_t *catalog; shz_pnp_row_t *rows, *node; GUID interface_guid;
    DWORD error; unsigned i; ULONG_PTR id; (void)parent;
    if (flags & ~(DIGCF_ALLCLASSES|DIGCF_PRESENT|DIGCF_DEVICEINTERFACE|DIGCF_DEFAULT|DIGCF_PROFILE)) {
        SetLastError(ERROR_INVALID_FLAGS); return INVALID_HANDLE_VALUE;
    }
    if (flags & (DIGCF_DEFAULT|DIGCF_PROFILE)) { SetLastError(ERROR_NOT_SUPPORTED); return INVALID_HANDLE_VALUE; }
    if (!(flags & DIGCF_ALLCLASSES) && !guid) { SetLastError(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE; }
    if (enumerator && enumerator[0] == '{') { SetLastError(ERROR_NOT_SUPPORTED); return INVALID_HANDLE_VALUE; }
    if (enumerator && !(flags & DIGCF_DEVICEINTERFACE)) {
        for (i = 0; enumerator[i]; ++i) if (enumerator[i] == '\\') { SetLastError(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE; }
    }
    error = snapshot(&catalog);
    if (error) { SetLastError(error); return INVALID_HANDLE_VALUE; }
    rows = (shz_pnp_row_t *)(catalog + 1);
    lock(); set = new_set((flags & (DIGCF_ALLCLASSES|DIGCF_DEVICEINTERFACE)) ? NULL : guid);
    if (!set) { error = ERROR_NOT_ENOUGH_MEMORY; goto failed; }
    for (i = 0; i < catalog->count; ++i) {
        shz_pnp_row_t *row = &rows[i];
        if (!enumerator_matches(enumerator,row)) continue;
        if (flags & DIGCF_DEVICEINTERFACE) {
            if (row->kind != SHZ_PNP_INTERFACE || ((flags & DIGCF_PRESENT) && !row->enabled)) continue;
            memcpy(&interface_guid,row->interface_guid,sizeof interface_guid);
            if (!(flags & DIGCF_ALLCLASSES) && !same_guid(guid,&interface_guid)) continue;
            node = catalog_node(catalog,row->node_id);
            if (!add_item(set,node) || !add_item(set,row)) { error = ERROR_NOT_ENOUGH_MEMORY; goto failed; }
        } else if (row->kind == SHZ_PNP_NODE && class_matches(set,row) && !add_item(set,row)) {
            error = ERROR_NOT_ENOUGH_MEMORY; goto failed;
        }
    }
    set->next = sets; sets = set;
    id = set->id;
    unlock(); HeapFree(GetProcessHeap(),0,catalog); return (HDEVINFO)id;
failed:
    if (set) free_set(set);
    unlock(); HeapFree(GetProcessHeap(),0,catalog); SetLastError(error); return INVALID_HANDLE_VALUE;
}
DLLAPI BOOL WINAPI SetupDiEnumDeviceInfo(HDEVINFO handle, DWORD index, PSP_DEVINFO_DATA output)
{
    struct setup_set *set; struct setup_item *item; BOOL result;
    lock(); set = find_set(handle);
    if (!set) { unlock(); return failure(ERROR_INVALID_HANDLE); }
    if (!output || output->cbSize != sizeof *output) { unlock(); return failure(ERROR_INVALID_USER_BUFFER); }
    for (item = set->items; item; item = item->next)
        if (item->row.kind == SHZ_PNP_NODE && !index--) break;
    if (!item) { unlock(); return failure(ERROR_NO_MORE_ITEMS); }
    result = fill_device(item,output); unlock(); return result;
}
DLLAPI BOOL WINAPI SetupDiEnumDeviceInterfaces(HDEVINFO handle, PSP_DEVINFO_DATA device, const GUID *guid,
                                             DWORD index, PSP_DEVICE_INTERFACE_DATA output)
{
    struct setup_set *set; struct setup_item *item, *node = NULL; GUID found; BOOL result;
    lock(); set = find_set(handle);
    if (!set) { unlock(); return failure(ERROR_INVALID_HANDLE); }
    if (!guid) { unlock(); return failure(ERROR_INVALID_PARAMETER); }
    if (!output || output->cbSize != sizeof *output) { unlock(); return failure(ERROR_INVALID_USER_BUFFER); }
    if (device && !(node = data_item(set,device))) { unlock(); return failure(ERROR_INVALID_PARAMETER); }
    for (item = set->items; item; item = item->next) {
        if (item->row.kind != SHZ_PNP_INTERFACE || (node && node->row.node_id != item->row.node_id)) continue;
        memcpy(&found,item->row.interface_guid,sizeof found);
        if (same_guid(guid,&found) && !index--) break;
    }
    if (!item) { unlock(); return failure(ERROR_NO_MORE_ITEMS); }
    result = fill_interface(item,output); unlock(); return result;
}
DLLAPI BOOL WINAPI SetupDiOpenDeviceInfoW(HDEVINFO handle, PCWSTR instance, HWND parent, DWORD flags, PSP_DEVINFO_DATA output)
{
    struct setup_set *set; struct setup_item *item; shz_pnp_catalog_t *catalog; shz_pnp_row_t *rows;
    DWORD error; unsigned i; BOOL result; (void)parent;
    if (flags & ~(DIOD_INHERIT_CLASSDRVS|DIOD_CANCEL_REMOVE)) return failure(ERROR_INVALID_FLAGS);
    if (flags) return failure(ERROR_NOT_SUPPORTED);
    if (!instance || !*instance) return failure(ERROR_NOT_SUPPORTED); /* root devnode is not in this catalog */
    lock(); set = find_set(handle); unlock();
    if (!set) return failure(ERROR_INVALID_HANDLE);
    error = snapshot(&catalog); if (error) return failure(error);
    lock(); set = find_set(handle);
    if (!set) { error = ERROR_INVALID_HANDLE; goto failed; }
    rows = (shz_pnp_row_t *)(catalog + 1);
    for (i = 0; i < catalog->count; ++i)
        if (rows[i].kind == SHZ_PNP_NODE && equal(instance,(const WCHAR *)rows[i].instance)) break;
    if (i == catalog->count) { error = ERROR_NO_SUCH_DEVINST; goto failed; }
    if (!class_matches(set,&rows[i])) { error = ERROR_CLASS_MISMATCH; goto failed; }
    item = add_item(set,&rows[i]);
    if (!item) { error = ERROR_NOT_ENOUGH_MEMORY; goto failed; }
    result = fill_device(item,output); unlock(); HeapFree(GetProcessHeap(),0,catalog); return result;
failed: unlock(); HeapFree(GetProcessHeap(),0,catalog); return failure(error);
}
DLLAPI BOOL WINAPI SetupDiOpenDeviceInterfaceW(HDEVINFO handle, PCWSTR path, DWORD flags, PSP_DEVICE_INTERFACE_DATA output)
{
    struct setup_set *set; struct setup_item *item; shz_pnp_catalog_t *catalog; shz_pnp_row_t *rows, *node;
    WCHAR converted[160]; DWORD error; unsigned i; BOOL result;
    if (flags & ~DIODI_NO_ADD) return failure(ERROR_INVALID_FLAGS);
    if (!path || !*path) return failure(ERROR_INVALID_PARAMETER);
    lock(); set = find_set(handle); unlock();
    if (!set) return failure(ERROR_INVALID_HANDLE);
    error = snapshot(&catalog); if (error) return failure(error);
    lock(); set = find_set(handle);
    if (!set) { error = ERROR_INVALID_HANDLE; goto failed; }
    rows = (shz_pnp_row_t *)(catalog + 1);
    for (i = 0; i < catalog->count; ++i) if (rows[i].kind == SHZ_PNP_INTERFACE) {
        win32_link(&rows[i],converted);
        if (equal(path,converted) || equal(path,(const WCHAR *)rows[i].link)) break;
    }
    if (i == catalog->count) { error = ERROR_NO_SUCH_DEVICE_INTERFACE; goto failed; }
    node = catalog_node(catalog,rows[i].node_id);
    if (!class_matches(set,node)) { error = ERROR_CLASS_MISMATCH; goto failed; }
    if ((flags & DIODI_NO_ADD) && !node_item(set,node->node_id)) { error = ERROR_NO_SUCH_DEVICE_INTERFACE; goto failed; }
    if (!add_item(set,node) || !(item = add_item(set,&rows[i]))) { error = ERROR_NOT_ENOUGH_MEMORY; goto failed; }
    result = fill_interface(item,output); unlock(); HeapFree(GetProcessHeap(),0,catalog); return result;
failed: unlock(); HeapFree(GetProcessHeap(),0,catalog); return failure(error);
}
static DWORD live_item(struct setup_item *item, shz_pnp_row_t *output)
{
    shz_pnp_catalog_t *catalog; shz_pnp_row_t *rows; unsigned i; DWORD error = snapshot(&catalog);
    if (error) return error;
    rows = (shz_pnp_row_t *)(catalog + 1);
    for (i = 0; i < catalog->count; ++i)
        if (rows[i].kind == item->row.kind && rows[i].node_id == item->row.node_id &&
            equal((const WCHAR *)rows[i].instance,(const WCHAR *)item->row.instance) &&
            (item->row.kind == SHZ_PNP_NODE ||
             (equal((const WCHAR *)rows[i].link,(const WCHAR *)item->row.link) &&
              !memcmp(rows[i].interface_guid,item->row.interface_guid,16)))) break;
    if (i == catalog->count) error = item->row.kind == SHZ_PNP_NODE ? ERROR_NO_SUCH_DEVINST : ERROR_NO_SUCH_DEVICE_INTERFACE;
    else *output = rows[i];
    HeapFree(GetProcessHeap(),0,catalog); return error;
}
DLLAPI BOOL WINAPI SetupDiGetDeviceInterfaceDetailW(HDEVINFO handle, PSP_DEVICE_INTERFACE_DATA data,
    PSP_DEVICE_INTERFACE_DETAIL_DATA_W detail, DWORD size, PDWORD required, PSP_DEVINFO_DATA device)
{
    struct setup_set *set; struct setup_item *item, *node; shz_pnp_row_t live;
    WCHAR path[160]; DWORD error, bytes; BOOL result;
    lock(); set = find_set(handle);
    if (!set) { unlock(); return failure(ERROR_INVALID_HANDLE); }
    item = interface_item(set,data);
    if (!item) { unlock(); return failure(ERROR_INVALID_PARAMETER); }
    if ((!detail && size) || (detail && (size < sizeof *detail || detail->cbSize != sizeof *detail)) ||
        (device && device->cbSize != sizeof *device)) { unlock(); return failure(ERROR_INVALID_USER_BUFFER); }
    error = live_item(item,&live);
    if (error) { unlock(); return failure(error); }
    win32_link(&live,path);
    bytes = (DWORD)(offsetof(SP_DEVICE_INTERFACE_DETAIL_DATA_W,DevicePath) + (length(path)+1)*sizeof(WCHAR));
    if (required) *required = bytes;
    node = node_item(set,live.node_id);
    if (!node) { unlock(); return failure(ERROR_INVALID_DATA); }
    result = fill_device(node,device);
    if (!result) { unlock(); return FALSE; }
    if (!detail || size < bytes) { unlock(); return failure(ERROR_INSUFFICIENT_BUFFER); }
    memcpy(detail->DevicePath,path,(length(path)+1)*sizeof(WCHAR));
    unlock(); return TRUE;
}
static DWORD open_node_key(const shz_pnp_row_t *node, DWORD type, REGSAM access, HKEY *output)
{
    WCHAR path[320]; const WCHAR *base, *suffix; unsigned n = 0, i;
    if (type == DIREG_DRV) {
        if (!node->driver_key[0]) return ERROR_KEY_DOES_NOT_EXIST;
        base = L"System\\CurrentControlSet\\Control\\Class\\"; suffix = (const WCHAR *)node->driver_key;
    } else { base = L"System\\CurrentControlSet\\Enum\\"; suffix = (const WCHAR *)node->instance; }
    for (i = 0; base[i]; ++i) path[n++] = base[i];
    for (i = 0; suffix[i]; ++i) path[n++] = suffix[i];
    if (type == DIREG_DEV) {
        suffix = L"\\Device Parameters";
        for (i = 0; suffix[i]; ++i) path[n++] = suffix[i];
    }
    path[n] = 0;
    return (DWORD)RegOpenKeyExW(HKEY_LOCAL_MACHINE,path,0,access,output);
}
DLLAPI HKEY WINAPI SetupDiOpenDevRegKey(HDEVINFO handle, PSP_DEVINFO_DATA data, DWORD scope,
                                     DWORD profile, DWORD type, REGSAM access)
{
    struct setup_set *set; struct setup_item *item; shz_pnp_row_t live; HKEY key = NULL; DWORD error;
    lock(); set = find_set(handle);
    if (!set) { error = ERROR_INVALID_HANDLE; goto failed; }
    item = data_item(set,data);
    if (!item) { error = ERROR_INVALID_PARAMETER; goto failed; }
    if (scope != DICS_FLAG_GLOBAL) { error = scope == DICS_FLAG_CONFIGSPECIFIC ? ERROR_NOT_SUPPORTED : ERROR_INVALID_FLAGS; goto failed; }
    (void)profile; /* ignored for global scope, per Microsoft */
    if (type != DIREG_DEV && type != DIREG_DRV) { error = ERROR_INVALID_FLAGS; goto failed; }
    error = live_item(item,&live);
    if (!error) error = open_node_key(&live,type,access,&key);
    if (error) goto failed;
    unlock(); return key;
failed: unlock(); SetLastError(error); return (HKEY)INVALID_HANDLE_VALUE;
}
static const GUID device_property_guid = {0xa45c254e,0xdf1c,0x4efd,{0x80,0x20,0x67,0xd1,0x46,0xa8,0x50,0xe0}};
static const GUID instance_property_guid = {0x78c34fc8,0x104a,0x4aca,{0x9e,0xa4,0x52,0x4d,0x52,0x99,0x6e,0x57}};
static DWORD registry_property(const shz_pnp_row_t *row, const WCHAR *name, DWORD expected,
                              PBYTE buffer, DWORD size, PDWORD required)
{
    HKEY key; DWORD error, regtype = 0, bytes = 0, actual = 0;
    BYTE *snapshot = NULL;
    error = open_node_key(row,0,KEY_QUERY_VALUE,&key);
    if (error) return error == ERROR_FILE_NOT_FOUND ? ERROR_NOT_FOUND : error;
    error = (DWORD)RegQueryValueExW(key,name,NULL,&regtype,NULL,&bytes);
    if (!error && regtype != expected) error = ERROR_INVALID_DATA;
    if (!error) {
        if (!bytes || (bytes & 1u)) error = ERROR_INVALID_DATA;
        else {
            snapshot = HeapAlloc(GetProcessHeap(),0,bytes);
            if (!snapshot) error = ERROR_NOT_ENOUGH_MEMORY;
        }
    }
    if (!error) {
        const WCHAR *text; unsigned units, i;
        actual = bytes;
        error = (DWORD)RegQueryValueExW(key,name,NULL,&regtype,snapshot,&actual);
        /* Registry values can change between the size and data queries, and
         * RegQueryValueEx does not guarantee string termination. Publish a
         * typed property only from this validated actual second snapshot. */
        if (regtype != expected) error = ERROR_INVALID_DATA;
        if (error == ERROR_MORE_DATA) {
            if (required) *required = actual;
            error = ERROR_INSUFFICIENT_BUFFER;
        } else if (!error) {
            text = (const WCHAR *)snapshot; units = actual / sizeof(WCHAR);
            if (actual > bytes || (actual & 1u) || !units || text[units-1] ||
                (expected == REG_MULTI_SZ && (units < 2 || text[units-2]))) error = ERROR_INVALID_DATA;
            if (!error && expected == REG_MULTI_SZ)
                for (i = 0; i + 2 < units; ++i)
                    if (!text[i] && !text[i+1]) { error = ERROR_INVALID_DATA; break; }
            if (!error) {
                if (required) *required = actual;
                if (!buffer || size < actual) error = ERROR_INSUFFICIENT_BUFFER;
                else memcpy(buffer,snapshot,actual);
            }
        }
    }
    if (snapshot) HeapFree(GetProcessHeap(),0,snapshot);
    RegCloseKey(key);
    return error == ERROR_FILE_NOT_FOUND ? ERROR_NOT_FOUND : error;
}
DLLAPI BOOL WINAPI SetupDiGetDevicePropertyW(HDEVINFO handle, PSP_DEVINFO_DATA data, const DEVPROPKEY *property,
    DEVPROPTYPE *type, PBYTE buffer, DWORD size, PDWORD required, DWORD flags)
{
    struct setup_set *set; struct setup_item *item; shz_pnp_row_t live;
    const WCHAR *text = NULL, *regname = NULL; WCHAR service[64]; GUID guid;
    DWORD error, bytes = 0, regtype = REG_SZ; unsigned i;
    if (flags) return failure(ERROR_INVALID_FLAGS);
    if (!property || !type) return failure(ERROR_INVALID_PARAMETER);
    if (!buffer && size) return failure(ERROR_INVALID_USER_BUFFER);
    lock(); set = find_set(handle);
    if (!set) { error = ERROR_INVALID_HANDLE; goto failed; }
    item = data_item(set,data);
    if (!item) { error = ERROR_INVALID_PARAMETER; goto failed; }
    error = live_item(item,&live); if (error) goto failed;
    if (same_guid(&property->fmtid,&instance_property_guid) && property->pid == 256) text = (const WCHAR *)live.instance;
    else if (same_guid(&property->fmtid,&device_property_guid)) {
        switch (property->pid) {
        case 2: text = (const WCHAR *)live.description; break;
        case 3: regname = L"HardwareID"; regtype = REG_MULTI_SZ; break;
        case 4: regname = L"CompatibleIDs"; regtype = REG_MULTI_SZ; break;
        case 6:
            for (i = 0; live.service[i]; ++i) service[i] = (WCHAR)(unsigned char)live.service[i];
            service[i] = 0; text = service; break;
        case 9: regname = L"Class"; break;
        case 10:
            if (!parse_guid(live.class_guid,&guid)) { error = ERROR_NOT_FOUND; goto failed; }
            *type = DEVPROP_TYPE_GUID; bytes = sizeof guid; break;
        case 11: text = (const WCHAR *)live.driver_key; break;
        case 13: text = (const WCHAR *)live.manufacturer; break;
        case 14: regname = L"FriendlyName"; break;
        default: error = ERROR_NOT_FOUND; goto failed;
        }
    } else { error = ERROR_NOT_FOUND; goto failed; }
    if (regname) {
        *type = regtype == REG_MULTI_SZ ? DEVPROP_TYPE_STRING_LIST : DEVPROP_TYPE_STRING;
        error = registry_property(&live,regname,regtype,buffer,size,required);
        if (error) goto failed;
        unlock(); return TRUE;
    }
    if (text) {
        if (!*text) { error = ERROR_NOT_FOUND; goto failed; }
        *type = DEVPROP_TYPE_STRING; bytes = (length(text)+1)*sizeof(WCHAR);
    }
    if (required) *required = bytes;
    if (!buffer || size < bytes) { error = ERROR_INSUFFICIENT_BUFFER; goto failed; }
    memcpy(buffer,text ? (const void *)text : (const void *)&guid,bytes);
    unlock(); return TRUE;
failed: unlock(); return failure(error);
}
