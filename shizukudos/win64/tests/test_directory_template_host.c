/* SPDX-License-Identifier: GPL-2.0-only
 * Complete candidate and actual existing UTF function bodies, headers adapted.
 * Independent native filesystem model: stored attributes, handle access,
 * directory identity, and injected native failures; no guest/application claim.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t DWORD, ULONG, ACCESS_MASK;
typedef int32_t LONG, NTSTATUS;
typedef uint64_t ULONGLONG, ULONG_PTR;
typedef uint16_t WCHAR, USHORT;
typedef uint8_t BYTE;
typedef int BOOL;
typedef void *HANDLE;
typedef const WCHAR *LPCWSTR;
typedef const char *LPCSTR;
typedef struct { DWORD nLength; void *lpSecurityDescriptor; BOOL bInheritHandle; } SECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
typedef struct { USHORT Length, MaximumLength; WCHAR *Buffer; } SHZ_UNICODE_STRING;
typedef struct { ULONG Length; HANDLE RootDirectory; SHZ_UNICODE_STRING *ObjectName; ULONG Attributes;
                 void *SecurityDescriptor, *SecurityQualityOfService; } SHZ_OBJECT_ATTRIBUTES;
typedef struct { ULONG_PTR Status, Information; } SHZ_IO_STATUS_BLOCK;
#define WINAPI
#define NTAPI
#define K32API
#define TRUE 1
#define FALSE 0
#define FILE_ATTRIBUTE_READONLY 1u
#define FILE_ATTRIBUTE_HIDDEN 2u
#define FILE_ATTRIBUTE_SYSTEM 4u
#define FILE_ATTRIBUTE_DIRECTORY 0x10u
#define FILE_ATTRIBUTE_ARCHIVE 0x20u
#define FILE_ATTRIBUTE_NORMAL 0x80u
#define FILE_ATTRIBUTE_TEMPORARY 0x100u
#define FILE_ATTRIBUTE_OFFLINE 0x1000u
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED 0x2000u
#define FILE_LIST_DIRECTORY 1u
#define FILE_READ_ATTRIBUTES 0x80u
#define FILE_WRITE_ATTRIBUTES 0x100u
#define DELETE 0x10000u
#define SYNCHRONIZE 0x100000u
#define FILE_OPEN_D 1u
#define FILE_CREATE_D 2u
#define OPT_DIRECTORY 1u
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xc0000001)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xc0000004)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xc0000022)
#define STATUS_OBJECT_NAME_INVALID ((NTSTATUS)0xc0000033)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xc0000034)
#define STATUS_OBJECT_NAME_COLLISION ((NTSTATUS)0xc0000035)
#define STATUS_OBJECT_PATH_NOT_FOUND ((NTSTATUS)0xc000003a)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define STATUS_NOT_A_DIRECTORY ((NTSTATUS)0xc0000103)
#define ERROR_FILE_NOT_FOUND 2u
#define ERROR_PATH_NOT_FOUND 3u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_INVALID_DATA 13u
#define ERROR_NOT_SUPPORTED 50u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_INVALID_NAME 123u
#define ERROR_ALREADY_EXISTS 183u
#define ERROR_DIRECTORY 267u

static unsigned checks, creation_calls, setter_calls, trace_calls, unsupported_calls;
static DWORD last_error;
static size_t k32_wlen(const WCHAR *s);
static int k32_utf8_to_wide(const char *, int, WCHAR *, int);
static NTSTATUS k32_dos_to_nt(LPCWSTR, WCHAR *, size_t);
static DWORD shz_last_error(void) { return last_error; }
static void shz_set_last_error(DWORD error) { last_error = error; }
static DWORD k32_nt_error(NTSTATUS);
static BOOL k32_unsupported(const char *, const char *, DWORD);
static void k32_trace_hex(const char *, const char *, ULONG_PTR);
static BOOL CreateDirectoryW(LPCWSTR, LPSECURITY_ATTRIBUTES);
static NTSTATUS NtCreateFile(HANDLE *, ACCESS_MASK, SHZ_OBJECT_ATTRIBUTES *, SHZ_IO_STATUS_BLOCK *, void *, ULONG,
                            ULONG, ULONG, ULONG, void *, ULONG);
static NTSTATUS NtClose(HANDLE);
static NTSTATUS NtQueryInformationFile(HANDLE, SHZ_IO_STATUS_BLOCK *, void *, ULONG, ULONG);
static NTSTATUS NtSetInformationFile(HANDLE, SHZ_IO_STATUS_BLOCK *, void *, ULONG, ULONG);
static NTSTATUS NtQueryVolumeInformationFile(HANDLE, SHZ_IO_STATUS_BLOCK *, void *, ULONG, ULONG);

#include "actual_utf_production.inc"
#include "directory_template_production.inc"

#define CHECK(value) do { ++checks; if (!(value)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#value); exit(2); } } while (0)
#define NODES 48
#define HANDLES 48
enum { C_ROOT, D_ROOT, C_BASE, D_BASE, C_SOURCE, D_SOURCE, C_FILE, FIRST_NEW };
enum fault { F_NONE, F_SOURCE_OPEN, F_SOURCE_BASIC, F_SOURCE_VOLUME, F_PARENT_OPEN, F_PARENT_VOLUME,
             F_CREATE, F_DEST_VOLUME, F_SET, F_DEST_BASIC, F_SET_NO_CHANGE, F_CLOSE_PARENT,
             F_CLOSE_SOURCE, F_CLOSE_DEST, F_CLEAR, F_DISPOSITION };
typedef struct { WCHAR path[320]; BOOL exists, directory, ram, pending; ULONG attrs, flags; unsigned filesystem; } node;
typedef struct { node *object; ACCESS_MASK access; BOOL live; } host_handle;
static node nodes[NODES];
static host_handle handles[HANDLES];
static enum fault fault;
static BOOL fault_hit, also_fail_rollback, moved_destination_to_disk;
static unsigned malformed_volume, live_handles;
static const DWORD attribute_bits[] = { 1, 2, 4, 0x20, 0x100, 0x1000, 0x2000 };
static WCHAR source_path[320], destination_path[320];

static void wide_ascii(WCHAR *out, const char *ascii)
{
    do { *out++ = (unsigned char)*ascii; } while (*ascii++);
}
static BOOL wide_equal(const WCHAR *a, const WCHAR *b)
{
    for (; *a && *a == *b; ++a, ++b) { }
    return *a == *b;
}
static node *lookup(const WCHAR *path)
{
    unsigned i;
    for (i = 0; i < NODES; ++i) if (nodes[i].exists && wide_equal(nodes[i].path,path)) return nodes + i;
    return NULL;
}
static void node_init(unsigned index, const char *path, BOOL directory, BOOL ram, ULONG attrs)
{
    node *object = nodes + index;
    wide_ascii(object->path,path);
    object->exists = TRUE; object->directory = directory; object->ram = ram;
    object->attrs = attrs; object->flags = 6; object->filesystem = ram ? 1 : 2;
}
static void reset(void)
{
    CHECK(live_handles == 0);
    memset(nodes,0,sizeof nodes); memset(handles,0,sizeof handles);
    node_init(C_ROOT,"\\??\\C:\\",TRUE,TRUE,0x10);
    node_init(D_ROOT,"\\??\\D:\\",TRUE,FALSE,0x10);
    node_init(C_BASE,"\\??\\C:\\BASE",TRUE,TRUE,0x10);
    node_init(D_BASE,"\\??\\D:\\BASE",TRUE,FALSE,0x10);
    node_init(C_SOURCE,"\\??\\C:\\BASE\\SOURCE",TRUE,TRUE,0x10);
    node_init(D_SOURCE,"\\??\\D:\\BASE\\SOURCE",TRUE,FALSE,0x10);
    node_init(C_FILE,"\\??\\C:\\BASE\\FILE",FALSE,TRUE,0x80);
    wide_ascii(source_path,"C:\\BASE\\SOURCE"); wide_ascii(destination_path,"C:\\BASE\\NEW");
    creation_calls = setter_calls = trace_calls = unsupported_calls = 0;
    fault = F_NONE; fault_hit = also_fail_rollback = moved_destination_to_disk = FALSE;
    malformed_volume = 0; last_error = 0x456789;
}
static BOOL fail_once(enum fault operation)
{
    if (!fault_hit && fault == operation) { fault_hit = TRUE; return TRUE; }
    return FALSE;
}
static host_handle *get_handle(HANDLE handle)
{
    uintptr_t p = (uintptr_t)handle, first = (uintptr_t)handles, end = (uintptr_t)(handles + HANDLES);
    CHECK(p >= first && p < end && (p - first) % sizeof *handles == 0);
    CHECK(((host_handle *)handle)->live);
    return handle;
}
static BOOL is_new(const node *object) { return object >= nodes + FIRST_NEW; }
static DWORD k32_nt_error(NTSTATUS status)
{
    DWORD error;
    switch (status) {
    case STATUS_UNSUCCESSFUL: error = 31; break;
    case STATUS_INFO_LENGTH_MISMATCH: error = ERROR_INVALID_PARAMETER; break;
    case STATUS_ACCESS_DENIED: error = ERROR_ACCESS_DENIED; break;
    case STATUS_OBJECT_NAME_INVALID: error = ERROR_INVALID_NAME; break;
    case STATUS_OBJECT_NAME_NOT_FOUND: error = ERROR_FILE_NOT_FOUND; break;
    case STATUS_OBJECT_NAME_COLLISION: error = ERROR_ALREADY_EXISTS; break;
    case STATUS_OBJECT_PATH_NOT_FOUND: error = ERROR_PATH_NOT_FOUND; break;
    case STATUS_NOT_SUPPORTED: error = ERROR_NOT_SUPPORTED; break;
    case STATUS_NOT_A_DIRECTORY: error = ERROR_DIRECTORY; break;
    default: fprintf(stderr,"unexpected status %08x\n",(unsigned)status); abort();
    }
    last_error = error; return error;
}
static BOOL k32_unsupported(const char *api, const char *reason, DWORD error)
{
    CHECK(!strcmp(api,"CreateDirectoryExW") && *reason && error == ERROR_NOT_SUPPORTED);
    ++unsupported_calls; last_error = error; return FALSE;
}
static void k32_trace_hex(const char *api, const char *operation, ULONG_PTR status)
{
    CHECK(*api && *operation && status); ++trace_calls; last_error = 0xbadf00d;
}
static NTSTATUS k32_dos_to_nt(LPCWSTR path, WCHAR *out, size_t cap)
{
    static const WCHAR prefix[] = { '\\','?','?','\\' };
    size_t n = k32_wlen(path), offset = 0;
    if (n >= 4 && path[0] == '\\' && path[1] == '\\' && path[2] == '?' && path[3] == '\\') offset = 4;
    if (4 + n - offset + 1 > cap) return STATUS_OBJECT_NAME_INVALID;
    memcpy(out,prefix,sizeof prefix); memcpy(out + 4,path + offset,(n - offset + 1) * sizeof *out);
    last_error = 0xaabbccdd; /* A successful helper must not leak this through the public success contract. */
    return STATUS_SUCCESS;
}
static NTSTATUS NtCreateFile(HANDLE *out, ACCESS_MASK access, SHZ_OBJECT_ATTRIBUTES *oa, SHZ_IO_STATUS_BLOCK *io,
                            void *allocation, ULONG attrs, ULONG share, ULONG disposition, ULONG options, void *ea, ULONG ea_length)
{
    node *object, *parent;
    WCHAR parent_path[320];
    size_t n;
    unsigned i;
    CHECK(out && oa && oa->Length == sizeof *oa && !oa->RootDirectory && !oa->SecurityDescriptor && !oa->SecurityQualityOfService);
    CHECK(io && !allocation && attrs == 0x80 && share == 3 && options == 0x21 && !ea && !ea_length);
    CHECK(oa->ObjectName && oa->ObjectName->Length == k32_wlen(oa->ObjectName->Buffer) * 2);
    CHECK(oa->ObjectName->MaximumLength == oa->ObjectName->Length + 2);
    object = lookup(oa->ObjectName->Buffer);
    if (disposition == FILE_OPEN_D) {
        if (object == nodes + C_SOURCE && fail_once(F_SOURCE_OPEN)) return STATUS_ACCESS_DENIED;
        if (object == nodes + C_BASE && fail_once(F_PARENT_OPEN)) return STATUS_ACCESS_DENIED;
        if (!object) return STATUS_OBJECT_NAME_NOT_FOUND;
        if (!object->directory) return STATUS_NOT_A_DIRECTORY;
    } else {
        CHECK(disposition == FILE_CREATE_D);
        ++creation_calls;
        if (fail_once(F_CREATE)) return STATUS_ACCESS_DENIED;
        if (object) return STATUS_OBJECT_NAME_COLLISION;
        n = k32_wlen(oa->ObjectName->Buffer); memcpy(parent_path,oa->ObjectName->Buffer,(n + 1) * 2);
        while (n > 7 && parent_path[n - 1] != '\\') --n;
        parent_path[n > 7 ? n - 1 : 7] = 0;
        parent = lookup(parent_path);
        if (!parent || !parent->directory) return STATUS_OBJECT_PATH_NOT_FOUND;
        for (i = FIRST_NEW; i < NODES && nodes[i].exists; ++i) { }
        CHECK(i < NODES); object = nodes + i; memset(object,0,sizeof *object);
        memcpy(object->path,oa->ObjectName->Buffer,(k32_wlen(oa->ObjectName->Buffer) + 1) * 2);
        object->exists = object->directory = TRUE; object->attrs = 0x10;
        object->ram = moved_destination_to_disk ? FALSE : parent->ram;
        object->filesystem = object->ram ? 1 : 2; object->flags = parent->flags;
    }
    for (i = 0; i < HANDLES && handles[i].live; ++i) { }
    CHECK(i < HANDLES); handles[i].object = object; handles[i].access = access; handles[i].live = TRUE;
    ++live_handles; *out = handles + i; io->Status = 0; io->Information = disposition == FILE_CREATE_D ? 2 : 1;
    return STATUS_SUCCESS;
}
static NTSTATUS NtClose(HANDLE handle)
{
    host_handle *h = get_handle(handle);
    node *object = h->object;
    if ((object == nodes + C_BASE && fail_once(F_CLOSE_PARENT)) ||
        (object == nodes + C_SOURCE && fail_once(F_CLOSE_SOURCE)) || (is_new(object) && fail_once(F_CLOSE_DEST)))
        return STATUS_ACCESS_DENIED;
    h->live = FALSE; --live_handles;
    if (object->pending) object->exists = FALSE;
    return STATUS_SUCCESS;
}
static NTSTATUS NtQueryInformationFile(HANDLE handle, SHZ_IO_STATUS_BLOCK *io, void *out, ULONG length, ULONG cls)
{
    host_handle *h = get_handle(handle); node *object = h->object; dirx_basic basic;
    CHECK(cls == 4 && length == 40 && io && out && (h->access & FILE_READ_ATTRIBUTES));
    if ((object == nodes + C_SOURCE && fail_once(F_SOURCE_BASIC)) || (is_new(object) && fail_once(F_DEST_BASIC)))
        return STATUS_ACCESS_DENIED;
    memset(&basic,0,sizeof basic); basic.create = 111; basic.access = 222; basic.write = 333; basic.change = 444;
    basic.attrs = object->attrs; memcpy(out,&basic,40); io->Status = 0; io->Information = 40; return STATUS_SUCCESS;
}
static NTSTATUS NtQueryVolumeInformationFile(HANDLE handle, SHZ_IO_STATUS_BLOCK *io, void *out, ULONG length, ULONG cls)
{
    node *object = get_handle(handle)->object; dirx_fsinfo info; const char *name; unsigned i;
    CHECK(cls == 5 && length >= 32 && io && out);
    if ((object == nodes + C_SOURCE && fail_once(F_SOURCE_VOLUME)) ||
        (object == nodes + C_BASE && fail_once(F_PARENT_VOLUME)) || (is_new(object) && fail_once(F_DEST_VOLUME)))
        return STATUS_ACCESS_DENIED;
    memset(&info,0,sizeof info); name = object->filesystem == 1 ? "SHZFS" : object->filesystem == 2 ? "FAT32" : "OTHER";
    info.flags = object->flags; info.max_component = 127; info.name_bytes = (ULONG)strlen(name) * 2;
    for (i = 0; i < strlen(name); ++i) info.name[i] = (unsigned char)name[i];
    io->Status = 0; io->Information = 12 + info.name_bytes;
    if (object == nodes + C_SOURCE) {
        if (malformed_volume == 1) io->Information = 11;
        if (malformed_volume == 2) info.name_bytes = 100;
        if (malformed_volume == 3) info.name_bytes = 9;
        if (malformed_volume == 4) io->Information = 12;
    }
    memcpy(out,&info,sizeof info); return STATUS_SUCCESS;
}
static NTSTATUS NtSetInformationFile(HANDLE handle, SHZ_IO_STATUS_BLOCK *io, void *buffer, ULONG length, ULONG cls)
{
    host_handle *h = get_handle(handle); node *object = h->object;
    CHECK(io && buffer && is_new(object));
    if (cls == 4) {
        dirx_basic basic; BOOL clearing;
        CHECK(length == 40 && (h->access & FILE_WRITE_ATTRIBUTES)); memcpy(&basic,buffer,40);
        CHECK(!basic.create && !basic.access && !basic.write && !basic.change);
        clearing = basic.attrs == 0x80; ++setter_calls;
        if (clearing && (fail_once(F_CLEAR) || (also_fail_rollback && fault_hit))) return STATUS_ACCESS_DENIED;
        if (!clearing && fail_once(F_SET)) return STATUS_ACCESS_DENIED;
        if (!object->ram) return STATUS_NOT_SUPPORTED;
        if (!clearing && fail_once(F_SET_NO_CHANGE)) return STATUS_SUCCESS;
        CHECK(!(basic.attrs & ~0x31a7u));
        object->attrs = (basic.attrs & 0x3127u) | 0x10;
    } else {
        CHECK(cls == 13 && length == 1 && *(BYTE *)buffer == 1 && (h->access & DELETE));
        if (fail_once(F_DISPOSITION) || (also_fail_rollback && fault_hit)) return STATUS_ACCESS_DENIED;
        if (object->attrs & 1) return STATUS_ACCESS_DENIED;
        object->pending = TRUE;
    }
    io->Status = 0; io->Information = 0; return STATUS_SUCCESS;
}
static BOOL CreateDirectoryW(LPCWSTR path, LPSECURITY_ATTRIBUTES security)
{
    WCHAR nt[320]; HANDLE handle; NTSTATUS status;
    CHECK(!security);
    status = k32_dos_to_nt(path,nt,320);
    if (!status) status = dirx_open(nt,FILE_LIST_DIRECTORY,FILE_CREATE_D,&handle);
    if (status) { k32_nt_error(status); return FALSE; }
    CHECK(NtClose(handle) == STATUS_SUCCESS); return TRUE;
}
static BOOL destination_exists(const char *path)
{
    WCHAR nt[320]; wide_ascii(nt,path); return lookup(nt) != NULL;
}
static void check_source_unchanged(ULONG attributes)
{
    CHECK(nodes[C_SOURCE].exists && nodes[C_SOURCE].attrs == attributes && !nodes[C_SOURCE].pending);
    CHECK(nodes[C_BASE].exists && nodes[C_BASE].attrs == 0x10 && !nodes[C_BASE].pending);
    CHECK(live_handles == 0);
}

int main(void)
{
    unsigned mode, bit, i; ULONG attrs; DWORD prior; SECURITY_ATTRIBUTES security;
    static const ULONG unavailable_flags[] = { 8, 0x10, 0x80, 0x8000, 0x20000, 0x40000, 0x800000 };
    static const enum fault precreate_faults[] = { F_SOURCE_OPEN,F_SOURCE_BASIC,F_SOURCE_VOLUME,F_PARENT_OPEN,F_PARENT_VOLUME,F_CREATE };
    static const enum fault postcreate_faults[] = { F_DEST_VOLUME,F_SET,F_DEST_BASIC,F_SET_NO_CHANGE,F_CLOSE_PARENT,F_CLOSE_SOURCE,F_CLOSE_DEST };
    _Static_assert(sizeof(WCHAR) == 2 && sizeof(dirx_basic) == 40 && sizeof(SECURITY_ATTRIBUTES) == 24,"native AMD64 scalar/structure ABI");
    for (mode = 0; mode < 128; ++mode) {
        reset(); attrs = 0;
        for (bit = 0; bit < 7; ++bit) if (mode & (1u << bit)) attrs |= attribute_bits[bit];
        nodes[C_SOURCE].attrs = attrs | 0x10; prior = last_error;
        CHECK(mode & 1 ? CreateDirectoryExA("C:\\BASE\\SOURCE","C:\\BASE\\NEW",NULL) :
                         CreateDirectoryExW(source_path,destination_path,NULL));
        CHECK(last_error == prior && creation_calls == 1 && setter_calls == (attrs != 0));
        CHECK(nodes[FIRST_NEW].exists && nodes[FIRST_NEW].attrs == (attrs | 0x10) && nodes[FIRST_NEW].directory);
        check_source_unchanged(attrs | 0x10);
    }
    /* Real existing UTF conversion is included as an unchanged dependency. */
    reset(); CHECK(CreateDirectoryExA("C:\\BASE\\SOURCE","C:\\BASE\\\xeb\xb3\xb5\xec\x82\xac",NULL));
    CHECK(nodes[FIRST_NEW].path[12] == 0xbcf5 && nodes[FIRST_NEW].path[13] == 0xc0ac);
    CHECK(live_handles == 0);
    for (i = 0; i < 2; ++i) {
        reset(); prior = last_error;
        CHECK(i ? CreateDirectoryExA(NULL,"C:\\BASE\\NEW",NULL) : CreateDirectoryExW(NULL,destination_path,NULL));
        CHECK(last_error == prior && creation_calls == 1 && nodes[FIRST_NEW].exists && nodes[FIRST_NEW].attrs == 0x10);
        CHECK(live_handles == 0);
    }
    reset(); wide_ascii(source_path,"D:\\BASE\\SOURCE"); wide_ascii(destination_path,"D:\\BASE\\NEW"); prior = last_error;
    CHECK(CreateDirectoryExW(source_path,destination_path,NULL));
    CHECK(last_error == prior && nodes[FIRST_NEW].exists && !nodes[FIRST_NEW].ram && setter_calls == 0 && live_handles == 0);
    reset(); nodes[D_SOURCE].attrs = 0x33; wide_ascii(source_path,"D:\\BASE\\SOURCE"); prior = last_error;
    CHECK(CreateDirectoryExW(source_path,destination_path,NULL));
    CHECK(last_error == prior && nodes[FIRST_NEW].exists && nodes[FIRST_NEW].ram && nodes[FIRST_NEW].attrs == 0x33);
    CHECK(nodes[D_SOURCE].attrs == 0x33 && live_handles == 0);
    for (bit = 0; bit < 7; ++bit) {
        reset(); nodes[C_SOURCE].attrs = 0x10 | attribute_bits[bit]; wide_ascii(destination_path,"D:\\BASE\\NEW");
        CHECK(!CreateDirectoryExW(source_path,destination_path,NULL));
        CHECK(last_error == 50 && creation_calls == 0 && !destination_exists("\\??\\D:\\BASE\\NEW") && live_handles == 0);
        CHECK(unsupported_calls == 1);
    }
    for (i = 0; i < sizeof unavailable_flags / sizeof unavailable_flags[0]; ++i) {
        reset(); nodes[C_SOURCE].flags |= unavailable_flags[i];
        CHECK(!CreateDirectoryExW(source_path,destination_path,NULL));
        CHECK(last_error == 50 && creation_calls == 0 && live_handles == 0);
        reset(); nodes[C_SOURCE].attrs = 0x12; nodes[C_BASE].flags |= unavailable_flags[i];
        CHECK(!CreateDirectoryExW(source_path,destination_path,NULL));
        CHECK(last_error == 50 && creation_calls == 0 && live_handles == 0);
    }
    for (bit = 0; bit < 32; ++bit) if (!((0x3127u | 0x10u | 0x80u) & (1u << bit))) {
        reset(); nodes[C_SOURCE].attrs |= 1u << bit;
        CHECK(!CreateDirectoryExW(source_path,destination_path,NULL));
        CHECK(last_error == 50 && creation_calls == 0 && live_handles == 0);
    }
    for (i = 0; i < 4; ++i) {
        reset(); malformed_volume = i + 1;
        CHECK(!CreateDirectoryExW(source_path,destination_path,NULL));
        CHECK(last_error == 87 && creation_calls == 0 && live_handles == 0);
    }
    reset(); nodes[C_SOURCE].filesystem = 3;
    CHECK(!CreateDirectoryExW(source_path,destination_path,NULL));
    CHECK(last_error == 50 && creation_calls == 0 && live_handles == 0);
    reset(); nodes[C_SOURCE].attrs = 0;
    CHECK(!CreateDirectoryExW(source_path,destination_path,NULL));
    CHECK(last_error == 267 && creation_calls == 0 && live_handles == 0);
    reset(); wide_ascii(source_path,"C:\\BASE\\ABSENT");
    CHECK(!CreateDirectoryExW(source_path,destination_path,NULL));
    CHECK(last_error == 2 && creation_calls == 0 && live_handles == 0);
    reset(); wide_ascii(source_path,"C:\\BASE\\FILE");
    CHECK(!CreateDirectoryExW(source_path,destination_path,NULL));
    CHECK(last_error == 267 && creation_calls == 0 && live_handles == 0);
    reset(); wide_ascii(destination_path,"C:\\BASE\\ABSENT\\NEW");
    CHECK(!CreateDirectoryExW(source_path,destination_path,NULL));
    CHECK(last_error == 3 && live_handles == 0);
    reset(); wide_ascii(destination_path,"C:\\BASE\\SOURCE");
    CHECK(!CreateDirectoryExW(source_path,destination_path,NULL));
    CHECK(last_error == 183 && nodes[C_SOURCE].attrs == 0x10 && live_handles == 0);
    reset(); source_path[0] = 0;
    CHECK(!CreateDirectoryExW(source_path,destination_path,NULL)); CHECK(last_error == 3 && creation_calls == 0);
    CHECK(!CreateDirectoryExW(NULL,NULL,NULL)); CHECK(last_error == 87 && creation_calls == 0);
    CHECK(!CreateDirectoryExA(NULL,NULL,NULL)); CHECK(last_error == 87 && creation_calls == 0);
    CHECK(!CreateDirectoryExA(NULL,"",NULL)); CHECK(last_error == 3 && creation_calls == 0);
    memset(&security,0,sizeof security); security.nLength = sizeof security; security.bInheritHandle = TRUE;
    reset(); prior = last_error;
    CHECK(CreateDirectoryExW(source_path,destination_path,&security)); CHECK(last_error == prior && live_handles == 0);
    reset(); security.lpSecurityDescriptor = (void *)(uintptr_t)1;
    CHECK(!CreateDirectoryExW(source_path,destination_path,&security)); CHECK(last_error == 50 && creation_calls == 0 && live_handles == 0);
    reset(); CHECK(!CreateDirectoryExW(NULL,destination_path,&security)); CHECK(last_error == 50 && creation_calls == 0);
    reset(); security.nLength = 0; CHECK(!CreateDirectoryExW(NULL,destination_path,&security)); CHECK(last_error == 87 && creation_calls == 0);

    for (i = 0; i < sizeof precreate_faults / sizeof precreate_faults[0]; ++i) {
        reset(); nodes[C_SOURCE].attrs = 0x13; fault = precreate_faults[i];
        CHECK(!CreateDirectoryExW(source_path,destination_path,NULL));
        CHECK(fault_hit && last_error == 5 && !nodes[FIRST_NEW].exists && live_handles == 0);
        check_source_unchanged(0x13);
    }
    for (i = 0; i < sizeof postcreate_faults / sizeof postcreate_faults[0]; ++i) {
        reset(); nodes[C_SOURCE].attrs = 0x13; fault = postcreate_faults[i];
        CHECK(!CreateDirectoryExW(source_path,destination_path,NULL));
        CHECK(fault_hit && last_error == (fault == F_SET_NO_CHANGE ? 50u : 5u) && creation_calls == 1);
        CHECK(!nodes[FIRST_NEW].exists && live_handles == 0);
        check_source_unchanged(0x13);
    }
    /* Namespace change after the parent's RAM preflight must not enable a
     * success-shaped disk setter, even if the created volume is different. */
    reset(); nodes[C_SOURCE].attrs = 0x12; moved_destination_to_disk = TRUE;
    CHECK(!CreateDirectoryExW(source_path,destination_path,NULL));
    CHECK(last_error == 50 && !nodes[FIRST_NEW].exists && setter_calls == 0 && live_handles == 0);

    /* A genuine native rollback failure can leave a directory. It must still
     * fail, retain the original API error, and report the failed cleanup. */
    reset(); nodes[C_SOURCE].attrs = 0x13; fault = F_DEST_BASIC; also_fail_rollback = TRUE;
    CHECK(!CreateDirectoryExW(source_path,destination_path,NULL));
    CHECK(last_error == 5 && nodes[FIRST_NEW].exists && nodes[FIRST_NEW].attrs == 0x13 && live_handles == 0 && trace_calls == 2);

    reset(); for (i = 0; i < 298; ++i) destination_path[i] = 'A'; destination_path[298] = 0;
    CHECK(!CreateDirectoryExW(NULL,destination_path,NULL)); CHECK(last_error == 123 && creation_calls == 0);
    reset(); wide_ascii(destination_path,"\\\\?\\UNC\\SERVER\\SHARE\\NEW");
    CHECK(!CreateDirectoryExW(NULL,destination_path,NULL)); CHECK(last_error == 50 && creation_calls == 0);
    reset(); wide_ascii(destination_path,"C:\\BASE\\NEW\\\\");
    CHECK(CreateDirectoryExW(source_path,destination_path,NULL));
    CHECK(destination_exists("\\??\\C:\\BASE\\NEW") && live_handles == 0);
    printf("DIRECTORY_TEMPLATE_HOST: %u checks PASS\n",checks);
    return 0;
}
