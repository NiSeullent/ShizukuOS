/* SPDX-License-Identifier: GPL-2.0-only
 * CreateDirectoryExW/A: actual directory creation and supported basic metadata.
 * Original implementation from the Microsoft CreateDirectoryEx contract and
 * inspected Kernel64 filesystem providers; no upstream implementation copied.
 *
 * The current SHZFS/FAT32 providers have no EAs, named streams or ACL storage.
 * SHZFS stores basic attributes; FAT32's attribute setter cannot persist them.
 * Unsupported metadata fails explicitly. NULL template is a platform extension
 * that delegates to ordinary creation. A uses the existing UTF-8 path ABI.
 */
#include "k32.h"

#define DIRX_ATTRS (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | \
                   FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_OFFLINE | \
                   FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
/* Persistent ACLs, compression, reparse points, compressed volumes, encryption,
 * named streams and extended attributes have no directory-copy providers here. */
#define DIRX_UNAVAILABLE_FS 0x00868098u

typedef struct { ULONGLONG create, access, write, change; ULONG attrs, pad; } dirx_basic;
typedef struct { ULONG flags; LONG max_component; ULONG name_bytes; WCHAR name[32]; } dirx_fsinfo;
typedef struct { ULONG flags; BOOL ram; } dirx_caps;

static BOOL dirx_error(NTSTATUS status)
{
    k32_nt_error(status);
    return FALSE;
}

static BOOL dirx_limit(const char *reason)
{
    return k32_unsupported("CreateDirectoryExW", reason, ERROR_NOT_SUPPORTED);
}

/* Resolve once, before opening the parent or creating the destination. Unlike
 * the existing helper, do not allow an overlong verbatim name to be truncated. */
static NTSTATUS dirx_path(LPCWSTR path, WCHAR nt[320])
{
    size_t n;
    NTSTATUS status;
    for (n = 0; n < 298 && path[n]; ++n) { }
    if (n == 298) return STATUS_OBJECT_NAME_INVALID;
    status = k32_dos_to_nt(path, nt, 320);
    if (status) return status;
    n = k32_wlen(nt);
    if (n < 7 || nt[0] != '\\' || nt[1] != '?' || nt[2] != '?' || nt[3] != '\\' ||
        !((nt[4] >= 'A' && nt[4] <= 'Z') || (nt[4] >= 'a' && nt[4] <= 'z')) || nt[5] != ':' || nt[6] != '\\')
        return STATUS_NOT_SUPPORTED;
    while (n > 7 && nt[n - 1] == '\\') nt[--n] = 0;
    return STATUS_SUCCESS;
}

static NTSTATUS dirx_open(WCHAR *nt, ACCESS_MASK access, ULONG disposition, HANDLE *handle)
{
    SHZ_UNICODE_STRING name;
    SHZ_OBJECT_ATTRIBUTES attributes;
    SHZ_IO_STATUS_BLOCK io;
    name.Buffer = nt;
    name.Length = (USHORT)(k32_wlen(nt) * sizeof(WCHAR));
    name.MaximumLength = name.Length + sizeof(WCHAR);
    memset(&attributes, 0, sizeof attributes);
    attributes.Length = sizeof attributes;
    attributes.ObjectName = &name;
    memset(&io, 0, sizeof io);
    /* FileAttributes at creation is deliberately NORMAL: the current native
     * backend ignores that field. Copy through the actual held-handle setter. */
    return NtCreateFile(handle, access | SYNCHRONIZE, &attributes, &io, NULL,
                        FILE_ATTRIBUTE_NORMAL, 3, disposition, OPT_DIRECTORY | 0x20, NULL, 0);
}

static NTSTATUS dirx_basic_query(HANDLE handle, dirx_basic *basic)
{
    SHZ_IO_STATUS_BLOCK io;
    memset(&io, 0, sizeof io);
    memset(basic, 0, sizeof *basic);
    return NtQueryInformationFile(handle, &io, basic, sizeof *basic, 4);
}

static NTSTATUS dirx_capabilities(HANDLE handle, dirx_caps *caps)
{
    static const WCHAR ram_name[] = { 'S', 'H', 'Z', 'F', 'S' };
    static const WCHAR disk_name[] = { 'F', 'A', 'T', '3', '2' };
    dirx_fsinfo info;
    SHZ_IO_STATUS_BLOCK io;
    NTSTATUS status;
    memset(&info, 0, sizeof info);
    memset(&io, 0, sizeof io);
    status = NtQueryVolumeInformationFile(handle, &io, &info, sizeof info, 5);
    if (status) return status;
    if (io.Information < 12 || info.name_bytes > sizeof info.name || info.name_bytes & 1 ||
        io.Information < 12 + info.name_bytes)
        return STATUS_INFO_LENGTH_MISMATCH;
    /* Scope capability inference to the two inspected providers. An unfamiliar
     * filesystem must not inherit an invented "no extra metadata" assumption. */
    if (info.name_bytes != sizeof ram_name) return STATUS_NOT_SUPPORTED;
    caps->ram = !memcmp(info.name, ram_name, sizeof ram_name);
    if (!caps->ram && memcmp(info.name, disk_name, sizeof disk_name)) return STATUS_NOT_SUPPORTED;
    caps->flags = info.flags;
    return info.flags & DIRX_UNAVAILABLE_FS ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

static NTSTATUS dirx_set_attrs(HANDLE handle, ULONG attrs)
{
    dirx_basic basic;
    SHZ_IO_STATUS_BLOCK io;
    memset(&basic, 0, sizeof basic);
    memset(&io, 0, sizeof io);
    basic.attrs = attrs;
    return NtSetInformationFile(handle, &io, &basic, sizeof basic, 4);
}

static void dirx_cleanup_trace(const char *operation, NTSTATUS status)
{
    if (status) k32_trace_hex("CreateDirectoryEx cleanup ", operation, (ULONG)status);
}

/* Undo only a directory this call actually created, using its held handle.
 * A later failure after READONLY was applied requires clearing it before the
 * current backend accepts disposition. Every cleanup failure stays visible. */
static void dirx_rollback(HANDLE handle, BOOL may_be_readonly)
{
    SHZ_IO_STATUS_BLOCK io;
    BYTE remove = 1;
    NTSTATUS status;
    if (may_be_readonly) {
        status = dirx_set_attrs(handle, FILE_ATTRIBUTE_NORMAL);
        dirx_cleanup_trace("clear attributes", status);
    }
    memset(&io, 0, sizeof io);
    status = NtSetInformationFile(handle, &io, &remove, sizeof remove, 13);
    dirx_cleanup_trace("directory disposition", status);
    status = NtClose(handle);
    dirx_cleanup_trace("close created handle", status);
}

K32API BOOL WINAPI CreateDirectoryExW(LPCWSTR template_path, LPCWSTR new_path, LPSECURITY_ATTRIBUTES security)
{
    WCHAR source_name[320], destination_name[320], parent_name[320];
    HANDLE source = NULL, parent = NULL, destination = NULL;
    dirx_basic basic;
    dirx_caps caps;
    ULONG copy_attrs = 0;
    NTSTATUS status, close_status;
    DWORD prior_error = shz_last_error();
    BOOL set_attempted = FALSE;
    const char *limit = NULL;
    size_t n;

    if (!new_path) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!*new_path) { shz_set_last_error(ERROR_PATH_NOT_FOUND); return FALSE; }
    if (security && security->nLength != sizeof *security) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (security && security->lpSecurityDescriptor) return dirx_limit("directory security descriptor storage unavailable");
    status = dirx_path(new_path, destination_name);
    if (status) return dirx_error(status);
    if (!template_path) {
        BOOL ok = CreateDirectoryW(destination_name + 4, NULL);
        if (ok) shz_set_last_error(prior_error);
        return ok;
    }
    if (!*template_path) { shz_set_last_error(ERROR_PATH_NOT_FOUND); return FALSE; }
    status = dirx_path(template_path, source_name);
    if (status) return dirx_error(status);
    status = dirx_open(source_name, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES, FILE_OPEN_D, &source);
    if (status) goto failure;
    status = dirx_basic_query(source, &basic);
    if (status) goto failure;
    if (!(basic.attrs & FILE_ATTRIBUTE_DIRECTORY)) { status = STATUS_NOT_A_DIRECTORY; goto failure; }
    if (basic.attrs & ~(DIRX_ATTRS | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_NORMAL)) {
        status = STATUS_NOT_SUPPORTED; limit = "template metadata has no copy provider"; goto failure;
    }
    copy_attrs = basic.attrs & DIRX_ATTRS;
    status = dirx_capabilities(source, &caps);
    if (status) { if (status == STATUS_NOT_SUPPORTED) limit = "template filesystem metadata cannot be copied"; goto failure; }

    if (copy_attrs) {
        memcpy(parent_name, destination_name, (k32_wlen(destination_name) + 1) * sizeof(WCHAR));
        n = k32_wlen(parent_name);
        while (n > 7 && parent_name[n - 1] != '\\') --n;
        parent_name[n > 7 ? n - 1 : 7] = 0;
        status = dirx_open(parent_name, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES, FILE_OPEN_D, &parent);
        if (status) goto failure;
        status = dirx_capabilities(parent, &caps);
        if (status) { if (status == STATUS_NOT_SUPPORTED) limit = "destination filesystem metadata cannot be copied"; goto failure; }
        if (!caps.ram) { status = STATUS_NOT_SUPPORTED; limit = "disk provider cannot persist copied directory attributes"; goto failure; }
    }
    status = dirx_open(destination_name, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | DELETE,
                       FILE_CREATE_D, &destination);
    if (status) goto failure;
    /* Recheck the created object's actual volume: no assumptions from a drive
     * letter or the earlier parent name survive a namespace change. */
    status = dirx_capabilities(destination, &caps);
    if (status) { if (status == STATUS_NOT_SUPPORTED) limit = "created directory filesystem metadata unavailable"; goto failure; }
    if (copy_attrs && !caps.ram) { status = STATUS_NOT_SUPPORTED; limit = "created directory has no persistent attribute setter"; goto failure; }
    if (copy_attrs) {
        set_attempted = TRUE;
        status = dirx_set_attrs(destination, copy_attrs);
        if (status) goto failure;
    }
    status = dirx_basic_query(destination, &basic);
    if (status) goto failure;
    if (basic.attrs != (copy_attrs | FILE_ATTRIBUTE_DIRECTORY)) { status = STATUS_NOT_SUPPORTED; limit = "directory attribute copy did not persist"; goto failure; }

    /* Retain the created handle until the other owned handles are released, so
     * their close failures can still roll back this call's actual directory. */
    if (parent) { status = NtClose(parent); if (status) goto failure; parent = NULL; }
    status = NtClose(source);
    if (status) goto failure;
    source = NULL;
    status = NtClose(destination);
    if (status) goto failure;
    destination = NULL;
    shz_set_last_error(prior_error);
    return TRUE;

failure:
    if (destination) dirx_rollback(destination, set_attempted && (copy_attrs & FILE_ATTRIBUTE_READONLY));
    if (parent) { close_status = NtClose(parent); dirx_cleanup_trace("close parent handle", close_status); }
    if (source) { close_status = NtClose(source); dirx_cleanup_trace("close template handle", close_status); }
    return limit ? dirx_limit(limit) : dirx_error(status);
}

K32API BOOL WINAPI CreateDirectoryExA(LPCSTR template_path, LPCSTR new_path, LPSECURITY_ATTRIBUTES security)
{
    WCHAR source[300], destination[300];
    if (!new_path) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (k32_utf8_to_wide(new_path, -1, destination, 300) <= 0 ||
        (template_path && k32_utf8_to_wide(template_path, -1, source, 300) <= 0)) {
        shz_set_last_error(ERROR_INVALID_NAME);
        return FALSE;
    }
    return CreateDirectoryExW(template_path ? source : NULL, destination, security);
}
