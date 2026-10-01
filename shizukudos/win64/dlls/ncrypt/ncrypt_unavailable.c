/* SPDX-License-Identifier: GPL-2.0-only
 * Original CNG key-storage provider absence boundary, not a KSP port.
 * No provider/key objects are allocated or registered by this DLL. Therefore
 * every supplied object handle is invalid, without dereferencing its value.
 * NCryptOpenStorageProvider reports the genuinely absent provider DLL, clears
 * its typed output and never advertises a software/TPM/smart-card provider.
 * Microsoft NCrypt and SECURITY_STATUS contracts are linked in README.md.
 */
#ifdef SHZ_NCRYPT_HOST_TEST
#include "../../tests/ncrypt_boundary_host_contract.h"
#else
#include "nt.h"
#include <ncrypt.h>
#endif

/* At most 16 provider-open observations per process, using the existing opt-in
 * diagnostics channel. Provider aliases/flags are public configuration, never
 * key material. Preserve caller LastError even when tracing is disabled. */
static volatile LONG trace_calls;
static void trace_open(LPCWSTR name, DWORD flags, SECURITY_STATUS status)
{
    static const char hex[] = "0123456789abcdef";
    const char *text;
    WCHAR value[2];
    char line[256];
    unsigned n = 0, i;
    LONG previous;
    DWORD saved = shz_last_error();
    DWORD length = GetEnvironmentVariableW(L"SHZ_K32TRACE", value, 2);
    if (length != 1 || value[0] != '1') { shz_set_last_error(saved); return; }
    do {
        previous = InterlockedCompareExchange(&trace_calls, 0, 0);
        if (previous >= 16) { shz_set_last_error(saved); return; }
    } while (InterlockedCompareExchange(&trace_calls, previous + 1, previous) != previous);
    text = "NCrypt boundary: OpenStorageProvider provider=\"";
    while (*text) line[n++] = *text++;
    if (!name) {
        text = "<default>";
        while (*text) line[n++] = *text++;
    } else for (i = 0; i < 96; ++i) {
        WCHAR c;
        SIZE_T read = 0;
        uintptr_t address = (uintptr_t)name;
        /* This metadata read is never part of provider lookup. Do not let
         * opt-in logging fault on an unreadable caller name or read past its
         * terminating word. The real process-memory API enforces permissions. */
        if (address > UINTPTR_MAX - i * sizeof c
            || !ReadProcessMemory(GetCurrentProcess(), (const void *)(address + i * sizeof c),
                                  &c, sizeof c, &read)
            || read != sizeof c) {
            text = "<unreadable>";
            while (*text) line[n++] = *text++;
            break;
        }
        if (!c) break;
        line[n++] = c >= 32 && c <= 126 && c != '"' && c != '\\' ? (char)c : '?';
    }
    text = "\" flags=";
    while (*text) line[n++] = *text++;
    for (i = 0; i < 8; ++i) line[n++] = hex[(flags >> (28 - 4 * i)) & 15];
    text = " status=";
    while (*text) line[n++] = *text++;
    for (i = 0; i < 8; ++i) line[n++] = hex[((DWORD)status >> (28 - 4 * i)) & 15];
    line[n++] = '\n';
    NtShzDebugPrint(line, n);
    shz_set_last_error(saved);
}

DLLAPI SECURITY_STATUS WINAPI NCryptOpenStorageProvider(NCRYPT_PROV_HANDLE *provider,
                                                        LPCWSTR name, DWORD flags)
{
    SECURITY_STATUS status;
    if (!provider) status = NTE_INVALID_PARAMETER;
    else {
        *provider = 0;
        status = flags ? NTE_BAD_FLAGS : NTE_PROV_DLL_NOT_FOUND;
    }
    trace_open(name, flags, status);
    return status;
}

DLLAPI SECURITY_STATUS WINAPI NCryptCreatePersistedKey(NCRYPT_PROV_HANDLE provider,
    NCRYPT_KEY_HANDLE *key, LPCWSTR algorithm, LPCWSTR name, DWORD legacy_spec, DWORD flags)
{
    (void)provider; (void)algorithm; (void)name; (void)legacy_spec; (void)flags;
    if (!key) return NTE_INVALID_PARAMETER;
    *key = 0;
    return NTE_INVALID_HANDLE;
}

DLLAPI SECURITY_STATUS WINAPI NCryptOpenKey(NCRYPT_PROV_HANDLE provider,
    NCRYPT_KEY_HANDLE *key, LPCWSTR name, DWORD legacy_spec, DWORD flags)
{
    (void)provider; (void)name; (void)legacy_spec; (void)flags;
    if (!key) return NTE_INVALID_PARAMETER;
    *key = 0;
    return NTE_INVALID_HANDLE;
}

DLLAPI SECURITY_STATUS WINAPI NCryptImportKey(NCRYPT_PROV_HANDLE provider,
    NCRYPT_KEY_HANDLE import_key, LPCWSTR type, NCryptBufferDesc *parameters,
    NCRYPT_KEY_HANDLE *key, PBYTE data, DWORD size, DWORD flags)
{
    (void)provider; (void)import_key; (void)type; (void)parameters;
    (void)data; (void)size; (void)flags;
    if (!key) return NTE_INVALID_PARAMETER;
    *key = 0;
    return NTE_INVALID_HANDLE;
}

DLLAPI SECURITY_STATUS WINAPI NCryptGetProperty(NCRYPT_HANDLE object, LPCWSTR name,
    PBYTE output, DWORD capacity, DWORD *result, DWORD flags)
{
    (void)object; (void)name; (void)output; (void)capacity; (void)flags;
    if (!result) return NTE_INVALID_PARAMETER;
    *result = 0;
    return NTE_INVALID_HANDLE;
}

DLLAPI SECURITY_STATUS WINAPI NCryptExportKey(NCRYPT_KEY_HANDLE key,
    NCRYPT_KEY_HANDLE export_key, LPCWSTR type, NCryptBufferDesc *parameters,
    PBYTE output, DWORD capacity, DWORD *result, DWORD flags)
{
    (void)key; (void)export_key; (void)type; (void)parameters;
    (void)output; (void)capacity; (void)flags;
    if (!result) return NTE_INVALID_PARAMETER;
    *result = 0;
    return NTE_INVALID_HANDLE;
}

DLLAPI SECURITY_STATUS WINAPI NCryptSignHash(NCRYPT_KEY_HANDLE key, VOID *padding,
    PBYTE hash, DWORD hash_size, PBYTE signature, DWORD capacity, DWORD *result, DWORD flags)
{
    (void)key; (void)padding; (void)hash; (void)hash_size;
    (void)signature; (void)capacity; (void)flags;
    if (!result) return NTE_INVALID_PARAMETER;
    *result = 0;
    return NTE_INVALID_HANDLE;
}

DLLAPI SECURITY_STATUS WINAPI NCryptCreateClaim(NCRYPT_KEY_HANDLE subject,
    NCRYPT_KEY_HANDLE authority, DWORD type, NCryptBufferDesc *parameters,
    PBYTE claim, DWORD capacity, DWORD *result, DWORD flags)
{
    (void)subject; (void)authority; (void)type; (void)parameters;
    (void)claim; (void)capacity; (void)flags;
    if (!result) return NTE_INVALID_PARAMETER;
    *result = 0;
    return NTE_INVALID_HANDLE;
}

DLLAPI SECURITY_STATUS WINAPI NCryptSetProperty(NCRYPT_HANDLE object, LPCWSTR name,
    PBYTE input, DWORD size, DWORD flags)
{
    (void)object; (void)name; (void)input; (void)size; (void)flags;
    return NTE_INVALID_HANDLE;
}

DLLAPI SECURITY_STATUS WINAPI NCryptIsAlgSupported(NCRYPT_PROV_HANDLE provider,
                                                  LPCWSTR algorithm, DWORD flags)
{
    (void)provider; (void)algorithm; (void)flags;
    return NTE_INVALID_HANDLE;
}

DLLAPI SECURITY_STATUS WINAPI NCryptFinalizeKey(NCRYPT_KEY_HANDLE key, DWORD flags)
{
    (void)key; (void)flags;
    return NTE_INVALID_HANDLE;
}

DLLAPI SECURITY_STATUS WINAPI NCryptDeleteKey(NCRYPT_KEY_HANDLE key, DWORD flags)
{
    (void)key; (void)flags;
    return NTE_INVALID_HANDLE;
}

DLLAPI SECURITY_STATUS WINAPI NCryptFreeObject(NCRYPT_HANDLE object)
{
    (void)object;
    return NTE_INVALID_HANDLE;
}
