/* SPDX-License-Identifier: GPL-2.0-only
 * Real static-import NCrypt negative boundary. This checks unavailable
 * providers/invalid handles, never successful cryptography or app fallback. */
#include "k32test.h"
#include <ncrypt.h>

#define STATUS_IS(call, expected) ((call) == (SECURITY_STATUS)(expected))

int main(void)
{
    struct { ULONG_PTR before; NCRYPT_HANDLE handle; ULONG_PTR after; } output;
    struct { DWORD before, value, after; } count;
    BYTE bytes[32], original[32];
    WCHAR original_trace[128];
    DWORD original_length, original_error;
    void *unreadable;
    NCRYPT_HANDLE invalid;
    unsigned i;
    LPCWSTR names[] = {NULL, MS_KEY_STORAGE_PROVIDER, MS_PLATFORM_KEY_STORAGE_PROVIDER};
    const ULONG_PTR guard1 = 0x1122334455667788ull, guard2 = 0x8877665544332211ull;

    printf("NCrypt negative boundary: no software/TPM provider or cryptographic success supported\n");
    original_trace[0] = 0;
    SetLastError(0);
    original_length = GetEnvironmentVariableW(L"SHZ_K32TRACE", original_trace, 128);
    original_error = GetLastError();
    CHECK(original_length < 128, "trace environment can be restored within its bounded buffer");
    if (original_length >= 128) return k32t_finish("T_NCRYPT_BOUNDARY");
    CHECK(SetEnvironmentVariableW(L"SHZ_K32TRACE", NULL), "disable only this fixture process's opt-in trace");
    unreadable = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
    CHECK(unreadable != NULL, "allocate a genuine inaccessible handle/buffer page");
    if (!unreadable) return k32t_finish("T_NCRYPT_BOUNDARY");
    invalid = (NCRYPT_HANDLE)(ULONG_PTR)unreadable;
    output.before = guard1; output.after = guard2;
    count.before = 0x12345678u; count.after = 0x87654321u;
    memset(bytes, 0x5a, sizeof bytes); memcpy(original, bytes, sizeof bytes);

    for (i = 0; i < sizeof names / sizeof names[0]; ++i) {
        output.handle = ~(NCRYPT_HANDLE)0;
        SetLastError(123);
        CHECK(STATUS_IS(NCryptOpenStorageProvider(&output.handle, names[i], 0), NTE_PROV_DLL_NOT_FOUND)
              && output.handle == 0, "default/software/platform provider is genuinely unavailable with NULL output");
        CHECK_ERR(123, "SECURITY_STATUS and disabled trace preserve caller LastError");
    }
    output.handle = ~(NCRYPT_HANDLE)0;
    CHECK(STATUS_IS(NCryptOpenStorageProvider(&output.handle, MS_KEY_STORAGE_PROVIDER, 1), NTE_BAD_FLAGS)
          && output.handle == 0, "provider-open does not accept undocumented flags or publish a handle");
    CHECK(STATUS_IS(NCryptOpenStorageProvider(NULL, MS_KEY_STORAGE_PROVIDER, 0), NTE_INVALID_PARAMETER),
          "provider-open rejects missing required handle output");

    output.handle = ~(NCRYPT_HANDLE)0;
    CHECK(STATUS_IS(NCryptCreatePersistedKey(invalid, &output.handle, NULL, NULL, 0, 0), NTE_INVALID_HANDLE)
          && !output.handle, "invalid provider cannot create a persisted key");
    output.handle = ~(NCRYPT_HANDLE)0;
    CHECK(STATUS_IS(NCryptOpenKey(invalid, &output.handle, NULL, 0, 0), NTE_INVALID_HANDLE)
          && !output.handle, "invalid provider cannot open a key");
    output.handle = ~(NCRYPT_HANDLE)0;
    CHECK(STATUS_IS(NCryptImportKey(invalid, invalid, NULL, unreadable, &output.handle,
                                  unreadable, MAXDWORD, 0), NTE_INVALID_HANDLE) && !output.handle,
          "invalid provider cannot import a key or read inaccessible input descriptors");
    CHECK(STATUS_IS(NCryptCreatePersistedKey(invalid, NULL, NULL, NULL, 0, 0), NTE_INVALID_PARAMETER),
          "key creation rejects missing output");
    CHECK(STATUS_IS(NCryptOpenKey(invalid, NULL, NULL, 0, 0), NTE_INVALID_PARAMETER),
          "key open rejects missing output");
    CHECK(STATUS_IS(NCryptImportKey(invalid, 0, NULL, NULL, NULL, NULL, 0, 0), NTE_INVALID_PARAMETER),
          "key import rejects missing output");

    count.value = MAXDWORD;
    CHECK(STATUS_IS(NCryptGetProperty(invalid, NULL, bytes, sizeof bytes, &count.value, 0), NTE_INVALID_HANDLE)
          && !count.value, "invalid object property reports no bytes");
    count.value = MAXDWORD;
    CHECK(STATUS_IS(NCryptExportKey(invalid, invalid, NULL, unreadable, bytes, sizeof bytes,
                                  &count.value, 0), NTE_INVALID_HANDLE) && !count.value,
          "invalid key export reports no bytes without reading inaccessible descriptors");
    count.value = MAXDWORD;
    CHECK(STATUS_IS(NCryptSignHash(invalid, unreadable, unreadable, MAXDWORD, bytes, sizeof bytes,
                                 &count.value, 0), NTE_INVALID_HANDLE) && !count.value,
          "invalid key cannot sign or consume inaccessible padding/hash");
    count.value = MAXDWORD;
    CHECK(STATUS_IS(NCryptCreateClaim(invalid, invalid, 0, unreadable, bytes, sizeof bytes,
                                    &count.value, 0), NTE_INVALID_HANDLE) && !count.value,
          "invalid keys cannot create attestation or consume inaccessible claim descriptors");
    CHECK(STATUS_IS(NCryptGetProperty(invalid, NULL, unreadable, MAXDWORD, NULL, 0), NTE_INVALID_PARAMETER),
          "property rejects missing result count");
    CHECK(STATUS_IS(NCryptExportKey(invalid, 0, NULL, NULL, unreadable, MAXDWORD, NULL, 0), NTE_INVALID_PARAMETER),
          "export rejects missing result count");
    CHECK(STATUS_IS(NCryptSignHash(invalid, unreadable, unreadable, MAXDWORD,
                                 unreadable, MAXDWORD, NULL, 0), NTE_INVALID_PARAMETER),
          "sign rejects missing result count");
    CHECK(STATUS_IS(NCryptCreateClaim(invalid, 0, 0, NULL, unreadable, MAXDWORD, NULL, 0), NTE_INVALID_PARAMETER),
          "claim rejects missing result count");
    CHECK(STATUS_IS(NCryptSetProperty(invalid, NULL, unreadable, MAXDWORD, 0), NTE_INVALID_HANDLE),
          "invalid object cannot set properties or read inaccessible data");
    CHECK(STATUS_IS(NCryptIsAlgSupported(invalid, NULL, 0), NTE_INVALID_HANDLE),
          "invalid provider cannot advertise algorithm support");
    CHECK(STATUS_IS(NCryptFinalizeKey(invalid, 0), NTE_INVALID_HANDLE), "invalid key cannot finalize");
    CHECK(STATUS_IS(NCryptDeleteKey(invalid, 0), NTE_INVALID_HANDLE), "invalid key cannot delete");
    CHECK(STATUS_IS(NCryptFreeObject(invalid), NTE_INVALID_HANDLE), "invalid handle cannot claim successful cleanup");
    CHECK(STATUS_IS(NCryptFreeObject(0), NTE_INVALID_HANDLE), "NULL handle cannot claim successful cleanup");
    CHECK(memcmp(bytes, original, sizeof bytes) == 0, "failed property/export/sign/claim leave caller data untouched");
    CHECK(output.before == guard1 && output.after == guard2, "pointer-sized output stays within its guard words");
    CHECK(count.before == 0x12345678u && count.after == 0x87654321u, "DWORD result stays within its guard words");

    CHECK(SetEnvironmentVariableW(L"SHZ_K32TRACE", L"1"), "enable only this fixture process's bounded metadata trace");
    SetLastError(123);
    CHECK(STATUS_IS(NCryptOpenStorageProvider(&output.handle, unreadable, 0), NTE_PROV_DLL_NOT_FOUND)
          && !output.handle, "opt-in trace safely marks a genuine inaccessible provider name");
    CHECK_ERR(123, "safe name capture preserves caller LastError and provider failure");
    SetLastError(123);
    CHECK(STATUS_IS(NCryptOpenStorageProvider(NULL, unreadable, 0), NTE_INVALID_PARAMETER),
          "opt-in trace cannot fault on invalid-output call with inaccessible name");
    CHECK_ERR(123, "invalid-output diagnostic preserves caller LastError");
    for (i = 0; i < 64; ++i) {
        SECURITY_STATUS status = NCryptOpenStorageProvider(&output.handle, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
        CHECK(status == (SECURITY_STATUS)NTE_PROV_DLL_NOT_FOUND && !output.handle,
              "repeated provider-open stays unavailable after bounded trace is exhausted");
    }
    CHECK_ERR(123, "exhausted trace preserves caller LastError");
    CHECK(SetEnvironmentVariableW(L"SHZ_K32TRACE",
          original_length || original_error != ERROR_ENVVAR_NOT_FOUND ? original_trace : NULL),
          "restore this fixture process's original opt-in setting");
    CHECK(VirtualFree(unreadable, 0, MEM_RELEASE), "release genuine inaccessible page");
    return k32t_finish("T_NCRYPT_BOUNDARY");
}
