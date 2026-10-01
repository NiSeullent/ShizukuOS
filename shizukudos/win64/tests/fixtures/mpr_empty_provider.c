/* SPDX-License-Identifier: GPL-2.0-only
 * Fixture-only provider with a genuinely empty resource set. Its live enum
 * owns an actual kernel event. It supplies no network connection, share,
 * credential, mapping or product-health success; it proves MPR dispatch. */
#include "mpr_empty_provider.h"
#include <winnetwk.h>
#include <npapi.h>

static MPR_FIXTURE_STATS stats;

__declspec(dllexport) DWORD WINAPI NPGetCaps(DWORD index)
{
    ++stats.caps;
    if (index == WNNC_SPEC_VERSION) return WNNC_SPEC_VERSION51;
    if (index == WNNC_ENUMERATION) return WNNC_ENUM_GLOBAL;
    return 0; /* No network type, connection or authentication capabilities. */
}

__declspec(dllexport) DWORD WINAPI NPOpenEnum(DWORD scope, DWORD type, DWORD usage,
                                            NETRESOURCEW *resource, HANDLE *result)
{
    (void)resource;
    if (!result) return WN_BAD_POINTER;
    *result = NULL;
    if (scope != RESOURCE_GLOBALNET || type != RESOURCETYPE_ANY || usage)
        return WN_BAD_VALUE;
    if (stats.event) return WN_FUNCTION_BUSY;
    stats.event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!stats.event) return GetLastError();
    ++stats.opens;
    *result = stats.event;
    return WN_SUCCESS;
}

__declspec(dllexport) DWORD WINAPI NPEnumResource(HANDLE enumeration, DWORD *count,
                                                void *buffer, DWORD *bytes)
{
    DWORD flags;
    if (!enumeration || enumeration != stats.event || !GetHandleInformation(enumeration, &flags))
        return WN_BAD_HANDLE;
    if (!count || !buffer || !bytes) return WN_BAD_POINTER;
    ++stats.enumerations;
    *count = 0;
    return WN_NO_MORE_ENTRIES; /* The fixture has no resources to advertise. */
}

__declspec(dllexport) DWORD WINAPI NPCloseEnum(HANDLE enumeration)
{
    if (!enumeration || enumeration != stats.event) return WN_BAD_HANDLE;
    if (!CloseHandle(enumeration)) return GetLastError();
    stats.event = NULL;
    ++stats.closes;
    return WN_SUCCESS;
}

__declspec(dllexport) DWORD WINAPI MprFixtureQuery(MPR_FIXTURE_STATS *result, DWORD bytes)
{
    if (!result) return WN_BAD_POINTER;
    if (bytes != sizeof *result) return WN_BAD_VALUE;
    *result = stats;
    return WN_SUCCESS;
}
