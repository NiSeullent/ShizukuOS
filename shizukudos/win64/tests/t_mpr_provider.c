/* SPDX-License-Identifier: GPL-2.0-only
 * Dynamic Wine MPR guest contract for the actual seven sal3.dll imports.
 * The only positive provider fixture has zero resources and owns an actual
 * event; it proves registry/module dispatch, never network/product health.
 * Pinned Wine dereferences non-NULL enum handles as heap structs, so this
 * fixture never supplies a random/stale handle to MPR enum/close functions. */
#include "k32test.h"
#include <winnetwk.h>
#include <winreg.h>
#include "fixtures/mpr_empty_provider.h"

typedef struct {
    __typeof__(&WNetCloseEnum) closeEnum;
    __typeof__(&WNetEnumResourceW) enumResource;
    __typeof__(&WNetOpenEnumW) openEnum;
    __typeof__(&WNetCancelConnection2W) cancelConnection;
    __typeof__(&WNetGetUserW) getUser;
    __typeof__(&WNetAddConnection2W) addConnection;
    __typeof__(&WNetGetConnectionW) getConnection;
} MPR_API;

static const WCHAR parent_path[] = L"System\\CurrentControlSet\\Control\\NetworkProvider";
static const WCHAR order_path[] = L"System\\CurrentControlSet\\Control\\NetworkProvider\\Order";
static const WCHAR service_path[] = L"System\\CurrentControlSet\\Services\\ShzMprFixtureCb43";
static const WCHAR provider_name[] = L"Shizuku MPR empty test provider";
static const WCHAR order_value[] = L"ShzMprFixtureCb43";

static int bind_mpr(HMODULE module, MPR_API *api)
{
#define BIND(field, name) do { api->field = (__typeof__(api->field))GetProcAddress(module, name); \
    CHECK(api->field != NULL, "actual Office MPR import " name " resolves"); } while (0)
    BIND(closeEnum, "WNetCloseEnum");
    BIND(enumResource, "WNetEnumResourceW");
    BIND(openEnum, "WNetOpenEnumW");
    BIND(cancelConnection, "WNetCancelConnection2W");
    BIND(getUser, "WNetGetUserW");
    BIND(addConnection, "WNetAddConnection2W");
    BIND(getConnection, "WNetGetConnectionW");
#undef BIND
    return api->closeEnum && api->enumResource && api->openEnum && api->cancelConnection
        && api->getUser && api->addConnection && api->getConnection;
}

/* Check real input state before loading the upstream code, whose raw REG_SZ
 * parser assumes correctly terminated strings. Never overwrite an existing
 * order, even an empty one, to manufacture the unavailable-provider result. */
static int order_is_absent(void)
{
    HKEY key = NULL;
    DWORD bytes = 0;
    LONG status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, order_path, 0, KEY_QUERY_VALUE, &key);
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) return 1;
    if (status != ERROR_SUCCESS) return 0;
    status = RegQueryValueExW(key, L"ProviderOrder", NULL, NULL, NULL, &bytes);
    if (RegCloseKey(key) != ERROR_SUCCESS) return 0;
    return status == ERROR_FILE_NOT_FOUND;
}

static void unavailable_contract(MPR_API *api)
{
    struct { ULONG_PTR before; HANDLE value; ULONG_PTR after; } enumeration;
    NETRESOURCEW resource = {0};
    DWORD count = 1, bytes = sizeof resource;
    enumeration.before = 0x1122334455667788ull;
    enumeration.after = 0x8877665544332211ull;
    enumeration.value = (HANDLE)(ULONG_PTR)0xfeedbeef;
    CHECK(api->openEnum(RESOURCE_GLOBALNET, RESOURCETYPE_ANY, 0, NULL, &enumeration.value)
          == WN_NO_NETWORK && enumeration.value == NULL,
          "actual missing ProviderOrder leaves no network provider and clears enum output");
    CHECK_ERR(WN_NO_NETWORK, "provider absence reports its real WNet error");
    CHECK(enumeration.before == 0x1122334455667788ull && enumeration.after == 0x8877665544332211ull,
          "missing-provider enum output stays inside pointer-sized guards");
    CHECK(api->openEnum(RESOURCE_GLOBALNET, RESOURCETYPE_ANY, 0, NULL, NULL) == WN_BAD_POINTER,
          "enum open rejects NULL required output");
    CHECK(api->enumResource(NULL, &count, &resource, &bytes) == WN_BAD_POINTER,
          "resource enumeration rejects NULL handle before any object dereference");
    CHECK(api->closeEnum(NULL) == WN_BAD_HANDLE, "enum close rejects NULL handle without freeing arbitrary memory");
    resource.dwType = RESOURCETYPE_DISK;
    resource.lpRemoteName = L"\\\\shz-mpr-no-provider-test\\absent";
    CHECK(api->addConnection(&resource, NULL, NULL, 0) == WN_NO_NETWORK,
          "missing provider cannot create an invented connection/share");
    CHECK(api->cancelConnection(L"Z:", 0, FALSE) == WN_NO_NETWORK,
          "missing provider cannot claim successful connection cancellation");
}

static void identity_and_local_drive(MPR_API *api)
{
    WCHAR actual[256], remote[128];
    struct { ULONG_PTR before; WCHAR value[256]; ULONG_PTR after; } user;
    BYTE initial[sizeof user.value];
    DWORD expected = 256, size = 0, status, direct_size = 0, direct_error;
    UINT drive;
    BOOL have_identity;
    user.before = 0x1122334455667788ull; user.after = 0x8877665544332211ull;
    have_identity = GetUserNameW(actual, &expected);
    CHECK(have_identity, "independently read the runtime's actual current-user identity");
    if (!have_identity || !expected || expected > 256) return;
    SetLastError(0);
    CHECK(!GetUserNameW(NULL, &direct_size) && direct_size == expected,
          "actual identity API supplies required UTF16 character count");
    direct_error = GetLastError();
    status = api->getUser(NULL, NULL, &size);
    printf("MPR pinned upstream username sizing status=%lu (Windows WNet documents ERROR_MORE_DATA=%u)\n",
           (unsigned long)status, (unsigned)ERROR_MORE_DATA);
    CHECK(status == direct_error && size == expected,
          "pinned current-user delegation preserves actual size/status; full Windows error parity remains a gap");
    memset(user.value, 0x5a, sizeof user.value); memcpy(initial, user.value, sizeof initial);
    size = 1;
    CHECK(api->getUser(NULL, user.value, &size) == direct_error && size == expected,
          "short username buffer reports required characters without truncation");
    CHECK(memcmp(initial, user.value, sizeof initial) == 0, "short username buffer remains untouched");
    size = 256;
    CHECK(api->getUser(NULL, user.value, &size) == WN_SUCCESS && size == expected && k32t_weq(actual, user.value),
          "current default username equals independent actual profile identity");
    size = 256;
    CHECK(api->getUser(L"", user.value, &size) == WN_SUCCESS && k32t_weq(actual, user.value),
          "empty resource name selects actual current user");
    CHECK(user.before == 0x1122334455667788ull && user.after == 0x8877665544332211ull,
          "username buffer guards survive sizing and success");
    drive = GetDriveTypeW(L"C:\\");
    CHECK(drive == DRIVE_FIXED || drive == DRIVE_REMOVABLE || drive == DRIVE_CDROM,
          "independent drive API confirms C: is an actual local drive");
    if (drive == DRIVE_FIXED || drive == DRIVE_REMOVABLE || drive == DRIVE_CDROM) {
        size = 128; memset(remote, 0x5a, sizeof remote);
        CHECK(api->getConnection(L"C:", remote, &size) == WN_NOT_CONNECTED,
              "actual local C: has no fabricated remote network connection");
        CHECK_ERR(WN_NOT_CONNECTED, "local-drive lookup reports its actual WNet error");
    }
}

int main(void)
{
    HMODULE mpr = NULL, fixture = NULL;
    MPR_API api = {0};
    MPR_FIXTURE_QUERY query = NULL;
    MPR_FIXTURE_STATS stats = {0};
    HKEY order = NULL, service = NULL, provider = NULL, parent = NULL;
    HANDLE enumeration = NULL, actual_event = NULL;
    NETRESOURCEW resource = {0};
    struct { ULONG_PTR before; BYTE value[512]; ULONG_PTR after; } buffer;
    BYTE original[sizeof buffer.value];
    WCHAR provider_path[MAX_PATH];
    DWORD disposition = 0, order_disposition = 0, size, count, flags;
    DWORD path_length;
    LONG status;
    int service_created = 0, provider_created = 0, value_attempted = 0, parent_existed = 0;

    printf("MPR real guest/provider routing fixture; empty test provider is not network or publisher health\n");
    CHECK(order_is_absent(), "real registry has no ProviderOrder before MPR loads");
    if (!order_is_absent()) return k32t_finish("T_MPR_PROVIDER");
    mpr = LoadLibraryW(L"mpr.dll");
    CHECK(mpr != NULL, "load actual pinned MPR DLL with its real dependencies/initializer");
    if (!mpr || !bind_mpr(mpr, &api)) goto cleanup;
    identity_and_local_drive(&api);
    unavailable_contract(&api);
    CHECK(FreeLibrary(mpr), "unload unregistered-provider MPR instance");
    mpr = NULL;
    CHECK(GetModuleHandleW(L"mpr.dll") == NULL, "MPR genuinely detached before provider registry is changed");
    if (GetModuleHandleW(L"mpr.dll")) goto cleanup;

    fixture = LoadLibraryW(L"mprfix.dll");
    CHECK(fixture != NULL, "load test-only provider module, which has no shares or connection capability");
    if (!fixture) goto cleanup;
    query = (MPR_FIXTURE_QUERY)GetProcAddress(fixture, "MprFixtureQuery");
    CHECK(query != NULL, "test-only provider exports actual dispatch counters");
    if (!query) goto cleanup;
    CHECK(query(&stats, sizeof stats) == WN_SUCCESS && !stats.opens && !stats.enumerations && !stats.closes && !stats.event,
          "new provider owns no enumeration/event before MPR dispatch");
    path_length = GetModuleFileNameW(fixture, provider_path, MAX_PATH);
    CHECK(path_length && path_length < MAX_PATH && provider_path[path_length] == 0,
          "registry provider path comes from actual loaded native fixture module");
    if (!path_length || path_length >= MAX_PATH) goto cleanup;

    status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, parent_path, 0, KEY_READ, &parent);
    CHECK(status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND,
          "record actual provider-order parent existence before creating any fixture keys");
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND) goto cleanup;
    parent_existed = status == ERROR_SUCCESS;
    if (parent) { CHECK(RegCloseKey(parent) == ERROR_SUCCESS, "close parent observation handle"); parent = NULL; }
    status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, service_path, 0, NULL, REG_OPTION_NON_VOLATILE,
                            KEY_ALL_ACCESS, NULL, &service, &disposition);
    service_created = status == ERROR_SUCCESS && disposition == REG_CREATED_NEW_KEY;
    CHECK(service_created, "create fresh isolated fixture service; preexisting service is never overwritten");
    if (!service_created) goto cleanup;
    status = RegCreateKeyExW(service, L"NetworkProvider", 0, NULL, REG_OPTION_NON_VOLATILE,
                            KEY_ALL_ACCESS, NULL, &provider, &disposition);
    provider_created = status == ERROR_SUCCESS && disposition == REG_CREATED_NEW_KEY;
    CHECK(provider_created, "create fresh provider metadata under owned fixture service");
    if (!provider_created) goto cleanup;
    status = RegSetValueExW(provider, L"ProviderPath", 0, REG_SZ, (BYTE *)provider_path,
                            (path_length + 1) * sizeof(WCHAR));
    CHECK(status == ERROR_SUCCESS, "register actual loaded DLL path as terminated UTF16 REG_SZ");
    if (status != ERROR_SUCCESS) goto cleanup;
    status = RegSetValueExW(provider, L"Name", 0, REG_SZ, (const BYTE *)provider_name, sizeof provider_name);
    CHECK(status == ERROR_SUCCESS, "register explicit test-only provider name as terminated UTF16 REG_SZ");
    if (status != ERROR_SUCCESS) goto cleanup;
    status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, order_path, 0, NULL, REG_OPTION_NON_VOLATILE,
                            KEY_ALL_ACCESS, NULL, &order, &order_disposition);
    CHECK(status == ERROR_SUCCESS && order != NULL, "open/create isolated missing-order registry key");
    if (status != ERROR_SUCCESS) goto cleanup;
    CHECK(order_is_absent(), "ProviderOrder remains genuinely absent immediately before fixture write");
    if (!order_is_absent()) goto cleanup;
    value_attempted = 1;
    status = RegSetValueExW(order, L"ProviderOrder", 0, REG_SZ, (const BYTE *)order_value, sizeof order_value);
    CHECK(status == ERROR_SUCCESS, "register exactly one actual fixture service for dynamic provider initialization");
    if (status != ERROR_SUCCESS) goto cleanup;

    mpr = LoadLibraryW(L"mpr.dll");
    CHECK(mpr != NULL, "reload unchanged MPR with real registry-provider initialization");
    if (!mpr || !bind_mpr(mpr, &api)) goto cleanup;
    CHECK(query(&stats, sizeof stats) == WN_SUCCESS && stats.caps >= 4 && !stats.event,
          "MPR actually loaded registered module and queried its provider capabilities");
    resource.dwScope = RESOURCE_GLOBALNET;
    resource.dwType = RESOURCETYPE_ANY;
    resource.dwUsage = RESOURCEUSAGE_CONTAINER;
    resource.lpProvider = (WCHAR *)provider_name;
    CHECK(api.openEnum(RESOURCE_GLOBALNET, RESOURCETYPE_ANY, 0, &resource, &enumeration) == WN_SUCCESS && enumeration,
          "actual named-provider dispatch opens a genuine owned empty enumerator");
    if (!enumeration) goto cleanup;
    CHECK(query(&stats, sizeof stats) == WN_SUCCESS && stats.opens == 1 && stats.event != NULL,
          "real provider callback created exactly one actual event");
    actual_event = stats.event;
    CHECK(GetHandleInformation(actual_event, &flags), "provider's enum event is an actual live kernel handle");
    buffer.before = 0x1122334455667788ull; buffer.after = 0x8877665544332211ull;
    memset(buffer.value, 0x5a, sizeof buffer.value); memcpy(original, buffer.value, sizeof original);
    count = MAXDWORD; size = 0;
    CHECK(api.enumResource(enumeration, &count, buffer.value, &size) == WN_MORE_DATA && size == sizeof(NETRESOURCEW),
          "router negotiates real NETRESOURCE structure size before provider dispatch");
    CHECK(query(&stats, sizeof stats) == WN_SUCCESS && stats.enumerations == 0,
          "short caller buffer has not called provider or invented resource data");
    size = sizeof buffer.value;
    CHECK(api.enumResource(enumeration, &count, NULL, &size) == WN_BAD_POINTER,
          "genuine owned enum rejects NULL data output");
    CHECK(api.enumResource(enumeration, NULL, buffer.value, &size) == WN_BAD_POINTER,
          "genuine owned enum rejects NULL count output");
    CHECK(api.enumResource(enumeration, &count, buffer.value, NULL) == WN_BAD_POINTER,
          "genuine owned enum rejects NULL size output");
    count = MAXDWORD; size = sizeof buffer.value;
    CHECK(api.enumResource(enumeration, &count, buffer.value, &size) == WN_NO_MORE_ENTRIES && count == 0,
          "actual empty provider callback reports no resources rather than fabricated network shares");
    CHECK(query(&stats, sizeof stats) == WN_SUCCESS && stats.enumerations == 1 && stats.closes == 0,
          "real provider dispatch counter proves one enumeration callback");
    CHECK(memcmp(original, buffer.value, sizeof original) == 0 && buffer.before == 0x1122334455667788ull
          && buffer.after == 0x8877665544332211ull, "empty/invalid enumeration leaves data and surrounding guards untouched");
    CHECK(api.closeEnum(enumeration) == WN_SUCCESS, "close only the genuinely opened MPR enumerator");
    enumeration = NULL;
    CHECK(query(&stats, sizeof stats) == WN_SUCCESS && stats.closes == 1 && !stats.event,
          "actual close callback releases exactly the provider-owned event");
    CHECK(!GetHandleInformation(actual_event, &flags) && GetLastError() == ERROR_INVALID_HANDLE,
          "closed provider event is genuinely absent from the kernel handle table");

cleanup:
    if (enumeration && mpr && api.closeEnum) {
        CHECK(api.closeEnum(enumeration) == WN_SUCCESS, "failure cleanup closes genuine still-owned enumerator");
        enumeration = NULL;
    }
    if (mpr) { CHECK(FreeLibrary(mpr), "detach current MPR module before removing its registry metadata"); mpr = NULL; }
    if (provider) { CHECK(RegCloseKey(provider) == ERROR_SUCCESS, "close owned provider registry handle"); provider = NULL; }
    if (provider_created) CHECK(RegDeleteKeyW(service, L"NetworkProvider") == ERROR_SUCCESS,
                                "remove only owned fixture metadata key");
    if (service) { CHECK(RegCloseKey(service) == ERROR_SUCCESS, "close fixture service registry handle"); service = NULL; }
    if (service_created) CHECK(RegDeleteKeyW(HKEY_LOCAL_MACHINE, service_path) == ERROR_SUCCESS,
                               "remove only freshly created fixture service");
    if (order && value_attempted) {
        status = RegDeleteValueW(order, L"ProviderOrder");
        CHECK(status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND, "remove attempted fixture-only ProviderOrder value");
    }
    if (order) { CHECK(RegCloseKey(order) == ERROR_SUCCESS, "close provider-order registry handle"); order = NULL; }
    if (order_disposition == REG_CREATED_NEW_KEY)
        CHECK(RegDeleteKeyW(HKEY_LOCAL_MACHINE, order_path) == ERROR_SUCCESS, "remove only freshly created empty Order key");
    if (order_disposition == REG_CREATED_NEW_KEY && !parent_existed)
        CHECK(RegDeleteKeyW(HKEY_LOCAL_MACHINE, parent_path) == ERROR_SUCCESS, "remove only freshly created empty order parent");
    if (fixture) { CHECK(FreeLibrary(fixture), "release caller's provider-module reference after MPR detach"); fixture = NULL; }
    CHECK(order_is_absent(), "actual registry ProviderOrder absence is restored after success or failure");
    status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, service_path, 0, KEY_READ, &service);
    if (service) RegCloseKey(service);
    if (service_created) CHECK(status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND,
                               "owned fixture service is genuinely absent after cleanup");
    mpr = LoadLibraryW(L"mpr.dll");
    CHECK(mpr != NULL, "reload production MPR against restored genuine absent-provider state");
    if (mpr) {
        if (bind_mpr(mpr, &api)) unavailable_contract(&api);
        CHECK(FreeLibrary(mpr), "close final restored-state MPR instance");
    }
    return k32t_finish("T_MPR_PROVIDER");
}
