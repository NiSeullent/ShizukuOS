/* SPDX-License-Identifier: GPL-2.0-only
 * Query real registry state independently of WER. Only absent, uniquely named
 * fixture values are changed; existing exclusion values and keys are retained. */
#include "k32test.h"
#include <werapi.h>

static const WCHAR list_path[] = L"Software\\Microsoft\\Windows Error Reporting\\ExcludedApplications";
static WCHAR user_name[120], machine_name[120], worker_name[120];
static HANDLE acquired, release_worker;
static HRESULT worker_add;

static void unique_name(WCHAR *out, const WCHAR *prefix)
{
    static const WCHAR hex[] = L"0123456789abcdef";
    DWORD pid = GetCurrentProcessId();
    unsigned i = 0, n;
    while (prefix[i]) { out[i] = prefix[i]; ++i; }
    for (n = 0; n < 8; ++n) out[i++] = hex[(pid >> ((7 - n) * 4)) & 15];
    out[i++] = '.'; out[i++] = 'b'; out[i++] = 'i'; out[i++] = 'n'; out[i] = 0;
}

static LONG read_value(HKEY root, const WCHAR *name, DWORD *type, DWORD *value, DWORD *size)
{
    HKEY key;
    LONG result = RegOpenKeyExW(root, list_path, 0, KEY_QUERY_VALUE, &key), closed;
    if (result) return result;
    result = RegQueryValueExW(key, name, NULL, type, (BYTE *)value, size);
    closed = RegCloseKey(key);
    return result ? result : closed;
}

static int absent(HKEY root, const WCHAR *name)
{
    DWORD type = 0, value = 0, size = sizeof value;
    LONG result = read_value(root, name, &type, &value, &size);
    return result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND;
}

static int excluded(HKEY root, const WCHAR *name)
{
    DWORD type = 0, value = 0, size = sizeof value;
    return read_value(root, name, &type, &value, &size) == ERROR_SUCCESS
        && type == REG_DWORD && size == sizeof value && value == 1;
}

static DWORD WINAPI exclusion_worker(void *unused)
{
    HRESULT removed;
    (void)unused;
    worker_add = WerAddExcludedApplication(worker_name, FALSE);
    if (!SetEvent(acquired)) {
        if (worker_add == S_OK) WerRemoveExcludedApplication(worker_name, FALSE);
        return 3;
    }
    if (WaitForSingleObject(release_worker, 5000) != WAIT_OBJECT_0) {
        if (worker_add == S_OK) WerRemoveExcludedApplication(worker_name, FALSE);
        return 2;
    }
    removed = worker_add == S_OK ? WerRemoveExcludedApplication(worker_name, FALSE) : worker_add;
    return worker_add == S_OK && removed == S_OK ? 0 : 1;
}

int main(void)
{
    WCHAR full[160], overlong[MAX_PATH + 1];
    HMODULE module = GetModuleHandleW(L"wer.dll");
    HANDLE thread = NULL;
    DWORD exit_code = 1;
    HRESULT result;
    DWORD acquired_result;
    unsigned i, n;
    BOOL user_owned = FALSE, machine_owned = FALSE;
    unique_name(user_name, L"codex-wer-01a0f3d0-cb43-user-\xD55C\xAE00-");
    unique_name(machine_name, L"codex-wer-01a0f3d0-cb43-machine-");
    unique_name(worker_name, L"codex-wer-01a0f3d0-cb43-worker-");
    CHECK(module && GetProcAddress(module, "WerAddExcludedApplication")
          && GetProcAddress(module, "WerRemoveExcludedApplication"), "actual WER module exports both exclusion operations");
    CHECK(module && !GetProcAddress(module, "WerReportCreate"), "absent report backend is not exported as fabricated success");
    CHECK(WerAddExcludedApplication(NULL, FALSE) == E_INVALIDARG
          && WerRemoveExcludedApplication(NULL, TRUE) == E_INVALIDARG, "NULL executable name is rejected before registry access");
    CHECK(WerAddExcludedApplication(L"", FALSE) == E_INVALIDARG
          && WerRemoveExcludedApplication(L"C:\\", FALSE) == E_INVALIDARG, "empty basename and trailing separator are rejected");
    for (i = 0; i < MAX_PATH; ++i) overlong[i] = 'a';
    overlong[MAX_PATH] = 0;
    CHECK(WerAddExcludedApplication(overlong, FALSE) == E_INVALIDARG
          && WerRemoveExcludedApplication(overlong, FALSE) == E_INVALIDARG, "MAX_PATH without room for terminator is rejected");

    CHECK(absent(HKEY_CURRENT_USER, user_name), "unique Unicode user exclusion is genuinely absent before any mutation");
    if (!absent(HKEY_CURRENT_USER, user_name)) goto done;
    result = WerRemoveExcludedApplication(user_name, FALSE);
    CHECK(FAILED(result) && absent(HKEY_CURRENT_USER, user_name), "removing an absent user exclusion returns a real failure");
    n = 0; full[n++] = 'C'; full[n++] = ':'; full[n++] = '\\';
    for (i = 0; user_name[i]; ++i) full[n++] = user_name[i];
    full[n] = 0;
    result = WerAddExcludedApplication(full, FALSE); user_owned = result == S_OK;
    CHECK(user_owned, "real HKCU exclusion creation succeeds for Unicode .bin basename");
    if (user_owned) {
        CHECK(excluded(HKEY_CURRENT_USER, user_name), "independent registry query finds DWORD 1 under the exact basename");
        CHECK(absent(HKEY_CURRENT_USER, full), "full path is not incorrectly stored as the value name");
        CHECK(WerAddExcludedApplication(user_name, FALSE) == S_OK
              && excluded(HKEY_CURRENT_USER, user_name), "adding the same user exclusion preserves its real registry value");
        CHECK(WerRemoveExcludedApplication(full, FALSE) == S_OK, "real user exclusion deletes using the same basename rule");
        CHECK(absent(HKEY_CURRENT_USER, user_name), "independent query confirms actual user value deletion");
        CHECK(FAILED(WerRemoveExcludedApplication(user_name, FALSE)), "second removal cannot invent successful deletion");
        user_owned = !absent(HKEY_CURRENT_USER, user_name);
    }

    CHECK(absent(HKEY_LOCAL_MACHINE, machine_name), "unique machine exclusion is genuinely absent before mutation");
    if (absent(HKEY_LOCAL_MACHINE, machine_name)) {
        result = WerAddExcludedApplication(machine_name, TRUE); machine_owned = result == S_OK;
        CHECK(result == S_OK || result == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED), "actual machine rights determine success or an honest access error");
        if (machine_owned) {
            CHECK(excluded(HKEY_LOCAL_MACHINE, machine_name), "independent registry query confirms actual HKLM DWORD 1");
            CHECK(absent(HKEY_CURRENT_USER, machine_name), "machine exclusion does not modify the user hive");
            CHECK(WerRemoveExcludedApplication(machine_name, TRUE) == S_OK, "actual machine exclusion deletes with matching hive selection");
            CHECK(absent(HKEY_LOCAL_MACHINE, machine_name), "actual machine value is absent after deletion");
            machine_owned = !absent(HKEY_LOCAL_MACHINE, machine_name);
        } else CHECK(absent(HKEY_LOCAL_MACHINE, machine_name), "access failure leaves the actual machine value absent");
    }

    CHECK(absent(HKEY_CURRENT_USER, worker_name), "unique worker exclusion is absent before second thread starts");
    if (!absent(HKEY_CURRENT_USER, worker_name)) goto done;
    acquired = CreateEventW(NULL, TRUE, FALSE, NULL);
    release_worker = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (acquired && release_worker) thread = CreateThread(NULL, 0, exclusion_worker, NULL, 0, NULL);
    CHECK(thread != NULL, "real native second thread starts WER exclusion operation");
    if (thread) {
        acquired_result = WaitForSingleObject(acquired, 5000);
        CHECK(acquired_result == WAIT_OBJECT_0, "worker publishes completed actual registry operation");
        if (acquired_result == WAIT_OBJECT_0)
            CHECK(worker_add == S_OK && excluded(HKEY_CURRENT_USER, worker_name), "main thread independently observes worker's real registry value");
        CHECK(SetEvent(release_worker), "worker release event signals");
        if (WaitForSingleObject(thread, 5000) != WAIT_OBJECT_0) {
            CHECK(0, "worker must join before cleanup"); return k32t_finish("T_WER_EXCLUSIONS");
        }
        CHECK(GetExitCodeThread(thread, &exit_code) && !exit_code, "worker completes actual deletion before thread exit");
        CHECK(absent(HKEY_CURRENT_USER, worker_name), "independent query confirms worker's actual deletion");
        if (worker_add == S_OK && !absent(HKEY_CURRENT_USER, worker_name))
            WerRemoveExcludedApplication(worker_name, FALSE);
        CHECK(CloseHandle(thread), "joined worker handle closes");
    }
done:
    if (machine_owned) WerRemoveExcludedApplication(machine_name, TRUE);
    if (user_owned) WerRemoveExcludedApplication(user_name, FALSE);
    if (release_worker) CHECK(CloseHandle(release_worker), "owned worker release event closes");
    if (acquired) CHECK(CloseHandle(acquired), "owned worker publication event closes");
    return k32t_finish("T_WER_EXCLUSIONS");
}
