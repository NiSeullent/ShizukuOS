/* SPDX-License-Identifier: GPL-2.0-only */
#include "k32test.h"
#include <winreg.h>

int main(void)
{
    HKEY user = NULL, first = NULL, second = NULL, readonly = NULL, rejected = NULL;
    DWORD disposition = 0, value = 0xcb430718, actual = 0, type = 0, bytes = sizeof actual;
    CHECK(RegOpenCurrentUser(KEY_READ, NULL) == ERROR_INVALID_PARAMETER, "current-user open rejects null output");
    CHECK(RegOpenCurrentUser(KEY_ALL_ACCESS, &user) == ERROR_SUCCESS && user && user != HKEY_CURRENT_USER,
          "current-user open returns an actual owned native profile handle");
    if (!user) return k32t_finish("T_REG_CURRENT_USER");
    CHECK(RegCreateKeyExW(user, L"Software\\ShzCurrentUserProbe", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &first, &disposition)
          == ERROR_SUCCESS, "owned profile handle creates genuine isolated child key");
    if (first) {
        CHECK(RegSetValueExW(first, L"ActualValue", 0, REG_DWORD, (const BYTE *)&value, sizeof value) == ERROR_SUCCESS,
              "actual registry child value is written");
        CHECK(RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\ShzCurrentUserProbe", 0, KEY_READ, &second) == ERROR_SUCCESS,
              "predefined current-user view opens same actual child key");
        if (second) {
            CHECK(RegQueryValueExW(second, L"ActualValue", NULL, &type, (BYTE *)&actual, &bytes) == ERROR_SUCCESS &&
                  type == REG_DWORD && bytes == sizeof value && actual == value,
                  "native owned handle and predefined profile share genuine stored bytes");
            CHECK(RegCloseKey(second) == ERROR_SUCCESS, "independent child read handle closes");
        }
        CHECK(RegCloseKey(first) == ERROR_SUCCESS, "created child handle closes");
    }
    CHECK(RegOpenCurrentUser(KEY_READ, &readonly) == ERROR_SUCCESS && readonly && readonly != user,
          "second current-user open creates separate read-only owned handle");
    if (readonly) {
        CHECK(RegCreateKeyExW(readonly, L"ShzMustNotBeCreated", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &rejected, NULL)
              == ERROR_ACCESS_DENIED && !rejected, "read-only profile handle cannot create a child");
        CHECK(RegCloseKey(readonly) == ERROR_SUCCESS, "read-only owned profile handle closes");
    }
    CHECK(RegDeleteKeyW(user, L"Software\\ShzCurrentUserProbe") == ERROR_SUCCESS,
          "actual isolated probe child is removed");
    CHECK(RegCloseKey(user) == ERROR_SUCCESS, "owned current-user handle closes");
    CHECK(RegQueryInfoKeyW(user, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_INVALID_HANDLE,
          "closed actual profile handle is rejected");
    return k32t_finish("T_REG_CURRENT_USER");
}
