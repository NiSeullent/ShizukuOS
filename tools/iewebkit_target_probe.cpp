/* Native target/provider probe. This is not a rendered-document test. */
#include "engine_loader.h"
#include <windows.h>
#include <winver.h>
#include <cstdio>
#include <cstring>

static bool file_version(const char *path, DWORD *ms, DWORD *ls) {
  DWORD ignored = 0, length = GetFileVersionInfoSizeA(path, &ignored);
  if (!length || length > 1024 * 1024)
    return false;
  void *data = HeapAlloc(GetProcessHeap(), 0, length);
  VS_FIXEDFILEINFO *info = NULL;
  UINT size = 0;
  bool good = data && GetFileVersionInfoA(path, 0, length, data) &&
              VerQueryValueA(data, "\\", reinterpret_cast<void **>(&info), &size) &&
              size >= sizeof *info && info->dwSignature == 0xfeef04bd;
  if (good) {
    *ms = info->dwFileVersionMS;
    *ls = info->dwFileVersionLS;
  }
  if (data)
    HeapFree(GetProcessHeap(), 0, data);
  return good;
}

int main(int argc, char **argv) {
  const char *nonce = argc == 2 ? argv[1] : "manual";
  if (argc > 2 || std::strlen(nonce) > 80)
    return 2;
  for (const char *p = nonce; *p; ++p)
    if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
          (*p >= '0' && *p <= '9') || *p == '-'))
      return 2;
  FILE *log = std::fopen("IETARGET.LOG", "wb");
  if (!log)
    return 2;
  std::fprintf(log, "schema=win98modern.iewebkit-target.v1\nnonce=%s\n", nonce);
  OSVERSIONINFOA os;
  std::memset(&os, 0, sizeof os);
  os.dwOSVersionInfoSize = sizeof os;
  bool os_ok = GetVersionExA(&os) && os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS &&
               os.dwMajorVersion == 4 && os.dwMinorVersion == 10 &&
               (os.dwBuildNumber & 0xffff) == 2222;
  std::fprintf(log, "os=%lu.%lu.%lu\nplatform=%lu\n",
               os.dwMajorVersion, os.dwMinorVersion, os.dwBuildNumber & 0xffff,
               os.dwPlatformId);
  char shdocvw[MAX_PATH], ie[MAX_PATH];
  UINT n = GetSystemDirectoryA(shdocvw, sizeof shdocvw);
  bool sh_path = n && n + sizeof "\\SHDOCVW.DLL" <= sizeof shdocvw;
  if (sh_path)
    std::strcat(shdocvw, "\\SHDOCVW.DLL");
  HKEY key = NULL;
  DWORD type = 0, bytes = sizeof ie;
  std::memset(ie, 0, sizeof ie);
  bool ie_path = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
      "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\IEXPLORE.EXE",
      0, KEY_QUERY_VALUE, &key) == ERROR_SUCCESS;
  if (ie_path) {
    ie_path = RegQueryValueExA(key, NULL, NULL, &type,
                              reinterpret_cast<BYTE *>(ie), &bytes) == ERROR_SUCCESS &&
              type == REG_SZ && bytes > 1 && bytes <= sizeof ie && ie[bytes - 1] == 0;
    RegCloseKey(key);
  }
  DWORD sh_ms = 0, sh_ls = 0, ie_ms = 0, ie_ls = 0;
  bool sh_ok = sh_path && file_version(shdocvw, &sh_ms, &sh_ls);
  bool ie_ok = ie_path && file_version(ie, &ie_ms, &ie_ls);
  std::fprintf(log, "shdocvw_version=%u.%u.%u.%u\niexplore_version=%u.%u.%u.%u\n",
      HIWORD(sh_ms), LOWORD(sh_ms), HIWORD(sh_ls), LOWORD(sh_ls),
      HIWORD(ie_ms), LOWORD(ie_ms), HIWORD(ie_ls), LOWORD(ie_ls));
  bool target = os_ok && sh_ok && ie_ok && sh_ms == 0x00050000 &&
                ie_ms == sh_ms && sh_ls == MAKELONG(3500, 2614) && ie_ls == sh_ls;
  std::fprintf(log, "target_matched=%d\n", target ? 1 : 0);
  IEWKLoadedEngine engine;
  std::memset(&engine, 0, sizeof engine);
  int status = target ? iewk_load_engine(GetModuleHandleA(NULL), &engine) : IEWK_BAD_ABI;
  std::fprintf(log, "provider_status=%d\n", status);
  if (status == IEWK_OK) {
    std::fprintf(log, "provider_name=%s\nprovider_source_sha256=%s\nprovider_caps=%lu\n",
        engine.api->engine_name, engine.api->source_sha256,
        static_cast<unsigned long>(engine.api->capabilities));
    iewk_unload_engine(&engine);
  }
  std::fprintf(log, "rendering_verified=0\n");
  std::fclose(log);
  return !target ? 4 : status == IEWK_OK ? 0 : 3;
}
