/* SPDX-License-Identifier: GPL-2.0-only -- real Windows98 PMA endpoint probe.
 * Uses actual native events, Windows threads/processes and the loaded VxD.
 * Native execution is separate from compilation and host boundary models. */
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include "client.h"
static HANDLE log_file;
static void record(const char *message, uint64_t value) {
  static const char hex[] = "0123456789abcdef";
  char line[180];
  DWORD n = 0, written, i;
  while (*message && n < sizeof line - 22)
    line[n++] = *message++;
  line[n++] = ' ';
  line[n++] = '0';
  line[n++] = 'x';
  for (i = 0; i < 16; i++)
    line[n++] = hex[(value >> (60 - i * 4)) & 15u];
  line[n++] = '\r';
  line[n++] = '\n';
  if (!WriteFile(log_file, line, n, &written, NULL) || written != n ||
      !FlushFileBuffers(log_file))
    ExitProcess(90);
}
static void fail(const char *message, uint64_t error) {
  record(message, error);
  CloseHandle(log_file);
  ExitProcess(1);
}
static DWORD WINAPI foreign_thread(void *p) {
  HANDLE device = *(HANDLE *)p;
  struct ntwv_pma_ticket ticket;
  DWORD got = 0;
  BOOL ok = DeviceIoControl(device, NTWV_IOCTL_PMA_QUERY, NULL, 0, &ticket,
                            sizeof ticket, &got, NULL);
  return !ok && GetLastError() == NTWV_ERROR_ACCESS_DENIED ? 0 : 1;
}
static int foreign_mode(void) {
  const char *p = GetCommandLineA(), *word = "/foreign";
  while (*p) {
    const char *a = p, *b = word;
    while (*a && *b && *a == *b) {
      a++;
      b++;
    }
    if (!*b)
      return 1;
    p++;
  }
  return 0;
}
static void child_foreign(void) {
  HANDLE device;
  struct ntwv_pma_ticket ticket;
  DWORD got = 0;
  log_file = CreateFileA("PMAFOREIGN.LOG", GENERIC_WRITE, FILE_SHARE_READ, NULL,
                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (log_file == INVALID_HANDLE_VALUE)
    ExitProcess(2);
  device =
      CreateFileA("\\\\.\\NTWRAP9X.VXD", 0, 0, NULL, OPEN_EXISTING, 0, NULL);
  if (device == INVALID_HANDLE_VALUE)
    fail("FAIL foreign device open", GetLastError());
  if (DeviceIoControl(device, NTWV_IOCTL_PMA_QUERY, NULL, 0, &ticket,
                      sizeof ticket, &got, NULL) ||
      GetLastError() != NTWV_ERROR_ACCESS_DENIED)
    fail("FAIL foreign process admission", GetLastError());
  record("PASS native VMM rejects foreign process", GetCurrentProcessId());
  CloseHandle(device);
  CloseHandle(log_file);
  ExitProcess(0);
}
static void verify_foreign_process(void) {
  STARTUPINFOA startup;
  PROCESS_INFORMATION process;
  unsigned char *p = (unsigned char *)&startup;
  DWORD i, code, wait;
  char command[] = "PMAQUERY.EXE /foreign";
  for (i = 0; i < sizeof startup; i++)
    p[i] = 0;
  startup.cb = sizeof startup;
  if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup,
                      &process))
    fail("FAIL foreign CreateProcess", GetLastError());
  wait = WaitForSingleObject(process.hProcess, 30000);
  if (wait != WAIT_OBJECT_0 || !GetExitCodeProcess(process.hProcess, &code) ||
      code != 0)
    fail("FAIL foreign process result", wait);
  record("PASS foreign native process exited normally", process.dwProcessId);
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
}
void mainCRTStartup(void) {
  struct ntwp_client client = {0};
  shz_pma_info_t info;
  uint64_t previous = 0, now = 0;
  DWORD previous_lifetime = 0, cycle, rc, exit_code = 259;
  DWORD version = GetVersion();
  if (foreign_mode())
    child_foreign();
  log_file = CreateFileA("PMAQUERY.LOG", GENERIC_WRITE, FILE_SHARE_READ, NULL,
                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (log_file == INVALID_HANDLE_VALUE)
    ExitProcess(2);
  record("START actual Windows98 PMA QUERY", version);
  if ((version & 0xffffu) != 0x0a04u || !(version & 0x80000000u))
    fail("FAIL actual Windows98 identity", version);
  record("PASS actual Windows98 identity", version);
  for (cycle = 0; cycle < 2; cycle++) {
    HANDLE thread;
    rc = ntwp_client_open(&client, 3000);
    if (rc)
      fail("FAIL authoritative registration", rc);
    if (client.owner.owner_generation <= previous_lifetime)
      fail("FAIL owner lifetime progression", client.owner.owner_generation);
    previous_lifetime = client.owner.owner_generation;
    record("PASS authoritative native VMM owner", client.owner.pid);
    record("PASS authoritative native VMM thread", client.owner.tid);
    record("PASS native owner lifetime", client.owner.owner_generation);
    thread = CreateThread(NULL, 0, foreign_thread, &client.device, 0, NULL);
    if (!thread)
      fail("FAIL native CreateThread", GetLastError());
    if (WaitForSingleObject(thread, 30000) != WAIT_OBJECT_0 ||
        !GetExitCodeThread(thread, &exit_code) || exit_code != 0)
      fail("FAIL foreign thread admission", exit_code);
    CloseHandle(thread);
    record("PASS native VMM rejects foreign thread", cycle + 1);
    if (cycle == 0)
      verify_foreign_process();
    for (DWORD q = 0; q < 2; q++) {
      rc = ntwp_client_query(&client, &info);
      if (rc)
        fail("FAIL native event QUERY completion", rc);
      if (client.last_request_id <= previous || info.now_ns < now)
        fail("FAIL query correlation or monotonic snapshot",
             client.last_request_id);
      previous = client.last_request_id;
      now = info.now_ns;
      record("PASS native Windows event wait completion",
             client.last_request_id);
      record("PASS backend monotonic snapshot", info.now_ns);
      record("PASS matched Kernel64 channel generation", info.generation);
    }
    rc = ntwp_client_close(&client, 10000);
    if (rc)
      fail("FAIL confirmed PROCESS_EXIT rundown", rc);
    record("PASS confirmed PROCESS_EXIT rundown", cycle + 1);
  }
  record("PASS actual native PMA QUERY probe", 0);
  CloseHandle(log_file);
  ExitProcess(0);
}
