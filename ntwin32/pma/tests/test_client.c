/* SPDX-License-Identifier: GPL-2.0-only -- actual client, modeled Win32
 * boundary. */
#include "../client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    ++checks;                                                                  \
    if (!(x)) {                                                                \
      fprintf(stderr, "line%d: %s\n", __LINE__, #x);                           \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static unsigned checks, waits, closes, fail_event_close, fail_device_close;
static DWORD error, ticks, tid = 55, close_busy, timeout_mode, bad_ticket,
                           bad_info, query_copy_failure, query_zero_error,
                           stale_take, take_busy, sleep_step=1;
static uint64_t sequence;
HANDLE CreateEventA(void *a, BOOL manual, BOOL signal, const char *name) {
  CHECK(!a && !manual && !signal && !name);
  return (HANDLE)(uintptr_t)7;
}
HANDLE CreateFileA(const char *name, DWORD access, DWORD share, void *sec,
                   DWORD disposition, DWORD flags, HANDLE t) {
  CHECK(!strcmp(name, "\\\\.\\NTWRAP9X.VXD") && !access && !share && !sec &&
        disposition == OPEN_EXISTING && !flags && !t);
  return (HANDLE)(uintptr_t)8;
}
BOOL CloseHandle(HANDLE h) {
  CHECK(h == (HANDLE)(uintptr_t)7 || h == (HANDLE)(uintptr_t)8);
  closes++;
  if (h==(HANDLE)(uintptr_t)8 && fail_device_close) { fail_device_close=0;error=31;return FALSE; }
  if (h==(HANDLE)(uintptr_t)7 && fail_event_close) { fail_event_close=0;error=31;return FALSE; }
  return TRUE;
}
BOOL ResetEvent(HANDLE h) {
  CHECK(h == (HANDLE)(uintptr_t)7);
  return TRUE;
}
DWORD GetLastError(void) { return error; }
DWORD GetCurrentThreadId(void) { return tid; }
DWORD GetTickCount(void) { return ticks; }
void Sleep(DWORD ms) { ticks += ms*sleep_step; }
DWORD WaitForSingleObject(HANDLE h, DWORD timeout) {
  CHECK(h == (HANDLE)(uintptr_t)7 && timeout);
  waits++;
  ticks += timeout_mode ? timeout : 1;
  return timeout_mode ? WAIT_TIMEOUT : WAIT_OBJECT_0;
}
BOOL DeviceIoControl(HANDLE h, DWORD code, void *in, DWORD in_size, void *out,
                     DWORD out_size, DWORD *got, void *overlapped) {
  CHECK(h == (HANDLE)(uintptr_t)8 && out && got && !overlapped);
  memset(out, 0, out_size);
  if (code == NTWV_IOCTL_PMA_REGISTER) {
    struct ntwv_pma_registration *r = in;
    struct ntwv_pma_owner *o = out;
    CHECK(in_size == 16 && out_size == 32 && r->event_handle == 7);
    o->magic = NTWV_PMA_ENDPOINT_MAGIC;
    o->size = 32;
    o->domain = SHZ_DOM_WIN98;
    o->pid = 2;
    o->tid = 3;
    o->owner_generation = 1;
    o->thread_generation = 1;
    o->channel_generation = 9;
  } else {
    CHECK(!in && !in_size);
    if (code == NTWV_IOCTL_PMA_QUERY) {
      struct ntwv_pma_ticket *t = out;
      CHECK(out_size == 16);
      t->request_id = ++sequence;
      t->generation = bad_ticket ? 8 : 9;
      if (query_copy_failure) { error=NTWV_ERROR_NOACCESS;return FALSE; }
      if (query_zero_error) { error=0;return FALSE; }
    } else if (code == NTWV_IOCTL_PMA_TAKE) {
      struct ntwv_pma_result *r = out;
      CHECK(out_size == 96);
      if (stale_take) { stale_take--;error=NTWV_ERROR_NO_MORE_ITEMS;return FALSE; }
      if (take_busy) { error=NTWV_ERROR_BUSY;return FALSE; }
      r->magic = NTWV_PMA_ENDPOINT_MAGIC;
      r->size = 96;
      r->kind = NTWV_PMA_RESULT_QUERY;
      r->request_id = sequence;
      r->generation = 9;
      r->info.magic = SHZ_PMA_MAGIC;
      r->info.size = 64;
      r->info.abi_major = 1;
      r->info.features = SHZ_PMA_FEATURES;
      r->info.max_owners = 8;
      r->info.max_threads = 32;
      r->info.max_objects = 32;
      r->info.max_waits = 64;
      r->info.max_completions = 128;
      r->info.generation = 9;
      r->info.self_domain = SHZ_DOM_KERNEL64;
      r->info.peer_domain = SHZ_DOM_WIN98;
      r->info.now_ns = bad_info ? 0 : 100 + sequence;
    } else {
      CHECK(code == NTWV_IOCTL_PMA_CLOSE && out_size == 4);
      if (close_busy) {
        close_busy--;
        error = NTWV_ERROR_BUSY;
        return FALSE;
      }
    }
  }
  *got = out_size;
  return TRUE;
}
int main(void) {
  struct ntwp_client c={0};
  shz_pma_info_t info;
  unsigned saved;
  CHECK(ntwp_client_open(&c, 1000) == 0);
  CHECK(ntwp_client_query(&c, &info) == 0 && waits == 1 && info.now_ns == 101);
  CHECK(ntwp_client_query(&c, &info) == 0 && waits == 2);
  tid++;
  CHECK(ntwp_client_query(&c, &info) == NTWV_ERROR_ACCESS_DENIED);
  CHECK(ntwp_client_close(&c, 10) == NTWV_ERROR_ACCESS_DENIED);
  tid--;
  close_busy = 100;
  saved = closes;
  CHECK(ntwp_client_close(&c, 3) == NTWV_ERROR_TIMEOUT);
  CHECK(c.registered && closes == saved && c.event);
  close_busy = 0;
  CHECK(ntwp_client_close(&c, 3) == 0 && !c.registered && closes == saved + 2);
  CHECK(ntwp_client_open(&c, 1000) == 0);
  timeout_mode = 1;
  CHECK(ntwp_client_query(&c, &info) == NTWV_ERROR_TIMEOUT && c.query_active);
  CHECK(ntwp_client_query(&c, &info) == NTWV_ERROR_BUSY);
  timeout_mode = 0;
  CHECK(ntwp_client_close(&c, 3) == 0);
  CHECK(ntwp_client_open(&c, 1000) == 0);
  bad_ticket = 1;
  CHECK(ntwp_client_query(&c, &info) == NTWV_ERROR_REVISION_MISMATCH &&
        c.query_active);
  bad_ticket = 0;
  CHECK(ntwp_client_close(&c, 3) == 0);
  CHECK(ntwp_client_open(&c, 1000) == 0);
  CHECK(ntwp_client_query(&c, &info) == 0);
  bad_info = 1;
  CHECK(ntwp_client_query(&c, &info) == NTWV_ERROR_REVISION_MISMATCH &&
        c.query_active);
  bad_info = 0;
  CHECK(ntwp_client_close(&c, 3) == 0);
  CHECK(ntwp_client_open(&c,1000)==0);
  fail_event_close=1;
  CHECK(ntwp_client_close(&c,3)==31);
  CHECK(c.event && !c.registered);
  CHECK(ntwp_client_close(&c,3)==0);
  CHECK(c.event==NULL);
  CHECK(ntwp_client_open(&c,1000)==0);
  fail_device_close=1;
  saved=closes;
  CHECK(ntwp_client_close(&c,3)==31 && !c.registered);
  CHECK(c.device!=(HANDLE)(intptr_t)-1 && c.event && closes==saved+1);
  tid++;
  CHECK(ntwp_client_close(&c,3)==NTWV_ERROR_ACCESS_DENIED);
  tid--;
  CHECK(ntwp_client_close(&c,3)==0 && c.device==INVALID_HANDLE_VALUE && !c.event);
  CHECK(ntwp_client_open(&c,1000)==0);
  query_copy_failure=1;
  CHECK(ntwp_client_query(&c,&info)==NTWV_ERROR_NOACCESS && c.query_active);
  query_copy_failure=0;
  CHECK(ntwp_client_query(&c,&info)==NTWV_ERROR_BUSY);
  CHECK(ntwp_client_close(&c,3)==0);
  CHECK(ntwp_client_open(&c,1000)==0);
  saved=closes;
  CHECK(ntwp_client_open(&c,1000)==NTWV_ERROR_BUSY && closes==saved);
  stale_take=1;
  saved=waits;
  CHECK(ntwp_client_query(&c,&info)==0 && waits==saved+2);
  CHECK(ntwp_client_close(&c,3)==0);
  CHECK(ntwp_client_open(&c,1)==0);
  take_busy=1;sleep_step=1000;
  CHECK(ntwp_client_query(&c,&info)==NTWV_ERROR_TIMEOUT && c.query_active);
  take_busy=0;sleep_step=1;
  CHECK(ntwp_client_close(&c,3)==0);
  CHECK(ntwp_client_open(&c,1000)==0);
  query_zero_error=1;
  CHECK(ntwp_client_query(&c,&info)==NTWV_ERROR_GEN_FAILURE && c.query_active);
  query_zero_error=0;
  CHECK(ntwp_client_close(&c,3)==0);
  ticks=UINT32_MAX-1;
  CHECK(ntwp_client_open(&c,1000)==0);
  CHECK(ntwp_client_query(&c,&info)==0);
  CHECK(ntwp_client_query(&c,&info)==0 && ticks==0);
  close_busy=2;
  CHECK(ntwp_client_close(&c,100)==0);
  printf("native client %u checks (Win32 boundary modeled)\n", checks);
  return 0;
}
