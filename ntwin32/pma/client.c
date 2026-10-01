/* SPDX-License-Identifier: GPL-2.0-only -- original native Windows event
 * client. */
#include "client.h"
static void clear(void *v, size_t n) {
  unsigned char *p = v;
  while (n--)
    *p++ = 0;
}
static DWORD last_error(void) {
  const DWORD error = GetLastError();
  return error ? error : NTWV_ERROR_GEN_FAILURE;
}
static DWORD close_handles(struct ntwp_client *c);
static DWORD io(struct ntwp_client *c, DWORD code, void *in, DWORD in_size,
                void *out, DWORD out_size) {
  DWORD got = 0;
  if (!DeviceIoControl(c->device, code, in, in_size, out, out_size, &got, NULL))
    return last_error();
  return got == out_size ? 0 : NTWV_ERROR_REVISION_MISMATCH;
}
DWORD ntwp_client_open(struct ntwp_client *c, DWORD timeout_ms) {
  struct ntwv_pma_registration r;
  DWORD rc;
  if (!c || !timeout_ms || timeout_ms > NTWV_PMA_TIMEOUT_MAX_MS)
    return NTWV_ERROR_INVALID_PARAMETER;
  if (c->registered || c->query_active || c->event ||
      (c->device && c->device != INVALID_HANDLE_VALUE))
    return NTWV_ERROR_BUSY;
  clear(c, sizeof *c);
  c->device = INVALID_HANDLE_VALUE;
  c->native_tid = GetCurrentThreadId();
  c->timeout_ms = timeout_ms;
  c->event = CreateEventA(NULL, FALSE, FALSE, NULL);
  if (!c->event)
    return last_error();
  /* Keep the VxD resident across connections: its sequence/lifetime namespace
   * must outlive the backend epoch. No delete-on-close unload request here. */
  c->device =
      CreateFileA("\\\\.\\NTWRAP9X.VXD", 0, 0, NULL, OPEN_EXISTING, 0, NULL);
  if (c->device == INVALID_HANDLE_VALUE) {
    rc = last_error();
    (void)close_handles(c);
    return rc;
  }
  r.size = sizeof r;
  r.event_handle = (uint32_t)(uintptr_t)c->event;
  r.timeout_ms = timeout_ms;
  r.reserved = 0;
  rc = io(c, NTWV_IOCTL_PMA_REGISTER, &r, sizeof r, &c->owner, sizeof c->owner);
  if (rc) {
    (void)close_handles(c);
    return rc;
  }
  c->registered = 1;
  if (c->owner.magic != NTWV_PMA_ENDPOINT_MAGIC ||
      c->owner.size != sizeof c->owner || c->owner.domain != SHZ_DOM_WIN98 ||
      !c->owner.pid || !c->owner.tid || !c->owner.owner_generation ||
      !c->owner.thread_generation || !c->owner.channel_generation)
    return NTWV_ERROR_REVISION_MISMATCH;
  return 0;
}
DWORD ntwp_client_query(struct ntwp_client *c, shz_pma_info_t *info) {
  struct ntwv_pma_ticket ticket;
  struct ntwv_pma_result result;
  DWORD rc, start, budget;
  if (!c || !info || !c->registered)
    return NTWV_ERROR_NOT_READY;
  if (GetCurrentThreadId() != c->native_tid)
    return NTWV_ERROR_ACCESS_DENIED;
  if (c->query_active)
    return NTWV_ERROR_BUSY;
  if (!ResetEvent(c->event))
    return last_error();
  /* QUERY may be admitted before its ticket copy fails. Preserve uncertain
   * admission until actual CLOSE acknowledgement; do not issue another QUERY. */
  c->query_active = 1;
  rc = io(c, NTWV_IOCTL_PMA_QUERY, NULL, 0, &ticket, sizeof ticket);
  if (rc)
    return rc;
  if (!ticket.request_id || ticket.request_id <= c->last_request_id ||
      ticket.generation != c->owner.channel_generation || ticket.reserved)
    return NTWV_ERROR_REVISION_MISMATCH;
  c->last_request_id = ticket.request_id;
  start = GetTickCount();
  budget = c->timeout_ms + 2000u;
  for (;;) {
    DWORD elapsed = (DWORD)(GetTickCount() - start), wait;
    if (elapsed >= budget)
      return NTWV_ERROR_TIMEOUT;
    wait = WaitForSingleObject(c->event, budget - elapsed);
    if (wait == WAIT_TIMEOUT)
      return NTWV_ERROR_TIMEOUT;
    if (wait == WAIT_FAILED)
      return last_error();
    if (wait != WAIT_OBJECT_0)
      return NTWV_ERROR_GEN_FAILURE;
    do {
      rc = io(c, NTWV_IOCTL_PMA_TAKE, NULL, 0, &result, sizeof result);
      if (rc == NTWV_ERROR_BUSY)
        Sleep(1);
    } while (rc == NTWV_ERROR_BUSY && (DWORD)(GetTickCount() - start) < budget);
    if (rc == NTWV_ERROR_BUSY)
      return NTWV_ERROR_TIMEOUT;
    if (rc == NTWV_ERROR_NO_MORE_ITEMS)
      continue; /* stale notification; keep matching this ticket */
    if (rc)
      return rc;
    if (result.magic != NTWV_PMA_ENDPOINT_MAGIC ||
        result.size != sizeof result ||
        result.request_id != ticket.request_id ||
        result.generation != ticket.generation || result.reserved)
      return NTWV_ERROR_REVISION_MISMATCH;
    if (result.kind == NTWV_PMA_RESULT_ERROR)
      return result.error ? result.error : NTWV_ERROR_GEN_FAILURE;
    if (result.kind != NTWV_PMA_RESULT_QUERY || result.error ||
        result.info.magic != SHZ_PMA_MAGIC ||
        result.info.size != sizeof result.info ||
        result.info.abi_major != SHZ_PMA_ABI_MAJOR || result.info.flags ||
        result.info.generation != ticket.generation ||
        result.info.self_domain != SHZ_DOM_KERNEL64 ||
        result.info.peer_domain != SHZ_DOM_WIN98 ||
        (result.info.features &
         (SHZ_PMA_FEATURE_EVENTS | SHZ_PMA_FEATURE_LIFECYCLE)) !=
            (SHZ_PMA_FEATURE_EVENTS | SHZ_PMA_FEATURE_LIFECYCLE) ||
        !result.info.max_owners || !result.info.max_threads ||
        !result.info.max_objects || !result.info.max_waits ||
        !result.info.max_completions || result.info.now_ns < c->last_now_ns)
      return NTWV_ERROR_REVISION_MISMATCH;
    c->last_now_ns = result.info.now_ns;
    *info = result.info;
    c->query_active = 0;
    return 0;
  }
}
static DWORD close_handles(struct ntwp_client *c) {
  if (c->device && c->device != INVALID_HANDLE_VALUE) {
    if (!CloseHandle(c->device))
      return last_error();
    c->device = INVALID_HANDLE_VALUE;
  }
  if (c->event) {
    if (!CloseHandle(c->event))
      return last_error();
    c->event = NULL;
  }
  return 0;
}
DWORD ntwp_client_close(struct ntwp_client *c, DWORD budget_ms) {
  DWORD start, rc, status;
  if (!c || !budget_ms || budget_ms > NTWV_PMA_TIMEOUT_MAX_MS)
    return NTWV_ERROR_INVALID_PARAMETER;
  if (!c->registered && !c->event &&
      (!c->device || c->device == INVALID_HANDLE_VALUE))
    return 0;
  if (GetCurrentThreadId() != c->native_tid)
    return NTWV_ERROR_ACCESS_DENIED;
  if (!c->registered)
    return close_handles(c); /* actual rundown was already acknowledged */
  start = GetTickCount();
  do {
    status = ~0u;
    rc = io(c, NTWV_IOCTL_PMA_CLOSE, NULL, 0, &status, sizeof status);
    if (!rc) {
      if (status)
        return NTWV_ERROR_GEN_FAILURE;
      c->registered = 0;
      c->query_active = 0;
      return close_handles(c);
    }
    if (rc != NTWV_ERROR_BUSY)
      return rc;
    Sleep(NTWV_PMA_POLL_MS);
  } while ((DWORD)(GetTickCount() - start) < budget_ms);
  return NTWV_ERROR_TIMEOUT; /* all handles retained; cleanup is still
                                unconfirmed */
}
