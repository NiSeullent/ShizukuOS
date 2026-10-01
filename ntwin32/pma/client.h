/* SPDX-License-Identifier: GPL-2.0-only -- original native Windows client. */
#ifndef NTWP_CLIENT_H
#define NTWP_CLIENT_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include "pma_endpoint.h"
#include <windows.h>
/* Initialize with {0}. Keep this object and its handles until close succeeds.
 * All calls belong to the actual registering thread; the VxD authenticates it. */
struct ntwp_client {
  HANDLE device, event;
  DWORD native_tid, timeout_ms, registered, query_active;
  uint64_t last_request_id, last_now_ns;
  struct ntwv_pma_owner owner;
};
DWORD ntwp_client_open(struct ntwp_client *, DWORD);
DWORD ntwp_client_query(struct ntwp_client *, shz_pma_info_t *);
DWORD ntwp_client_close(struct ntwp_client *, DWORD);
#endif
