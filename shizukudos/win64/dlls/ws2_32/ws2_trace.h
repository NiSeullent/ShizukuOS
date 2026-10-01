/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_WS2_TRACE_H
#define SHZ_WS2_TRACE_H
void ws2_trace_failure(const char *function, unsigned error);
void ws2_trace_request(const char *function, unsigned request, unsigned overlapped, unsigned callback);
void ws2_trace_guid(const void *guid);
#endif
