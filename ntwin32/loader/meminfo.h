/* SPDX-License-Identifier: GPL-2.0-only
 * PROCESS_MEMORY_COUNTERS from a statm text. Missing text fails. The
 * counters are not invented. Wine psapi was not copied.
 */
#ifndef NTW_MEMINFO_H
#define NTW_MEMINFO_H
#include <stdint.h>
int ntw_mem_parse_statm(const char *text, uint32_t *size_pages, uint32_t *resident_pages);
int ntw_mem_store(uint8_t *buffer, uint32_t bytes, uint32_t faults, uint32_t working_set, uint32_t pagefile,
                  uint32_t private_bytes, uint32_t *error);
int ntw_perf_parse(const char *text, uint32_t *mem_total_kb, uint32_t *mem_avail_kb,
                   uint32_t *commit_as_kb, uint32_t *commit_limit_kb);
int ntw_perf_store(uint8_t *buffer, uint32_t bytes, uint32_t commit_total, uint32_t commit_limit,
                   uint32_t physical_total, uint32_t physical_available, uint32_t *error);
#endif
