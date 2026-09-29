/* SPDX-License-Identifier: GPL-2.0-only */
#include "meminfo.h"
int ntw_mem_parse_statm(const char *text, uint32_t *size_pages, uint32_t *resident_pages) {
    uint32_t i = 0, field = 0, seen = 0, vals[2] = {0, 0};
    if (!text || !size_pages || !resident_pages || !text[0]) return 0;
    while (text[i] && field < 2u) {
        char ch = text[i++];
        if (ch == ' ' || ch == '\n') {
            if (!seen) continue;
            field++;
            seen = 0;
            continue;
        }
        if (ch < '0' || ch > '9') return 0;
        vals[field] = vals[field] * 10u + (uint32_t)(ch - '0');
        seen = 1;
    }
    if (seen && field < 2u) field++;
    if (field < 2u) return 0;
    *size_pages = vals[0];
    *resident_pages = vals[1];
    return 1;
}
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
int ntw_mem_store(uint8_t *buffer, uint32_t bytes, uint32_t faults, uint32_t working_set, uint32_t pagefile,
                  uint32_t private_bytes, uint32_t *error) {
    uint32_t i, used;
    if (!error) return 0;
    if (!buffer) { *error = 87; return 0; }
    if (bytes < 40u) { *error = 122; return 0; }
    used = bytes >= 44u ? 44u : 40u;
    for (i = 0; i < used; ++i) buffer[i] = 0;
    put32(buffer, used);
    put32(buffer + 4, faults);
    put32(buffer + 8, working_set);
    put32(buffer + 12, working_set);
    put32(buffer + 32, pagefile);
    put32(buffer + 36, pagefile);
    if (used == 44u) put32(buffer + 40, private_bytes);
    *error = 0;
    return 1;
}
static int key_value(const char *text, const char *key, uint32_t *out) {
    uint32_t i = 0;
    if (!text || !key || !out) return 0;
    while (text[i]) {
        uint32_t k = 0, line = i;
        while (key[k] && text[line + k] == key[k]) k++;
        if (!key[k] && text[line + k] == ':') {
            uint32_t n = line + k + 1, value = 0, seen = 0;
            while (text[n] == ' ' || text[n] == '\t') n++;
            while (text[n] >= '0' && text[n] <= '9') { seen = 1; value = value * 10u + (uint32_t)(text[n] - '0'); n++; }
            if (!seen) return 0;
            *out = value;
            return 1;
        }
        while (text[i] && text[i] != '\n') i++;
        if (text[i] == '\n') i++;
    }
    return 0;
}
int ntw_perf_parse(const char *text, uint32_t *mem_total_kb, uint32_t *mem_avail_kb,
                   uint32_t *commit_as_kb, uint32_t *commit_limit_kb) {
    if (!mem_total_kb || !mem_avail_kb || !commit_as_kb || !commit_limit_kb) return 0;
    if (!key_value(text, "MemTotal", mem_total_kb)) return 0;
    if (!key_value(text, "MemAvailable", mem_avail_kb)) return 0;
    if (!key_value(text, "Committed_AS", commit_as_kb)) return 0;
    if (!key_value(text, "CommitLimit", commit_limit_kb)) return 0;
    return 1;
}
int ntw_perf_store(uint8_t *buffer, uint32_t bytes, uint32_t commit_total, uint32_t commit_limit,
                   uint32_t physical_total, uint32_t physical_available, uint32_t *error) {
    uint32_t i;
    if (!error) return 0;
    if (!buffer) { *error = 87; return 0; }
    if (bytes < 56u) { *error = 122; return 0; }
    for (i = 0; i < 56u; ++i) buffer[i] = 0;
    put32(buffer, 56u);
    put32(buffer + 4, commit_total);
    put32(buffer + 8, commit_limit);
    put32(buffer + 12, commit_total);
    put32(buffer + 16, physical_total);
    put32(buffer + 20, physical_available);
    put32(buffer + 40, 4096u);
    *error = 0;
    return 1;
}
