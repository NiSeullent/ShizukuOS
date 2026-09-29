/* SPDX-License-Identifier: GPL-2.0-only */
#include "meminfo.h"
#include <stdio.h>
static int failures;
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
int main(void) {
    uint8_t buf[48];
    uint32_t error = 0, size = 0, resident = 0;
    C(ntw_mem_parse_statm(0, &size, &resident) == 0);
    C(ntw_mem_parse_statm("nope", &size, &resident) == 0);
    C(ntw_mem_parse_statm("123 45 1 2 3 4 0\n", &size, &resident) == 1 && size == 123 && resident == 45);
    C(ntw_mem_store(0, 40, 1, 2, 3, 4, &error) == 0 && error == 87);
    C(ntw_mem_store(buf, 16, 1, 2, 3, 4, &error) == 0 && error == 122);
    C(ntw_mem_store(buf, 40, 7, 8192, 4096, 99, &error) == 1);
    C(rd32(buf) == 40 && rd32(buf + 4) == 7 && rd32(buf + 12) == 8192 && rd32(buf + 32) == 4096);
    C(ntw_mem_store(buf, 44, 7, 8192, 4096, 99, &error) == 1 && rd32(buf) == 44 && rd32(buf + 40) == 99);
    {
        const char *sample = "MemTotal: 2048 kB\nMemAvailable: 1024 kB\nCommitted_AS: 512 kB\nCommitLimit: 4096 kB\n";
        uint32_t total = 0, avail = 0, committed = 0, limit = 0;
        C(ntw_perf_parse("MemTotal: 1 kB\n", &total, &avail, &committed, &limit) == 0);
        C(ntw_perf_parse(sample, &total, &avail, &committed, &limit) == 1 && total == 2048 && avail == 1024 && committed == 512 && limit == 4096);
        C(ntw_perf_store(0, 56, 1, 2, 3, 4, &error) == 0 && error == 87);
        C(ntw_perf_store(buf, 16, 1, 2, 3, 4, &error) == 0 && error == 122);
        C(ntw_perf_store(buf, 56, committed * 1024u, limit * 1024u, total * 1024u, avail * 1024u, &error) == 1);
        C(rd32(buf) == 56 && rd32(buf + 16) == 2048u * 1024u && rd32(buf + 40) == 4096u);
    }
    if (failures) { fprintf(stderr, "failures %d\n", failures); return 1; }
    printf("{\"passed\":true,\"meminfo\":true}\n");
    return 0;
}
