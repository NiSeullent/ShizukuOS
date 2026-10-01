/* SPDX-License-Identifier: GPL-2.0-only
 * Evaluate separately pinned synchronous fixtures in a fresh real runtime.
 * This does not implement Test262's complete host/module/async protocol. */
#include "m98_trident_script.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>
#include <sys/syscall.h>
#include <unistd.h>

uint32_t m98_script_thread_id(void) {
    long tid = syscall(SYS_gettid);
    return tid > 0 && (unsigned long)tid <= UINT32_MAX ? (uint32_t)tid : 0;
}
int m98_script_platform_ready(void) {
    return sizeof(double) == 8 && DBL_MANT_DIG == 53 && FLT_MANT_DIG == 24 ? 0 : -1;
}

int main(int argc, char **argv) {
    m98_script_options options = { sizeof(options), 32u << 20, 256u << 10,
                                  1000, 128, NULL };
    m98_script_context context = 0;
    int result, index, failed = 0;
    if (argc < 2 || argc > 34) return 2;
    result = m98_script_open(&options, &context);
    if (result || !context) {
        fprintf(stderr, "host runtime initialization status %d\n", result);
        return 3;
    }
    for (index = 1; index < argc; ++index) {
        FILE *file = fopen(argv[index], "rb");
        char *source = malloc((1u << 20) + 1);
        size_t count;
        m98_script_result value;
        m98_script_details detail;
        if (!file || !source) {
            if (file) fclose(file);
            free(source);
            failed = 4;
            break;
        }
        count = fread(source, 1, (1u << 20) + 1, file);
        result = ferror(file);
        if (fclose(file)) result = 1;
        if (result || !count || count > (1u << 20)) {
            free(source);
            failed = 5;
            break;
        }
        memset(&value, 0, sizeof(value));
        value.size = sizeof(value);
        result = m98_script_eval(context, source, (uint32_t)count, &value);
        free(source);
        if (result) {
            memset(&detail, 0, sizeof(detail));
            detail.size = sizeof(detail);
            if (!m98_script_info(context, &detail))
                fprintf(stderr, "fixture phase %d status %d: %.*s\n", index,
                        result, (int)detail.exception_utf8_bytes,
                        detail.exception_utf8);
            failed = 6;
            break;
        }
        if (!value.lease || m98_script_release_result(context, value.lease)) {
            failed = 7;
            break;
        }
    }
    if (m98_script_close(context)) failed = 8;
    if (!failed) puts("PASS: isolated synchronous semantic fixtures; host only");
    return failed;
}
