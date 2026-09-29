/* SPDX-License-Identifier: GPL-2.0-only */
#include "critsec.h"
#include <stdio.h>
static int failures;
static uint32_t tid = 7;
uint32_t ntw_cs_thread_id(void) { return tid; }
void ntw_cs_yield(void) { }
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
int main(void) {
    ntw_critical_section section, dirty;
    uint32_t sentinel = 0x11111111u;
    dirty.debug_info = sentinel;
    C(sizeof(ntw_critical_section) == 24);
    C(ntw_cs_initialize(0, 0, 0) == 0 && ntw_cs_last_error() == 87 && dirty.debug_info == sentinel);
    C(ntw_cs_initialize(&dirty, 0, 1) == 0 && dirty.debug_info == sentinel);
    C(ntw_cs_initialize(&dirty, 0xff000000u, 0) == 0 && dirty.debug_info == sentinel);
    C(ntw_cs_initialize(&section, 4000, NTW_CS_NO_DEBUG_INFO) == 1);
    C(section.debug_info == 0xffffffffu && section.lock_count == -1 && section.spin_count == 0);
    C(section.recursion_count == 0 && section.owning_thread == 0);
    ntw_cs_enter(&section);
    C(section.owning_thread == 7 && section.recursion_count == 1 && section.lock_count == 0);
    ntw_cs_enter(&section);
    C(section.recursion_count == 2 && section.lock_count == 1);
    tid = 9;
    C(ntw_cs_try_enter(&section) == 0 && section.owning_thread == 7 && section.recursion_count == 2);
    ntw_cs_leave(&section);
    C(ntw_cs_last_error() == 288 && section.owning_thread == 7 && section.recursion_count == 2);
    tid = 7;
    ntw_cs_leave(&section);
    C(section.recursion_count == 1 && section.lock_count == 0 && section.owning_thread == 7);
    ntw_cs_leave(&section);
    C(section.recursion_count == 0 && section.lock_count == -1 && section.owning_thread == 0);
    tid = 3;
    C(ntw_cs_try_enter(&section) == 1 && section.owning_thread == 3);
    ntw_cs_delete(&section);
    C(section.owning_thread == 3 && ntw_cs_last_error() == 87);
    ntw_cs_leave(&section);
    ntw_cs_delete(&section);
    C(section.debug_info == 0 && section.lock_count == -1);
    C(ntw_cs_initialize(&section, 0, 0) == 1 && section.debug_info != 0 && section.debug_info != 0xffffffffu);
    if (failures) return 1;
    printf("{\"passed\":true,\"layout\":24}\n");
    return 0;
}
