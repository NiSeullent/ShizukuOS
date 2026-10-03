/* SPDX-License-Identifier: GPL-2.0-only
 * gcc -O2 -Wall -Wextra -Werror this.c ; exercises the production decision core. */
#include "../appcompat/k32_runtime_topology_core.h"
#include <stdio.h>
#include <stdlib.h>
static int n;
#define V(c) do { ++n; if (!(c)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #c); exit(1); } } while (0)
int main(void)
{
    uint32_t req, keep; uint64_t m = 9; uint16_t g = 9, cnt, grp[2] = {7, 7};
    /* guarantee */
    req = 0; V(shzrt_stack_guarantee(&req, 0, &keep) == 0 && req == 0 && keep == 0);       /* query, none recorded */
    req = 0; V(shzrt_stack_guarantee(&req, 16384, &keep) == 0 && req == 16384);            /* query returns previous */
    req = 4096; V(shzrt_stack_guarantee(&req, 16384, &keep) == 0 && req == 16384 && keep == 16384); /* never shrinks */
    req = 16384; V(shzrt_stack_guarantee(&req, 16384, &keep) == 0 && req == 16384);
    req = 100; V(shzrt_stack_guarantee(&req, 0, &keep) == SHZRT_ERROR_NOT_SUPPORTED && req == 100 && keep == 0); /* grow: refused, unchanged */
    req = 0xfffff001u; V(shzrt_stack_guarantee(&req, 0, &keep) == SHZRT_ERROR_INVALID_PARAMETER); /* overflow on rounding */
    V(shzrt_stack_guarantee(0, 0, &keep) == SHZRT_ERROR_INVALID_PARAMETER);
    /* numa */
    req = 5; V(shzrt_numa_highest(&req) == 0 && req == 0);
    V(shzrt_numa_highest(0) == SHZRT_ERROR_INVALID_PARAMETER);
    V(shzrt_numa_node_mask(0, &m, &g, 1) == 0 && m == 1 && g == 0);
    m = 9; V(shzrt_numa_node_mask(1, &m, &g, 1) == SHZRT_ERROR_INVALID_PARAMETER && m == 9);
    V(shzrt_numa_node_mask(0, 0, &g, 1) == SHZRT_ERROR_INVALID_PARAMETER);
    /* process groups */
    cnt = 0; V(shzrt_process_groups(&cnt, grp) == SHZRT_ERROR_INSUFFICIENT_BUFFER && cnt == 1 && grp[0] == 7);
    cnt = 2; V(shzrt_process_groups(&cnt, grp) == 0 && cnt == 1 && grp[0] == 0 && grp[1] == 7);
    cnt = 1; V(shzrt_process_groups(&cnt, 0) == SHZRT_ERROR_INVALID_PARAMETER);
    V(shzrt_process_groups(0, grp) == SHZRT_ERROR_INVALID_PARAMETER);
    V(shzrt_large_page_minimum() == 0);
    printf("runtime_topology host PASS %d checks\n", n);
    return 0;
}
