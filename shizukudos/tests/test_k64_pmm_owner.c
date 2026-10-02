/* SPDX-License-Identifier: GPL-2.0-only
 * Serialized observer regression entry: use the same actual allocator/provider
 * host boundary as the concurrency control, rather than treating initial
 * unavailable bits as caller allocation provenance. Historical20 checks remain
 * frozen with their original source in the previous227-source AP milestone.
 */
#define main shz_memory_control_main
#include "test_k64_memory_concurrency.c"
#undef main
int main(void)
{
    char *arguments[]={"pmm-owner","observer"};
    return shz_memory_control_main(2,arguments);
}
