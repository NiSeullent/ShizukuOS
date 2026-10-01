/* SPDX-License-Identifier: GPL-2.0-only
 * Exercise the production projection. Literal expected rows come from:
 * https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities
 * Raw class-3 saturation conversion is verified against ReactOS kernel32:
 * https://github.com/reactos/reactos/blob/master/dll/win32/kernel32/client/thread.c
 * This catches inert acceptance, absolute/relative confusion, incorrect process
 * class selection, saturation loss, invalid gaps and writes on refusal.
 */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../kcommon/nt_sched_policy.h"

static unsigned checks, failures;
#define CHECK(expression) do { \
    ++checks; \
    if (!(expression)) { \
        ++failures; \
        fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); \
    } \
} while (0)

struct row { uint32_t process_class; int32_t win_level, nt_increment; uint32_t absolute; };
static const struct row expected[] = {
    {0x40u,-15,-16,1}, {0x40u,-2,-2,2}, {0x40u,-1,-1,3}, {0x40u,0,0,4},
    {0x40u,1,1,5}, {0x40u,2,2,6}, {0x40u,15,16,15},
    {0x4000u,-15,-16,1}, {0x4000u,-2,-2,4}, {0x4000u,-1,-1,5}, {0x4000u,0,0,6},
    {0x4000u,1,1,7}, {0x4000u,2,2,8}, {0x4000u,15,16,15},
    {0x20u,-15,-16,1}, {0x20u,-2,-2,6}, {0x20u,-1,-1,7}, {0x20u,0,0,8},
    {0x20u,1,1,9}, {0x20u,2,2,10}, {0x20u,15,16,15},
    {0x8000u,-15,-16,1}, {0x8000u,-2,-2,8}, {0x8000u,-1,-1,9}, {0x8000u,0,0,10},
    {0x8000u,1,1,11}, {0x8000u,2,2,12}, {0x8000u,15,16,15},
    {0x80u,-15,-16,1}, {0x80u,-2,-2,11}, {0x80u,-1,-1,12}, {0x80u,0,0,13},
    {0x80u,1,1,14}, {0x80u,2,2,15}, {0x80u,15,16,15}
};

static shz_nt_sched_projection_t untouched(void)
{
    const shz_nt_sched_projection_t value = {UINT32_MAX, INT32_MIN, INT32_MAX, UINT32_MAX};
    return value;
}

static void check_row(const struct row *row)
{
    shz_nt_sched_projection_t win = untouched(), nt = untouched(), roundtrip = untouched();
    CHECK(shz_nt_sched_from_win32(row->process_class, row->win_level, &win) == SHZ_NT_SCHED_OK);
    CHECK(win.process_class == row->process_class);
    CHECK(win.win32_priority == row->win_level);
    CHECK(win.nt_base_increment == row->nt_increment);
    CHECK(win.absolute_priority == row->absolute);
    CHECK(shz_nt_sched_from_base_increment(row->process_class, row->nt_increment, &nt) == SHZ_NT_SCHED_OK);
    CHECK(nt.process_class == row->process_class);
    CHECK(nt.win32_priority == row->win_level);
    CHECK(nt.nt_base_increment == row->nt_increment);
    CHECK(nt.absolute_priority == row->absolute);
    CHECK(shz_nt_sched_from_base_increment(win.process_class, win.nt_base_increment, &roundtrip) == SHZ_NT_SCHED_OK);
    CHECK(roundtrip.win32_priority == row->win_level && roundtrip.absolute_priority == row->absolute);
    CHECK(shz_nt_sched_from_win32(nt.process_class, nt.win32_priority, &roundtrip) == SHZ_NT_SCHED_OK);
    CHECK(roundtrip.nt_base_increment == row->nt_increment && roundtrip.absolute_priority == row->absolute);
}

static void refusal(uint32_t process_class, int32_t value, shz_nt_sched_result_t win_status,
                    shz_nt_sched_result_t nt_status)
{
    const shz_nt_sched_projection_t before = untouched();
    shz_nt_sched_projection_t after = before;
    CHECK(shz_nt_sched_from_win32(process_class, value, &after) == win_status);
    CHECK(memcmp(&after, &before, sizeof after) == 0);
    CHECK(shz_nt_sched_from_base_increment(process_class, value, &after) == nt_status);
    CHECK(memcmp(&after, &before, sizeof after) == 0);
    CHECK(shz_nt_sched_from_win32(process_class, value, NULL) == SHZ_NT_SCHED_INVALID_ARGUMENT);
    CHECK(shz_nt_sched_from_base_increment(process_class, value, NULL) == SHZ_NT_SCHED_INVALID_ARGUMENT);
}

int main(void)
{
    static const uint32_t classes[] = {0x40u,0x4000u,0x20u,0x8000u,0x80u};
    static const uint32_t unknown_classes[] = {0u,1u,0x60u,0x120u,0x10000u,0x20000u,UINT32_MAX};
    static const int32_t boundaries[] = {INT32_MIN,INT32_MIN+1,-65536,-32768,-257,-256,-129,-128,
                                        -17,17,127,128,255,256,32767,65535,INT32_MAX-1,INT32_MAX};
    unsigned i,j;
    int32_t value;
    for(i=0;i<sizeof expected/sizeof expected[0];++i)check_row(&expected[i]);
    for(i=0;i<sizeof classes/sizeof classes[0];++i) {
        for(value=-32;value<=32;++value) {
            shz_nt_sched_projection_t out=untouched();
            const shz_nt_sched_projection_t before=out;
            const int win_valid=value==-15 || (value>=-2 && value<=2) || value==15;
            const int nt_valid=value==-16 || (value>=-2 && value<=2) || value==16;
            CHECK(shz_nt_sched_from_win32(classes[i],value,&out)==
                  (win_valid?SHZ_NT_SCHED_OK:SHZ_NT_SCHED_INVALID_ARGUMENT));
            if(!win_valid)CHECK(memcmp(&out,&before,sizeof out)==0);
            out=before;
            CHECK(shz_nt_sched_from_base_increment(classes[i],value,&out)==
                  (nt_valid?SHZ_NT_SCHED_OK:SHZ_NT_SCHED_INVALID_ARGUMENT));
            if(!nt_valid)CHECK(memcmp(&out,&before,sizeof out)==0);
            CHECK(shz_nt_sched_from_win32(classes[i],value,NULL)==SHZ_NT_SCHED_INVALID_ARGUMENT);
            CHECK(shz_nt_sched_from_base_increment(classes[i],value,NULL)==SHZ_NT_SCHED_INVALID_ARGUMENT);
        }
        for(j=0;j<sizeof boundaries/sizeof boundaries[0];++j)
            refusal(classes[i],boundaries[j],SHZ_NT_SCHED_INVALID_ARGUMENT,SHZ_NT_SCHED_INVALID_ARGUMENT);
        refusal(classes[i],0x10000,SHZ_NT_SCHED_UNSUPPORTED,SHZ_NT_SCHED_INVALID_ARGUMENT);
        refusal(classes[i],0x20000,SHZ_NT_SCHED_UNSUPPORTED,SHZ_NT_SCHED_INVALID_ARGUMENT);
    }
    for(i=0;i<sizeof unknown_classes/sizeof unknown_classes[0];++i) {
        refusal(unknown_classes[i],0,SHZ_NT_SCHED_INVALID_ARGUMENT,SHZ_NT_SCHED_INVALID_ARGUMENT);
        refusal(unknown_classes[i],INT32_MIN,SHZ_NT_SCHED_INVALID_ARGUMENT,SHZ_NT_SCHED_INVALID_ARGUMENT);
    }
    for(value=-32;value<=32;++value)
        refusal(0x100u,value,SHZ_NT_SCHED_UNSUPPORTED,SHZ_NT_SCHED_UNSUPPORTED);
    refusal(0x100u,INT32_MIN,SHZ_NT_SCHED_UNSUPPORTED,SHZ_NT_SCHED_UNSUPPORTED);
    refusal(0x100u,INT32_MAX,SHZ_NT_SCHED_UNSUPPORTED,SHZ_NT_SCHED_UNSUPPORTED);
    printf("NT_SCHED_POLICY_HOST: %u checks, %u failures\n",checks,failures);
    return failures ? 1 : 0;
}
