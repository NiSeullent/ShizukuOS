/* SPDX-License-Identifier: GPL-2.0-only */
#include "dead_screen.h"
#include "../kernel64/k64.h"
#include <stdio.h>
_Static_assert(sizeof(struct regs)==22*8,"actual Kernel64 interrupt frame");
_Static_assert(offsetof(struct regs,vector)==15*8,"actual vector slot");
_Static_assert(offsetof(struct regs,rip)==17*8,"actual fault IP slot");
_Static_assert(offsetof(struct regs,rsp)==20*8,"actual fault SP slot");
_Static_assert(sizeof(ds_fault)<=1024,"bounded captured fault");
_Static_assert(sizeof(ds_state)<=4096,"bounded static fault/game state");
int main(void)
{
    printf("{\"machine\":\"x86_64 Kernel64\",\"regs_bytes\":%zu,\"vector_offset\":%zu,\"rip_offset\":%zu,"
           "\"rsp_offset\":%zu,\"fault_bytes\":%zu,\"state_bytes\":%zu,\"surface_bytes\":%zu}\n",
           sizeof(struct regs),offsetof(struct regs,vector),offsetof(struct regs,rip),offsetof(struct regs,rsp),
           sizeof(ds_fault),sizeof(ds_state),sizeof(ds_surface));
    return 0;
}
