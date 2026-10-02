/* SPDX-License-Identifier: GPL-2.0-only
 * Negative controls for actual C decode/reset and absolute completion bounds.
 * Clock/PCI/MMIO/DMA are explicitly modeled; no actual device or VM. */
#define main transport_fixture_main
#include "virtio_blk_host.c"
#undef main
int main(void)
{
    w98_owned_block_t b;uint8_t out[512];unsigned accepted=0;
    fixture();f.pci[0x58/4]=0;CHECK(w98_vblk_init(&driver,&cfg,sizeof cfg,&io)==-1);
    if(driver.reset_acknowledged){++accepted;puts("pre-decode reset acknowledged");}
    fixture();CHECK(!w98_vblk_init(&driver,&cfg,sizeof cfg,&io));CHECK(!w98_vblk_block(&driver,&b));admitted_model_map(&b);CHECK(!w98_vblk_seal_member(&driver,&map));f.notify_tick_delay=3000;
    if(!b.read(b.opaque,4096,1,out)){++accepted;puts("late notify completion accepted");}
    fixture();CHECK(!w98_vblk_init(&driver,&cfg,sizeof cfg,&io));CHECK(!w98_vblk_block(&driver,&b));admitted_model_map(&b);CHECK(!w98_vblk_seal_member(&driver,&map));f.completion_tick_delay=3000;
    if(!b.read(b.opaque,4096,1,out)){++accepted;puts("late final completion accepted");}
    fixture();CHECK(!w98_vblk_init(&driver,&cfg,sizeof cfg,&io));f.reset_tick_delay=3000;
    if(!w98_vblk_close(&driver) || driver.reset_acknowledged){++accepted;puts("late reset acknowledged");}
    CHECK(accepted==0);
    printf("PASS %u checks; actual C decode/reset and deadline refusal with modeled hardware/TSC only\n",checks);return 0;
}
