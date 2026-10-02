/* SPDX-License-Identifier: GPL-2.0-only
 * Admission controls use modeled PCI/MMIO only. No actual device or VM. */
#define main transport_fixture_main
#include "virtio_blk_host.c"
#undef main
int main(void)
{
    unsigned accepted=0;
    fixture();f.no_queues=1;if(!w98_vblk_init(&driver,&cfg,sizeof cfg,&io)){++accepted;puts("zero queues admitted");}
    fixture();f.pci[0x58/4]=0;if(!w98_vblk_init(&driver,&cfg,sizeof cfg,&io)){++accepted;puts("overlapping common/notify admitted");}
    fixture();f.ignore_command=1;if(!w98_vblk_init(&driver,&cfg,sizeof cfg,&io)){++accepted;puts("unacknowledged PCI command admitted");}
    CHECK(accepted==0);
    printf("PASS %u checks; exact polled-device admission with bounded mocked registers only\n",checks);return 0;
}
