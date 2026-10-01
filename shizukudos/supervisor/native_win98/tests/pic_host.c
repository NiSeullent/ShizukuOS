/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>
#include "../../src/devices.h"
static unsigned checks;
#define CHECK(v) do {++checks;if(!(v)){fprintf(stderr,"FAIL line%d %s\n",__LINE__,#v);exit(2);}}while(0)
static void out(unsigned p,unsigned v){CHECK(dev_pio_out(p,1,v));}
static unsigned in(unsigned p){uint32_t v=0;CHECK(dev_pio_in(p,1,&v));return v;}
static void init(unsigned ae)
{
 dev_init(1000000000ull,128ull<<20);
 out(0x20,0x11);out(0xa0,0x11);out(0x21,0x20);out(0xa1,0x28);out(0x21,4);out(0xa1,2);out(0x21,1|ae);out(0xa1,1|ae);out(0x21,0xfb);out(0xa1,0x3f);
}
int main(void)
{
 init(0);CHECK(!dev_irq_pending());dev_irq_raise(14);CHECK(dev_irq_pending());CHECK(dev_ack_irq()==0x2e);CHECK(!dev_irq_pending());
 out(0x20,0x0b);out(0xa0,0x0b);CHECK(in(0x20)==4);CHECK(in(0xa0)==0x40);
 /* A second slave request waits for both real slave and cascade EOIs. */
 dev_irq_raise(15);CHECK(!dev_irq_pending());out(0xa0,0x20);CHECK(!dev_irq_pending());out(0x20,0x20);CHECK(dev_irq_pending());CHECK(dev_ack_irq()==0x2f);CHECK(!dev_irq_pending());out(0xa0,0x20);out(0x20,0x20);CHECK(!dev_irq_pending());
 /* Masking retains the latched peripheral edge and unmask restores cascade. */
 out(0xa1,0xff);dev_irq_raise(14);CHECK(!dev_irq_pending());out(0xa1,0xbf);CHECK(dev_irq_pending());CHECK(dev_ack_irq()==0x2e);out(0xa0,0x20);out(0x20,0x20);
 /* Coalesced same-line edge and fixed slave priority. */
 out(0xa1,0x3f);dev_irq_raise(15);dev_irq_raise(14);dev_irq_raise(14);CHECK(dev_ack_irq()==0x2e);out(0xa0,0x20);out(0x20,0x20);CHECK(dev_ack_irq()==0x2f);out(0xa0,0x20);out(0x20,0x20);CHECK(!dev_irq_pending());
 /* A real higher-priority master edge outranks IRQ14. */
 out(0x21,0xfa);dev_irq_raise(14);dev_irq_raise(0);CHECK(dev_ack_irq()==0x20);CHECK(!dev_irq_pending());out(0x20,0x20);CHECK(dev_ack_irq()==0x2e);out(0xa0,0x20);out(0x20,0x20);
 init(2);dev_irq_raise(14);CHECK(dev_ack_irq()==0x2e);out(0x20,0x0b);out(0xa0,0x0b);CHECK(in(0x20)==0 && in(0xa0)==0);dev_irq_raise(15);CHECK(dev_ack_irq()==0x2f && !dev_irq_pending());
 dev_irq_raise(16);CHECK(!dev_irq_pending());
 printf("PASS %u actualPIC cascade/EOI/mask/priority checks\n",checks);return 0;
}
