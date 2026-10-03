/* SPDX-License-Identifier: GPL-2.0-only
 * Host control for the actual devices.c inner KBC + native_input.c outer i8042
 * provider. The outer controller below is a test model of QEMU's PS/2 wire
 * behaviour (commands -> ACK/BAT/ID bytes, status OBF/AUX/parity/timeout);
 * no production logic is duplicated. Modeled time, no VM, no QMP. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#define SHZ_CPU_H
static uint64_t now;
static uint64_t rdtsc(void){return now;}
static uint8_t inb(uint16_t p){(void)p;return 0;}
static void outb(uint16_t p,uint8_t v){(void)p;(void)v;}
#include "../../src/devices.c"
#include "../native_input.c"
static unsigned checks;
#define CHECK(v) do{++checks;if(!(v)){fprintf(stderr,"FAIL line%d: %s\n",__LINE__,#v);exit(2);}}while(0)
#define HZ 1193182000ull
static void out(unsigned p,unsigned v){CHECK(dev_pio_out((uint16_t)p,1,v));}
static unsigned in(unsigned p){uint32_t v=0;CHECK(dev_pio_in((uint16_t)p,1,&v));return v;}
static void reply(unsigned v){CHECK((in(0x64)&1)==1);CHECK(in(0x60)==v);}

/* ---- outer i8042 model ---- */
static struct {
    uint8_t q[512],aux[512],extra[512];unsigned head,count;
    uint8_t config,pending,kbd_pending,set,mouse_stream,mute,kscan,nodisable;
    unsigned reads,writes;uint8_t log[512];unsigned nlog;
} fake;
static void fq(uint8_t b,int aux,uint8_t extra)
{unsigned s=(fake.head+fake.count)%512;fake.q[s]=b;fake.aux[s]=(uint8_t)aux;fake.extra[s]=extra;CHECK(++fake.count<512);}
static uint8_t fake_in(void *o,uint16_t port)
{
    (void)o;++fake.reads;now+=1000;
    if(port==0x64)return (uint8_t)(0x14|(fake.count?1:0)|(fake.count && fake.aux[fake.head]?0x20:0)|(fake.count?fake.extra[fake.head]:0));
    if(!fake.count)return 0;
    uint8_t b=fake.q[fake.head];fake.head=(fake.head+1)%512;--fake.count;return b;
}
static void fake_kbd(uint8_t v)
{
    if(fake.kbd_pending){fake.kbd_pending=0;if(!v){fq(0xfa,0,0);fq(fake.config&0x40?(fake.set==2?0x41:fake.set==1?0x43:0x3f):fake.set,0,0);}else{fake.set=v;fq(0xfa,0,0);}return;}
    if(v==0xf0)fake.kbd_pending=1;else if(v==0xf5)fake.kscan=0;else if(v==0xf4)fake.kscan=1;
    fq(0xfa,0,0);
}
static void fake_mouse(uint8_t v)
{
    fq(0xfa,1,0);
    if(v==0xff){fq(0xaa,1,0);fq(0,1,0);fake.mouse_stream=0;}
    else if(v==0xf2)fq(0,1,0);
    else if(v==0xf4)fake.mouse_stream=1;
}
static void fake_out(void *o,uint16_t port,uint8_t v)
{
    (void)o;++fake.writes;if(fake.nlog<512)fake.log[fake.nlog++]=v;
    if(fake.mute)return;
    if(port==0x64){fake.pending=0;
        switch(v){case 0x20:fq(fake.config,0,0);break;case 0x60:case 0xd4:fake.pending=v;break;
        case 0xad:if(!fake.nodisable)fake.config|=0x10;break;case 0xae:fake.config&=(uint8_t)~0x10;break;
        case 0xa7:fake.config|=0x20;break;case 0xa8:fake.config&=(uint8_t)~0x20;break;default:break;}
        return;}
    if(fake.pending==0x60)fake.config=v;else if(fake.pending==0xd4)fake_mouse(v);else fake_kbd(v);
    fake.pending=0;
}
static uint64_t fake_now(void *o){(void)o;return now;}
static const w98_i8042_io_t io={0,fake_in,fake_out,fake_now};
static int logged(const uint8_t *seq,unsigned n)
{for(unsigned i=0;i+n<=fake.nlog;++i)if(!memcmp(fake.log+i,seq,n))return 1;return 0;}

/* ---- live owner model: actual native_input.c binding check ---- */
static w98_i8042_t port;
static int domain_object,runnable=1;
static w98_input_binding_t expected,live;
static int validate(void *c)
{return c==&port && port.ready && !w98_input_binding_current(&expected,&live,runnable)?SHZ_DRIVER_OK:SHZ_REVOKED;}
static int poll(void *c){if(validate(c))return SHZ_REVOKED;return w98_i8042_poll(&port)<0?SHZ_IO:SHZ_DRIVER_OK;}
static const struct dev_native_keyboard_ops kops={&port,validate,poll};
static const struct dev_native_pointer_ops mops={&port,validate,validate};

static void start(void)
{
    now=1000000000;dev_init(HZ,128ull<<20);dev_native_win98_enable();
    out(0x20,0x11);out(0xa0,0x11);out(0x21,0x20);out(0xa1,0x28);out(0x21,4);out(0xa1,2);out(0x21,1);out(0xa1,1);
    out(0x21,0xf9);out(0xa1,0xef); /* IRQ1, cascade, IRQ12 */
}
static void eoi(int slave){if(slave)out(0xa0,0x20);out(0x20,0x20);}
static void key(const uint8_t *b,unsigned n){for(unsigned i=0;i<n;++i)fq(b[i],0,0);}
static void expect_keys(const uint8_t *b,unsigned n)
{
    dev_poll(now);
    for(unsigned i=0;i<n;++i){CHECK(dev_irq_pending());CHECK(dev_ack_irq()==0x21);CHECK((in(0x64)&0x21)==1);CHECK(in(0x60)==b[i]);eoi(0);}
    dev_poll(now);CHECK(!(in(0x64)&1));CHECK(!dev_irq_pending());
}
static void stale_setup(void)
{
    start();memset(&fake,0,sizeof fake);fake.set=2;
    CHECK(!w98_i8042_init(&port,&io,&port,HZ,3));
    domain_object=1;expected=(w98_input_binding_t){&domain_object,0x123000,1,0};live=expected;runnable=1;
    memset(&keyboard_ops,0,sizeof keyboard_ops);memset(&pointer_ops,0,sizeof pointer_ops);
    CHECK(dev_native_keyboard_attach(&kops)==SHZ_DRIVER_OK && dev_native_pointer_attach(&mops)==SHZ_DRIVER_OK);
}
static void policy(uint8_t b[96],uint32_t w[40])
{
    memset(b,0,96);memset(w,0,160);
    b[0]='W';b[1]='9';b[2]='I';b[3]='N';b[4]=1;b[6]=96;b[8]=3;b[12]=1;
    for(unsigned i=0;i<32;++i){b[16+i]=(uint8_t)(0xa0+i);b[48+i]=(uint8_t)(0x30+i);}
    for(unsigned i=0;i<8;++i){w[16+i]=le32(b+16+i*4);w[24+i]=le32(b+48+i*4);}
}
int main(void)
{
    uint8_t b[96];uint32_t w[40];w98_input_policy_t admitted;
    /* Policy: exact versioned/known flags, bound to the gate nonce + VGA config hash. */
    policy(b,w);CHECK(!w98_input_policy_admit(b,96,w,&admitted) && admitted.flags==3 && !memcmp(&admitted,b,96));
    CHECK(w98_input_policy_admit(b,95,w,&admitted) && w98_input_policy_admit(b,97,w,&admitted) && w98_input_policy_admit(0,96,w,&admitted));
    static const unsigned bad[][2]={{0,'X'},{4,2},{6,95},{8,0},{8,7},{11,0x80},{12,2},{16,0},{47,0},{48,0},{79,0},{80,1},{95,1}};
    for(unsigned i=0;i<sizeof bad/sizeof bad[0];++i){policy(b,w);b[bad[i][0]]=(uint8_t)bad[i][1];CHECK(w98_input_policy_admit(b,96,w,&admitted));}
    policy(b,w);memset(b+16,0,32);for(unsigned i=0;i<8;++i)w[16+i]=0;CHECK(w98_input_policy_admit(b,96,w,&admitted));
    policy(b,w);w[31]^=1;CHECK(w98_input_policy_admit(b,96,w,&admitted));

    /* Opt-in absent: no outer access, no keyboard source, inner KBC unchanged. */
    start();memset(&fake,0,sizeof fake);fq(0x1c,0,0);
    for(unsigned n=0;n<10;++n){now+=HZ/10;dev_poll(now);}
    CHECK(!fake.reads && !fake.writes && !(in(0x64)&1) && !dev_irq_pending());
    out(0x60,0xff);reply(0xfa);reply(0xaa);CHECK(!(in(0x64)&1));
    CHECK(dev_native_keyboard_input(&port,(const uint8_t *)"\x1c",1)==SHZ_BUSY);
    CHECK(dev_native_observation()->key_delivered==0 && dev_native_observation()->key_dropped==0);

    /* Bounded init timeout on a silent controller. */
    memset(&fake,0,sizeof fake);fake.mute=1;uint64_t t0=now;
    CHECK(w98_i8042_init(&port,&io,&port,HZ,3)==-1 && port.last_error==4 && !port.ready);
    CHECK(now-t0<HZ/2);CHECK(w98_i8042_init(&port,&io,&port,HZ,4)==-1 && port.last_error==1);

    /* Known outer state: stale bytes flushed, IRQs+translation off, set 2, F4, mouse reset/ID0/F4. */
    start();memset(&fake,0,sizeof fake);fake.config=0x47;fake.set=2;fq(0x1c,0,0);fq(0xfa,1,0);
    CHECK(!w98_i8042_init(&port,&io,&port,HZ,3) && port.ready);
    CHECK(fake.config==0x04 && port.outer_config==0x04 && fake.set==2 && fake.mouse_stream && !fake.count);
    CHECK(logged((const uint8_t *)"\xf0\x02",2) && logged((const uint8_t *)"\xf4",1) && logged((const uint8_t *)"\xd4\xff",2) && logged((const uint8_t *)"\xd4\xf4",2));
    CHECK(port.responses==2);
    domain_object=1;expected=(w98_input_binding_t){&domain_object,0x123000,1,0};live=expected;runnable=1;
    CHECK(dev_native_keyboard_attach(&kops)==SHZ_DRIVER_OK && dev_native_pointer_attach(&mops)==SHZ_DRIVER_OK);
    CHECK(dev_native_keyboard_attach(&kops)==SHZ_BUSY);
    dev_poll(now);CHECK(!(in(0x64)&1) && !dev_irq_pending()); /* outer ACKs never reach the inner FIFO */

    /* Win98 default: set 2 + inner translation -> set 1 bytes, IRQ1 per byte. */
    key((const uint8_t *)"\x1c\xf0\x1c",3);expect_keys((const uint8_t *)"\x1e\x9e",2);
    key((const uint8_t *)"\xe0\x75\xe0\xf0\x75",5);expect_keys((const uint8_t *)"\xe0\x48\xe0\xc8",4);
    key((const uint8_t *)"\xe1\x14\x77\xe1\xf0\x14\xf0\x77",8);expect_keys((const uint8_t *)"\xe1\x1d\x45\xe1\x9d\xc5",6);
    /* Guest disables translation: raw set 2. */
    out(0x64,0x60);out(0x60,0x05);key((const uint8_t *)"\x1c\xf0\x1c",3);expect_keys((const uint8_t *)"\x1c\xf0\x1c",3);
    /* Guest set 1 without translation. */
    out(0x60,0xf0);reply(0xfa);out(0x60,1);reply(0xfa);key((const uint8_t *)"\x5a\xf0\x5a",3);expect_keys((const uint8_t *)"\x1c\x9c",2);
    /* Set 3 is refused, never approximated. */
    const uint32_t dropped0=dev_native_observation()->key_dropped;
    out(0x60,0xf0);reply(0xfa);out(0x60,3);reply(0xfa);key((const uint8_t *)"\x1c",1);dev_poll(now);
    CHECK(!(in(0x64)&1) && dev_native_observation()->key_dropped==dropped0+1);
    out(0x60,0xf0);reply(0xfa);out(0x60,2);reply(0xfa);out(0x64,0x60);out(0x60,0x45);
    /* Outer responses, parity/timeout and malformed sequences are not forwarded. */
    const uint32_t responses0=port.responses,malformed0=port.malformed;
    key((const uint8_t *)"\xfa\xaa\xfe",3);fq(0x1c,0,0x80);fq(0x1c,0,0x40);
    key((const uint8_t *)"\xe0\xe0\xf0\xe0\x90\xe1\x15\xe0\x00",9);dev_poll(now);
    CHECK(!(in(0x64)&1) && port.responses==responses0+3 && port.parity_timeout==2 && port.malformed==malformed0+5);
    key((const uint8_t *)"\x1c",1);expect_keys((const uint8_t *)"\x1e",1); /* resynchronized */

    /* Bounded poll and finite queues: 40 events without guest reads. */
    const uint32_t events0=port.key_events,drop0=port.dropped;
    for(unsigned n=0;n<20;++n)key((const uint8_t *)"\x1c\xf0\x1c",3);
    dev_poll(now);CHECK(fake.count==60-W98_I8042_POLL_BYTES);
    dev_poll(now);CHECK(!fake.count);
    const uint32_t accepted=port.key_events-events0;
    CHECK(accepted==12+16 && port.dropped-drop0==40-accepted);
    unsigned got=0; /* events 17..21 and 34..40 were dropped whole (bounded ring), never split */
    for(unsigned guard=0;guard<200 && (in(0x64)&1);++guard){const unsigned v=in(0x60);CHECK(v==(got<16?(got&1?0x9e:0x1e):(got&1?0x1e:0x9e)));++got;dev_poll(now);}
    CHECK(got==accepted);while(dev_irq_pending()){(void)dev_ack_irq();eoi(0);}

    /* Mouse: guest enables inner AUX stream; packet round-trips without double Y inversion. */
    out(0x64,0x60);out(0x60,0x47);out(0x64,0xa8);out(0x64,0xd4);out(0x60,0xf4);CHECK((in(0x64)&0x21)==0x21);CHECK(in(0x60)==0xfa);
    while(dev_irq_pending()){(void)dev_ack_irq();eoi(1);}
    fq(0x05,1,0);fq(0x48,1,0);fq(0x10,1,0);fq(0x10,1,0); /* misframed byte, then X-overflow packet */
    fq(0x29,1,0);fq(0x05,1,0);fq(0xfb,1,0);now+=HZ/100+1;dev_poll(now);
    CHECK(port.mouse_packets==1);CHECK(dev_irq_pending() && dev_ack_irq()==0x2c);
    CHECK((in(0x64)&0x21)==0x21 && in(0x60)==0x29 && in(0x60)==0x05 && in(0x60)==0xfb);eoi(1);

    /* Revocation: generation change detaches at the next guest port read; queued events die. */
    out(0x64,0xad);key((const uint8_t *)"\x1c",1);dev_poll(now);CHECK(key_ring_count==1 && !(in(0x64)&1));
    live.generation=2;CHECK(!(in(0x64)&1));CHECK(!keyboard_bound && !key_ring_count && !pointer_bound);
    out(0x64,0xae);key((const uint8_t *)"\x1c",1);const unsigned left=fake.count;dev_poll(now);
    CHECK(fake.count==left && !(in(0x64)&1));CHECK(dev_native_keyboard_input(&port,(const uint8_t *)"\x1c",1)==SHZ_BUSY);
    CHECK(dev_native_keyboard_detach(&port)==SHZ_DRIVER_OK && dev_native_pointer_detach(&port)==SHZ_DRIVER_OK);
    CHECK(dev_native_keyboard_attach(&kops)==SHZ_REVOKED);
    live=expected;live.vmcs^=0x1000;CHECK(dev_native_keyboard_attach(&kops)==SHZ_REVOKED);
    live=expected;live.owner_cpu=1;CHECK(dev_native_keyboard_attach(&kops)==SHZ_REVOKED);
    live=expected;runnable=0;CHECK(dev_native_keyboard_attach(&kops)==SHZ_REVOKED);
    runnable=1;w98_i8042_quiesce(&port);CHECK(!port.ready && dev_native_keyboard_attach(&kops)==SHZ_REVOKED);
    CHECK(fake.log[fake.nlog-3]==0xad && fake.log[fake.nlog-2]==0xa7 && fake.log[fake.nlog-1]==0x20 && port.quiesce_ok && (fake.config&0x30)==0x30);

    /* Domain re-enable drops every binding. */
    CHECK(!w98_i8042_init(&port,&io,&port,HZ,1));CHECK(dev_native_keyboard_attach(&kops)==SHZ_DRIVER_OK);
    dev_native_win98_enable();CHECK(dev_native_keyboard_input(&port,(const uint8_t *)"\x1c",1)==SHZ_BUSY);

    uint32_t s[8];w98_input_status_words(&port,W98_INPUT_STATE_REVOKED,1,5,s);
    CHECK(s[0]==W98_INPUT_STATUS_MAGIC && (s[1]&0xff)==3 && ((s[1]>>8)&0xff)==1 && (s[1]>>24)==1 && s[2]==1 && s[5]==port.dropped+5);

    /* ---- B11: stale queued inner bytes, reply preservation, mouse resync ---- */
    /* 1. Host-derived keyboard bytes queued in the inner FIFO die on revoke; an inner command
     * ACK queued behind them stays, with OBF/IRQ1 consistent for it alone. */
    stale_setup();key((const uint8_t *)"\x1c\xf0\x1c",3);dev_poll(now);
    CHECK(kbc_fifo_count==2 && dev_irq_pending());
    out(0x60,0xf4); /* inner keyboard command: ACK reply queued after the events */
    CHECK(kbc_fifo_count==3 && (kbc_fifo_aux[0]&FIFO_HOST) && !(kbc_fifo_aux[(kbc_fifo_head+2)%16]&FIFO_HOST));
    live.generation=2;
    CHECK((in(0x64)&0x21)==1 && kbc_fifo_count==1); /* purge at the owner check; ACK kept */
    CHECK(dev_irq_pending() && dev_ack_irq()==0x21 && in(0x60)==0xfa);eoi(0);
    CHECK(!(in(0x64)&1) && !dev_irq_pending() && !kbc_fifo_count);
    /* Next owner (generation 2) sees nothing of the previous owner's input. */
    CHECK(dev_native_keyboard_detach(&port)==SHZ_DRIVER_OK && dev_native_pointer_detach(&port)==SHZ_DRIVER_OK);
    expected.generation=2;CHECK(dev_native_keyboard_attach(&kops)==SHZ_DRIVER_OK);
    dev_poll(now);CHECK(!(in(0x64)&1) && !dev_irq_pending());

    /* 2. Only host bytes queued: revoke leaves OBF and the IRQ line deasserted. */
    stale_setup();key((const uint8_t *)"\x1c",1);dev_poll(now);CHECK((in(0x64)&1) && dev_irq_pending());
    live.vmcs^=0x1000;CHECK(!(in(0x64)&1) && !dev_irq_pending() && !kbc_fifo_count);
    /* Detach purges too (no revalidation needed). */
    stale_setup();key((const uint8_t *)"\x1c",1);dev_poll(now);CHECK(kbc_fifo_count==1);
    CHECK(dev_native_keyboard_detach(&port)==SHZ_DRIVER_OK);CHECK(!kbc_fifo_count && !dev_irq_pending());
    /* A fresh attach also drops host bytes left behind by an earlier owner. */
    stale_setup();key((const uint8_t *)"\x1c",1);dev_poll(now);
    keyboard_bound=0;CHECK(dev_native_keyboard_detach(&port)==SHZ_DRIVER_OK && !kbc_fifo_count);

    /* 3. Pointer packets (host-derived aux) purge on revoke; the keyboard ACK queued behind
     * them survives and IRQ12 is lowered, IRQ1 asserted for the ACK. */
    stale_setup();out(0x64,0x60);out(0x60,0x47);out(0x64,0xd4);out(0x60,0xf4);CHECK(in(0x60)==0xfa);
    while(dev_irq_pending()){(void)dev_ack_irq();eoi(1);}
    fq(0x09,1,0);fq(0x05,1,0);fq(0x00,1,0);now+=HZ/100+1;dev_poll(now);
    CHECK(kbc_fifo_count==3 && (kbc_fifo_aux[kbc_fifo_head]&FIFO_HOST));
    out(0x60,0xf4);CHECK(kbc_fifo_count==4);
    live.generation=2;CHECK((in(0x64)&0x21)==1 && kbc_fifo_count==1);
    CHECK(dev_irq_pending() && dev_ack_irq()==0x21 && in(0x60)==0xfa);eoi(0);CHECK(!dev_irq_pending());
    /* Inner pointer replies (non-host) are not misclassified as input by the keyboard purge. */
    stale_setup();out(0x64,0xd4);out(0x60,0xf2);CHECK(kbc_fifo_count==2 && !(kbc_fifo_aux[kbc_fifo_head]&FIFO_HOST));
    CHECK(dev_native_keyboard_detach(&port)==SHZ_DRIVER_OK && kbc_fifo_count==2 && (in(0x64)&0x21)==0x21);

    /* 4. Mouse reset mid-stream (AA 00 at a frame boundary): partial dropped, F4 re-issued, counted. */
    stale_setup();out(0x64,0x60);out(0x60,0x47);out(0x64,0xd4);out(0x60,0xf4);CHECK(in(0x60)==0xfa);
    while(dev_irq_pending()){(void)dev_ack_irq();eoi(1);}
    fake.mouse_stream=0;fake.nlog=0;fq(0xaa,1,0);fq(0x00,1,0);dev_poll(now);
    CHECK(port.resyncs==1 && fake.mouse_stream==1 && logged((const uint8_t *)"\xd4\xf4",2) && !port.aux_len && !port.bat_pending);
    CHECK(!fake.count && port.mouse_packets==0 && port.malformed==1 && !(in(0x64)&1));
    /* Same reset while two bytes of a packet are buffered: the partial packet is not delivered. */
    fake.mouse_stream=0;fake.nlog=0;fq(0x09,1,0);fq(0x05,1,0);fq(0xaa,1,0);fq(0x00,1,0);dev_poll(now);
    CHECK(port.resyncs==2 && fake.mouse_stream==1 && port.aux_len==0 && port.mouse_packets==0 && !(in(0x64)&1));
    /* AA as a legitimate dy byte, followed by a real packet start, is movement (not a reset). */
    fq(0x29,1,0);fq(0x05,1,0);fq(0xaa,1,0);fq(0x09,1,0);fq(0x01,1,0);fq(0x01,1,0);now+=HZ/100+1;dev_poll(now);
    CHECK(port.resyncs==2 && port.mouse_packets==2);
    /* ACK/NAK strays never frame as movement. */
    const uint32_t mp=port.mouse_packets,rs=port.responses;
    fq(0xfa,1,0);fq(0xfe,1,0);fq(0x09,1,0);fq(0x05,1,0);fq(0x01,1,0);dev_poll(now);
    CHECK(port.mouse_packets==mp+1 && port.responses==rs+2 && port.resyncs==2);
    /* Repeated bad framing resynchronizes through F4 and stays bounded. */
    fake.mouse_stream=0;fq(0x01,1,0);fq(0x02,1,0);fq(0x04,1,0);CHECK(port.resyncs==2);fq(0x01,1,0);dev_poll(now);
    CHECK(port.resyncs==3 && fake.mouse_stream==1 && !port.bad_run && !port.ack_wait);
    /* Resync with no ACK (dead mouse) disables the mouse stream and counts the failure. */
    fake.mute=1;fake.nlog=0;fq(0x01,1,0);fq(0x02,1,0);fq(0x04,1,0);fq(0x01,1,0);dev_poll(now);
    CHECK(port.ack_wait && port.tries==1 && port.resync_failed==0 && (port.flags&W98_INPUT_MOUSE));
    for(unsigned n=0;n<W98_I8042_RESYNC_TRIES+2 && port.resync_failed==0;++n){now+=HZ/10;dev_poll(now);}
    CHECK(port.resync_failed==1 && !port.ack_wait && !(port.flags&W98_INPUT_MOUSE) && port.resyncs==3 && port.tries==W98_I8042_RESYNC_TRIES);
    {unsigned f4=0;for(unsigned i=0;i+1<fake.nlog;++i)if(fake.log[i]==0xd4 && fake.log[i+1]==0xf4)++f4;CHECK(f4==W98_I8042_RESYNC_TRIES);}
    const unsigned wr=fake.writes;now+=HZ/10;dev_poll(now);CHECK(fake.writes==wr); /* stream disabled: no further outer writes, no hang */
    fake.mute=0;
    /* Parity/timeout never starts a packet or a reset; a held AA is forgotten. */
    stale_setup();fq(0xaa,1,0x40);fq(0x00,1,0);dev_poll(now);CHECK(port.resyncs==0 && port.parity_timeout==1);
    fq(0xaa,1,0);fq(0x00,1,0x80);dev_poll(now);CHECK(port.resyncs==0 && port.parity_timeout==2);
    /* Keyboard-side ACK/parity/timeout bytes never become guest keys (checked above); an aux ACK
     * never reaches the keyboard path either. */
    fq(0xfa,1,0);dev_poll(now);CHECK(!(in(0x64)&1) && !dev_irq_pending());

    /* ---- B12 ---- */
    /* 1. Exactly one buffered byte then AA 00: fail-safe, partial dropped + counted, F4 re-issued. */
    stale_setup();out(0x64,0x60);out(0x60,0x47);out(0x64,0xd4);out(0x60,0xf4);CHECK(in(0x60)==0xfa);
    while(dev_irq_pending()){(void)dev_ack_irq();eoi(1);}
    fake.mouse_stream=0;fq(0x09,1,0);fq(0xaa,1,0);fq(0x00,1,0);dev_poll(now);
    CHECK(port.mouse_packets==0 && port.resyncs==1 && port.malformed==1 && fake.mouse_stream==1 && !port.aux_len && !(in(0x64)&1));
    CHECK(port.dropped==0 && port.responses>=1);
    /* A legal dx=-86 with dy!=0 is still movement (AA then non-zero commits it as data). */
    fq(0x09,1,0);fq(0xaa,1,0);fq(0x05,1,0);dev_poll(now);CHECK(port.mouse_packets==1 && port.resyncs==1);
    /* AA that is the last byte of a burst and whose 00 arrives within the hold window: still a reset. */
    fake.mouse_stream=0;fq(0x09,1,0);fq(0xaa,1,0);dev_poll(now);CHECK(port.bat_pending && port.aux_len==1 && port.mouse_packets==1);
    fq(0x00,1,0);dev_poll(now);CHECK(!port.bat_pending && port.resyncs==2 && fake.mouse_stream==1 && port.mouse_packets==1);
    /* No second byte within the window: AA is committed as data (bounded hold, no stall). */
    fq(0x09,1,0);fq(0xaa,1,0);dev_poll(now);CHECK(port.bat_pending);
    now+=HZ/1000*(W98_I8042_BAT_HOLD_MS+1);dev_poll(now);CHECK(!port.bat_pending && port.aux_len==2);
    fq(0x05,1,0);dev_poll(now);CHECK(port.mouse_packets==2 && port.resyncs==2);
    /* AA held at byte 2 expires into a delivered packet. */
    fq(0x09,1,0);fq(0x01,1,0);fq(0xaa,1,0);dev_poll(now);CHECK(port.bat_pending && port.mouse_packets==2);
    now+=HZ/1000*(W98_I8042_BAT_HOLD_MS+1);dev_poll(now);CHECK(!port.bat_pending && port.mouse_packets==3);
    /* Bytes arriving between a reset and its F4 ACK are dropped, never movement. */
    fake.mute=1;fq(0x09,1,0);fq(0xaa,1,0);fq(0x00,1,0);dev_poll(now);CHECK(port.ack_wait && port.resyncs==2);
    fake.mute=0;fq(0x09,1,0);fq(0x01,1,0);fq(0x01,1,0);fq(0xfa,1,0);dev_poll(now);
    CHECK(!port.ack_wait && port.resyncs==3 && port.mouse_packets==3 && port.dropped>=3);
    /* 2. Watchdog: lost F4 ACK after a reset is retried, then the stream is disabled (counted). */
    stale_setup();fake.mute=1;fq(0xaa,1,0);fq(0x00,1,0);dev_poll(now);
    CHECK(port.ack_wait && port.tries==1);fake.mute=0;now+=HZ/10;dev_poll(now);
    CHECK(port.ack_wait && port.tries==2); /* retry written, ACK queued by the model */
    dev_poll(now);CHECK(!port.ack_wait && port.resyncs==1 && port.resync_failed==0);
    /* 3. Keyboard hot reset: filtered, reinitialised (set 2, scanning on), never forwarded. */
    stale_setup();fake.set=3;fake.kscan=0;fake.nlog=0;const uint32_t ev=port.key_events;
    fq(0xaa,0,0);dev_poll(now);
    CHECK(port.kbd_resets==1 && port.kbd_reinit_failed==0 && fake.set==2 && fake.kscan==1 && !fake.count && (port.flags&W98_INPUT_KEYBOARD));
    CHECK(logged((const uint8_t *)"\xf5",1) && logged((const uint8_t *)"\xf0\x02",2) && logged((const uint8_t *)"\xf4",1));
    CHECK(!(in(0x64)&1) && !dev_irq_pending() && port.key_events==ev);
    /* Keys after the reset work; AA mid-sequence drops the partial and reinitialises; FA/BAT never keys. */
    key((const uint8_t *)"\x1c\xf0\x1c",3);expect_keys((const uint8_t *)"\x1e\x9e",2);
    fake.set=1;fq(0xe0,0,0);fq(0xaa,0,0);fq(0xfa,0,0);dev_poll(now);
    CHECK(port.kbd_resets==2 && fake.set==2 && !port.key_len && !(in(0x64)&1) && !dev_irq_pending());
    /* Keys read in the same burst after the BAT are real post-reset keys: delivered, reinit still runs. */
    fake.set=3;fq(0xaa,0,0);fq(0x1c,0,0);fq(0xf0,0,0);fq(0x1c,0,0);expect_keys((const uint8_t *)"\x1e\x9e",2);
    CHECK(port.kbd_resets==3 && !port.kbd_reinit_failed && fake.set==2);
    /* Dead keyboard: bounded failure disables the keyboard source, counted. */
    fake.mute=1;uint64_t tk=now;fq(0xaa,0,0);dev_poll(now);
    CHECK(port.kbd_reinit_failed==1 && !(port.flags&W98_INPUT_KEYBOARD) && now-tk<HZ);
    fake.mute=0;fq(0x1c,0,0);dev_poll(now);CHECK(!(in(0x64)&1));
    /* 4. Detach/quiesce: ports end disabled, outer buffer drained, config read back; original saved, not restored. */
    stale_setup();fq(0x1c,0,0);fq(0xfa,1,0);CHECK(port.orig_valid);
    w98_i8042_quiesce(&port);CHECK(port.quiesce_ok && !fake.count && (fake.config&0x30)==0x30 && !port.ready && w98_i8042_poll(&port)==-1);
    stale_setup();fake.nodisable=1;w98_i8042_quiesce(&port);CHECK(!port.quiesce_ok); /* read-back must see the disable bits */
    stale_setup();fake.mute=1;uint64_t tq=now;w98_i8042_quiesce(&port);CHECK(!port.quiesce_ok && now-tq<HZ);

    printf("PASS %u actual devices.c+native_input.c outer-i8042/inner-KBC checks (modeled time and outer controller, no VM)\n",checks);
    return 0;
}
