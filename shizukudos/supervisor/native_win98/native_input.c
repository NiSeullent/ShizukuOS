/* SPDX-License-Identifier: GPL-2.0-only */
#include "native_input.h"
#include "../src/devices.h"
static uint32_t le32(const uint8_t *p){return p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint16_t sat16(uint32_t v){return v>0xffffu?0xffffu:(uint16_t)v;}
static void bump(uint32_t *v){if(*v!=UINT32_MAX)++*v;}

int w98_input_policy_admit(const void *blob,uint64_t bytes,const uint32_t w[40],w98_input_policy_t *out)
{
    uint8_t copy[W98_INPUT_POLICY_BYTES];const uint8_t *src=blob;unsigned acc=0,nonce=0;
    if(!src || !w || !out || bytes!=W98_INPUT_POLICY_BYTES)return -1;
    for(unsigned i=0;i<sizeof copy;++i)copy[i]=src[i]; /* one read; checks see the copy only */
    if(le32(copy)!=W98_INPUT_POLICY_MAGIC || (copy[4]|copy[5]<<8)!=W98_INPUT_POLICY_VERSION ||
       (copy[6]|copy[7]<<8)!=W98_INPUT_POLICY_BYTES || !le32(copy+8) || (le32(copy+8)&~W98_INPUT_KNOWN_FLAGS) ||
       le32(copy+12)!=W98_INPUT_MACHINE_Q35_I8042)return -1;
    for(unsigned i=80;i<96;++i)acc|=copy[i];
    for(unsigned i=0;i<8;++i){acc|=le32(copy+16+i*4)^w[16+i];acc|=le32(copy+48+i*4)^w[24+i];nonce|=w[16+i];}
    if(acc || !nonce)return -1;
    uint8_t *o=(uint8_t *)out;for(unsigned i=0;i<sizeof copy;++i)o[i]=copy[i];
    return 0;
}
int w98_input_binding_current(const w98_input_binding_t *e,const w98_input_binding_t *l,int live_runnable)
{
    return e && l && live_runnable && e->domain && e->domain==l->domain && e->generation &&
        e->generation==l->generation && e->vmcs && e->vmcs==l->vmcs && e->owner_cpu==l->owner_cpu?0:-1;
}

/* ---------------------------------------------------------------- outer i8042 */
static uint8_t status(w98_i8042_t *p){return p->io.in(p->io.opaque,W98_I8042_STATUS);}
static int expired(w98_i8042_t *p,uint64_t start,uint32_t ms)
{uint64_t n=p->io.now(p->io.opaque);return n<start || n-start>=p->hz/1000*ms;}
static int wait_writable(w98_i8042_t *p)
{
    const uint64_t start=p->io.now(p->io.opaque);
    for(uint32_t spin=0;spin<W98_I8042_SPIN_MAX;++spin){if(!(status(p)&2))return 0;if(expired(p,start,W98_I8042_STEP_MS))break;}
    return -1;
}
static int command(w98_i8042_t *p,uint8_t v)
{if(wait_writable(p))return -1;p->io.out(p->io.opaque,W98_I8042_STATUS,v);return 0;}
static int data(w98_i8042_t *p,uint8_t v)
{if(wait_writable(p))return -1;p->io.out(p->io.opaque,W98_I8042_DATA,v);return 0;}
/* Wait for one byte from the selected source; the other source's bytes are
 * discarded (counted). Parity/timeout status is a failure, never data. */
static int receive(w98_i8042_t *p,int aux,uint8_t *v,uint32_t ms)
{
    const uint64_t start=p->io.now(p->io.opaque);
    for(uint32_t spin=0;spin<W98_I8042_SPIN_MAX;++spin){
        const uint8_t st=status(p);
        if(st&1){const uint8_t b=p->io.in(p->io.opaque,W98_I8042_DATA);
            if(st&0xc0){bump(&p->parity_timeout);return -1;}
            if(!!(st&0x20)==!!aux){*v=b;return 0;}
            bump(&p->responses);continue;}
        if(expired(p,start,ms))break;
    }
    return -1;
}
static int device(w98_i8042_t *p,int aux,uint8_t v)
{
    uint8_t r;
    if((aux && command(p,0xd4)) || data(p,v) || receive(p,aux,&r,W98_I8042_STEP_MS) || r!=0xfa)return -1;
    return 0;
}
static int config(w98_i8042_t *p,uint8_t v)
{
    uint8_t r;
    if(command(p,0x60) || data(p,v) || command(p,0x20) || receive(p,0,&r,W98_I8042_STEP_MS) || r!=v)return -1;
    return 0;
}
static int fail(w98_i8042_t *p,uint32_t code){p->last_error=code;w98_i8042_quiesce(p);return -1;}
int w98_i8042_init(w98_i8042_t *p,const w98_i8042_io_t *io,void *owner,uint64_t hz,uint32_t flags)
{
    uint8_t cfg,v;
    if(!p)return -1;
    uint8_t *z=(uint8_t *)p;for(unsigned i=0;i<sizeof *p;++i)z[i]=0;
    if(!io || !io->in || !io->out || !io->now || !owner || hz<1000000 || hz>1000000000000ull ||
       !flags || (flags&~W98_INPUT_KNOWN_FLAGS)){p->last_error=1;return -1;}
    p->io=*io;p->owner=owner;p->hz=hz;p->flags=flags;
    if(command(p,0xad) || command(p,0xa7))return fail(p,2);
    unsigned n=0;
    while(n<W98_I8042_FLUSH_BYTES && (status(p)&1)){(void)p->io.in(p->io.opaque,W98_I8042_DATA);bump(&p->responses);++n;}
    if(status(p)&1)return fail(p,3);
    if(command(p,0x20) || receive(p,0,&cfg,W98_I8042_STEP_MS))return fail(p,4);
    p->orig_config=cfg;p->orig_valid=1;
    const uint8_t system=cfg&0x04;
    /* Both clocks inhibited, outer IRQ1/IRQ12 off, translation off (raw set 2). */
    if(config(p,(uint8_t)(system|0x30)))return fail(p,5);
    if(flags&W98_INPUT_KEYBOARD){
        if(command(p,0xae) || device(p,0,0xf5) || device(p,0,0xf0) || device(p,0,0x02) ||
           device(p,0,0xf0) || device(p,0,0x00) || receive(p,0,&v,W98_I8042_STEP_MS) || v!=2 ||
           device(p,0,0xf4))return fail(p,6);
    }
    if(flags&W98_INPUT_MOUSE){
        /* Reset clears any wheel/ID negotiation: standard ID0 3-byte packets at
         * 4 counts/mm, 100 Hz, then F4 stream enable. */
        if(command(p,0xa8) || device(p,1,0xff) || receive(p,1,&v,W98_I8042_RESET_MS) || v!=0xaa ||
           receive(p,1,&v,W98_I8042_STEP_MS) || v || device(p,1,0xf2) ||
           receive(p,1,&v,W98_I8042_STEP_MS) || v || device(p,1,0xf4))return fail(p,7);
    }
    const uint8_t final=(uint8_t)(system|(flags&W98_INPUT_KEYBOARD?0:0x10)|(flags&W98_INPUT_MOUSE?0:0x20));
    if(config(p,final))return fail(p,8);
    p->outer_config=final;p->ready=1;return 0;
}
void w98_i8042_quiesce(w98_i8042_t *p)
{
    if(!p)return;
    p->ready=0;p->key_len=p->aux_len=0;
    if(!p->io.in || !p->io.out || !p->io.now || !p->hz)return;
    (void)command(p,0xad);(void)command(p,0xa7);
    for(unsigned n=0;n<W98_I8042_FLUSH_BYTES && (status(p)&1);++n)(void)p->io.in(p->io.opaque,W98_I8042_DATA);
    uint8_t cfg;
    p->quiesce_ok=!command(p,0x20) && !receive(p,0,&cfg,W98_I8042_STEP_MS) && (cfg&0x30)==0x30;
}
static int set2_response(uint8_t b)
{return b==0x00 || b==0xff || b==0xfa || b==0xfe || b==0xee || b==0xaa || b==0xfc || b==0xfd;}
static void key_byte(w98_i8042_t *p,uint8_t b)
{
    static const uint8_t pause_make[8]={0xe1,0x14,0x77,0xe1,0xf0,0x14,0xf0,0x77};
    if(b==0xaa){ /* keyboard BAT: hot reset */
        if(p->key_len){bump(&p->malformed);p->key_len=0;}
        bump(&p->responses);p->kbd_reinit=1;return;
    }
    if(!p->key_len && set2_response(b)){bump(&p->responses);return;}
    if(p->key_len && p->key[0]==0xe1) {
        if(p->key_len>=8 || b!=pause_make[p->key_len]){bump(&p->malformed);p->key_len=0;return;}
        p->key[p->key_len++]=b;if(p->key_len<8)return;
    } else if(b==0xe1 || b==0xe0) {
        if(p->key_len){bump(&p->malformed);p->key_len=0;return;}
        p->key[p->key_len++]=b;return;
    } else if(b==0xf0) {
        if(p->key_len>1 || (p->key_len==1 && p->key[0]!=0xe0)){bump(&p->malformed);p->key_len=0;return;}
        p->key[p->key_len++]=b;return;
    } else {
        if(!b || b>0x84){bump(&p->malformed);p->key_len=0;return;}
        p->key[p->key_len++]=b;
    }
    const int r=dev_native_keyboard_input(p->owner,p->key,p->key_len);
    if(r==SHZ_DRIVER_OK)bump(&p->key_events);else bump(&p->dropped);
    p->key_len=0;
}
/* Re-establish the known stream state (F4) and packet framing. Non-blocking watchdog: F4 is sent
 * and the ACK is awaited by the poll loop (stray movement bytes meanwhile are dropped, counted);
 * w98_i8042_poll re-sends F4 after STEP_MS of silence up to W98_I8042_RESYNC_TRIES times and then
 * disables the mouse stream (resync_failed). Nothing here loops without a bound. */
static void aux_f4(w98_i8042_t *p)
{
    while(p->tries<W98_I8042_RESYNC_TRIES){
        ++p->tries;
        if(!command(p,0xd4) && !data(p,0xf4)){p->ack_wait=1;p->ack_start=p->io.now(p->io.opaque);return;}
    }
    p->ack_wait=0;bump(&p->resync_failed);p->flags&=~W98_INPUT_MOUSE;
}
static void aux_resync(w98_i8042_t *p)
{
    p->aux_len=0;p->bat_pending=0;p->bad_run=0;p->tries=0;aux_f4(p);
}
static void aux_deliver(w98_i8042_t *p)
{
    p->aux_len=0;p->bad_run=0;
    if(p->aux[0]&0xc0){bump(&p->dropped);return;} /* overflow packets are discarded */
    const int32_t dx=(int32_t)p->aux[1]-(p->aux[0]&0x10?256:0),dy=(int32_t)p->aux[2]-(p->aux[0]&0x20?256:0);
    /* PS/2 Y is positive-up; the inner pointer API takes HID positive-down and converts once. */
    if(dev_native_pointer_input(p->owner,dx,-dy,(uint8_t)(p->aux[0]&7))==SHZ_DRIVER_OK)bump(&p->mouse_packets);
    else bump(&p->dropped);
}
/* A reset's BAT byte 0xAA is held at packet byte 0, 1 or 2: AA 00 drops the partial packet and
 * re-issues F4 (fail-safe). At byte 1 AA 00 is also the legal movement dx=-86,dy=0; it is dropped
 * (counted) rather than risk a spurious packet after a reset. The held AA becomes data only when a
 * different byte follows, or after W98_I8042_BAT_HOLD_MS without a second byte (residual: a reset
 * whose 00 arrives later than that window is read as dx=-86 plus stray data, then resynchronised by
 * the bad-framing rule). */
static void aux_commit_held(w98_i8042_t *p)
{
    p->bat_pending=0;
    if(p->aux_len==2){p->aux[2]=0xaa;aux_deliver(p);}else p->aux[p->aux_len++]=0xaa;
}
static void aux_byte(w98_i8042_t *p,uint8_t b)
{
    if(p->ack_wait){ /* waiting for the F4 ACK: everything else belongs to the broken stream */
        if(b==0xfa){p->ack_wait=0;bump(&p->resyncs);}else bump(&p->dropped);
        return;
    }
    if(p->bat_pending){
        if(!b){p->bat_pending=0;bump(&p->responses);bump(&p->malformed);aux_resync(p);return;}
        aux_commit_held(p);
    }
    if(!p->aux_len){
        if(b==0xfa || b==0xfe){bump(&p->responses);return;} /* ACK/NAK/resend never framed as movement */
        if(b==0xaa){p->bat_pending=1;p->hold_start=p->io.now(p->io.opaque);return;}
        if(!(b&8)){bump(&p->malformed);if(++p->bad_run>=W98_I8042_BAD_RUN)aux_resync(p);return;} /* resynchronize on bit3 */
    } else if(b==0xaa){p->bat_pending=1;p->hold_start=p->io.now(p->io.opaque);return;}
    p->aux[p->aux_len++]=b;if(p->aux_len<3)return;
    aux_deliver(p);
}
/* Keyboard hot reset (BAT 0xAA at a frame boundary or mid-sequence; 0xAA is no set-2 code): the
 * partial sequence is dropped and the keyboard is brought back to the setup state: F5, set 2,
 * read-back 2, F4. Stale scan bytes ahead of each ACK are dropped (counted); every wait is bounded.
 * Failure disables the keyboard source (counted). ACK/BAT/ID bytes are consumed here, never keys. */
static int kbd_cmd(w98_i8042_t *p,uint8_t v)
{
    uint8_t r;
    if(data(p,v))return -1;
    for(unsigned i=0;i<W98_I8042_RESYNC_SKIP;++i){
        if(receive(p,0,&r,W98_I8042_STEP_MS))return -1;
        if(r==0xfa)return 0;
        bump(&p->dropped);
    }
    return -1;
}
static void kbd_reinit(w98_i8042_t *p)
{
    uint8_t v;
    p->kbd_reinit=0;p->key_len=0;bump(&p->kbd_resets);
    if(kbd_cmd(p,0xf5)||kbd_cmd(p,0xf0)||kbd_cmd(p,0x02)||kbd_cmd(p,0xf0)||kbd_cmd(p,0x00)||
       receive(p,0,&v,W98_I8042_STEP_MS)||v!=2||kbd_cmd(p,0xf4)){
        bump(&p->kbd_reinit_failed);p->flags&=~W98_INPUT_KEYBOARD;
    }
}
int w98_i8042_poll(w98_i8042_t *p)
{
    unsigned n=0;
    if(!p || !p->ready)return -1;
    for(;n<W98_I8042_POLL_BYTES;++n){
        const uint8_t st=status(p);
        if(!(st&1))break;
        const uint8_t b=p->io.in(p->io.opaque,W98_I8042_DATA);
        if(st&0xc0){bump(&p->parity_timeout);if(st&0x20){p->aux_len=0;p->bat_pending=0;}else p->key_len=0;continue;}
        if(st&0x20){if(p->flags&W98_INPUT_MOUSE)aux_byte(p,b);else bump(&p->responses);}
        else if(p->flags&W98_INPUT_KEYBOARD)key_byte(p,b);
        else bump(&p->responses);
    }
    if(p->bat_pending && (p->io.now(p->io.opaque)<p->hold_start ||
       p->io.now(p->io.opaque)-p->hold_start>=p->hz/1000*W98_I8042_BAT_HOLD_MS))aux_commit_held(p);
    if(p->ack_wait && expired(p,p->ack_start,W98_I8042_STEP_MS)){p->ack_wait=0;aux_f4(p);}
    if(p->kbd_reinit && (p->flags&W98_INPUT_KEYBOARD))kbd_reinit(p);
    p->kbd_reinit=0;
    return (int)n;
}
void w98_input_status_words(const w98_i8042_t *p,uint32_t state,uint32_t generation,uint32_t extra,uint32_t out[8])
{
    if(!out)return;
    for(unsigned i=0;i<8;++i)out[i]=0;
    if(!p)return;
    uint32_t dropped=p->dropped>UINT32_MAX-extra?UINT32_MAX:p->dropped+extra;
    out[0]=W98_INPUT_STATUS_MAGIC;
    out[1]=(state&0xff)|(p->flags&0xff)<<8|(uint32_t)p->outer_config<<16|(p->ready?1u<<24:0)|
        (uint32_t)(p->resyncs>127?127:p->resyncs)<<25;
    out[2]=generation;out[3]=p->key_events;out[4]=p->mouse_packets;out[5]=dropped;
    out[6]=sat16(p->parity_timeout)|(uint32_t)sat16(p->malformed)<<16;
    out[7]=sat16(p->responses)|(uint32_t)sat16(p->last_error)<<16;
}
