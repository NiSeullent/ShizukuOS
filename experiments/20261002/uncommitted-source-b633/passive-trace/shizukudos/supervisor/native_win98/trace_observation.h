/* SPDX-License-Identifier: GPL-2.0-only
 * Fixed passive bookkeeping. No pointers to guest/device state or I/O APIs.
 * Values are observations, never boot, reset or device-authority assertions.
 */
#ifndef W98_TRACE_OBSERVATION_H
#define W98_TRACE_OBSERVATION_H
#include <stdint.h>
#define W98_OBS_PIO_RECORDS 32u
#define W98_OBS_SERIAL_BYTES 32768u
typedef struct {
    uint64_t sequence,tsc;
    uint32_t value;
    uint16_t port;
    uint8_t width,write;
} w98_obs_pio_t;
typedef struct {
    uint64_t start,last,hz,reasons[64],other_reason,pio_count;
    uint64_t controller_f[16],d1_values,d1_bit0_clear,port92_bit0_set;
    w98_obs_pio_t pio[W98_OBS_PIO_RECORDS];
    uint32_t serial_bytes;
    uint8_t started,clock_refused,snapshots,d1_pending,truncated;
} w98_observation_t;
static inline void w98_obs_increment(uint64_t *n)
{if(*n!=UINT64_MAX)++*n;}
static inline void w98_obs_init(w98_observation_t *s,uint64_t now,uint64_t hz)
{
    *s=(w98_observation_t){0};s->start=s->last=now;s->hz=hz;
    s->started=hz>=1000000;
}
static inline unsigned w98_obs_exit(w98_observation_t *s,uint64_t now,unsigned reason)
{
    if(!s->started || s->clock_refused)return 0;
    if(now<s->last){s->clock_refused=1;return 0;}
    s->last=now;
    if(reason<64)w98_obs_increment(&s->reasons[reason]);
    else w98_obs_increment(&s->other_reason);
    if(s->snapshots<2 && (now-s->start)/s->hz>=(s->snapshots?240u:60u))
        return ++s->snapshots;
    return 0;
}
static inline void w98_obs_pio(w98_observation_t *s,uint64_t now,uint16_t port,
                               unsigned bytes,int write,uint32_t value)
{
    if(!s->started || (bytes!=1 && bytes!=2 && bytes!=4))return;
    if(!((port>=0x1f0 && port<=0x1f7) || port==0x3f6 || port==0x20 ||
         port==0x21 || port==0xa0 || port==0xa1 || (port>=0x40 && port<=0x43) ||
         port==0x60 || port==0x61 || port==0x64 || port==0x92))return;
    if(write && bytes==1){
        const unsigned byte=value&255u;
        if(port==0x64){s->d1_pending=byte==0xd1;
            if(byte>=0xf0)w98_obs_increment(&s->controller_f[byte-0xf0]);}
        else if(port==0x60 && s->d1_pending){s->d1_pending=0;
            w98_obs_increment(&s->d1_values);
            if(!(byte&1))w98_obs_increment(&s->d1_bit0_clear);}
        if(port==0x92 && (byte&1))w98_obs_increment(&s->port92_bit0_set);
    }
    if(s->pio_count==UINT64_MAX)return;
    w98_obs_pio_t *r=&s->pio[s->pio_count%W98_OBS_PIO_RECORDS];
    r->sequence=++s->pio_count;r->tsc=now;r->value=value;
    r->port=port;r->width=(uint8_t)bytes;r->write=(uint8_t)!!write;
}
/* Whole-line admission keeps emitted byte accounting exact. Reserve a small
 * fixed marker for truncation; caller emits that marker at most once.
 */
static inline int w98_obs_line(w98_observation_t *s,unsigned bytes)
{
    if(s->truncated || bytes>W98_OBS_SERIAL_BYTES-64u ||
       s->serial_bytes>W98_OBS_SERIAL_BYTES-64u-bytes)return 0;
    s->serial_bytes+=bytes;return 1;
}
#endif
