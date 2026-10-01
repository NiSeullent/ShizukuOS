/* SPDX-License-Identifier: GPL-2.0-only
 * Shared bounded operation controller; native and host platforms are distinct.
 */
#define M98_NET_IMPLEMENTATION
#include "m98_tls13_native.h"
#define STEP_LIMIT 20000u
#define TRANSFER_LIMIT (1u<<20)
static volatile int entered;
static uint32_t generation;
static struct {
    m98_net_handle handle;
    m98_net_backend api;
    m98_tls_client *tls;
    m98_net_details detail;
    uint32_t start, duration, io_ms;
    int expired, platform_started;
} session;
static void clear(void *p,size_t n){unsigned char *b=p;while(n--)*b++=0;}
static int enter(void){return __sync_bool_compare_and_swap(&entered,0,1);}
static void leave(void){__sync_lock_release(&entered);}
static int bounded(uint32_t n){return n&&n<=300000u;}
static int hostname(const char *s){uint32_t n=0,label=0;int alpha=0;char previous=0;
    if(!s||!*s)return 0;
    while(*s){unsigned char c=(unsigned char)*s++;
        if(++n>253)return 0;
        if(c=='.'){if(!label||previous=='-')return 0;label=0;}
        else{int a=(c>='a'&&c<='z')||(c>='A'&&c<='Z');
            if(!a&&!(c>='0'&&c<='9')&&c!='-')return 0;
            if(!label&&c=='-')return 0;
            if(++label>63)return 0;
            alpha|=a;
        }previous=(char)c;
    }return label&&previous!='-'&&alpha;
}
static int options_valid(const m98_net_options *o){uint32_t i;static const char begin[]="-----BEGIN CERTIFICATE-----";
    if(!o||o->size!=sizeof(*o)||o->reserved||!o->port||!o->ipv4[0]||o->ipv4[0]>=224||
       !hostname(o->hostname)||!o->ca_pem||o->ca_bytes<sizeof(begin)||o->ca_bytes>TRANSFER_LIMIT||
       o->ca_pem[o->ca_bytes-1]||!bounded(o->connect_ms)||!bounded(o->handshake_ms)||!bounded(o->io_ms))return 0;
    for(i=0;i<sizeof(begin)-1;++i)if(o->ca_pem[i]!=(unsigned char)begin[i])return 0;
    for(i=0;i+1<o->ca_bytes;++i)if(!o->ca_pem[i])return 0;
    return 1;
}
static void begin_phase(uint32_t phase,uint32_t duration){
    session.detail.phase=phase;session.start=m98_net_platform.ticks();session.duration=duration;session.expired=0;
}
static uint32_t remaining(void){uint32_t elapsed=m98_net_platform.ticks()-session.start;
    if(session.expired||elapsed>=session.duration){session.expired=1;return 0;}
    return session.duration-elapsed;
}
static int entropy(void *user,unsigned char *p,size_t n){(void)user;
    if(!remaining())return 0;
    return m98_net_platform.random(NULL,p,n)==1&&remaining()?1:0;
}
static int64_t utc(void *user){int64_t result;(void)user;
    if(!remaining())return -1;
    result=m98_net_platform.utc(NULL);return remaining()?result:-1;
}
static int bio_send(void *user,const unsigned char *p,size_t n){int result;(void)user;
    if(!remaining())return -1;
    result=m98_net_platform.send(NULL,p,n);return remaining()?result:-1;
}
static int bio_recv(void *user,unsigned char *p,size_t n){int result;(void)user;
    if(!remaining())return -1;
    result=m98_net_platform.recv(NULL,p,n);return remaining()?result:-1;
}
static int complete_api(void){return session.api.create&&session.api.handshake&&session.api.write&&
    session.api.read&&session.api.shutdown&&session.api.backend_error&&session.api.verify_flags&&
    session.api.is_established&&session.api.free;
}
static void snapshot_error(void){
    session.detail.os_error=m98_net_platform.error();
    if(session.tls){session.detail.backend_error=session.api.backend_error(session.tls);
        session.detail.verify_flags=session.api.verify_flags(session.tls);}
}
static int cleanup(void){int result=0;
    if(session.tls){session.api.free(session.tls);session.tls=NULL;}
    if(session.platform_started){result=m98_net_platform.stop();if(!result)session.platform_started=0;}
    session.detail.cleanup_error=result?m98_net_platform.error():0;
    session.detail.cleanup_pending=result!=0;session.detail.established=0;
    return result?M98_NET_CLEANUP:0;
}
static int failed(int result){int cleaned;
    if(session.expired)result=M98_NET_TIMEOUT;
    if(result)snapshot_error();else session.detail.os_error=0;
    session.detail.result=result;session.detail.phase=M98_NET_DEAD;
    cleaned=cleanup();return cleaned?cleaned:result;
}
static int wait_for(int want,int connecting){uint32_t time=remaining();int result;
    if(!time)return M98_NET_TIMEOUT;
    result=m98_net_platform.wait(want,time,connecting);
    if(result==M98_NET_TIMEOUT)session.expired=1;
    if(!remaining())return M98_NET_TIMEOUT;
    return result;
}
int m98_net_open(const m98_net_options *o,m98_net_handle *out){m98_tls_options tls;uint32_t step;int result;
    if(!out)return M98_NET_INVALID;
    *out=0;
    if(!enter())return M98_NET_BUSY;
    if(session.handle){leave();return M98_NET_BUSY;}
    if(!options_valid(o)){leave();return M98_NET_INVALID;}
    if(generation==UINT32_MAX){leave();return M98_NET_LIMIT;}
    clear(&session,sizeof(session));session.handle=++generation;session.io_ms=o->io_ms;
    session.detail.size=sizeof(session.detail);session.detail.verify_flags=UINT32_MAX;
    begin_phase(M98_NET_CONNECT,o->connect_ms);session.platform_started=1;
    result=m98_net_platform.start(&session.api);
    if(!result&&!complete_api())result=M98_NET_LOAD;
    if(!result&&!remaining())result=M98_NET_TIMEOUT;
    if(!result)result=m98_net_platform.connect(o->ipv4,o->port);
    if(!remaining())result=M98_NET_TIMEOUT;
    if(result==M98_TLS_WANT_WRITE){result=wait_for(result,1);if(!result)result=m98_net_platform.finish_connect();}
    if(!remaining())result=M98_NET_TIMEOUT;
    if(result)goto bad;
    begin_phase(M98_NET_HANDSHAKE,o->handshake_ms);clear(&tls,sizeof(tls));
    tls.entropy=entropy;tls.unix_time=utc;tls.send=bio_send;tls.recv=bio_recv;
    tls.ca=o->ca_pem;tls.ca_bytes=o->ca_bytes;tls.hostname=o->hostname;
    result=session.api.create(&tls,&session.tls);
    if(!remaining())result=M98_NET_TIMEOUT;
    if(result||!session.tls){if(!result)result=M98_NET_STATE;goto bad;}
    for(step=0;step<STEP_LIMIT;++step){
        if(!remaining()){result=M98_NET_TIMEOUT;goto bad;}
        result=session.api.handshake(session.tls);
        if(!remaining()){result=M98_NET_TIMEOUT;goto bad;}
        if(!result)break;
        if(result!=M98_TLS_WANT_READ&&result!=M98_TLS_WANT_WRITE)goto bad;
        result=wait_for(result,0);if(result)goto bad;
    }
    if(step==STEP_LIMIT){result=M98_NET_LIMIT;goto bad;}
    if(!session.api.is_established(session.tls)||session.api.verify_flags(session.tls)){
        result=M98_TLS_VERIFY;goto bad;
    }
    session.detail.phase=M98_NET_READY;session.detail.result=0;session.detail.established=1;
    session.detail.verify_flags=0;*out=session.handle;leave();return 0;
bad:
    result=failed(result);
    if(result==M98_NET_CLEANUP)*out=session.handle;else session.handle=0;
    leave();return result;
}
static int valid_live(m98_net_handle h){return h&&h==session.handle&&session.tls&&session.detail.established;}
static int operation(m98_net_handle h,void *data,size_t bytes,size_t *amount,int writing){
    uint32_t step;size_t completed=0,count=0;int result;
    if(!amount)return M98_NET_INVALID;
    *amount=0;
    if(!enter())return M98_NET_BUSY;
    if(!valid_live(h)){leave();return M98_NET_STATE;}
    if((!data&&bytes)||!bytes||bytes>TRANSFER_LIMIT){leave();return M98_NET_INVALID;}
    begin_phase(M98_NET_IO_PHASE,session.io_ms);
    for(step=0;step<STEP_LIMIT;++step){
        if(!remaining()){result=M98_NET_TIMEOUT;goto bad;}
        count=0;
        result=writing?session.api.write(session.tls,(unsigned char *)data+completed,bytes-completed,&count):
                       session.api.read(session.tls,data,bytes,&count);
        /* A completed plaintext write remains observable even if its CPU call
         * finishes beyond the deadline. Return no late read payload count;
         * the caller buffer remains unspecified on read error. */
        if(result==0&&(!count||count>bytes-completed)){result=M98_NET_IO;goto bad;}
        if(writing&&result==0)completed+=count;
        if(!remaining()){result=M98_NET_TIMEOUT;goto bad;}
        if(result==0){
            if(!writing)completed=count;
            if(!writing||completed==bytes){*amount=completed;session.detail.phase=M98_NET_READY;
                session.detail.result=0;leave();return 0;}
        }else{
            if(count){result=M98_NET_IO;goto bad;}
            if(result!=M98_TLS_WANT_READ&&result!=M98_TLS_WANT_WRITE)goto bad;
            result=wait_for(result,0);if(result)goto bad;
        }
    }
    result=M98_NET_LIMIT;
bad:
    if(writing)*amount=completed;
    result=failed(result);leave();return result;
}
int m98_net_write(m98_net_handle h,const void *p,size_t n,size_t *written){return operation(h,(void *)p,n,written,1);}
int m98_net_read(m98_net_handle h,void *p,size_t n,size_t *read_bytes){return operation(h,p,n,read_bytes,0);}
int m98_net_shutdown(m98_net_handle h){uint32_t step;int result;unsigned char discard[256];
    if(!enter())return M98_NET_BUSY;
    if(!valid_live(h)){leave();return M98_NET_STATE;}
    begin_phase(M98_NET_SHUTDOWN,session.io_ms);session.detail.established=0;
    for(step=0;step<STEP_LIMIT;++step){
        if(!remaining()){result=M98_NET_TIMEOUT;goto bad;}
        result=session.api.shutdown(session.tls);
        if(!remaining()){result=M98_NET_TIMEOUT;goto bad;}
        if(!result)break;
        if(result!=M98_TLS_WANT_READ&&result!=M98_TLS_WANT_WRITE)goto bad;
        result=wait_for(result,0);if(result)goto bad;
    }
    if(step==STEP_LIMIT){result=M98_NET_LIMIT;goto bad;}
    result=m98_net_platform.half_close();if(result)goto bad;
    /* The frozen backend is terminal after sending close_notify. Drain TCP
     * ciphertext only: this cannot assert an authenticated peer TLS close. */
    for(step=0;step<STEP_LIMIT;++step){
        if(!remaining()){result=M98_NET_TIMEOUT;goto bad;}
        result=bio_recv(NULL,discard,sizeof(discard));
        if(!remaining()){result=M98_NET_TIMEOUT;goto bad;}
        if(!result){result=failed(0);leave();return result;}
        if(result>0){if((size_t)result>sizeof(discard)){result=M98_NET_IO;goto bad;}continue;}
        if(result!=-2){result=M98_NET_IO;goto bad;}
        result=wait_for(M98_TLS_WANT_READ,0);if(result)goto bad;
    }result=M98_NET_LIMIT;
bad:result=failed(result);leave();return result;
}
int m98_net_close(m98_net_handle h){int result;
    if(!enter())return M98_NET_BUSY;
    if(!h||h!=session.handle){leave();return M98_NET_STATE;}
    snapshot_error();session.detail.phase=M98_NET_DEAD;result=cleanup();
    if(!result)session.handle=0;
    leave();return result;
}
int m98_net_info(m98_net_handle h,m98_net_details *out){
    if(!out||out->size!=sizeof(*out))return M98_NET_INVALID;
    if(!enter())return M98_NET_BUSY;
    if(!h||h!=session.handle){leave();return M98_NET_STATE;}
    *out=session.detail;leave();return 0;
}
