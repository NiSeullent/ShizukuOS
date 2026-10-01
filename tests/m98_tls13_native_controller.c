/* SPDX-License-Identifier: GPL-2.0-only
 * Production-controller fault models. No Windows/TLS cryptography claims. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/m98_tls13_native.c"
static unsigned checks;
#define C(x) do{++checks;if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
enum {NORMAL,START_ERROR,INCOMPLETE_API,CONNECT_ERROR,CONNECT_TIMEOUT,FINISH_ERROR,
      CREATE_ERROR,CREATE_NULL,ENTROPY_ERROR,ENTROPY_TWO,CLOCK_ERROR,HANDSHAKE_ERROR,
      HANDSHAKE_TIMEOUT,HANDSHAKE_LIMIT,VERIFY_FLAGS,NOT_ESTABLISHED,WRITE_ERROR,
      READ_ERROR,WRITE_COUNT_ERROR,WRITE_ZERO,READ_COUNT_ERROR,AUTHENTICATED_EOF,
      TRANSPORT_EOF,SHUTDOWN_ERROR,SHUTDOWN_TIMEOUT,STOP_ERROR,HALF_CLOSE_ERROR,
      DRAIN_TIMEOUT,DRAIN_ERROR,DRAIN_COUNT_ERROR,DRAIN_LIMIT,WRITE_LATE};
static struct {int fault, resources,client,ready,stop_fault,reenter;
    unsigned starts,stops,frees,waits,hs_calls,write_calls,send_calls,shutdown_calls;
    uint32_t now,advance;int entropy_value; m98_tls_options options;
    const void *retry_ptr;size_t retry_size;
} model;
static unsigned char received[1024];static size_t received_size;
static m98_tls_client *token(void){return (m98_tls_client *)(uintptr_t)0x1234;}
static int random_cb(void *u,unsigned char *p,size_t n){(void)u;
    if(model.fault==ENTROPY_ERROR)return 0;
    if(model.fault==ENTROPY_TWO)return 2;
    memset(p,0x7a,n);return 1;
}
static int64_t clock_cb(void *u){(void)u;return model.fault==CLOCK_ERROR?-1:INT64_C(1790856000);}
static uint32_t tick(void){uint32_t now=model.now;model.now+=model.advance;return now;}
static uint32_t error_cb(void){return 12345;}
static int send_cb(void *u,const unsigned char *p,size_t n){(void)u;
    ++model.send_calls;
    if(model.reenter){m98_net_handle other=999;model.reenter=0;C(m98_net_open(NULL,&other)==M98_NET_BUSY&&other==0);}
    if(model.send_calls%3==1)return -2;
    if(n>7)n=7;
    C(received_size+n<=sizeof(received));memcpy(received+received_size,p,n);received_size+=n;return (int)n;
}
static int recv_cb(void *u,unsigned char *p,size_t n){(void)u;
    if(session.detail.phase==M98_NET_SHUTDOWN){
        if(model.fault==DRAIN_TIMEOUT)return -2;
        if(model.fault==DRAIN_ERROR)return -1;
        if(model.fault==DRAIN_COUNT_ERROR)return (int)n+1;
        if(model.fault==DRAIN_LIMIT){memset(p,0xcc,n);return (int)n;}
        return 0;
    }
    if(n>5)n=5;
    memset(p,'R',n);return (int)n;
}
static int create(const m98_tls_options *o,m98_tls_client **out){unsigned char entropy_bytes[32];
    model.options=*o;*out=NULL;
    C(!strcmp(o->hostname,"localhost")&&o->ca_bytes>26&&o->ca[0]=='-');
    if(model.fault==CREATE_ERROR)return M98_TLS_BUSY;
    if(o->entropy(o->user,entropy_bytes,sizeof(entropy_bytes))!=1)return M98_TLS_ENTROPY;
    if(o->unix_time(o->user)<1)return M98_TLS_CLOCK;
    if(model.fault==CREATE_NULL)return 0;
    model.client=1;*out=token();return 0;
}
static int handshake_cb(m98_tls_client *p){C(p==token()&&model.client);++model.hs_calls;
    if(model.fault==HANDSHAKE_ERROR)return M98_TLS_VERIFY;
    if(model.fault==HANDSHAKE_TIMEOUT||model.fault==HANDSHAKE_LIMIT)return M98_TLS_WANT_READ;
    if(model.hs_calls<3)return model.hs_calls==1?M98_TLS_WANT_READ:M98_TLS_WANT_WRITE;
    model.ready=1;return 0;
}
static int write_cb(m98_tls_client *p,const void *data,size_t n,size_t *count){int sent;
    C(p==token()&&model.client);++model.write_calls;*count=0;
    if(model.fault==WRITE_ERROR)return M98_TLS_PROTOCOL;
    if(model.fault==WRITE_COUNT_ERROR){*count=n+1;return 0;}
    if(model.fault==WRITE_ZERO)return 0;
    if(model.fault==WRITE_LATE){*count=n;model.now+=session.duration;return 0;}
    if(model.retry_ptr){C(model.retry_ptr==data&&model.retry_size==n);model.retry_ptr=NULL;}
    sent=model.options.send(model.options.user,data,n);
    if(sent==-2){model.retry_ptr=data;model.retry_size=n;return M98_TLS_WANT_WRITE;}
    if(sent<0)return M98_TLS_IO;
    *count=(size_t)sent;return 0;
}
static int read_cb(m98_tls_client *p,void *data,size_t n,size_t *count){C(p==token()&&model.client);*count=0;
    if(model.fault==READ_ERROR)return M98_TLS_PROTOCOL;
    if(model.fault==READ_COUNT_ERROR){*count=n+1;return 0;}
    if(model.fault==AUTHENTICATED_EOF)return M98_TLS_EOF;
    if(model.fault==TRANSPORT_EOF)return M98_TLS_PROTOCOL;
    *count=(size_t)model.options.recv(model.options.user,data,n);return 0;
}
static int shutdown_cb(m98_tls_client *p){C(p==token()&&model.client);++model.shutdown_calls;
    if(model.fault==SHUTDOWN_ERROR)return M98_TLS_IO;
    if(model.fault==SHUTDOWN_TIMEOUT)return M98_TLS_WANT_WRITE;
    return model.shutdown_calls==1?M98_TLS_WANT_WRITE:0;
}
static int backend_error_cb(const m98_tls_client *p){C(p==token());return -456;}
static uint32_t verify_cb(const m98_tls_client *p){C(p==token());return model.fault==VERIFY_FLAGS?1:0;}
static int established_cb(const m98_tls_client *p){C(p==token());return model.ready&&model.fault!=NOT_ESTABLISHED;}
static void free_cb(m98_tls_client *p){C(p==token()&&model.client);model.client=0;model.ready=0;++model.frees;}
static int start_cb(m98_net_backend *b){++model.starts;model.resources=1;
    *b=(m98_net_backend){create,handshake_cb,write_cb,read_cb,shutdown_cb,backend_error_cb,verify_cb,established_cb,free_cb};
    if(model.fault==INCOMPLETE_API)b->free=NULL;
    return model.fault==START_ERROR?M98_NET_LOAD:0;
}
static int connect_cb(const uint8_t *ip,uint16_t port){C(ip[0]==127&&ip[3]==1&&port==4433);
    return model.fault==CONNECT_ERROR?M98_NET_IO:M98_TLS_WANT_WRITE;
}
static int wait_cb(int want,uint32_t ms,int connecting){C(ms&&ms<=300000&&(want==1||want==2));++model.waits;
    if((connecting&&model.fault==CONNECT_TIMEOUT)||model.fault==HANDSHAKE_TIMEOUT||model.fault==SHUTDOWN_TIMEOUT||model.fault==DRAIN_TIMEOUT)
        return M98_NET_TIMEOUT;
    return 0;
}
static int finish_cb(void){return model.fault==FINISH_ERROR?M98_NET_IO:0;}
static int half_close_cb(void){return model.fault==HALF_CLOSE_ERROR?M98_NET_IO:0;}
static int stop_cb(void){++model.stops;C(!model.client);
    if(model.stop_fault){--model.stop_fault;return M98_NET_CLEANUP;}
    model.resources=0;return 0;
}
const m98_net_platform_ops m98_net_platform={start_cb,connect_cb,wait_cb,finish_cb,half_close_cb,send_cb,recv_cb,random_cb,clock_cb,tick,error_cb,stop_cb};
static const unsigned char ca[]="-----BEGIN CERTIFICATE-----\nmodel-only-not-a-certificate\n-----END CERTIFICATE-----\n";
static m98_net_options options(void){m98_net_options o={0};o.size=sizeof(o);o.ipv4[0]=127;o.ipv4[3]=1;
    o.port=4433;o.hostname="localhost";o.ca_pem=ca;o.ca_bytes=sizeof(ca);o.connect_ms=o.handshake_ms=o.io_ms=2000;return o;
}
static void reset(int fault){C(!session.handle&&!model.resources&&!model.client&&!entered);
    memset(&model,0,sizeof(model));received_size=0;model.fault=fault;model.advance=1;
}
static void rejected_open(int fault,int expected){m98_net_options o=options();m98_net_handle h=999;
    reset(fault);if(fault==HANDSHAKE_LIMIT)model.advance=0;
    C(m98_net_open(&o,&h)==expected&&h==0);C(!model.resources&&!model.client&&model.stops==1);
}
int main(void){m98_net_options o; m98_net_handle h,old,other; m98_net_details detail;unsigned i;size_t amount;char data[111],out[20];
    memset(data,'P',sizeof(data));
    rejected_open(START_ERROR,M98_NET_LOAD);rejected_open(INCOMPLETE_API,M98_NET_LOAD);
    rejected_open(CONNECT_ERROR,M98_NET_IO);rejected_open(CONNECT_TIMEOUT,M98_NET_TIMEOUT);
    rejected_open(FINISH_ERROR,M98_NET_IO);rejected_open(CREATE_ERROR,M98_TLS_BUSY);
    rejected_open(CREATE_NULL,M98_NET_STATE);rejected_open(ENTROPY_ERROR,M98_TLS_ENTROPY);
    rejected_open(ENTROPY_TWO,M98_TLS_ENTROPY);rejected_open(CLOCK_ERROR,M98_TLS_CLOCK);
    rejected_open(HANDSHAKE_ERROR,M98_TLS_VERIFY);rejected_open(HANDSHAKE_TIMEOUT,M98_NET_TIMEOUT);
    rejected_open(HANDSHAKE_LIMIT,M98_NET_LIMIT);rejected_open(VERIFY_FLAGS,M98_TLS_VERIFY);
    rejected_open(NOT_ESTABLISHED,M98_TLS_VERIFY);
    reset(NORMAL);o=options();model.now=UINT32_MAX-10;C(m98_net_open(&o,&h)==0&&h);
    old=h;C(m98_net_open(&o,&other)==M98_NET_BUSY&&other==0);
    model.reenter=1;C(m98_net_write(h,data,sizeof(data),&amount)==0&&amount==sizeof(data));
    C(received_size==sizeof(data)&&!memcmp(received,data,sizeof(data))&&model.write_calls>10);
    C(m98_net_read(h,out,sizeof(out),&amount)==0&&amount==5&&out[0]=='R');
    C(m98_net_shutdown(h)==0&&model.frees==1&&!model.resources);
    C(m98_net_write(h,data,1,&amount)==M98_NET_STATE&&amount==0);
    C(m98_net_close(h)==0);C(m98_net_close(h)==M98_NET_STATE);
    reset(NORMAL);C(m98_net_open(&o,&h)==0&&h!=old);C(m98_net_read(old,out,sizeof(out),&amount)==M98_NET_STATE&&amount==0);
    C(m98_net_close(h)==0);
    for(i=WRITE_ERROR;i<=TRANSPORT_EOF;++i){int expect=i==AUTHENTICATED_EOF?3:(i==WRITE_ERROR||i==READ_ERROR||i==TRANSPORT_EOF)?M98_TLS_PROTOCOL:M98_NET_IO;
        reset(NORMAL);C(m98_net_open(&o,&h)==0);model.fault=(int)i;
        C((i==WRITE_ERROR||i==WRITE_COUNT_ERROR||i==WRITE_ZERO?m98_net_write(h,data,sizeof(data),&amount):m98_net_read(h,out,sizeof(out),&amount))==expect);
        C(amount==0&&!model.resources&&!model.client);detail.size=sizeof(detail);C(m98_net_info(h,&detail)==0&&detail.result==expect&&!detail.established);
        C(m98_net_close(h)==0);
    }
    for(i=SHUTDOWN_ERROR;i<=SHUTDOWN_TIMEOUT;++i){reset(NORMAL);C(m98_net_open(&o,&h)==0);model.fault=(int)i;
        C(m98_net_shutdown(h)==(i==SHUTDOWN_ERROR?M98_TLS_IO:M98_NET_TIMEOUT)&&!model.resources);C(m98_net_close(h)==0);}
    for(i=HALF_CLOSE_ERROR;i<=DRAIN_LIMIT;++i){reset(NORMAL);C(m98_net_open(&o,&h)==0);model.fault=(int)i;
        if(i==DRAIN_LIMIT)model.advance=0;
        C(m98_net_shutdown(h)==(i==DRAIN_TIMEOUT?M98_NET_TIMEOUT:i==DRAIN_LIMIT?M98_NET_LIMIT:M98_NET_IO));
        C(!model.resources&&!model.client);C(m98_net_close(h)==0);}
    reset(NORMAL);C(m98_net_open(&o,&h)==0);model.fault=WRITE_LATE;
    C(m98_net_write(h,data,sizeof(data),&amount)==M98_NET_TIMEOUT&&amount==sizeof(data));
    C(!model.resources&&!model.client);C(m98_net_close(h)==0);
    reset(START_ERROR);model.stop_fault=1;C(m98_net_open(&o,&h)==M98_NET_CLEANUP&&h&&model.resources);
    detail.size=sizeof(detail);C(m98_net_info(h,&detail)==0&&detail.result==M98_NET_LOAD&&detail.cleanup_pending&&detail.cleanup_error==12345);
    C(m98_net_open(&o,&other)==M98_NET_BUSY);C(m98_net_close(h)==0&&!model.resources);
    reset(NORMAL);C(m98_net_open(&o,&h)==0);model.stop_fault=1;C(m98_net_close(h)==M98_NET_CLEANUP&&model.frees==1&&model.resources);
    C(m98_net_close(h)==0&&model.frees==1&&!model.resources);
    reset(NORMAL);o.port=0;C(m98_net_open(&o,&h)==M98_NET_INVALID&&!model.starts);o=options();o.hostname="127.0.0.1";C(m98_net_open(&o,&h)==M98_NET_INVALID);
    o=options();o.connect_ms=0;C(m98_net_open(&o,&h)==M98_NET_INVALID);o=options();o.io_ms=300001;C(m98_net_open(&o,&h)==M98_NET_INVALID);
    o=options();o.ca_bytes--;C(m98_net_open(&o,&h)==M98_NET_INVALID);o=options();o.reserved=1;C(m98_net_open(&o,&h)==M98_NET_INVALID);
    o=options();o.ipv4[0]=224;C(m98_net_open(&o,&h)==M98_NET_INVALID);o=options();generation=UINT32_MAX;C(m98_net_open(&o,&h)==M98_NET_LIMIT&&!model.starts);
    printf("PASS: native transport controller %u assertions; model only, no Windows/TLS claim\n",checks);return 0;
}
