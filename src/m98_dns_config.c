/* SPDX-License-Identifier: GPL-2.0-only
 * Independently authored public ABI adapter; no upstream body copied.
 */
#include "m98_dns_config.h"
static void copy(void *dst,const void *src,uint32_t n) {
    uint8_t *d=dst; const uint8_t *s=src; uint32_t i;
    for(i=0;i<n;++i)d[i]=s[i];
}
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static void wr32(uint8_t *p,uint32_t x) {
    p[0]=(uint8_t)x;p[1]=(uint8_t)(x>>8);p[2]=(uint8_t)(x>>16);p[3]=(uint8_t)(x>>24);
}
static int alen(const char *p,uint32_t cap,uint32_t *n) {
    uint32_t i;for(i=0;i<cap;++i)if(!p[i]){*n=i;return 1;}return 0;
}
static int wlen(const uint16_t *p,uint32_t cap,uint32_t *n) {
    uint32_t i;for(i=0;i<cap;++i){
        uint16_t c=p[i];if(!c){*n=i;return 1;}
        if(c>=0xd800&&c<=0xdbff){
            if(i+1>=cap||p[i+1]<0xdc00||p[i+1]>0xdfff)return 0;
            ++i;
        }else if(c>=0xdc00&&c<=0xdfff)return 0;
    }return 0;
}
static int ipv4(const uint8_t *p,uint8_t out[4]) {
    uint32_t n,i=0,k; if(!alen((const char *)p,16,&n)||!n)return 0;
    for(k=0;k<4;++k){uint32_t value=0,digits=0;
        while(i<n&&p[i]>='0'&&p[i]<='9'){
            value=value*10+p[i++]-'0';if(++digits>3||value>255)return 0;
        }
        if(!digits)return 0;
        out[k]=(uint8_t)value;
        if(k<3){if(i>=n||p[i++]!='.')return 0;}else if(i!=n)return 0;
    }return 1;
}
static int node_offset(uint32_t ptr,uint32_t base,uint32_t size,uint32_t *off) {
    uint32_t n;if(ptr<base)return 0;n=ptr-base;
    if(n!=M98_DNS_FIXED4_LIST&&(n<M98_DNS_FIXED4_SIZE||(n&3)))return 0;
    if(size<40||n>size-40)return 0;
    *off=n;return 1;
}
uint32_t m98_dns_parse_fixed4(const void *buffer,uint32_t size,uint32_t base,
                             m98_dns_decode decode,void *ctx,m98_dns_snapshot *out) {
    const uint8_t *p=buffer;m98_dns_snapshot snap={0};
    uint32_t n,off=M98_DNS_FIXED4_LIST,seen[64],count=0,i,j;
    if(!p||!out||!decode)return M98_DNS_INVALID_PARAMETER;
    if(size<M98_DNS_FIXED4_SIZE||size>65536u||base>UINT32_MAX-size)return M98_DNS_INVALID_DATA;
    if(!alen((const char *)p,132,&n))return M98_DNS_INVALID_DATA;
    copy(snap.host_a,p,n+1);
    if(decode(ctx,(const char *)p,n,snap.host_w,132)||!wlen(snap.host_w,132,&i)||(n==0)!=(i==0))return M98_DNS_INVALID_DATA;
    if(!alen((const char *)p+132,132,&n))return M98_DNS_INVALID_DATA;
    copy(snap.domain_a,p+132,n+1);
    if(decode(ctx,(const char *)p+132,n,snap.domain_w,132)||!wlen(snap.domain_w,132,&i)||(n==0)!=(i==0))return M98_DNS_INVALID_DATA;
    /* CurrentDnsServer is reserved; only DnsServerList has pointer semantics. */
    for(;;){uint32_t next;uint8_t ip[4];
        if(count==64)return M98_DNS_INVALID_DATA;
        for(i=0;i<count;++i)if(seen[i]>off?seen[i]-off<40:off-seen[i]<40)return M98_DNS_INVALID_DATA;
        seen[count++]=off;
        if(p[off+4]){
            if(!ipv4(p+off+4,ip))return M98_DNS_INVALID_DATA;
            if(ip[0]||ip[1]||ip[2]||ip[3]){
                for(i=0;i<snap.server_count;++i){for(j=0;j<4&&snap.servers[i][j]==ip[j];++j){}if(j==4)break;}
                if(i==snap.server_count)copy(snap.servers[snap.server_count++],ip,4);
            }
        }else if(!alen((const char *)p+off+4,16,&n))return M98_DNS_INVALID_DATA;
        next=rd32(p+off);if(!next)break;
        if(!node_offset(next,base,size,&off))return M98_DNS_INVALID_DATA;
    }
    copy(out,&snap,sizeof(snap));return M98_DNS_OK;
}
static int utf8(const uint16_t *s,uint32_t n,uint8_t *out,uint32_t *bytes) {
    uint32_t i,k=0;for(i=0;i<n;++i){uint32_t c=s[i];
        if(c>=0xd800&&c<=0xdbff)c=0x10000+((c-0xd800)<<10)+(s[++i]-0xdc00);
        if(c<0x80)out[k++]=(uint8_t)c;
        else if(c<0x800){out[k++]=(uint8_t)(0xc0|(c>>6));out[k++]=(uint8_t)(0x80|(c&63));}
        else if(c<0x10000){out[k++]=(uint8_t)(0xe0|(c>>12));out[k++]=(uint8_t)(0x80|((c>>6)&63));out[k++]=(uint8_t)(0x80|(c&63));}
        else{out[k++]=(uint8_t)(0xf0|(c>>18));out[k++]=(uint8_t)(0x80|((c>>12)&63));out[k++]=(uint8_t)(0x80|((c>>6)&63));out[k++]=(uint8_t)(0x80|(c&63));}
    }out[k++]=0;*bytes=k;return 1;
}
uint32_t m98_dns_validate_request(uint32_t config,uint32_t flags,
                                 const uint16_t *adapter,const void *reserved,
                                 void *buffer,const uint32_t *length,m98_dns_alloc alloc) {
    if(!length||reserved||(flags&~1u)||(flags&&(!buffer||!alloc)))return M98_DNS_INVALID_PARAMETER;
    if(adapter)return M98_DNS_NOT_SUPPORTED;
    switch(config){case 0:case 1:case 2:case 6:case 12:case 13:case 14:case 15:case 16:case 17:return 0;
        default:return M98_DNS_NOT_SUPPORTED;}
}
uint32_t m98_dns_query(const m98_dns_snapshot *s,uint32_t config,uint32_t flags,
                       const uint16_t *adapter,const void *reserved,void *buffer,
                       uint32_t *length,m98_dns_alloc alloc,void *ctx) {
    uint8_t data[1056];uint16_t wide[264];char ansi[264];
    uint32_t ha,da,hw,dw,i,j,n=0,needed=0,charset=0,status;int full=0,domain=0;
    status=m98_dns_validate_request(config,flags,adapter,reserved,buffer,length,alloc);
    if(status)return status;
    if(!s)return M98_DNS_INVALID_PARAMETER;
    switch(config){
    case M98_DNS_SERVERS:break;
    case M98_DNS_DOMAIN_W:domain=1;charset=1;break;
    case M98_DNS_DOMAIN_A:domain=1;charset=2;break;
    case M98_DNS_DOMAIN_UTF8:domain=1;charset=3;break;
    case M98_DNS_HOST_W:charset=1;break;
    case M98_DNS_HOST_A:charset=2;break;
    case M98_DNS_HOST_UTF8:charset=3;break;
    case M98_DNS_FULL_W:full=1;charset=1;break;
    case M98_DNS_FULL_A:full=1;charset=2;break;
    case M98_DNS_FULL_UTF8:full=1;charset=3;break;
    default:return M98_DNS_NOT_SUPPORTED;
    }
    if(!alen(s->host_a,132,&ha)||!alen(s->domain_a,132,&da)||
       !wlen(s->host_w,132,&hw)||!wlen(s->domain_w,132,&dw)||
       (ha==0)!=(hw==0)||(da==0)!=(dw==0)||s->server_count>64)return M98_DNS_INVALID_DATA;
    if(config==M98_DNS_SERVERS){
        for(i=0;i<s->server_count;++i){
            if(!(s->servers[i][0]|s->servers[i][1]|s->servers[i][2]|s->servers[i][3]))continue;
            for(j=0;j<n;++j){uint32_t k;for(k=0;k<4&&data[4+4*j+k]==s->servers[i][k];++k){}if(k==4)break;}
            if(j==n)copy(data+4+4*n++,s->servers[i],4);
        }wr32(data,n);needed=4+4*n;
    }else if(charset==2){
        const char *a=domain?s->domain_a:s->host_a;uint32_t count=domain?da:ha;
        if(!domain&&!full)for(count=0;count<ha&&a[count]!='.';++count){}
        copy(ansi,a,count);n=count;
        for(i=0;i<ha&&s->host_a[i]!='.';++i){}
        /* IP Helper may already return the FQDN. Preserve it verbatim. */
        if(full&&ha&&da&&i==ha){ansi[n++]='.';copy(ansi+n,s->domain_a,da);n+=da;}ansi[n]=0;
        needed=n+1;copy(data,ansi,needed);
    }else{
        const uint16_t *w=domain?s->domain_w:s->host_w;uint32_t count=domain?dw:hw;
        if(!domain&&!full)for(count=0;count<hw&&w[count]!='.';++count){}
        copy(wide,w,count*2);n=count;
        for(i=0;i<hw&&s->host_w[i]!='.';++i){}
        if(full&&hw&&dw&&i==hw){wide[n++]='.';copy(wide+n,s->domain_w,dw*2);n+=dw;}wide[n]=0;
        if(charset==3)utf8(wide,n,data,&needed);
        else{needed=(n+1)*2;for(i=0;i<=n;++i){data[2*i]=(uint8_t)wide[i];data[2*i+1]=(uint8_t)(wide[i]>>8);}}
    }
    if(flags){void *p=alloc(ctx,needed);if(!p)return M98_DNS_NOMEM;
        copy(p,data,needed);copy(buffer,&p,sizeof(p));*length=needed;return M98_DNS_OK;
    }
    if(!buffer||*length<needed){*length=needed;
        if(config==M98_DNS_SERVERS)return buffer?M98_DNS_MORE_DATA:M98_DNS_OK;
        return M98_DNS_INSUFFICIENT_BUFFER;
    }
    copy(buffer,data,needed);*length=needed;return M98_DNS_OK;
}
