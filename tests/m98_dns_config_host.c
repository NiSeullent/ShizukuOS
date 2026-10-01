/* SPDX-License-Identifier: GPL-2.0-only */
#include "m98_dns_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define C(x) do{++checks;if(!(x)){fprintf(stderr,"FAIL %u line %d: %s\n",checks,__LINE__,#x);exit(1);}}while(0)
static void put32(uint8_t *p,uint32_t n){p[0]=n;p[1]=n>>8;p[2]=n>>16;p[3]=n>>24;}
static uint32_t ascii(void *ctx,const char *a,uint32_t n,uint16_t *w,uint32_t cap){
    uint32_t i;if(ctx)return 1;if(n>=cap)return 1;
    for(i=0;i<n;++i){if((uint8_t)a[i]>127)return 1;w[i]=(uint8_t)a[i];}w[n]=0;return 0;
}
static uint32_t empty_decode(void *ctx,const char *a,uint32_t n,uint16_t *w,uint32_t cap){
    (void)ctx;(void)a;(void)n;(void)cap;w[0]=0;return 0;
}
typedef struct{unsigned calls;int fail;void *p;uint32_t size;} allocator;
static void *allocation(void *ctx,uint32_t size){allocator *a=ctx;++a->calls;a->size=size;if(a->fail)return NULL;a->p=malloc(size);return a->p;}
static void fixture(uint8_t *b){
    memset(b,0,704);memcpy(b,"WIN98",6);memcpy(b+132,"example.test",13);
    put32(b+264,0x10000+584);put32(b+268,0x10000+584);memcpy(b+272,"192.0.2.53",11);
    put32(b+584,0x10000+624);memcpy(b+588,"198.51.100.7",13);
    memcpy(b+628,"192.0.2.53",11);
}
static void names(m98_dns_snapshot *s,const char *host,const char *domain){uint32_t i;
    memset(s,0,sizeof(*s));memcpy(s->host_a,host,strlen(host)+1);memcpy(s->domain_a,domain,strlen(domain)+1);
    for(i=0;host[i];++i)s->host_w[i]=(uint8_t)host[i];
    for(i=0;domain[i];++i)s->domain_w[i]=(uint8_t)domain[i];
}
static void failure(uint8_t *b,uint32_t size,uint32_t base,void *ctx){m98_dns_snapshot s,old;
    memset(&s,0xa5,sizeof(s));old=s;C(m98_dns_parse_fixed4(b,size,base,ascii,ctx,&s)!=0);C(!memcmp(&s,&old,sizeof(s)));
}
int main(void){
    uint8_t b[704],bad[704],out[1200];m98_dns_snapshot s={0},invalid;uint32_t n,status,i;
    allocator a={0};void *p;const uint16_t adapter[]={ 'x',0 };
    fixture(b);C(m98_dns_parse_fixed4(b,sizeof(b),0x10000,ascii,NULL,&s)==0);
    C(!strcmp(s.host_a,"WIN98")&&!strcmp(s.domain_a,"example.test"));
    C(s.server_count==2&&!memcmp(s.servers[0],"\xc0\x00\x02\x35",4)&&!memcmp(s.servers[1],"\xc6\x33\x64\x07",4));
    n=0;C(m98_dns_query(&s,6,0,NULL,NULL,NULL,&n,NULL,NULL)==0&&n==12);
    memset(out,0xcc,sizeof(out));n=11;C(m98_dns_query(&s,6,0,NULL,NULL,out,&n,NULL,NULL)==234&&n==12&&out[0]==0xcc);
    n=12;C(m98_dns_query(&s,6,0,NULL,NULL,out,&n,NULL,NULL)==0&&n==12);
    C(!memcmp(out,"\x02\0\0\0\xc0\0\x02\x35\xc6\x33\x64\x07",12)&&out[12]==0xcc);
    s.servers[2][0]=198;s.servers[2][1]=51;s.servers[2][2]=100;s.servers[2][3]=7;s.server_count=3;
    n=sizeof(out);C(m98_dns_query(&s,6,0,NULL,NULL,out,&n,NULL,NULL)==0&&n==12);
    n=99;C(m98_dns_query(&s,13,0,NULL,NULL,NULL,&n,NULL,NULL)==122&&n==6);
    n=5;out[0]=0xcc;C(m98_dns_query(&s,13,0,NULL,NULL,out,&n,NULL,NULL)==122&&n==6&&out[0]==0xcc);
    n=sizeof(out);C(m98_dns_query(&s,16,0,NULL,NULL,out,&n,NULL,NULL)==0&&n==19&&!strcmp((char *)out,"WIN98.example.test"));
    n=sizeof(out);C(m98_dns_query(&s,15,0,NULL,NULL,out,&n,NULL,NULL)==0&&n==38&&out[0]=='W'&&!out[1]&&out[36]==0&&out[37]==0);
    p=(void *)(uintptr_t)0x1234;n=999;
    C(m98_dns_query(&s,6,1,NULL,NULL,&p,&n,allocation,&a)==0&&p==a.p&&a.calls==1&&a.size==12&&n==12);
    C(((uint8_t *)p)[0]==2&&((uint8_t *)p)[4]==192);free(p);a.p=NULL;
    a.fail=1;p=(void *)(uintptr_t)0x1234;n=77;
    C(m98_dns_query(&s,6,1,NULL,NULL,&p,&n,allocation,&a)==8&&n==77&&p==(void *)(uintptr_t)0x1234&&a.calls==2);
    for(i=0;i<32;++i){if(i==0||i==1||i==2||i==6||(i>=12&&i<=17))continue;
        n=77;out[0]=0xcc;C(m98_dns_query(&s,i,0,NULL,NULL,out,&n,NULL,NULL)==50&&n==77&&out[0]==0xcc);
    }
    n=77;C(m98_dns_query(&s,6,2,NULL,NULL,out,&n,NULL,NULL)==87&&n==77);
    C(m98_dns_query(&s,6,0,adapter,NULL,out,&n,NULL,NULL)==50&&n==77);
    C(m98_dns_query(&s,6,0,NULL,out,out,&n,NULL,NULL)==87&&n==77);
    C(m98_dns_query(&s,6,1,NULL,NULL,&p,&n,NULL,NULL)==87&&n==77);
    C(m98_dns_query(&s,6,1,NULL,NULL,NULL,&n,allocation,&a)==87&&n==77);
    C(m98_dns_query(&s,6,0,NULL,NULL,out,NULL,NULL,NULL)==87);
    C(m98_dns_query(NULL,6,0,NULL,NULL,out,&n,NULL,NULL)==87&&n==77);
    C(m98_dns_validate_request(6,1,NULL,NULL,&p,&n,allocation)==0&&p==(void *)(uintptr_t)0x1234&&n==77&&a.calls==2);
    invalid=s;invalid.server_count=65;C(m98_dns_query(&invalid,6,0,NULL,NULL,out,&n,NULL,NULL)==13&&n==77);
    invalid=s;memset(invalid.host_a,'x',132);C(m98_dns_query(&invalid,13,0,NULL,NULL,out,&n,NULL,NULL)==13&&n==77);
    invalid=s;invalid.host_w[0]=0xd800;invalid.host_w[1]=0;C(m98_dns_query(&invalid,14,0,NULL,NULL,out,&n,NULL,NULL)==13&&n==77);
    invalid=s;invalid.domain_w[0]=0xdc00;invalid.domain_w[1]=0;C(m98_dns_query(&invalid,2,0,NULL,NULL,out,&n,NULL,NULL)==13&&n==77);
    invalid=s;invalid.host_w[0]=0;C(m98_dns_query(&invalid,14,0,NULL,NULL,out,&n,NULL,NULL)==13&&n==77);
    invalid=s;invalid.host_w[0]=0xd83d;invalid.host_w[1]=0xde00;invalid.host_w[2]=0xac00;invalid.host_w[3]=0;
    n=sizeof(out);C(m98_dns_query(&invalid,14,0,NULL,NULL,out,&n,NULL,NULL)==0&&n==8&&!memcmp(out,"\xf0\x9f\x98\x80\xea\xb0\x80\0",8));
    invalid=s;memset(invalid.host_a,'h',131);invalid.host_a[131]=0;memset(invalid.domain_a,'d',131);invalid.domain_a[131]=0;
    for(i=0;i<131;++i){invalid.host_w[i]=0xac00;invalid.domain_w[i]=0xac01;}invalid.host_w[131]=invalid.domain_w[131]=0;
    n=sizeof(out);C(m98_dns_query(&invalid,17,0,NULL,NULL,out,&n,NULL,NULL)==0&&n==788&&out[787]==0);
    n=sizeof(out);C(m98_dns_query(&invalid,15,0,NULL,NULL,out,&n,NULL,NULL)==0&&n==528);
    n=sizeof(out);C(m98_dns_query(&invalid,16,0,NULL,NULL,out,&n,NULL,NULL)==0&&n==264);
    {const char *cases[][4]={
      {"WIN98.example.test","example.test","WIN98.example.test","WIN98"},
      {"WIN98.EXAMPLE.TEST","example.test","WIN98.EXAMPLE.TEST","WIN98"},
      {"WIN98.example.test","EXAMPLE.TEST","WIN98.example.test","WIN98"},
      {"WIN98.other.test","example.test","WIN98.other.test","WIN98"},
      {"WIN98.","example.test","WIN98.","WIN98"},
      {"WIN98","","WIN98","WIN98"},{"","example.test","",""},
      {"WIN98","example.test","WIN98.example.test","WIN98"}};
      uint32_t row,config,k;
      for(row=0;row<sizeof(cases)/sizeof(cases[0]);++row){names(&invalid,cases[row][0],cases[row][1]);
        for(config=15;config<=17;++config){n=sizeof(out);C(m98_dns_query(&invalid,config,0,NULL,NULL,out,&n,NULL,NULL)==0);
          k=(uint32_t)strlen(cases[row][2]);C(n==(k+1)*(config==15?2u:1u));
          if(config==15){for(i=0;i<=k;++i)C(out[2*i]==cases[row][2][i]&&!out[2*i+1]);}
          else C(!strcmp((char *)out,cases[row][2]));}
        n=sizeof(out);C(m98_dns_query(&invalid,13,0,NULL,NULL,out,&n,NULL,NULL)==0&&!strcmp((char *)out,cases[row][3]));
      }}
    memset(&invalid,0,sizeof(invalid));n=sizeof(out);C(m98_dns_query(&invalid,6,0,NULL,NULL,out,&n,NULL,NULL)==0&&n==4&&!out[0]);
    n=sizeof(out);C(m98_dns_query(&invalid,15,0,NULL,NULL,out,&n,NULL,NULL)==0&&n==2&&!out[0]&&!out[1]);
    memcpy(bad,b,sizeof(bad));put32(bad+624,0x10000+268);failure(bad,sizeof(bad),0x10000,NULL);
    memcpy(bad,b,sizeof(bad));put32(bad+584,0x10000+588);failure(bad,sizeof(bad),0x10000,NULL);
    memcpy(bad,b,sizeof(bad));put32(bad+268,0xffff);failure(bad,sizeof(bad),0x10000,NULL);
    memcpy(bad,b,sizeof(bad));put32(bad+268,0x10000+583);failure(bad,sizeof(bad),0x10000,NULL);
    memcpy(bad,b,sizeof(bad));put32(bad+268,0x10000+588);put32(bad+588,0x10000+628);failure(bad,sizeof(bad),0x10000,NULL);
    memcpy(bad,b,sizeof(bad));put32(bad+268,0x10000+688);failure(bad,sizeof(bad),0x10000,NULL);
    /* Reserved CurrentDnsServer must neither be dereferenced nor validated. */
    memcpy(bad,b,sizeof(bad));put32(bad+264,0xffffffff);
    C(m98_dns_parse_fixed4(bad,sizeof(bad),0x10000,ascii,NULL,&invalid)==0&&invalid.server_count==2);
    failure(b,sizeof(b),UINT32_MAX-500,NULL);failure(b,65537,0x10000,NULL);failure(b,sizeof(b),0x10000,b);
    memset(&invalid,0xa5,sizeof(invalid));{m98_dns_snapshot old=invalid;
      C(m98_dns_parse_fixed4(b,sizeof(b),0x10000,empty_decode,NULL,&invalid)==13&&!memcmp(&invalid,&old,sizeof(old)));}
    memcpy(bad,b,sizeof(bad));memset(bad,'a',132);failure(bad,sizeof(bad),0x10000,NULL);
    memcpy(bad,b,sizeof(bad));memset(bad+272,'1',16);failure(bad,sizeof(bad),0x10000,NULL);
    {const char *badips[]={"1.2.3","1.2.3.4x","256.0.0.1","-1.0.0.1","1..2.3","1.2.3.4.5","0000.1.2.3"," 1.2.3.4"};
      for(i=0;i<sizeof(badips)/sizeof(badips[0]);++i){memcpy(bad,b,sizeof(bad));memset(bad+272,0,16);memcpy(bad+272,badips[i],strlen(badips[i])+1);failure(bad,sizeof(bad),0x10000,NULL);}}
    for(i=0;i<664;++i)failure(b,i,0x10000,NULL);
    memset(bad,0,sizeof(bad));C(m98_dns_parse_fixed4(bad,584,0x10000,ascii,NULL,&invalid)==0&&invalid.server_count==0);
    memcpy(bad+272,"0.0.0.0",8);C(m98_dns_parse_fixed4(bad,584,0x10000,ascii,NULL,&invalid)==0&&invalid.server_count==0);
    {uint8_t *chain=calloc(1,4096);C(chain!=NULL);
      for(i=0;i<64;++i){uint32_t off=i?584+40*(i-1):268;char ip[16];
        snprintf(ip,sizeof(ip),"192.0.2.%u",i);memcpy(chain+off+4,ip,strlen(ip)+1);
        if(i<63)put32(chain+off,0x10000+584+40*i);}
      C(m98_dns_parse_fixed4(chain,4096,0x10000,ascii,NULL,&invalid)==0&&invalid.server_count==64);
      n=sizeof(out);C(m98_dns_query(&invalid,6,0,NULL,NULL,out,&n,NULL,NULL)==0&&n==260&&out[0]==64&&out[259]==63);
      put32(chain+584+40*62,0x10000+584+40*63);memcpy(chain+584+40*63+4,"192.0.2.64",11);
      C(m98_dns_parse_fixed4(chain,4096,0x10000,ascii,NULL,&invalid)==13);free(chain);}
    /* Deterministic structural corruption checks bounds and transactional output. */
    for(i=0;i<5000;++i){uint32_t seed=i*1664525u+1013904223u,idx=seed%704;m98_dns_snapshot old;
        memcpy(bad,b,sizeof(bad));bad[idx]^=(uint8_t)(1u<<(seed>>29));memset(&invalid,0xa5,sizeof(invalid));old=invalid;
        status=m98_dns_parse_fixed4(bad,sizeof(bad),0x10000,ascii,NULL,&invalid);
        C(status==0||status==13);if(status)C(!memcmp(&invalid,&old,sizeof(old)));else C(invalid.server_count<=64);
    }
    printf("PASS: DNS configuration %u checks; no DNS transactions\n",checks);return 0;
}
