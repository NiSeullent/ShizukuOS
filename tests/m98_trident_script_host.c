/* SPDX-License-Identifier: GPL-2.0-only
 * Real QuickJS execution with portable Automation doubles; no native claim. */
#include "m98_trident_script.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
static unsigned checks,retains,releases,result_cleanups,gets,calls;
static _Thread_local uint32_t thread_id=7;
static uint32_t callback,active;
static int reenter,invalid_return,retain_fail,change_fp;
static int32_t last_integer;
static const uint16_t root_name[]={'d','o','c','u','m','e','n','t'};
static const uint16_t sum_name[]={'s','u','m'};
static const uint16_t special[]={65,0,0xd800,0xdc00,0xdfff,0xd801};
#define C(x) do{++checks;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);}}while(0)
uint32_t m98_script_thread_id(void){return thread_id;}
int m98_script_platform_ready(void){return 0;}
static void value(m98_script_value *v,uint32_t type){memset(v,0,sizeof(*v));v->size=sizeof(*v);v->type=type;}
static unsigned short control(void){unsigned short word;__asm__ volatile("fnstcw %0":"=m"(word));return word;}
static unsigned short status_word(void){unsigned short word;__asm__ volatile("fnstsw %0":"=am"(word));return word;}
static int name_is(const uint16_t *p,uint32_t n,const char *text){uint32_t i;if(strlen(text)!=n)return 0;for(i=0;i<n;++i)if(p[i]!=(unsigned char)text[i])return 0;return 1;}
static int32_t get(void *user,uint32_t object,const uint16_t *name,uint32_t n,m98_script_value *out){(void)user;C(object==1);++gets;
    if(reenter){m98_script_details info={.size=sizeof(info)};reenter=0;C(m98_script_info(active,&info)==M98_SCRIPT_BUSY);}
    if(invalid_return){value(out,999);return 0;}
    if(name_is(name,n,"changeFP")){unsigned short altered=0x0a7f;__asm__ volatile("fldcw %0"::"m"(altered));value(out,M98_SCRIPT_INT32);out->integer=1;return 0;}
    if(name_is(name,n,"fp")){value(out,M98_SCRIPT_INT32);out->integer=control();return 0;}
    if(name_is(name,n,"again")){value(out,M98_SCRIPT_OBJECT);out->cookie=1;return 0;}
    if(name_is(name,n,"number")){value(out,M98_SCRIPT_INT32);out->integer=last_integer;return 0;}
    if(name_is(name,n,"special")){value(out,M98_SCRIPT_STRING);out->units=6;
        uint16_t *p=malloc(sizeof(special));C(p!=NULL);memcpy(p,special,sizeof(special));out->string=p;return 0;}
    if(name_is(name,n,"sum")){value(out,M98_SCRIPT_METHOD);out->cookie=1;out->string=sum_name;out->units=3;return 0;}
    value(out,M98_SCRIPT_STRING);out->units=2;uint16_t *p=malloc(4);C(p!=NULL);p[0]='E';p[1]='!';out->string=p;
    return (int32_t)0x80020003u;
}
static int32_t set(void *user,uint32_t object,const uint16_t *name,uint32_t n,const m98_script_value *in){(void)user;C(object==1);
    if(name_is(name,n,"number")){C(in->type==M98_SCRIPT_INT32);last_integer=in->integer;return 0;}
    if(name_is(name,n,"event")){C(in->type==M98_SCRIPT_FUNCTION&&in->cookie);callback=in->cookie;return 0;}
    if(name_is(name,n,"special")){C(in->type==M98_SCRIPT_STRING&&in->units==6&&!memcmp(in->string,special,sizeof(special)));return 0;}
    return (int32_t)0x80020003u;
}
static int32_t call(void *user,uint32_t object,const uint16_t *name,uint32_t n,const m98_script_value *args,uint32_t count,m98_script_value *out){(void)user;C(object==1&&name_is(name,n,"sum")&&count==2);C(args[0].type==M98_SCRIPT_INT32&&args[1].type==M98_SCRIPT_INT32);++calls;
    value(out,M98_SCRIPT_INT32);out->integer=args[0].integer+args[1].integer;return 0;
}
static int32_t retain(void *user,uint32_t object){(void)user;C(object==1);if(retain_fail)return (int32_t)0x80004005u;++retains;return 0;}
static void release(void *user,uint32_t object){(void)user;C(object==1);++releases;}
static void cleanup(void *user,m98_script_value *out){(void)user;++result_cleanups;if(change_fp){unsigned short altered=0x0a7f;__asm__ volatile("fldcw %0"::"m"(altered));}if(out->type==M98_SCRIPT_STRING)free((void *)out->string);}
static m98_script_host host={sizeof(host),NULL,get,set,call,retain,release,cleanup};
static m98_script_options options(void){m98_script_options o={sizeof(o),8u<<20,262144,100,32,&host};return o;}
static m98_script_result run(uint32_t h,const char *code,int expected){m98_script_result r={.size=sizeof(r)};int status=m98_script_eval(h,code,(uint32_t)strlen(code),&r);
    if(status!=expected){m98_script_details detail={.size=sizeof(detail)};m98_script_info(h,&detail);
        fprintf(stderr,"expected %d actual %d error %.255s source %.512s\n",expected,status,detail.exception_utf8,code);}
    C(status==expected);C(expected?(!r.lease):(r.lease&&r.value.size==sizeof(r.value)));return r;}
static void drop(uint32_t h,m98_script_result *r){C(m98_script_release_result(h,r->lease)==0);memset(r,0,sizeof(*r));}
static void expect_int(uint32_t h,const char *source,int32_t expected){m98_script_result r=run(h,source,0);C(r.value.type==M98_SCRIPT_INT32&&r.value.integer==expected);drop(h,&r);}
static void semantic_fixture(uint32_t h,const char *path,const char *expected){char source[16384];FILE *file=fopen(path,"rb");size_t n;unsigned i;
    C(file!=NULL);n=fread(source,1,sizeof(source)-1,file);C(n>0&&!ferror(file)&&feof(file));C(fclose(file)==0);source[n]=0;
    m98_script_result r=run(h,source,0);C(r.value.type==M98_SCRIPT_STRING&&r.value.units==strlen(expected));
    for(i=0;i<r.value.units;++i)C(r.value.string[i]==(unsigned char)expected[i]);
    drop(h,&r);printf("semantic_json=%s\n",expected);
}
static void *foreign_thread(void *cookie){uint32_t h=*(uint32_t *)cookie;m98_script_details info={.size=sizeof(info)};
    thread_id=9;C(m98_script_info(h,&info)==M98_SCRIPT_THREAD);C(m98_script_close(h)==M98_SCRIPT_THREAD);return NULL;
}
int main(void){m98_script_options o=options();m98_script_result r,held[16];m98_script_details info={.size=sizeof(info)};
    uint32_t h,old,jobs,fn,second;unsigned i;int status;
    C(m98_script_open(&o,&h)==0&&h);active=h;
    expect_int(h,"typeof Atomics==='undefined'&&typeof SharedArrayBuffer==='undefined'?1:0",1);
    expect_int(h,"(()=>{let a={x:3}; return a?.x ?? 9})()",3);
    expect_int(h,"[1,2,3].map(x=>x*2).reduce((a,b)=>a+b,0)",12);
    expect_int(h,"class A{#x=7; get(){return this.#x}}; new A().get()",7);
    expect_int(h,"Number((2n**64n)>>60n)",16);
    expect_int(h,"new Set([1,1,2]).size + new Uint8Array([3,4])[1]",6);
    expect_int(h,"/\\p{Letter}+/u.test('한국어')?1:0",1);
    expect_int(h,"Math.sumPrecise([1e20,1,-1e20])",1);
    expect_int(h,"Math.f16round(1.0001)===1?1:0",1);
    expect_int(h,"Date.UTC(2026,0,1)===1767225600000?1:0",1);
    expect_int(h,"Date.now()>1700000000000 && Number.isFinite(new Date().getTimezoneOffset())?1:0",1);
    semantic_fixture(h,"tests/trident_es2026_selected.js","{\"scope\":\"selected ES2026 semantic checks\",\"checks\":34,\"full_conformance_verified\":false,\"browser_dom_verified\":false}");
    semantic_fixture(h,"tests/trident_numeric_selected.js","{\"scope\":\"selected numeric semantics\",\"checks\":24,\"full_conformance_verified\":false,\"native_math_verified\":false}");
    expect_int(h,"JSON.stringify([NaN,Infinity,-Infinity,-0,1e21,1e-7,1.337])==='[null,null,null,0,1e+21,1e-7,1.337]'?1:0",1);
    expect_int(h,"String(NaN)==='NaN'&&String(Infinity)==='Infinity'&&String(-Infinity)==='-Infinity'&&String(-0)==='0'?1:0",1);
    r=run(h,"typeof document==='undefined' && typeof std==='undefined' && typeof os==='undefined'",0);C(r.value.type==M98_SCRIPT_BOOL&&r.value.integer);drop(h,&r);
    C(m98_script_bind_root(h,root_name,8,1)==0&&retains==1);
    unsigned char saved_fp[108] __attribute__((aligned(16)));unsigned short altered=0x0a7f;
    __asm__ volatile("fnsave %0\n\tfldcw %1":"=m"(saved_fp):"m"(altered):"memory");
    /* A caller's sticky invalid flag must survive without adding the script's
     * different divide-by-zero flag. This is an actual x87 environment test. */
    __asm__ volatile("fldz\n\tfldz\n\tfdivp\n\tfstp %%st(0)":::"memory");
    unsigned short before_status=status_word();C(control()==altered&&(before_status&1));
    change_fp=1;expect_int(h,"document.changeFP; document.fp",0x037f);change_fp=0;
    expect_int(h,"document.fp",0x037f);expect_int(h,"Math.log(0)===-Infinity?1:0",1);
    C(control()==altered&&status_word()==before_status);
    __asm__ volatile("frstor %0"::"m"(saved_fp):"memory");
    C(m98_script_bind_root(h,root_name,8,1)==M98_SCRIPT_STATE&&retains==1);
    expect_int(h,"document === document.again ? 1:0",1);C(retains==1);
    r=run(h,"document.special",0);C(r.value.type==M98_SCRIPT_STRING&&r.value.units==6&&!memcmp(r.value.string,special,sizeof(special)));drop(h,&r);
    expect_int(h,"document.special=document.special; document.number=11; document.number",11);
    reenter=1;expect_int(h,"document.number",11);C(!reenter);
    expect_int(h,"document.sum(8,9)",17);C(calls==1);
    expect_int(h,"document.sum===document.sum?1:0",1);
    r=run(h,"document.absent",M98_SCRIPT_HOST);C(m98_script_info(h,&info)==0&&info.host_hresult==(int32_t)0x80020003u);
    invalid_return=1;r=run(h,"document.number",M98_SCRIPT_HOST);invalid_return=0;
    expect_int(h,"globalThis.p=0; Promise.resolve(4).then(x=>p=x); p",0);
    C(m98_script_jobs(h,&jobs)==0&&jobs>0);expect_int(h,"p",4);
    r=run(h,"globalThis.f=(x)=>x+3; document.event=f; f",0);C(r.value.type==M98_SCRIPT_FUNCTION&&r.value.cookie==callback);fn=callback;drop(h,&r);
    r=run(h,"f",0);C(r.value.cookie==fn);drop(h,&r);
    m98_script_value arg;value(&arg,M98_SCRIPT_INT32);arg.integer=8;r=(m98_script_result){.size=sizeof(r)};
    C(m98_script_invoke(h,fn,&arg,1,&r)==0&&r.value.type==M98_SCRIPT_INT32&&r.value.integer==11);drop(h,&r);
    r=run(h,"(function(x){return this.number+x})",0);fn=r.value.cookie;drop(h,&r);
    m98_script_value receiver;value(&receiver,M98_SCRIPT_OBJECT);receiver.cookie=1;r=(m98_script_result){.size=sizeof(r)};
    C(m98_script_invoke_this(h,fn,&receiver,&arg,1,&r)==0&&r.value.type==M98_SCRIPT_INT32&&r.value.integer==19);drop(h,&r);
    thread_id=9;C(m98_script_info(h,&info)==M98_SCRIPT_THREAD);C(m98_script_close(h)==M98_SCRIPT_THREAD);thread_id=7;
    pthread_t other_thread;C(pthread_create(&other_thread,NULL,foreign_thread,&h)==0);C(pthread_join(other_thread,NULL)==0);
    expect_int(h,"globalThis.capacityCounter=0",0);
    r=run(h,"(()=>++capacityCounter)",0);fn=r.value.cookie;drop(h,&r);
    for(i=0;i<16;++i)held[i]=run(h,"'held copied string'",0);
    r=run(h,"++capacityCounter; document.number=88",M98_SCRIPT_LIMIT);
    r=(m98_script_result){.size=sizeof(r)};C(m98_script_invoke(h,fn,NULL,0,&r)==M98_SCRIPT_LIMIT&&!r.lease);
    for(i=0;i<16;++i)drop(h,&held[i]);
    expect_int(h,"capacityCounter",0);expect_int(h,"document.number",11);
    r=run(h,"while(true){}",M98_SCRIPT_LIMIT);C(m98_script_info(h,&info)==0&&info.interrupt_checks>0&&info.interrupt_checks<=101);
    expect_int(h,"2+2",4);r=run(h,"function recur(){recur()}; recur()",M98_SCRIPT_EXCEPTION);
    r=run(h,"'x'.repeat(32000000)",M98_SCRIPT_EXCEPTION);expect_int(h,"3+4",7);
    expect_int(h,"globalThis.moduleDenied=0; import('os').catch(()=>moduleDenied=1); 0",0);
    C(m98_script_jobs(h,&jobs)==0);expect_int(h,"moduleDenied",1);
    C(m98_script_open(&o,&second)==0&&second!=h);expect_int(second,"typeof document==='undefined'?1:0",1);C(m98_script_close(second)==0);
    old=h;C(m98_script_close(h)==0&&releases==retains);C(m98_script_info(old,&info)==M98_SCRIPT_STATE);
    C(m98_script_open(&o,&h)==0&&h!=old);active=h;r=(m98_script_result){.size=sizeof(r)};
    C(m98_script_invoke(h,fn,NULL,0,&r)==M98_SCRIPT_STATE);
    retain_fail=1;C(m98_script_bind_root(h,root_name,8,1)==M98_SCRIPT_HOST);retain_fail=0;C(m98_script_close(h)==0&&releases==retains);
    o=options();o.job_limit=2;C(m98_script_open(&o,&h)==0);r=run(h,"function again(){Promise.resolve().then(again)}; again(); 0",0);drop(h,&r);
    C(m98_script_jobs(h,&jobs)==M98_SCRIPT_LIMIT&&jobs==2);C(m98_script_close(h)==0);
    o=options();C(m98_script_open(&o,&h)==0);r=(m98_script_result){.size=sizeof(r)};
    const char bad_utf8[]={ (char)0xed,(char)0xa0,(char)0x80 };C(m98_script_eval(h,bad_utf8,3,&r)==M98_SCRIPT_INVALID);
    for(i=0;i<256;++i){r=run(h,"(()=>1)",0);drop(h,&r);}r=run(h,"(()=>1)",M98_SCRIPT_EXCEPTION);C(m98_script_close(h)==0);
    o=options();o.memory_bytes=1;status=m98_script_open(&o,&h);C(status==M98_SCRIPT_INVALID&&!h);
    C(result_cleanups==gets+calls);printf("PASS: real bounded QuickJS host %u assertions; Automation doubles, native pending\n",checks);return 0;
}
