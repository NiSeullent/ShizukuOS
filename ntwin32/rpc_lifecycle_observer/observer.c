/* SPDX-License-Identifier: GPL-2.0-only */
#include "observer.h"
#include "../native_environment/environment.h"
static uint16_t u16(const uint8_t *p){return (uint16_t)(p[0]|((uint16_t)p[1]<<8));}
static uint32_t u32(const uint8_t *p){return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static void p32(uint8_t *p,uint32_t n){unsigned i;for(i=0;i<4;i++)p[i]=(uint8_t)(n>>(i*8));}
static int same(const uint8_t *a,const uint8_t *b,size_t n){size_t i;for(i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;}
static int fits(uint32_t a,uint32_t n,uint32_t total){return a<=total&&n<=total-a;}
static int profile_ok(const rpc_profile *p){unsigned w,i;
    if(!p||!p->image_bytes||!fits(p->entry_rva,p->length[0],p->image_bytes)||
       !fits(p->store_rva,p->length[1],p->image_bytes)||!fits(p->state_rva,4,p->image_bytes)||
       !fits(p->flag_rva,4,p->image_bytes)||p->entry_rva==p->store_rva)return 0;
    for(w=0;w<2;w++){
        if(!p->length[w]||p->length[w]>RPC_WINDOW)return 0;
        for(i=0;i<RPC_WINDOW;i++)if(p->relocations[w][i]){
            unsigned j;
            if(p->relocations[w][i]!=1||i>p->length[w]||4>p->length[w]-i)return 0;
            for(j=1;j<4;j++)if(p->relocations[w][i+j])return 0;
        }
    }
    return 1;
}
int rpc_expected_code(const rpc_profile *p,unsigned w,uint32_t base,uint8_t out[RPC_WINDOW]){unsigned i;
    if(!out||w>1||!profile_ok(p)||base>UINT32_MAX-p->image_bytes)return 0;
    for(i=0;i<RPC_WINDOW;i++)out[i]=p->code[w][i];
    for(i=0;i<RPC_WINDOW;i++)if(p->relocations[w][i])p32(out+i,u32(out+i)+base-p->preferred_base);
    return 1;
}
static int file_rva(const uint8_t *f,size_t n,uint32_t table,unsigned sections,uint32_t rva,uint32_t count,uint32_t flags,uint32_t *offset){unsigned i,found=0;
    for(i=0;i<sections;i++){
        const uint8_t *s=f+table+40*i;uint32_t va=u32(s+12),raw=u32(s+16),ro=u32(s+20),attr=u32(s+36);
        if(rva<va||rva-va>raw||count>raw-(rva-va))continue;
        if((attr&flags)!=flags||(flags==0xc0000000u&&(attr&0x10000000u))||!fits(ro,raw,(uint32_t)n)||found)return 0;
        *offset=ro+rva-va;found=1;
    }
    return found;
}
int rpc_file_gate(const uint8_t *f,size_t n,const rpc_profile *p){env_sha h;uint8_t digest[32];uint32_t pe,op,table,offset;unsigned ns,i;
    if(!f||!profile_ok(p)||n!=p->file_bytes||n<512||n>UINT32_MAX)return 0;
    env_sha_init(&h);env_sha_update(&h,f,n);env_sha_final(&h,digest);if(!same(digest,p->sha256,32))return 0;
    pe=u32(f+60);if(u16(f)!=0x5a4d||pe!=p->pe_offset||!fits(pe,248,(uint32_t)n)||u32(f+pe)!=0x4550||u16(f+pe+4)!=0x14c)return 0;
    ns=u16(f+pe+6);if(!ns||ns>32||ns!=p->sections||u32(f+pe+8)!=p->timestamp||u16(f+pe+20)!=224||u16(f+pe+22)!=p->characteristics||(u16(f+pe+22)&0x2000)==0)return 0;
    op=pe+24;table=op+224;if(!fits(table,ns*40,(uint32_t)n)||p->size_headers>p->file_bytes||p->size_headers>p->image_bytes||!fits(table,ns*40,p->size_headers)||u16(f+op)!=0x10b||u32(f+op+16)!=p->entry_rva||
       u32(f+op+28)!=p->preferred_base||u32(f+op+56)!=p->image_bytes||u32(f+op+60)!=p->size_headers)return 0;
    for(i=0;i<ns;i++){
        const uint8_t *s=f+table+i*40;uint32_t va=u32(s+12),vs=u32(s+8),rs=u32(s+16),ro=u32(s+20),j;
        if(!fits(va,vs,p->image_bytes)||!fits(va,rs,p->image_bytes)||!fits(ro,rs,(uint32_t)n)||
           ((vs||rs)&&va<p->size_headers)||(rs&&ro<p->size_headers))return 0;
        for(j=0;j<i;j++){
            const uint8_t *t=f+table+j*40;uint32_t tv=u32(t+12),ts=u32(t+8),tr=u32(t+16),to=u32(t+20);
            uint32_t span=vs>rs?vs:rs,other=ts>tr?ts:tr;
            if(span&&other&&va<tv+other&&tv<va+span)return 0;
            if(rs&&tr&&ro<to+tr&&to<ro+rs)return 0;
        }
    }
    if(!file_rva(f,n,table,ns,p->entry_rva,p->length[0],0x60000000,&offset)||!same(f+offset,p->code[0],p->length[0]))return 0;
    if(!file_rva(f,n,table,ns,p->store_rva,p->length[1],0x60000000,&offset)||!same(f+offset,p->code[1],p->length[1]))return 0;
    return file_rva(f,n,table,ns,p->state_rva,4,0xc0000000,&offset)&&file_rva(f,n,table,ns,p->flag_rva,4,0xc0000000,&offset);
}
void rpc_gap(rpc_runtime *r){if(r)r->incomplete=1;}
static void bump(rpc_runtime *r,uint32_t *n){if(*n==UINT32_MAX){r->counter_overflow=1;rpc_gap(r);}else (*n)++;}
static rpc_thread *thread(rpc_runtime *r,uint32_t id){unsigned i;for(i=0;i<RPC_THREADS;i++)if(r->threads[i].used&&r->threads[i].id==id)return &r->threads[i];return NULL;}
int rpc_context_equal(const rpc_context *a,const rpc_context *b){unsigned i;
    for(i=0;i<R_COUNT;i++)if(i==R_DR6){if((a->v[i]&RPC_STATUS_MASK)!=(b->v[i]&RPC_STATUS_MASK))return 0;}else if(a->v[i]!=b->v[i])return 0;
    return 1;
}
static int code_live(rpc_runtime *r,const rpc_ops *ops,unsigned w){uint8_t expected[RPC_WINDOW],actual[RPC_WINDOW];uint32_t rva=w?r->profile->store_rva:r->profile->entry_rva;
    return rpc_expected_code(r->profile,w,r->base,expected)&&ops->read_memory(ops->opaque,r->base+rva,actual,r->profile->length[w])&&same(expected,actual,r->profile->length[w]);
}
static int arm(rpc_runtime *r,rpc_thread *t,const rpc_ops *ops){rpc_context before,after,verify;
    if(!t->handle||!ops->read_context(ops->opaque,t->handle,&before)){rpc_gap(r);return 0;}
    if((before.v[R_DR7]&0x20ffu)||(before.v[R_FLAGS]&0x100u)||
       (before.v[R_DR6]&RPC_STATUS_MASK)){rpc_gap(r);return 0;}
    t->original=before;after=before;after.v[R_DR0]=r->base+r->profile->entry_rva;after.v[R_DR1]=r->base+r->profile->store_rva;
    after.v[R_DR6]=before.v[R_DR6]&~3u;after.v[R_DR7]=(before.v[R_DR7]&~RPC_DR_MASK)|5u;t->armed=1;
    if(!ops->write_debug(ops->opaque,t->handle,&after)||!ops->read_context(ops->opaque,t->handle,&verify)||!rpc_context_equal(&after,&verify)){r->unsafe=1;rpc_gap(r);return RPC_UNSAFE;}
    bump(r,&r->arms);return 1;
}
int rpc_add_thread(rpc_runtime *r,uint32_t id,uintptr_t handle,const rpc_ops *ops){unsigned i;rpc_thread *t=NULL;
    if(!r||!id||!ops||thread(r,id)){rpc_gap(r);return 0;}
    for(i=0;i<RPC_THREADS;i++)if(!r->threads[i].used){t=&r->threads[i];break;}
    if(!t){rpc_gap(r);return 0;}t->used=1;t->armed=0;t->id=id;t->handle=handle;t->hits[0]=t->hits[1]=0;bump(r,&r->created);
    return r->base?arm(r,t,ops):1;
}
int rpc_bind_module(rpc_runtime *r,const rpc_profile *p,uint32_t base,const rpc_ops *ops){unsigned i;int result=1;
    if(!r||!ops||!base||!profile_ok(p)||base>UINT32_MAX-p->image_bytes||r->base){rpc_gap(r);return 0;}
    r->profile=p;r->base=base;
    if(!code_live(r,ops,0)||!code_live(r,ops,1)){r->base=0;r->profile=NULL;rpc_gap(r);return 0;}
    bump(r,&r->generations);
    for(i=0;i<RPC_THREADS;i++)if(r->threads[i].used){int n=arm(r,&r->threads[i],ops);if(n==RPC_UNSAFE)return n;if(!n)result=0;}
    return result;
}
int rpc_unbind_module(rpc_runtime *r,const rpc_ops *ops){unsigned i;
    if(!r||!ops||!r->base){rpc_gap(r);return 0;}
    for(i=0;i<RPC_THREADS;i++)if(r->threads[i].used&&r->threads[i].armed){rpc_thread *t=&r->threads[i];rpc_context before,after,verify;
        if(!ops->read_context(ops->opaque,t->handle,&before)){r->unsafe=1;rpc_gap(r);return RPC_UNSAFE;}
        /* Restore only still-owned slots. Never erase target/OS changes to
         * DR2/3, their controls, global flags or unrelated status bits. */
        if(before.v[R_DR0]!=r->base+r->profile->entry_rva||
           before.v[R_DR1]!=r->base+r->profile->store_rva||
           (before.v[R_DR7]&RPC_DR_MASK)!=5u){r->unsafe=1;rpc_gap(r);return RPC_UNSAFE;}
        after=before;after.v[R_DR0]=t->original.v[R_DR0];after.v[R_DR1]=t->original.v[R_DR1];
        after.v[R_DR6]=(before.v[R_DR6]&~3u)|(t->original.v[R_DR6]&3u);
        after.v[R_DR7]=(before.v[R_DR7]&~RPC_DR_MASK)|(t->original.v[R_DR7]&RPC_DR_MASK);
        if(!ops->write_debug(ops->opaque,t->handle,&after)||!ops->read_context(ops->opaque,t->handle,&verify)||!rpc_context_equal(&after,&verify)){r->unsafe=1;rpc_gap(r);return RPC_UNSAFE;}
        t->armed=0;bump(r,&r->restores);
    }
    r->base=0;r->profile=NULL;return 1;
}
int rpc_retire_thread(rpc_runtime *r,uint32_t id){rpc_thread *t=thread(r,id);if(!t){rpc_gap(r);return 0;}t->used=t->armed=0;t->handle=0;bump(r,&r->exit_threads);return 1;}
void rpc_retire_process(rpc_runtime *r){unsigned i;for(i=0;i<RPC_THREADS;i++)if(r->threads[i].used){r->threads[i].used=r->threads[i].armed=0;r->threads[i].handle=0;bump(r,&r->process_retired);}}
int rpc_observe(rpc_runtime *r,uint32_t id,uint32_t code,unsigned first,uint32_t address,const rpc_ops *ops,rpc_context *observed){rpc_thread *t;rpc_context c,after,verify;uint32_t mask;unsigned w;
    if(!r||!r->base||!ops||!observed||code!=0x80000004u||first!=1)return RPC_PASS;
    t=thread(r,id);if(!t||!t->armed)return RPC_PASS;
    if(!ops->read_context(ops->opaque,t->handle,&c)){r->unsafe=1;rpc_gap(r);return RPC_UNSAFE;}
    mask=c.v[R_DR6]&RPC_STATUS_MASK;if(mask!=1&&mask!=2)return RPC_PASS;w=mask==2;
    if(c.v[R_EIP]!=address||address!=r->base+(w?r->profile->store_rva:r->profile->entry_rva)||
       c.v[R_DR0]!=r->base+r->profile->entry_rva||c.v[R_DR1]!=r->base+r->profile->store_rva||
       (c.v[R_DR7]&RPC_DR_MASK)!=5u)return RPC_PASS;
    if(!code_live(r,ops,w)){r->unsafe=1;rpc_gap(r);return RPC_UNSAFE;}
    *observed=c;after=c;after.v[R_FLAGS]|=RPC_RF;after.v[R_DR6]&=~mask;
    if(!ops->write_resume(ops->opaque,t->handle,&after)||!ops->read_context(ops->opaque,t->handle,&verify)||!rpc_context_equal(&after,&verify)){r->unsafe=1;rpc_gap(r);return RPC_UNSAFE;}
    bump(r,&r->hits[w]);bump(r,&t->hits[w]);return w?RPC_STORE:RPC_ENTRY;
}
int rpc_complete(const rpc_runtime *r){unsigned i;if(!r||r->incomplete||r->unsafe||r->counter_overflow||!r->generations||!r->hits[0])return 0;for(i=0;i<RPC_THREADS;i++)if(r->threads[i].used)return 0;return 1;}
