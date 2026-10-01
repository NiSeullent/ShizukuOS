/* SPDX-License-Identifier: GPL-2.0-only
 * Tests the production codec and transaction, with OS operations replaced only
 * at their side-effect boundary. No host registry or system palette is used.
 * Source-only until the integration owner admits a bounded compiler/test run.
 */
#include "selector_core.h"
#include <stdio.h>
#include <string.h>

static unsigned checks, failures;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; \
    fprintf(stderr, "FAIL line %u: %s\n", (unsigned)__LINE__, #x); } } while (0)

enum fault { NO_FAULT, READ_PROFILE, READ_RUN, GET_COLORS, SET_COLORS,
    VERIFY_COLORS, WRITE_PROFILE, FLUSH_PROFILE, VERIFY_PROFILE,
    WRITE_RUN, FLUSH_RUN, VERIFY_RUN };
typedef struct fixture {
    uint32_t colors[SHZ_THEME_COLORS];
    shz_theme_value values[2];
    enum fault fault;
    unsigned fault_seen, writes, sets, value_written[2];
    unsigned rollback_failure;
} fixture;

static void le32(unsigned char *p, uint32_t v)
{ p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8); p[2]=(unsigned char)(v>>16); p[3]=(unsigned char)(v>>24); }
static void reset(fixture *f)
{
    unsigned i; memset(f,0,sizeof(*f));
    for(i=0;i<SHZ_THEME_COLORS;++i) f->colors[i]=i*0x010101u;
}
/* A hand-derived valid Classic record, independent of the production encoder. */
static void classic_record(shz_theme_value *v)
{
    unsigned i; memset(v,0,sizeof(*v)); v->present=1;
    v->type=SHZ_THEME_REG_BINARY; v->bytes=224;
    memcpy(v->data,"SHZCLR1",8); le32(v->data+8,1); le32(v->data+12,224);
    le32(v->data+16,0); le32(v->data+20,25);
    for(i=0;i<25;++i){le32(v->data+24+i*4,i*0x010101u);le32(v->data+124+i*4,i*0x010101u);}
}
static int trip(fixture *f, enum fault fault, uint32_t *error)
{
    if(f->fault==fault && !f->fault_seen){f->fault_seen=1;*error=1117;return 1;}
    return 0;
}
static int get_colors(void *context,uint32_t *out,uint32_t *error)
{
    fixture *f=context;
    if(trip(f,GET_COLORS,error))return 0;
    memcpy(out,f->colors,sizeof(f->colors));
    if(f->sets && trip(f,VERIFY_COLORS,error)) out[0]^=1;
    return 1;
}
static int set_colors(void *context,const uint32_t *in,uint32_t *error)
{
    fixture *f=context; ++f->sets; memcpy(f->colors,in,sizeof(f->colors));
    if(f->sets>1 && (f->rollback_failure&SHZ_THEME_ROLLBACK_COLORS)){f->colors[0]^=1;*error=5;return 0;}
    return !trip(f,SET_COLORS,error); /* Failed call already changed real fake state. */
}
static int read_value(void *context,unsigned target,shz_theme_value *out,uint32_t *error)
{
    fixture *f=context;
    if(!f->value_written[target] && trip(f,target?READ_RUN:READ_PROFILE,error))return 0;
    *out=f->values[target];
    if(f->value_written[target] && trip(f,target?VERIFY_RUN:VERIFY_PROFILE,error))out->bytes=0;
    return 1;
}
static int write_value(void *context,unsigned target,const shz_theme_value *value,uint32_t *error)
{
    fixture *f=context; ++f->writes; ++f->value_written[target]; f->values[target]=*value;
    if(f->value_written[target]>1 && (f->rollback_failure&(target?SHZ_THEME_ROLLBACK_RUN:SHZ_THEME_ROLLBACK_PROFILE))){*error=5;return 0;}
    return !trip(f,target?WRITE_RUN:WRITE_PROFILE,error);
}
static int flush_value(void *context,unsigned target,uint32_t *error)
{ fixture *f=context; return !trip(f,target?FLUSH_RUN:FLUSH_PROFILE,error); }
static shz_theme_ops operations(fixture *f)
{
    shz_theme_ops o={f,get_colors,set_colors,read_value,write_value,flush_value};return o;
}

static void codec_rejects_damage_without_changing_output(void)
{
    shz_theme_value v; shz_theme_profile p, before; unsigned char encoded[224],damaged[225];
    const unsigned offsets[]={0,8,12,16,20,27,127}; unsigned i;
    classic_record(&v); memset(&p,0x5a,sizeof(p));
    CHECK(shz_theme_decode(v.data,224,&p)); CHECK(p.style==0 && p.baseline[24]==0x181818u);
    CHECK(shz_theme_encode(&p,encoded) && !memcmp(encoded,v.data,224));
    for(i=0;i<sizeof(offsets)/sizeof(offsets[0]);++i){
        memcpy(damaged,v.data,224);damaged[offsets[i]]^=0x80;before=p;
        CHECK(!shz_theme_decode(damaged,224,&p)); CHECK(!memcmp(&before,&p,sizeof(p)));
    }
    before=p; CHECK(!shz_theme_decode(v.data,223,&p));
    memcpy(damaged,v.data,224);damaged[224]=0;
    CHECK(!shz_theme_decode(damaged,225,&p)); CHECK(!memcmp(&before,&p,sizeof(p)));
    p.selected[0]^=1; CHECK(!shz_theme_encode(&p,encoded));
}
static void command_and_startup_paths_are_bounded(void)
{
    const char *valid[]={"selector.exe","\"C:\\Theme Files\\selector.exe\" /restore","selector.exe /restore\t "};
    const int mode[]={0,1,1}; const char *invalid[]={"","selector.exe /restorex","selector.exe /restore extra","selector.exe \"/restore\"","\"selector.exe","selector.exe\" /restore"};
    const char path[]="C:\\Theme Files\\selector.exe";char long_path[261];shz_theme_value v,before;unsigned i;
    for(i=0;i<3;++i)CHECK(shz_theme_command_mode(valid[i],strlen(valid[i]))==mode[i]);
    for(i=0;i<6;++i)CHECK(shz_theme_command_mode(invalid[i],strlen(invalid[i]))==-1);
    CHECK(shz_theme_startup_value(path,sizeof(path)-1,&v));
    CHECK(v.type==1 && !strcmp((const char *)v.data,"\"C:\\Theme Files\\selector.exe\" /restore"));
    CHECK(v.bytes==strlen((const char *)v.data)+1);
    CHECK(!shz_theme_startup_value("relative.exe",12,&v));
    CHECK(!shz_theme_startup_value("C:\\bad\".exe",11,&v));
    memset(long_path,'a',sizeof(long_path));long_path[0]='C';long_path[1]=':';long_path[2]='\\';
    CHECK(shz_theme_startup_value(long_path,248,&v));CHECK(v.bytes==260 && v.data[259]==0);
    before=v;CHECK(!shz_theme_startup_value(long_path,249,&v));CHECK(!memcmp(&v,&before,sizeof(v)));
    CHECK(!shz_theme_startup_value(long_path,260,&v));CHECK(!memcmp(&v,&before,sizeof(v)));
    CHECK(!shz_theme_startup_value(long_path,(size_t)-1,&v));CHECK(!memcmp(&v,&before,sizeof(v)));
}
static void invalid_or_unreadable_snapshots_never_write(void)
{
    fixture f;shz_theme_ops o;shz_theme_result result;shz_theme_value run;unsigned i;
    CHECK(shz_theme_startup_value("C:\\SHZTHEME.EXE",15,&run));
    for(i=0;i<10;++i){
        reset(&f);o=operations(&f);
        if(i==0)f.fault=READ_PROFILE;
        if(i==1){classic_record(&f.values[0]);f.values[0].data[0]='X';}
        if(i==2)f.fault=READ_RUN;
        if(i==3){f.values[1].present=1;f.values[1].type=3;f.values[1].bytes=1;}
        if(i==4){f.values[1].present=1;f.values[1].type=2;f.values[1].bytes=513;}
        if(i==5)f.fault=GET_COLORS;
        if(i==6){classic_record(&f.values[0]);f.values[0].type=1;}
        if(i==7){classic_record(&f.values[0]);f.values[0].bytes=223;}
        if(i==8){f.values[1].present=1;f.values[1].type=1;f.values[1].bytes=2;memcpy(f.values[1].data,"xx",2);}
        if(i==9){f.values[1].present=1;f.values[1].type=1;f.values[1].bytes=3;f.values[1].data[1]='x';}
        CHECK(!shz_theme_apply(&o,f.colors,1,&run,&result));
        CHECK(f.sets==0 && f.writes==0 && result.status==SHZ_THEME_FAILED);
    }
}
static void success_preserves_baseline_and_can_return_to_classic(void)
{
    fixture f;shz_theme_ops o;shz_theme_result result;shz_theme_value run;shz_theme_profile p;uint32_t baseline[25];
    reset(&f);o=operations(&f);memcpy(baseline,f.colors,sizeof(baseline));
    CHECK(shz_theme_startup_value("C:\\SHZTHEME.EXE",15,&run));
    CHECK(shz_theme_apply(&o,baseline,1,&run,&result)); CHECK(result.status==SHZ_THEME_OK);
    CHECK(f.colors[2]==0x00d77800u && f.colors[15]==0x00f0f0f0u);
    CHECK(shz_theme_decode(f.values[0].data,f.values[0].bytes,&p));
    CHECK(!memcmp(p.baseline,baseline,sizeof(baseline)) && p.style==1);
    /* Passing the CURRENT ShizukuOS palette must not replace the stored baseline. */
    CHECK(shz_theme_apply(&o,f.colors,0,&run,&result));
    CHECK(!memcmp(f.colors,baseline,sizeof(baseline)));
}
static void every_post_mutation_failure_restores_real_previous_state(void)
{
    const enum fault faults[]={SET_COLORS,VERIFY_COLORS,WRITE_PROFILE,FLUSH_PROFILE,VERIFY_PROFILE,WRITE_RUN,FLUSH_RUN,VERIFY_RUN};
    fixture f;shz_theme_ops o;shz_theme_result result;shz_theme_value run,old[2];uint32_t colors[25];unsigned i,present;
    CHECK(shz_theme_startup_value("C:\\SHZTHEME.EXE",15,&run));
    for(present=0;present<2;++present)for(i=0;i<sizeof(faults)/sizeof(faults[0]);++i){
        reset(&f);o=operations(&f);f.fault=faults[i];
        if(present){classic_record(&f.values[0]);f.values[1].present=1;f.values[1].type=2;f.values[1].bytes=13;memcpy(f.values[1].data,"%TEMP%\\x.exe",13);}
        memcpy(old,f.values,sizeof(old));memcpy(colors,f.colors,sizeof(colors));
        CHECK(!shz_theme_apply(&o,colors,1,&run,&result));
        CHECK(result.status==SHZ_THEME_FAILED && result.rollback_attempted && !result.rollback_failed);
        CHECK(!memcmp(f.colors,colors,sizeof(colors)) && !memcmp(f.values,old,sizeof(old)));
    }
}
static void rollback_failure_is_explicit_and_other_restores_still_run(void)
{
    fixture f;shz_theme_ops o;shz_theme_result result;shz_theme_value run;unsigned bit;
    CHECK(shz_theme_startup_value("C:\\SHZTHEME.EXE",15,&run));
    for(bit=1;bit<=4;bit*=2){
        reset(&f);o=operations(&f);f.fault=WRITE_RUN;f.rollback_failure=bit;
        CHECK(!shz_theme_apply(&o,f.colors,1,&run,&result));
        CHECK(result.status==SHZ_THEME_ROLLBACK_FAILED && (result.rollback_failed&bit));
        CHECK(!f.values[0].present && !f.values[1].present && result.rollback_error==5);
    }
}
static void restore_requires_a_valid_profile_and_never_writes_registry(void)
{
    fixture f;shz_theme_ops o;shz_theme_result result;unsigned i;
    for(i=0;i<3;++i){reset(&f);o=operations(&f);if(i){classic_record(&f.values[0]);if(i==1)f.values[0].data[20]=24;}
        if(i==2)CHECK(shz_theme_restore(&o,&result));else CHECK(!shz_theme_restore(&o,&result));
        CHECK(f.writes==0);if(i!=2)CHECK(f.sets==0);
    }
}
int main(void)
{
    codec_rejects_damage_without_changing_output();command_and_startup_paths_are_bounded();
    invalid_or_unreadable_snapshots_never_write();success_preserves_baseline_and_can_return_to_classic();
    every_post_mutation_failure_restores_real_previous_state();rollback_failure_is_explicit_and_other_restores_still_run();
    restore_requires_a_valid_profile_and_never_writes_registry();
    if(failures){fprintf(stderr,"FAIL: %u/%u checks\n",failures,checks);return 1;}
    printf("PASS: %u selector codec/transaction checks\n",checks);return 0;
}
