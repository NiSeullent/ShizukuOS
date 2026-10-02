/* SPDX-License-Identifier: GPL-2.0-only */
#include "selector_core.h"

#define RGB_VALUE(r,g,b) ((uint32_t)(r) | ((uint32_t)(g)<<8) | ((uint32_t)(b)<<16))
static const unsigned char magic[8]={'S','H','Z','C','L','R','1',0};
static const uint32_t shizuku_colors[SHZ_THEME_COLORS]={
    RGB_VALUE(207,207,207), RGB_VALUE(19,46,69), RGB_VALUE(0,120,215),
    RGB_VALUE(120,128,136), RGB_VALUE(240,240,240), RGB_VALUE(255,255,255),
    RGB_VALUE(64,80,96), RGB_VALUE(0,0,0), RGB_VALUE(0,0,0), RGB_VALUE(255,255,255),
    RGB_VALUE(160,160,160), RGB_VALUE(192,192,192), RGB_VALUE(160,160,160),
    RGB_VALUE(0,120,215), RGB_VALUE(255,255,255), RGB_VALUE(240,240,240),
    RGB_VALUE(160,160,160), RGB_VALUE(128,128,128), RGB_VALUE(0,0,0),
    RGB_VALUE(240,240,240), RGB_VALUE(255,255,255), RGB_VALUE(96,96,96),
    RGB_VALUE(224,224,224), RGB_VALUE(0,0,0), RGB_VALUE(255,255,225)
};

static void zero(void *memory,size_t count)
{ unsigned char *p=memory;size_t i;for(i=0;i<count;++i)p[i]=0; }
static int equal(const void *a,const void *b,size_t count)
{ const unsigned char *x=a,*y=b;size_t i;for(i=0;i<count;++i)if(x[i]!=y[i])return 0;return 1; }
static void put32(unsigned char *p,uint32_t value)
{ unsigned i;for(i=0;i<4;++i)p[i]=(unsigned char)(value>>(i*8)); }
static uint32_t get32(const unsigned char *p)
{ return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static int valid_colors(const uint32_t *colors)
{ unsigned i;if(!colors)return 0;for(i=0;i<SHZ_THEME_COLORS;++i)if(colors[i]&0xff000000u)return 0;return 1; }
static int valid_profile(const shz_theme_profile *profile)
{
    unsigned i;
    if(!profile || profile->style>SHZ_THEME_SHIZUKUOS || !valid_colors(profile->baseline) || !valid_colors(profile->selected))return 0;
    for(i=0;i<SHZ_THEME_COLORS;++i)
        if(profile->selected[i]!=(profile->style==SHZ_THEME_CLASSIC?profile->baseline[i]:shizuku_colors[i]))return 0;
    return 1;
}
int shz_theme_make(uint32_t style,const uint32_t *baseline,shz_theme_profile *out)
{
    unsigned i;
    if(!out || style>SHZ_THEME_SHIZUKUOS || !valid_colors(baseline))return 0;
    out->style=style;
    for(i=0;i<SHZ_THEME_COLORS;++i){out->baseline[i]=baseline[i];out->selected[i]=style?shizuku_colors[i]:baseline[i];}
    return 1;
}
int shz_theme_encode(const shz_theme_profile *profile,unsigned char *out)
{
    unsigned i;
    if(!out || !valid_profile(profile))return 0;
    for(i=0;i<8;++i)out[i]=magic[i];
    put32(out+8,1);put32(out+12,SHZ_THEME_PROFILE_BYTES);put32(out+16,profile->style);put32(out+20,SHZ_THEME_COLORS);
    for(i=0;i<SHZ_THEME_COLORS;++i){put32(out+24+i*4,profile->baseline[i]);put32(out+24+SHZ_THEME_COLORS*4+i*4,profile->selected[i]);}
    return 1;
}
int shz_theme_decode(const unsigned char *data,size_t bytes,shz_theme_profile *out)
{
    shz_theme_profile candidate;unsigned i;
    if(!data || !out || bytes!=SHZ_THEME_PROFILE_BYTES || !equal(data,magic,8) ||
       get32(data+8)!=1 || get32(data+12)!=SHZ_THEME_PROFILE_BYTES || get32(data+20)!=SHZ_THEME_COLORS)return 0;
    candidate.style=get32(data+16);
    for(i=0;i<SHZ_THEME_COLORS;++i){candidate.baseline[i]=get32(data+24+i*4);candidate.selected[i]=get32(data+24+SHZ_THEME_COLORS*4+i*4);}
    if(!valid_profile(&candidate))return 0;
    *out=candidate;return 1;
}

int shz_theme_startup_value(const char *path,size_t length,shz_theme_value *out)
{
    static const char suffix[]="\" /restore";size_t i;
    /* Run's complete command must fit 260 bytes, including our quotes, option
     * and terminating NUL. Validate before touching caller output. */
    if(!path || !out || length<4 || length>260u-(sizeof(suffix)+1u) ||
       !((path[0]>='A' && path[0]<='Z') || (path[0]>='a' && path[0]<='z')) || path[1]!=':' || path[2]!='\\')return 0;
    for(i=0;i<length;++i)if((unsigned char)path[i]<32 || path[i]=='"')return 0;
    zero(out,sizeof(*out));out->present=1;out->type=SHZ_THEME_REG_SZ;
    out->bytes=(uint32_t)(length+sizeof(suffix)+1);out->data[0]='"';
    for(i=0;i<length;++i)out->data[i+1]=(unsigned char)path[i];
    for(i=0;i<sizeof(suffix);++i)out->data[length+1+i]=(unsigned char)suffix[i];
    return 1;
}
static int space(char c){return c==' ' || c=='\t';}
int shz_theme_command_mode(const char *line,size_t length)
{
    size_t i=0,start;static const char restore[]="/restore";
    if(!line || !length || length>=1024)return -1;
    while(i<length && space(line[i]))++i;
    if(i==length)return -1;
    if(line[i]=='"'){
        start=++i;while(i<length && line[i]!='"'){if((unsigned char)line[i]<32)return -1;++i;}
        if(i==start || i==length)return -1;
        ++i;if(i<length && !space(line[i]))return -1;
    }else{
        start=i;while(i<length && !space(line[i])){if(line[i]=='"' || (unsigned char)line[i]<32)return -1;++i;}
        if(i==start)return -1;
    }
    while(i<length && space(line[i]))++i;
    if(i==length)return 0;
    if(length-i<sizeof(restore)-1 || !equal(line+i,restore,sizeof(restore)-1))return -1;
    i+=sizeof(restore)-1;
    while(i<length && space(line[i]))++i;
    return i==length?1:-1;
}

static int bounded_value(const shz_theme_value *value)
{ return value && value->present<=1 && value->bytes<=SHZ_THEME_VALUE_BYTES && (value->present || !value->bytes); }
static int string_value(const shz_theme_value *value)
{
    uint32_t i;
    if(!bounded_value(value))return 0;
    if(!value->present)return 1;
    if((value->type!=SHZ_THEME_REG_SZ && value->type!=SHZ_THEME_REG_EXPAND_SZ) || !value->bytes || value->data[value->bytes-1])return 0;
    for(i=0;i+1<value->bytes;++i)if(!value->data[i] || value->data[i]<32)return 0;
    return 1;
}
static int startup_value(const shz_theme_value *value)
{
    shz_theme_value expected;uint32_t i;
    if(!string_value(value) || !value->present || value->type!=SHZ_THEME_REG_SZ || value->bytes<4 || value->data[0]!='"')return 0;
    for(i=1;i<value->bytes && value->data[i]!='"';++i){}
    if(i>=value->bytes || !shz_theme_startup_value((const char *)value->data+1,i-1,&expected))return 0;
    return value->bytes==expected.bytes && equal(value->data,expected.data,value->bytes);
}
static int same_value(const shz_theme_value *a,const shz_theme_value *b)
{
    return bounded_value(a) && bounded_value(b) && a->present==b->present &&
        (!a->present || (a->type==b->type && a->bytes==b->bytes && equal(a->data,b->data,a->bytes)));
}
static int ops_valid(const shz_theme_ops *ops)
{ return ops && ops->get_colors && ops->set_colors && ops->read_value && ops->write_value && ops->flush_value; }
static void initialize_result(shz_theme_result *result)
{ zero(result,sizeof(*result));result->status=SHZ_THEME_FAILED;result->saved_style=0xffffffffu; }
static int fail(shz_theme_result *result,enum shz_theme_phase phase,uint32_t error)
{ result->phase=phase;result->error=error?error:31u;return 0; }
static int read_profile(const shz_theme_ops *ops,shz_theme_value *value,shz_theme_profile *profile,shz_theme_result *result)
{
    uint32_t error=0;zero(value,sizeof(*value));
    if(!ops->read_value(ops->context,SHZ_THEME_PROFILE_VALUE,value,&error) || !bounded_value(value))return fail(result,SHZ_THEME_PHASE_PROFILE_SNAPSHOT,error);
    if(value->present && (value->type!=SHZ_THEME_REG_BINARY || !shz_theme_decode(value->data,value->bytes,profile)))return fail(result,SHZ_THEME_PHASE_PROFILE_INVALID,13u);
    return 1;
}
static int verify_value(const shz_theme_ops *ops,unsigned target,const shz_theme_value *expected,uint32_t *error)
{
    shz_theme_value actual;zero(&actual,sizeof(actual));
    if(!ops->read_value(ops->context,target,&actual,error))return 0;
    if(!same_value(&actual,expected)){*error=13;return 0;}return 1;
}
static int verify_colors(const shz_theme_ops *ops,const uint32_t *expected,uint32_t *error)
{
    uint32_t actual[SHZ_THEME_COLORS];
    if(!ops->get_colors(ops->context,actual,error))return 0;
    if(!valid_colors(actual) || !equal(actual,expected,sizeof(actual))){*error=13;return 0;}return 1;
}
static void rollback_note(shz_theme_result *result,unsigned bit,uint32_t error)
{
    result->rollback_failed|=bit;if(!result->rollback_error)result->rollback_error=error?error:31u;
    result->status=SHZ_THEME_ROLLBACK_FAILED;
}
static void rollback_value(const shz_theme_ops *ops,unsigned target,const shz_theme_value *old,unsigned bit,shz_theme_result *result)
{
    uint32_t error=0;int written,flushed,verified;
    written=ops->write_value(ops->context,target,old,&error);
    if(!written)rollback_note(result,bit,error);
    error=0;flushed=ops->flush_value(ops->context,target,&error);
    if(!flushed)rollback_note(result,bit,error);
    error=0;verified=verify_value(ops,target,old,&error);
    if(!verified)rollback_note(result,bit,error);
}
static void rollback_colors(const shz_theme_ops *ops,const uint32_t *old,shz_theme_result *result)
{
    uint32_t error=0;
    if(!ops->set_colors(ops->context,old,&error))rollback_note(result,SHZ_THEME_ROLLBACK_COLORS,error);
    error=0;if(!verify_colors(ops,old,&error))rollback_note(result,SHZ_THEME_ROLLBACK_COLORS,error);
}
int shz_theme_apply(const shz_theme_ops *ops,const uint32_t *initial_baseline,uint32_t style,
                    const shz_theme_value *run,shz_theme_result *result)
{
    shz_theme_value old_profile,old_run,next;shz_theme_profile previous,profile;
    uint32_t colors[SHZ_THEME_COLORS],error=0;enum shz_theme_phase phase;
    if(!result)return 0;
    initialize_result(result);
    if(!ops_valid(ops) || style>SHZ_THEME_SHIZUKUOS || !startup_value(run))return fail(result,SHZ_THEME_PHASE_ARGUMENT,87);
    if(!read_profile(ops,&old_profile,&previous,result))return 0;
    zero(&old_run,sizeof(old_run));
    if(!ops->read_value(ops->context,SHZ_THEME_RUN_VALUE,&old_run,&error) || !bounded_value(&old_run))return fail(result,SHZ_THEME_PHASE_RUN_SNAPSHOT,error);
    if(!string_value(&old_run))return fail(result,SHZ_THEME_PHASE_RUN_INVALID,13);
    if(!shz_theme_make(style,old_profile.present?previous.baseline:initial_baseline,&profile))return fail(result,SHZ_THEME_PHASE_ARGUMENT,87);
    error=0;if(!ops->get_colors(ops->context,colors,&error) || !valid_colors(colors))return fail(result,SHZ_THEME_PHASE_COLORS_SNAPSHOT,error);
    zero(&next,sizeof(next));next.present=1;next.type=SHZ_THEME_REG_BINARY;next.bytes=SHZ_THEME_PROFILE_BYTES;
    if(!shz_theme_encode(&profile,next.data))return fail(result,SHZ_THEME_PHASE_ARGUMENT,87);
    /* Attempt flags are set BEFORE calls: failing OS calls can have side effects. */
    phase=SHZ_THEME_PHASE_COLORS_APPLY;result->colors_attempted=1;error=0;
    if(!ops->set_colors(ops->context,profile.selected,&error))goto failed;
    phase=SHZ_THEME_PHASE_COLORS_READBACK;error=0;
    if(!verify_colors(ops,profile.selected,&error))goto failed;
    phase=SHZ_THEME_PHASE_PROFILE_WRITE;result->profile_attempted=1;error=0;
    if(!ops->write_value(ops->context,SHZ_THEME_PROFILE_VALUE,&next,&error))goto failed;
    phase=SHZ_THEME_PHASE_PROFILE_FLUSH;error=0;
    if(!ops->flush_value(ops->context,SHZ_THEME_PROFILE_VALUE,&error))goto failed;
    phase=SHZ_THEME_PHASE_PROFILE_READBACK;error=0;
    if(!verify_value(ops,SHZ_THEME_PROFILE_VALUE,&next,&error))goto failed;
    phase=SHZ_THEME_PHASE_RUN_WRITE;result->run_attempted=1;error=0;
    if(!ops->write_value(ops->context,SHZ_THEME_RUN_VALUE,run,&error))goto failed;
    phase=SHZ_THEME_PHASE_RUN_FLUSH;error=0;
    if(!ops->flush_value(ops->context,SHZ_THEME_RUN_VALUE,&error))goto failed;
    phase=SHZ_THEME_PHASE_RUN_READBACK;error=0;
    if(!verify_value(ops,SHZ_THEME_RUN_VALUE,run,&error))goto failed;
    result->status=SHZ_THEME_OK;result->saved_style=style;return 1;
failed:
    fail(result,phase,error);result->rollback_attempted=1;
    if(result->run_attempted)rollback_value(ops,SHZ_THEME_RUN_VALUE,&old_run,SHZ_THEME_ROLLBACK_RUN,result);
    if(result->profile_attempted)rollback_value(ops,SHZ_THEME_PROFILE_VALUE,&old_profile,SHZ_THEME_ROLLBACK_PROFILE,result);
    rollback_colors(ops,colors,result);return 0;
}
int shz_theme_restore(const shz_theme_ops *ops,shz_theme_result *result)
{
    shz_theme_value value;shz_theme_profile profile;uint32_t colors[SHZ_THEME_COLORS],error=0;
    enum shz_theme_phase phase;
    if(!result)return 0;
    initialize_result(result);
    if(!ops_valid(ops))return fail(result,SHZ_THEME_PHASE_ARGUMENT,87);
    if(!read_profile(ops,&value,&profile,result))return 0;
    if(!value.present)return fail(result,SHZ_THEME_PHASE_PROFILE_INVALID,2);
    if(!ops->get_colors(ops->context,colors,&error) || !valid_colors(colors))return fail(result,SHZ_THEME_PHASE_COLORS_SNAPSHOT,error);
    phase=SHZ_THEME_PHASE_COLORS_APPLY;result->colors_attempted=1;error=0;
    if(!ops->set_colors(ops->context,profile.selected,&error))goto failed;
    phase=SHZ_THEME_PHASE_COLORS_READBACK;error=0;
    if(!verify_colors(ops,profile.selected,&error))goto failed;
    result->status=SHZ_THEME_OK;result->saved_style=profile.style;return 1;
failed:
    fail(result,phase,error);result->rollback_attempted=1;rollback_colors(ops,colors,result);return 0;
}
