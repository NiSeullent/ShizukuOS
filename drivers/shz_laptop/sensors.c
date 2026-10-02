/* SPDX-License-Identifier: GPL-2.0-only */
#include "internal.h"
static int evaluate(const struct shz_acpi_provider *p,uint64_t node,const char method[5],
    struct shz_acpi_value *values,size_t expected) {
    size_t count=0,i;int r;
    if(!p || !p->evaluate) return SHZ_UNSUPPORTED;
    if(!p->validate || !p->owner || !p->generation || !node || !p->timeout_us ||
       p->timeout_us>30000000u) return SHZ_INVALID;
    if(p->validate(p->context,p->owner,p->generation,node)!=SHZ_OK) return SHZ_REVOKED;
    for(i=0;i<expected;i++){values[i].integer=0;values[i].kind=UINT32_MAX;}
    r=p->evaluate(p->context,node,method,values,expected,&count,p->timeout_us);if(r) return r;
    if(p->validate(p->context,p->owner,p->generation,node)!=SHZ_OK) return SHZ_REVOKED;
    if(count!=expected) return SHZ_MALFORMED;
    return SHZ_OK;
}
static int integer32(const struct shz_acpi_value *v,uint32_t *out) {
    if(v->kind!=SHZ_ACPI_INTEGER || v->integer>UINT32_MAX) return SHZ_MALFORMED;
    *out=(uint32_t)v->integer;return SHZ_OK;
}
int shz_acpi_battery(const struct shz_acpi_provider *p,uint64_t node,struct shz_battery *out) {
    struct shz_acpi_value values[13];struct shz_battery b;
    uint32_t sta,numbers[9];unsigned i;int r;
    if(!out) return SHZ_INVALID;
    shz_zero(&b,sizeof(b));
    r=evaluate(p,node,"_STA",values,1);if(r) return r;
    r=integer32(values,&sta);if(r) return r;
    if(sta&~31u) return SHZ_MALFORMED;
    if(!(sta&16u)) { *out=b;return SHZ_OK; }
    if(!(sta&1u)) return SHZ_MALFORMED;
    b.present=1;
    r=evaluate(p,node,"_BIF",values,13);if(r) return r;
    for(i=0;i<9;i++){
        r=integer32(values+i,numbers+i);if(r)return r;
        if(numbers[i]>INT32_MAX && numbers[i]!=UINT32_MAX)return SHZ_MALFORMED;
    }
    for(i=9;i<13;i++) if(values[i].kind!=SHZ_ACPI_STRING) return SHZ_MALFORMED;
    b.unit=numbers[0];b.full=numbers[2];
    if(b.unit>1) return SHZ_MALFORMED;
    r=evaluate(p,node,"_BST",values,4);if(r) return r;
    for(i=0;i<4;i++){
        r=integer32(values+i,numbers+i);if(r)return r;
        if(numbers[i]>INT32_MAX && numbers[i]!=UINT32_MAX)return SHZ_MALFORMED;
    }
    b.state=numbers[0];b.rate=numbers[1];b.remaining=numbers[2];b.voltage=numbers[3];
    if(b.state>15 || (b.state&3u)==3u) return SHZ_MALFORMED;
    if(b.remaining!=UINT32_MAX && b.full!=UINT32_MAX) {
        if(b.remaining>b.full) return SHZ_MALFORMED;
        if(b.full) {
            b.percent_known=1;
            /* Bounded integer comparison avoids overflowing 32-bit capacities
             * and avoids compiler 64-bit division helpers on i486. */
            for(i=1;i<=100;i++) {
                if((uint64_t)b.remaining*100u<(uint64_t)b.full*i) break;
                b.percent=(uint8_t)i;
            }
        }
    }
    *out=b;return SHZ_OK;
}
int shz_acpi_temperature(const struct shz_acpi_provider *p,uint64_t node,int32_t *out) {
    struct shz_acpi_value value;uint32_t t;int r;
    if(!out) return SHZ_INVALID;
    /* Relative temperatures need the device's critical reference temperature.
     * Do not render them as a fabricated absolute Celsius measurement. */
    r=evaluate(p,node,"_RTV",&value,1);
    if(r!=SHZ_NOT_FOUND) {
        if(r)return r;
        r=integer32(&value,&t);if(r)return r;
        if(t)return SHZ_UNSUPPORTED;
    }
    r=evaluate(p,node,"_TMP",&value,1);if(r) return r;
    r=integer32(&value,&t);if(r) return r;
    if(t>65535u) return SHZ_MALFORMED;
    *out=(int32_t)t*100-273150;return SHZ_OK;
}
static int boolean(const struct shz_acpi_provider *p,uint64_t node,const char method[5],int *out) {
    struct shz_acpi_value v;uint32_t b;int r;
    if(!out) return SHZ_INVALID;
    r=evaluate(p,node,method,&v,1);if(r) return r;
    r=integer32(&v,&b);if(r) return r;
    if(b>1) return SHZ_MALFORMED;
    *out=(int)b;return SHZ_OK;
}
int shz_acpi_lid(const struct shz_acpi_provider *p,uint64_t node,int *out) {
    return boolean(p,node,"_LID",out);
}
int shz_acpi_ac_power(const struct shz_acpi_provider *p,uint64_t node,int *out) {
    return boolean(p,node,"_PSR",out);
}
int shz_ec_sensor_read(struct shz_ec *e,const struct shz_ec_sensor *s,int32_t *out) {
    uint8_t raw;int64_t value;int r;
    if(!e || !s || !out || s->minimum>s->maximum || !s->scale_milli) return SHZ_INVALID;
    r=shz_ec_read(e,s->address,&raw);if(r) return r;
    value=(int64_t)raw*s->scale_milli+s->offset_milli;
    if(value<s->minimum || value>s->maximum || value<INT32_MIN || value>INT32_MAX)
        return SHZ_MALFORMED;
    *out=(int32_t)value;return SHZ_OK;
}
