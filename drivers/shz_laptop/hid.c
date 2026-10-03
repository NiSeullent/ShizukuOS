/* SPDX-License-Identifier: GPL-2.0-only */
#include "internal.h"
int shz_hid_parse_descriptor(const uint8_t *p,size_t n,struct shz_hid_descriptor *out) {
    struct shz_hid_descriptor d;unsigned i;
    if(!p || !out) return SHZ_INVALID;
    if(n!=30 || shz_le16(p)!=30) return SHZ_MALFORMED;
    if(shz_le16(p+2)!=0x100) return SHZ_UNSUPPORTED;
    for(i=26;i<30;i++) if(p[i]) return SHZ_MALFORMED;
    shz_zero(&d,sizeof(d));d.report_bytes=shz_le16(p+4);d.report_register=shz_le16(p+6);
    d.input_register=shz_le16(p+8);d.input_bytes=shz_le16(p+10);
    d.output_register=shz_le16(p+12);d.output_bytes=shz_le16(p+14);
    d.command_register=shz_le16(p+16);d.data_register=shz_le16(p+18);
    d.vendor=shz_le16(p+20);d.product=shz_le16(p+22);d.version=shz_le16(p+24);
    if(!d.vendor || !d.report_bytes || d.input_bytes<2) return SHZ_MALFORMED;
    if(d.report_bytes>SHZ_HID_DESCRIPTOR_MAX || d.input_bytes>SHZ_HID_REPORT_MAX ||
       d.output_bytes>SHZ_HID_REPORT_MAX) return SHZ_CAPACITY;
    *out=d;return SHZ_DRIVER_OK;
}
struct hid_global { uint32_t page,size,count;int32_t minimum,maximum;uint8_t report; };
struct hid_local { uint32_t usages[32],first,last;unsigned count;uint8_t range; };
static int32_t signed_item(uint32_t value,unsigned bytes) {
    unsigned bits=bytes*8;
    if(!bits) return 0;
    if(bits==32) return value<=INT32_MAX ? (int32_t)value:(int32_t)((int64_t)value-4294967296ll);
    if(value&(1u<<(bits-1))) return (int32_t)value-(int32_t)(1u<<bits);
    return (int32_t)value;
}
static uint32_t usage_value(const struct hid_global *g,uint32_t v,unsigned bytes) {
    return bytes==4 ? v:(g->page<<16)|(v&65535u);
}
static uint32_t local_usage(const struct hid_local *l,unsigned index) {
    if(l->count) return l->usages[index<l->count ? index:l->count-1];
    if(l->range==3) return l->first+(index<l->last-l->first ? index:l->last-l->first);
    return 0;
}
static int report_index(struct shz_hid_layout *l,uint8_t id) {
    unsigned i;
    for(i=0;i<l->report_count;i++) if(l->reports[i].id==id) return (int)i;
    if(l->report_count==SHZ_HID_REPORTS) return SHZ_CAPACITY;
    i=l->report_count++;l->reports[i].id=id;return (int)i;
}
int shz_hid_parse_report(const uint8_t *p,size_t n,struct shz_hid_layout *out) {
    struct shz_hid_layout l;struct hid_global g,stack[4];struct hid_local local;
    uint8_t groups[8],classes[8];unsigned depth=0,push=0,next_group=0;size_t pos=0;
    if(!p || !out || !n) return SHZ_INVALID;
    if(n>SHZ_HID_DESCRIPTOR_MAX) return SHZ_CAPACITY;
    shz_zero(&l,sizeof(l));shz_zero(&g,sizeof(g));shz_zero(&local,sizeof(local));
    while(pos<n) {
        uint8_t prefix=p[pos++];unsigned bytes=prefix&3u,type=(prefix>>2)&3u,tag=prefix>>4,i;
        uint32_t value=0;
        if(prefix==0xfe) return SHZ_UNSUPPORTED;
        if(bytes==3) bytes=4;
        if(bytes>n-pos) return SHZ_MALFORMED;
        for(i=0;i<bytes;i++) value|=(uint32_t)p[pos+i]<<(i*8);
        pos+=bytes;
        if(type==1) {
            switch(tag) {
            case 0: if(value>65535u)return SHZ_UNSUPPORTED;g.page=value;break;
            case 1: g.minimum=signed_item(value,bytes);break;
            case 2:
                if(g.minimum>=0 && value>INT32_MAX)return SHZ_UNSUPPORTED;
                g.maximum=g.minimum<0 ? signed_item(value,bytes):(int32_t)value;break;
            case 3:case 4:case 5:case 6:break; /* Physical ranges/unit retained by client descriptor. */
            case 7: if(value>32)return SHZ_UNSUPPORTED;g.size=value;break;
            case 8: if(!value || value>255)return SHZ_MALFORMED;g.report=(uint8_t)value;l.numbered=1;break;
            case 9: if(value>SHZ_HID_FIELDS)return SHZ_CAPACITY;g.count=value;break;
            case 10: if(push==4)return SHZ_CAPACITY;stack[push++]=g;break;
            case 11: if(!push)return SHZ_MALFORMED;g=stack[--push];break;
            default:return SHZ_UNSUPPORTED;
            }
        } else if(type==2) {
            switch(tag) {
            case 0:
                if(local.count==32)return SHZ_CAPACITY;
                local.usages[local.count++]=usage_value(&g,value,bytes);break;
            case 1:local.first=usage_value(&g,value,bytes);local.range|=1;break;
            case 2:local.last=usage_value(&g,value,bytes);local.range|=2;break;
            case 3:case 4:case 5:case 7:case 8:case 9:break;
            default:return SHZ_UNSUPPORTED;
            }
        } else if(type==0) {
            if(local.range && (local.range!=3 || local.last<local.first ||
                (local.first>>16)!=(local.last>>16))) return SHZ_MALFORMED;
            if(tag==10) {
                uint32_t usage=local_usage(&local,0);uint8_t group=depth ? groups[depth-1]:0;
                uint8_t app=depth ? classes[depth-1]:0;
                if(depth==8)return SHZ_CAPACITY;
                if(value==1) {
                    app=0;
                    if(usage==0x000d0005u){l.touchpad=1;app=2;}
                    if(usage==0x00010002u){l.pointer=1;app=1;}
                }
                if(usage==0x000d0022u) {
                    if(next_group==SHZ_HID_CONTACTS)return SHZ_CAPACITY;
                    group=(uint8_t)++next_group;
                }
                groups[depth]=group;classes[depth++]=app;
            } else if(tag==12) {
                if(!depth || bytes)return SHZ_MALFORMED;
                --depth;
            } else if(tag==8) {
                int index;uint32_t bits;
                if(!depth || !g.size || !g.count || value>255 || g.minimum>g.maximum)
                    return SHZ_MALFORMED;
                if(value&128u)return SHZ_UNSUPPORTED;
                /* Array selectors are usages only when firmware gives an exact
                 * contiguous selector/usage mapping. Other mappings need a
                 * richer client and must not silently generate wrong keys. */
                if(!(value&3u) && (local.range!=3 || local.count || g.minimum<0 ||
                    (local.first&65535u)!=(uint32_t)g.minimum ||
                    (local.last&65535u)!=(uint32_t)g.maximum ||
                    (local.first>>16)!=g.page))return SHZ_UNSUPPORTED;
                index=report_index(&l,g.report);if(index<0)return index;
                l.reports[index].pointer_class=(uint8_t)(l.reports[index].pointer_class|
                    (classes[depth-1]?classes[depth-1]:4));
                bits=g.size*g.count;
                if(bits>SHZ_HID_REPORT_MAX*8u-l.reports[index].bits)return SHZ_CAPACITY;
                if(!(value&1u)) {
                    if(g.count>SHZ_HID_FIELDS-l.count)return SHZ_CAPACITY;
                    for(i=0;i<g.count;i++) {
                        struct shz_hid_field *f=l.fields+l.count++;uint32_t usage=local_usage(&local,i);
                        f->bit=(uint16_t)(l.reports[index].bits+i*g.size);f->size=(uint8_t)g.size;
                        f->report=g.report;f->page=(uint16_t)(usage ? usage>>16:g.page);
                        f->usage=(uint16_t)usage;f->group=groups[depth-1];f->flags=(uint8_t)value;
                        if(!(value&2u)) { f->usage=65535;f->flags|=128u; }
                        f->minimum=g.minimum;f->maximum=g.maximum;
                    }
                }
                l.reports[index].bits=(uint16_t)(l.reports[index].bits+bits);
            } else if(tag!=9 && tag!=11) return SHZ_UNSUPPORTED;
            shz_zero(&local,sizeof(local));
        } else return SHZ_UNSUPPORTED;
    }
    if(depth || push || !l.count || !l.report_count) return SHZ_MALFORMED;
    if(l.numbered) for(pos=0;pos<l.report_count;pos++)if(!l.reports[pos].id)return SHZ_MALFORMED;
    shz_copy(out,&l,sizeof(l));return SHZ_DRIVER_OK;
}
static int field_value(const struct shz_hid_field *f,const uint8_t *p,size_t bits,int32_t *out) {
    uint32_t raw=0;unsigned i;int32_t value;
    if(!f->size || f->size>32 || (size_t)f->bit+f->size>bits || f->minimum>f->maximum)
        return SHZ_MALFORMED;
    for(i=0;i<f->size;i++) raw|=((uint32_t)(p[(f->bit+i)/8]>>((f->bit+i)%8))&1u)<<i;
    if(f->minimum<0) {
        value=signed_item(raw,f->size==32 ? 4:0);
        if(f->size<32) value=(raw&(1u<<(f->size-1))) ? (int32_t)((int64_t)raw-(1ll<<f->size)):(int32_t)raw;
    } else {
        if(raw>INT32_MAX)return SHZ_MALFORMED;
        value=(int32_t)raw;
    }
    if(value<f->minimum || value>f->maximum) return SHZ_MALFORMED;
    *out=value;return SHZ_DRIVER_OK;
}
int shz_hid_decode(const struct shz_hid_layout *l,const uint8_t *p,size_t n,
    struct shz_hid_value *out,size_t capacity,size_t *count) {
    unsigned i,pass;uint8_t id;size_t bits=0,used=0;int found=0;
    if(!l || !p || !count || (!out && capacity) || !n) return SHZ_INVALID;
    if(l->count>SHZ_HID_FIELDS || l->report_count>SHZ_HID_REPORTS || l->numbered>1) return SHZ_MALFORMED;
    id=l->numbered ? p[0]:0;
    if(l->numbered){++p;--n;}
    for(i=0;i<l->report_count;i++)if(l->reports[i].id==id){bits=l->reports[i].bits;found=1;break;}
    if(!found || !bits || n!=(bits+7)/8)return SHZ_MALFORMED;
    /* Validate all fields and capacity before publishing any output. */
    for(pass=0;pass<2;pass++) {
        used=0;
        for(i=0;i<l->count;i++) if(l->fields[i].report==id) {
            const struct shz_hid_field *f=l->fields+i;int32_t value;int r=field_value(f,p,bits,&value);
            if(r)return r;
            if((f->flags&128u) && !value)continue;
            if((f->flags&128u) && (value<0 || value>65535))return SHZ_MALFORMED;
            if(pass && out) {
                out[used].page=f->page;out[used].usage=(f->flags&128u) ? (uint16_t)value:f->usage;
                out[used].value=(f->flags&128u) ? 1:value;
                out[used].group=f->group;out[used].flags=f->flags;
            }
            ++used;
        }
        if(out && capacity<used)return SHZ_CAPACITY;
    }
    *count=used;return SHZ_DRIVER_OK;
}
int shz_hid_pointer(const struct shz_hid_layout *l,const uint8_t *p,size_t n,struct shz_pointer *out) {
    struct shz_hid_value v[SHZ_HID_FIELDS];struct shz_pointer result;
    struct shz_contact groups[SHZ_HID_CONTACTS+1];uint8_t tip[SHZ_HID_CONTACTS+1];
    size_t count,i;unsigned group,axes=0;int r,expected=-1,mode=-1;uint8_t app=0,id;
    if(!l || !out)return SHZ_INVALID;
    r=shz_hid_decode(l,p,n,v,SHZ_HID_FIELDS,&count);if(r)return r;
    id=l->numbered?p[0]:0;
    for(i=0;i<l->report_count;i++)if(l->reports[i].id==id){app=l->reports[i].pointer_class;break;}
    if(app!=1 && app!=2)return SHZ_UNSUPPORTED;
    shz_zero(&result,sizeof(result));shz_zero(groups,sizeof(groups));shz_zero(tip,sizeof(tip));
    for(i=0;i<count;i++) {
        group=v[i].group;if(group>SHZ_HID_CONTACTS)return SHZ_MALFORMED;
        if(v[i].page==1 && (v[i].usage==0x30 || v[i].usage==0x31)) {
            int relative=(v[i].flags&4u)!=0;
            if(mode>=0 && mode!=relative)return SHZ_UNSUPPORTED;
            mode=relative;++axes;
            if(v[i].usage==0x30){if(groups[group].has_x)return SHZ_UNSUPPORTED;groups[group].x=v[i].value;groups[group].has_x=1;}
            else {if(groups[group].has_y)return SHZ_UNSUPPORTED;groups[group].y=v[i].value;groups[group].has_y=1;}
        } else if(v[i].page==9 && v[i].usage>=1 && v[i].usage<=8) {
            if(v[i].value<0 || v[i].value>1)return SHZ_MALFORMED;
            if(v[i].value)result.buttons=(uint8_t)(result.buttons|(uint8_t)(1u<<(v[i].usage-1u)));
        } else if(v[i].page==0x0d && v[i].usage==0x42) {
            if(v[i].value<0 || v[i].value>1)return SHZ_MALFORMED;
            groups[group].active=(uint8_t)v[i].value;tip[group]=1;
        } else if(v[i].page==0x0d && v[i].usage==0x51) {
            if(v[i].value<0 || v[i].value>65535)return SHZ_MALFORMED;
            groups[group].id=(uint16_t)v[i].value;
        } else if(v[i].page==0x0d && v[i].usage==0x54) {
            if(v[i].value<0 || v[i].value>(int32_t)SHZ_HID_CONTACTS)return SHZ_MALFORMED;
            expected=v[i].value;
        }
    }
    if(!axes)return SHZ_UNSUPPORTED;
    result.relative=(uint8_t)mode;
    for(group=0;group<=SHZ_HID_CONTACTS;group++) {
        if(!tip[group] && groups[group].has_x && groups[group].has_y)groups[group].active=1;
        if(groups[group].active) {
            unsigned j;
            if(!groups[group].has_x || !groups[group].has_y || result.count==SHZ_HID_CONTACTS)return SHZ_MALFORMED;
            if(tip[group])for(j=0;j<result.count;j++)if(result.contacts[j].id==groups[group].id)return SHZ_MALFORMED;
            result.contacts[result.count++]=groups[group];
        }
    }
    if(expected>=0 && expected!=result.count)return SHZ_UNSUPPORTED; /* No partial-frame aggregation yet. */
    if(!result.count && app!=2)return SHZ_UNSUPPORTED;
    *out=result;return SHZ_DRIVER_OK;
}
