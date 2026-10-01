/* SPDX-License-Identifier: GPL-2.0-only */
#include "m98_vlc_locale_core.h"
static const m98_geo_record geographical[] = {
#include "m98_vlc_geo.inc"
};
int m98_locale_number(const char *p,size_t n,unsigned base,uint32_t *value)
{
    size_t i;uint32_t result=0;
    if(!p||!value||n<2||n>12||(base!=10&&base!=16)||p[n-1])return 0;
    for(i=0;i<n-1;i++){
        unsigned digit;
        if(p[i]>='0'&&p[i]<='9')digit=(unsigned)(p[i]-'0');
        else if(base==16&&p[i]>='a'&&p[i]<='f')digit=(unsigned)(p[i]-'a'+10);
        else if(base==16&&p[i]>='A'&&p[i]<='F')digit=(unsigned)(p[i]-'A'+10);
        else return 0;
        if(digit>=base||result>(UINT32_MAX-digit)/base)return 0;
        result=result*base+digit;
    }
    *value=result;return 1;
}
const m98_geo_record *m98_locale_geo(int32_t id)
{
    size_t first=0,last=sizeof(geographical)/sizeof(geographical[0]);
    while(first<last){size_t middle=first+(last-first)/2;
        if(geographical[middle].id<id)first=middle+1;
        else if(geographical[middle].id>id)last=middle;
        else return &geographical[middle];
    }
    return 0;
}
int m98_locale_geo_ascii(int32_t id,uint32_t type,char out[12],uint32_t *error)
{
    const m98_geo_record *geo=m98_locale_geo(id);const char *source=0;
    unsigned i=0,n=0;char reversed[12];uint32_t value;
    if(!out||!error)return 0;
    if(!geo){*error=87;return 0;}
    switch(type){
    case 1:case 18:
        value=(uint32_t)geo->id;
        do{reversed[n++]=(char)('0'+value%10);value/=10;}while(value);
        while(n)out[i++]=reversed[--n];out[i]=0;return (int)i+1;
    case 4:source=geo->iso2;break;
    case 5:source=geo->iso3;break;
    case 12:source=geo->uncode;break;
    case 17:source=geo->name;break;
    default:*error=120;return 0; /* Outside this explicit data profile. */
    }
    if(!source[0]){*error=120;return 0;}
    while(source[i]){out[i]=source[i];i++;}out[i]=0;return (int)i+1;
}
int m98_locale_group(uint32_t group,uint32_t flags,
                     int (*valid)(void *,uint32_t,uint32_t),void *context)
{
    /* Representative native NLS locales by script group. This fallback asks
     * the actual backend for installed/supported state, never fabricates it.
     * Native Language Groups registry metadata takes precedence in the DLL.
     */
    static const uint32_t locale[17][10]={
        {0x0409,0x0407,0x040c,0x0410,0x040a,0x0413,0x0414,0x041d,0x0406,0x040b},
        {0x0405,0x0415,0x0418,0x040e,0x041a,0x041b,0x0424,0x041c,0,0},
        {0x0425,0x0426,0x0427,0,0,0,0,0,0,0},
        {0x0408,0,0,0,0,0,0,0,0,0},
        {0x0419,0x0422,0x0423,0x0402,0x042f,0x0c1a,0,0,0,0},
        {0x041f,0x042c,0x043f,0x0440,0x0443,0x0444,0,0,0,0},
        {0x0411,0,0,0,0,0,0,0,0,0},{0x0412,0,0,0,0,0,0,0,0,0},
        {0x0404,0x0c04,0x1404,0,0,0,0,0,0,0},{0x0804,0x1004,0,0,0,0,0,0,0,0},
        {0x041e,0,0,0,0,0,0,0,0,0},{0x040d,0,0,0,0,0,0,0,0,0},
        {0x0401,0x0420,0x0429,0,0,0,0,0,0,0},{0x042a,0,0,0,0,0,0,0,0,0},
        {0x0439,0x0445,0x0446,0x0447,0x0448,0x0449,0x044a,0x044b,0x044c,0x044e},
        {0x0437,0,0,0,0,0,0,0,0,0},{0x042b,0,0,0,0,0,0,0,0,0}
    };unsigned i;
    if(!valid||group<1||group>17||(flags!=1&&flags!=2))return 0;
    for(i=0;i<10&&locale[group-1][i];i++)if(valid(context,locale[group-1][i],flags))return 1;
    return 0;
}
