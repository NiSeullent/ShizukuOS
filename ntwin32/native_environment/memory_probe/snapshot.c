/* SPDX-License-Identifier: GPL-2.0-only */
#include "snapshot.h"
_Static_assert(sizeof(mp_status)==32,"eight DWORDs");
uint32_t mp_flags(const mp_status *m)
{
 uint32_t f=0;
 if(!m)return MP_BAD_LENGTH;
 if(m->length!=32)f|=MP_BAD_LENGTH;if(m->load>100)f|=MP_BAD_LOAD;
 if(m->avail_phys>m->total_phys)f|=MP_PHYS_RELATION;
 if(m->avail_page>m->total_page)f|=MP_PAGE_RELATION;
 if(m->avail_virtual>m->total_virtual)f|=MP_VIRTUAL_RELATION;
 if(m->total_phys==UINT32_MAX||m->avail_phys==UINT32_MAX||m->total_page==UINT32_MAX||
    m->avail_page==UINT32_MAX||m->total_virtual==UINT32_MAX||m->avail_virtual==UINT32_MAX)f|=MP_DWORD_MAX;
 return f;
}
size_t mp_line(char *out,size_t capacity,const char *name,uint32_t value)
{
 size_t n=0,i;
 if(!out||!name)return 0;
 while(n<48&&name[n]){if(!((name[n]>='A'&&name[n]<='Z')||name[n]=='_'||(name[n]>='0'&&name[n]<='9')))return 0;n++;}
 if(!n||n==48||capacity<n+11)return 0;
 for(i=0;i<n;i++)out[i]=name[i];out[n++]='=';
 for(i=0;i<8;i++)out[n++]="0123456789ABCDEF"[(value>>(28-4*i))&15];
 out[n++]='\r';out[n++]='\n';return n;
}
uint32_t mp_tick_delta(uint32_t before,uint32_t after){return after-before;}
