/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_VLC_LOCALE_CORE_H
#define M98_VLC_LOCALE_CORE_H
#include <stdint.h>
#include <stddef.h>
typedef struct m98_geo_record {
    int32_t id;
    uint32_t classification;
    char name[4], iso2[4], iso3[4], uncode[4];
} m98_geo_record;
int m98_locale_number(const char *,size_t,unsigned,uint32_t *);
const m98_geo_record *m98_locale_geo(int32_t);
int m98_locale_geo_ascii(int32_t,uint32_t,char[12],uint32_t *);
int m98_locale_group(uint32_t,uint32_t,int (*)(void *,uint32_t,uint32_t),void *);
#endif
