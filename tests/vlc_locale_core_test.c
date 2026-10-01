/* SPDX-License-Identifier: GPL-2.0-only */
#include "m98_vlc_locale_core.h"
#include <stdio.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL %u line%u %s\n",checks,__LINE__,#x);return 1;}}while(0)
static int selected(void *context,uint32_t locale,uint32_t flags)
{unsigned *calls=context;(*calls)++;return locale==0x0412&&flags==2;}
int main(void)
{
    uint32_t value=0xabcdef01,error;unsigned calls=0,i;char out[12];
    CHECK(m98_locale_number("134",4,10,&value)&&value==134);
    CHECK(m98_locale_number("00000412",9,16,&value)&&value==0x0412);
    CHECK(m98_locale_number("FFFFFFFF",9,16,&value)&&value==UINT32_MAX);
    CHECK(m98_locale_number("4294967295",11,10,&value)&&value==UINT32_MAX);
    value=0x12345678;
    CHECK(!m98_locale_number("4294967296",11,10,&value)&&value==0x12345678);
    CHECK(!m98_locale_number("100000000",10,16,&value)&&value==0x12345678);
    CHECK(!m98_locale_number("-1",3,10,&value));CHECK(!m98_locale_number("+1",3,10,&value));
    CHECK(!m98_locale_number(" 1",3,10,&value));CHECK(!m98_locale_number("1 ",3,10,&value));
    CHECK(!m98_locale_number("1\0x",4,10,&value));CHECK(!m98_locale_number("0x12",5,16,&value));
    CHECK(!m98_locale_number("12",2,10,&value));CHECK(!m98_locale_number("",1,10,&value));
    CHECK(!m98_locale_number(0,3,10,&value));CHECK(!m98_locale_number("12",3,8,&value));
    CHECK(m98_locale_geo_ascii(134,4,out,&error)==3&&!strcmp(out,"KR"));
    CHECK(m98_locale_geo_ascii(134,5,out,&error)==4&&!strcmp(out,"KOR"));
    CHECK(m98_locale_geo_ascii(134,12,out,&error)==4&&!strcmp(out,"410"));
    CHECK(m98_locale_geo_ascii(244,4,out,&error)==3&&!strcmp(out,"US"));
    CHECK(m98_locale_geo_ascii(122,4,out,&error)==3&&!strcmp(out,"JP"));
    CHECK(m98_locale_geo_ascii(45,4,out,&error)==3&&!strcmp(out,"CN"));
    CHECK(m98_locale_geo_ascii(39070,17,out,&error)==4&&!strcmp(out,"001"));
    CHECK(m98_locale_geo_ascii(161832258,18,out,&error)==10&&!strcmp(out,"161832258"));
    CHECK(m98_locale_geo(134)->classification==16&&m98_locale_geo(39070)->classification==14);
    CHECK(!m98_locale_geo(-1));CHECK(!m98_locale_geo(0));CHECK(!m98_locale_geo(INT32_MAX));
    memset(out,0x55,sizeof(out));CHECK(!m98_locale_geo_ascii(-1,4,out,&error)&&error==87&&out[0]==0x55);
    CHECK(!m98_locale_geo_ascii(134,2,out,&error)&&error==120&&out[0]==0x55);
    for(i=0;i<20;i++)if(i!=1&&i!=4&&i!=5&&i!=12&&i!=17&&i!=18)
        CHECK(!m98_locale_geo_ascii(134,i,out,&error)&&error==120);
    CHECK(m98_locale_group(8,2,selected,&calls)&&calls==1);
    calls=0;CHECK(!m98_locale_group(8,1,selected,&calls)&&calls==1);
    calls=0;CHECK(!m98_locale_group(7,2,selected,&calls)&&calls==1);
    calls=0;CHECK(!m98_locale_group(0,1,selected,&calls)&&calls==0);
    CHECK(!m98_locale_group(18,1,selected,&calls)&&calls==0);
    CHECK(!m98_locale_group(8,3,selected,&calls)&&calls==0);
    CHECK(!m98_locale_group(8,0,selected,&calls)&&calls==0);
    CHECK(!m98_locale_group(8,1,0,&calls));
    printf("VLC_LOCALE_CORE_CHECKS=%u\nSTATUS=PASS\n",checks);return 0;
}
