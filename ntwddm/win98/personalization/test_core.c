/* SPDX-License-Identifier: GPL-2.0-only */
#include "core.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static unsigned checks,failures;
#define CHECK(c) do { ++checks; if(!(c)){++failures;fprintf(stderr,"ASSERT %u: %s\n",__LINE__,#c);} } while(0)
int main(int argc,char **argv)
{
    pz98_preferences p,q,untouched={1,20,1,1,0};
    unsigned char record[16], damaged[16], guard[4096], earlier[4096];
    char html[PZ98_HTML_BYTES], small[8];
    unsigned scene,fps,lang,pause,battery,i;
    if(argc>1 && !strcmp(argv[1],"--html")) {
        pz98_defaults(&p);
        if(!pz98_html(&p,html,sizeof html))return 2;
        fputs(html,stdout);return 0;
    }
    pz98_defaults(&p);
    CHECK(p.scene==0 && p.fps==10 && p.language==0 && !p.paused && p.battery_saver);
    CHECK(pz98_valid(&p));
    for(scene=0;scene<2;scene++)for(fps=5;fps<=20;fps*=2)for(lang=0;lang<2;lang++)
    for(pause=0;pause<2;pause++)for(battery=0;battery<2;battery++) {
        p=(pz98_preferences){scene,fps,lang,pause,battery};
        CHECK(pz98_encode(&p,record,16));
        q=untouched; CHECK(pz98_decode(record,16,&q)); CHECK(!memcmp(&p,&q,sizeof p));
        for(i=0;i<16;i++) {
            memcpy(damaged,record,16); damaged[i]^=0x80; q=untouched;
            CHECK(!pz98_decode(damaged,16,&q)); CHECK(!memcmp(&q,&untouched,sizeof q));
        }
    }
    pz98_defaults(&p); memset(record,0xaa,16);
    CHECK(!pz98_encode(&p,record,15)); CHECK(record[0]==0xaa && record[15]==0xaa);
    CHECK(!pz98_decode(record,17,&q));
    p.fps=1; CHECK(!pz98_valid(&p)); p.fps=21; CHECK(!pz98_valid(&p));
    pz98_defaults(&p);
    CHECK(pz98_interval(&p,1,0,1)==100);
    CHECK(pz98_interval(&p,0,0,1)==0 && pz98_interval(&p,-1,0,1)==0);
    CHECK(!pz98_interval(&p,1,1,1) && !pz98_interval(&p,1,0,0));
    p.battery_saver=0; p.fps=20; CHECK(pz98_interval(&p,0,0,1)==50);
    p.paused=1; CHECK(!pz98_interval(&p,1,0,1));
    for(scene=0;scene<2;scene++) {
        memset(guard,0xa5,sizeof guard);
        CHECK(pz98_render(guard+16,4000,17,13,80,0,scene));
        for(i=0;i<16;i++) CHECK(guard[i]==0xa5);
        for(i=0;i<13;i++) { unsigned j; for(j=68;j<80;j++) CHECK(guard[16+i*80+j]==0xa5); }
        for(i=16+13*80;i<sizeof guard;i++)CHECK(guard[i]==0xa5);
        memcpy(earlier,guard,sizeof guard);
        CHECK(pz98_render(guard+16,4000,17,13,80,7,scene));
        CHECK(memcmp(guard,earlier,sizeof guard)!=0);
        CHECK(pz98_render(guard+16,4000,17,13,80,UINT32_MAX,scene));
    }
    memcpy(earlier,guard,sizeof guard);
    CHECK(!pz98_render(guard,4096,0,1,4,0,0));
    CHECK(!pz98_render(guard,4096,1,1,3,0,0));
    CHECK(!pz98_render(guard,4096,1,1,5,0,0));
    CHECK(!pz98_render(guard,3,1,1,4,0,0));
    CHECK(!pz98_render(guard,4096,UINT32_MAX,UINT32_MAX,UINT32_MAX,0,0));
    CHECK(!pz98_render(guard,4096,17,13,80,0,2));
    CHECK(!memcmp(guard,earlier,sizeof guard));
    pz98_defaults(&p);
    CHECK(pz98_html(&p,html,sizeof html));
    CHECK(strstr(html,"setTimeout") && strstr(html,"document.all") && strstr(html,"3000"));
    CHECK(strstr(html,"Pause") && !strstr(html,"http:") && !strstr(html,"https:") && !strstr(html,"ActiveX"));
    memset(small,'x',sizeof small); CHECK(!pz98_html(&p,small,sizeof small));
    for(i=0;i<sizeof small;i++)CHECK(small[i]=='x');
    p.paused=1; CHECK(pz98_html(&p,html,sizeof html)); CHECK(strstr(html,"running=false"));
    p.language=1;CHECK(pz98_html(&p,html,sizeof html));CHECK(strstr(html,"일시정지 / 재개") && strstr(html,"5분 제한"));
    printf("%s: %u personalization core checks, %u failures\n",failures?"FAIL":"PASS",checks,failures);
    return failures?1:0;
}
