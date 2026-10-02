/* SPDX-License-Identifier: GPL-2.0-only */
#include "core.h"
#include <string.h>
void pz98_defaults(pz98_preferences *p) { if(p) *p=(pz98_preferences){0,10,0,0,1}; }
int pz98_valid(const pz98_preferences *p)
{
    return p && p->scene<2 && (p->fps==5 || p->fps==10 || p->fps==20) &&
           p->language<2 && p->paused<2 && p->battery_saver<2;
}
static uint32_t checksum(const unsigned char *b)
{
    uint32_t h=2166136261u; unsigned i;
    for(i=0;i<12;i++) h=(h^b[i])*16777619u;
    return h;
}
int pz98_encode(const pz98_preferences *p,unsigned char *b,size_t n)
{
    unsigned char r[16]={'P','Z','9','8',1,0,0,0,0,0,0,0,0,0,0,0};
    uint32_t h; unsigned i;
    if(!pz98_valid(p) || !b || n!=16) return 0;
    r[5]=(unsigned char)p->scene; r[6]=(unsigned char)p->fps; r[7]=(unsigned char)p->language;
    r[8]=(unsigned char)p->paused; r[9]=(unsigned char)p->battery_saver;
    h=checksum(r); for(i=0;i<4;i++)r[12+i]=(unsigned char)(h>>(i*8));
    memcpy(b,r,16); return 1;
}
int pz98_decode(const unsigned char *b,size_t n,pz98_preferences *p)
{
    pz98_preferences candidate; uint32_t h; unsigned i;
    if(!b || !p || n!=16 || memcmp(b,"PZ98",4) || b[4]!=1 || b[10] || b[11]) return 0;
    h=checksum(b); for(i=0;i<4;i++) if(b[12+i]!=(unsigned char)(h>>(i*8))) return 0;
    candidate=(pz98_preferences){b[5],b[6],b[7],b[8],b[9]};
    if(!pz98_valid(&candidate)) return 0;
    *p=candidate; return 1;
}
unsigned pz98_interval(const pz98_preferences *p,int ac,int suspended,int visible)
{
    if(!pz98_valid(p) || p->paused || suspended || !visible || (p->battery_saver && ac!=1)) return 0;
    return 1000u/p->fps;
}
int pz98_render(void *buffer,size_t bytes,unsigned width,unsigned height,unsigned pitch,uint32_t phase,unsigned scene)
{
    unsigned x,y; unsigned char *pixels=buffer;
    if(!pixels || !width || !height || width>1920 || height>1080 || scene>1 ||
       pitch<width*4u || pitch%4 || bytes>PZ98_MAX_BYTES || (size_t)height>bytes/pitch) return 0;
    for(y=0;y<height;y++)for(x=0;x<width;x++) {
        unsigned char *pixel=pixels+(size_t)y*pitch+x*4u;
        unsigned wave=(x+(phase&255u)+y*2u)%64u;
        if(wave>31)wave=63-wave;
        if(!scene) { pixel[0]=(unsigned char)(40+y*32u/height);pixel[1]=(unsigned char)(35+wave*4u);pixel[2]=12; }
        else { pixel[0]=(unsigned char)(48+y*32u/height);pixel[1]=(unsigned char)(16+wave);pixel[2]=(unsigned char)(35+y*20u/height); }
        pixel[3]=0;
    }
    for(x=0;x<24;x++) {
        unsigned px=(x*73u+(phase%width)*(scene?1u:2u))%width;
        unsigned py=(x*37u+(phase%height))%height;
        unsigned char *p=pixels+(size_t)py*pitch+px*4u;
        p[0]=scene?245:180;p[1]=scene?210:245;p[2]=scene?255:80;p[3]=0;
    }
    return 1;
}
typedef struct writer { char *p; size_t count; int failed; } writer;
static void append(writer *w,const char *s)
{
    while(*s) { if(w->count>=PZ98_HTML_BYTES-1){w->failed=1;return;}w->p[w->count++]=*s++; }
}
static void number(writer *w,unsigned value)
{
    char r[10]; unsigned n=0;
    do { r[n++]=(char)('0'+value%10); value/=10; } while(value);
    while(n) { char digit[2]={r[--n],0};append(w,digit); }
}
int pz98_html(const pz98_preferences *p,char *out,size_t capacity)
{
    char local[PZ98_HTML_BYTES];writer w={local,0,0};unsigned i;
    if(!pz98_valid(p) || !out) return 0;
    append(&w,"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\"><html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"><title>Shizuku wallpaper</title></head><body bgcolor=\"");
    append(&w,p->scene?"#231030":"#0c2328");append(&w,"\" style=\"margin:0;overflow:hidden\"><button onclick=\"toggle()\">");
    append(&w,p->language?"일시정지 / 재개":"Pause / Resume");append(&w,"</button><span id=\"status\">");
    append(&w,p->language?"오프라인 배경: 5분 뒤 자동으로 정지":"Offline animation: automatic stop after 5 minutes");append(&w,"</span>");
    for(i=0;i<24;i++) {
        append(&w,"<div id=\"dot");number(&w,i);append(&w,"\" style=\"position:absolute;width:4px;height:4px;background-color:");
        append(&w,p->scene?"#ffd2f5":"#50f5b4");append(&w,"\"></div>");
    }
    append(&w,"<script type=\"text/javascript\">var running=");append(&w,p->paused?"false":"true");
    append(&w,",frame=0,timer=null,started=(new Date()).getTime(),limit=");number(&w,p->fps*300u);append(&w,",delay=");number(&w,1000u/p->fps);
    append(&w,";function toggle(){running=!running;if(!running){if(timer!==null)clearTimeout(timer);timer=null;}else if(timer===null)tick();}function tick(){timer=null;if(!running)return;if(frame>=limit||(new Date()).getTime()-started>=300000){running=false;document.all.status.innerText='");
    append(&w,p->language?"정지: 5분 제한에 도달했습니다":"Paused: five-minute limit reached");
    append(&w,"';return;}var w=document.body.clientWidth,h=document.body.clientHeight;if(w<1)w=1;if(h<1)h=1;for(var i=0;i<24;i++){var d=document.all['dot'+i];d.style.pixelLeft=(i*73+frame*2)%w;d.style.pixelTop=(i*37+frame)%h;}frame++;timer=setTimeout(tick,delay);}tick();</script></body></html>\n");
    if(w.failed || w.count+1>capacity)return 0;
    local[w.count]=0;memcpy(out,local,w.count+1);return 1;
}
