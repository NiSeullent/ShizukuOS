/* SPDX-License-Identifier: GPL-2.0-only */
#include "dead_screen.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned cases,checks;
#define CHECK(c) do {++checks;if(!(c)){fprintf(stderr,"FAIL line %u: %s\n",__LINE__,#c);exit(1);}}while(0)
#define CASE() (++cases)
static ds_state state;
static ds_fault fault;
static uint32_t image[480][648];
static ds_surface surface={&image[0][0],640,480,648,480*648,0};
static char text[4096];static size_t text_len;static unsigned calls,fail_call;
static int writer(void *context,const char *s,size_t n)
{
    (void)context;
    ++calls;if(calls==fail_call)return -1;
    CHECK(text_len+n<sizeof text);
    CHECK(!memchr(s,0,n));
    memcpy(text+text_len,s,n);text_len+=n;text[text_len]=0;return 0;
}
static void start(void)
{
    ds_init(&state);memset(&fault,0,sizeof fault);
    fault.ip=(uint64_t)(uintptr_t)__builtin_return_address(0);
    __asm__ volatile("mov %%rsp,%0":"=r"(fault.sp));
    __asm__ volatile("pushfq;popq %0":"=r"(fault.flags));
    fault.frames[0]=fault.ip;fault.frame_count=1;
    strcpy(fault.reason,"HOST CONTROL: original renderer / native acceptance pending");
    CHECK(ds_latch(&state,DS_KERNEL_FATAL,&fault)==1);
}
static void write_ppm(const char *directory,const char *name)
{
    char path[1024];CHECK(snprintf(path,sizeof path,"%s/%s.ppm",directory,name)>0);
    FILE *f=fopen(path,"wb");CHECK(f);
    CHECK(fprintf(f,"P6\n640 480\n255\n")>0);
    for(unsigned y=0;y<480;++y) for(unsigned x=0;x<640;++x) {
        const uint32_t v=image[y][x];unsigned char p[3]={(unsigned char)(v>>16),(unsigned char)(v>>8),(unsigned char)v};
        CHECK(fwrite(p,1,3,f)==3);
    }
    CHECK(!fclose(f));
}
int main(int argc,char **argv)
{
    CASE();ds_init(&state);ds_state prior=state;
    CHECK(ds_latch(&state,DS_RECOVERABLE,&fault)==0);CHECK(!memcmp(&state,&prior,sizeof state));
    CHECK(ds_latch(&state,DS_KERNEL_FATAL,0)==0);CHECK(!memcmp(&state,&prior,sizeof state));
    CASE();start();ds_fault first=state.fault;fault.ip=7;fault.reason[0]='X';
    CHECK(ds_latch(&state,DS_KERNEL_FATAL,&fault)==-1);CHECK(!memcmp(&first,&state.fault,sizeof first));
    CASE();ds_init(&state);memset(&fault,'Z',sizeof fault);fault.frame_count=999;
    CHECK(ds_latch(&state,DS_KERNEL_FATAL,&fault)==1);CHECK(state.fault.frame_count==8);
    CHECK(!state.fault.reason[159]);CHECK(state.fault.registers_valid==1);
    CASE();start();text_len=calls=fail_call=0;CHECK(!ds_fallback(&state,writer,0));
    CHECK(!strncmp(text,"You session got wasted\nEnglish traceback:",41));
    CHECK(strstr(text,"FRAME=0x") && strstr(text,"Further unwind unavailable"));
    const unsigned writes=calls;
    CASE();for(unsigned n=1;n<=writes;++n) {text_len=calls=0;fail_call=n;CHECK(ds_fallback(&state,writer,0)==-1);CHECK(calls==n);}
    fail_call=0;
    CASE();start();state.fault.registers_valid=1;state.fault.vector=14;state.fault.error=3;
    state.fault.cr2=0xdeadbeef;for(unsigned i=0;i<DS_REGS;++i)state.fault.reg[i]=0xf000+i;
    text_len=calls=0;CHECK(!ds_fallback(&state,writer,0));CHECK(strstr(text,"VECTOR=0x000000000000000e"));
    CHECK(strstr(text,"CR2=0x00000000deadbeef"));CHECK(strstr(text,"R15=0x000000000000f00e"));
    CASE();CHECK(ds_surface_valid(&surface));ds_surface bad=surface;bad.span_words=479*648+639;
    CHECK(!ds_surface_valid(&bad));bad=surface;bad.pitch_words=639;CHECK(!ds_surface_valid(&bad));
    bad=surface;bad.width=639;CHECK(!ds_surface_valid(&bad));bad=surface;bad.height=479;CHECK(!ds_surface_valid(&bad));
    bad=surface;bad.width=4097;CHECK(!ds_surface_valid(&bad));bad=surface;bad.rgbx=2;CHECK(!ds_surface_valid(&bad));
    bad=surface;bad.pixels=(volatile uint32_t *)(uintptr_t)(UINTPTR_MAX-3);CHECK(!ds_surface_valid(&bad));
    bad=surface;bad.span_words=SIZE_MAX;CHECK(!ds_surface_valid(&bad));bad=surface;bad.pixels=(volatile uint32_t *)((uintptr_t)image+1);
    CHECK(!ds_surface_valid(&bad));
    CASE();start();memset(image,0xa5,sizeof image);CHECK(!ds_render(&state,&surface));
    for(unsigned y=0;y<480;++y)for(unsigned x=640;x<648;++x)CHECK(image[y][x]==0xa5a5a5a5);
    CHECK(state.korean && state.mode==DS_MENU);
    if(argc==2)write_ppm(argv[1],"menu-ko-host");
    CASE();ds_key_event(&state,DS_LANGUAGE);CHECK(!state.korean);CHECK(!ds_render(&state,&surface));
    if(argc==2)write_ppm(argv[1],"menu-en-host");
    CASE();bad=surface;bad.pixels=0;CHECK(ds_render(&state,&bad)==-1);CHECK(state.graphics_failed);
    prior=state;ds_key_event(&state,DS_ONE);ds_tick(&state);CHECK(!memcmp(&prior,&state,sizeof prior));
    CASE();start();ds_key_event(&state,DS_ONE);CHECK(state.mode==DS_TETRIS);
    for(unsigned p=0;p<7;++p) {
        memset(&state.tetris,0,sizeof state.tetris);state.tetris.piece=p;state.tetris.x=3;
        CHECK(ds_tetris_fits(&state.tetris,p,0,3,0));
        CHECK(!ds_tetris_fits(&state.tetris,p,0,-4,0));CHECK(!ds_tetris_fits(&state.tetris,p,0,10,0));
        CHECK(!ds_tetris_fits(&state.tetris,p,0,3,20));
        ds_key_event(&state,DS_DROP);unsigned cells=0;
        for(unsigned y=0;y<20;++y)for(unsigned x=0;x<10;++x)cells+=!!state.tetris.board[y][x];
        CHECK(cells==4);CHECK(!state.graphics_failed);
    }
    CASE();memset(&state.tetris,0,sizeof state.tetris);
    for(unsigned y=16;y<20;++y)for(unsigned x=0;x<10;++x)state.tetris.board[y][x]=1;
    state.tetris.board[15][4]=2;CHECK(ds_tetris_clear(&state.tetris)==4);
    CHECK(state.tetris.lines==4 && state.tetris.score==1600 && state.tetris.board[19][4]==2);
    CASE();memset(&state.tetris,0,sizeof state.tetris);state.tetris.lines=UINT32_MAX;state.tetris.score=UINT32_MAX-5;
    for(unsigned x=0;x<10;++x)state.tetris.board[19][x]=1;
    CHECK(ds_tetris_clear(&state.tetris)==1);CHECK(state.tetris.lines==UINT32_MAX && state.tetris.score==UINT32_MAX);
    CASE();start();ds_key_event(&state,DS_ONE);state.tetris.piece=0;state.tetris.rotation=1;state.tetris.x=-2;
    CHECK(ds_tetris_fits(&state.tetris,0,1,-2,0));ds_key_event(&state,DS_UP);
    CHECK(state.tetris.rotation==2);CHECK(ds_tetris_fits(&state.tetris,0,2,state.tetris.x,state.tetris.y));
    CASE();start();ds_key_event(&state,DS_ONE);state.tetris.y=17;state.tetris.piece=1;state.tetris.x=3;
    for(unsigned x=3;x<7;++x){state.tetris.board[0][x]=1;state.tetris.board[1][x]=1;}
    ds_key_event(&state,DS_DROP);CHECK(state.tetris.over);
    ds_key_event(&state,DS_RESTART);CHECK(!state.tetris.over && !state.tetris.lines);
    CASE();state.tetris.piece=99;ds_tick(&state);CHECK(state.graphics_failed);
    CASE();start();ds_key_event(&state,DS_ONE);ds_key_event(&state,DS_TRACE);CHECK(!state.show_trace);
    for(unsigned i=0;i<6;++i){state.tetris.board[19][i]=i+1;}
    CHECK(!ds_render(&state,&surface));
    if(argc==2)write_ppm(argv[1],"tetris-host");
    CASE();start();ds_key_event(&state,DS_TWO);ds_key_event(&state,DS_DROP);
    unsigned used=0;for(unsigned i=0;i<DS_BALLS;++i)used+=state.suika.ball[i].used;CHECK(used==1 && state.suika.cooldown);
    ds_key_event(&state,DS_DROP);unsigned again=0;for(unsigned i=0;i<DS_BALLS;++i)again+=state.suika.ball[i].used;CHECK(again==1);
    int32_t initial_y=state.suika.ball[0].y;for(unsigned i=0;i<120;++i)ds_tick(&state);
    CHECK(state.suika.ball[0].y>initial_y);CHECK(state.suika.ball[0].y<=288*256);
    CASE();memset(&state.suika,0,sizeof state.suika);state.suika.aim=120;
    for(unsigned i=0;i<2;++i){state.suika.ball[i].used=1;state.suika.ball[i].x=120*256;state.suika.ball[i].y=200*256;}
    ds_suika_step(&state.suika);CHECK(state.suika.ball[0].level==1 && !state.suika.ball[1].used && state.suika.score==2);
    CASE();for(unsigned i=0;i<2;++i){state.suika.ball[i].used=1;state.suika.ball[i].level=4;
        state.suika.ball[i].x=120*256;state.suika.ball[i].y=200*256;}
    ds_suika_step(&state.suika);CHECK(state.suika.ball[0].level==5 && !state.suika.ball[1].used);
    CASE();for(unsigned i=0;i<2;++i){state.suika.ball[i].used=1;state.suika.ball[i].level=5;
        state.suika.ball[i].x=120*256;state.suika.ball[i].y=200*256;}
    ds_suika_step(&state.suika);CHECK(state.suika.ball[0].used && state.suika.ball[1].used);
    CHECK(state.suika.ball[0].x!=state.suika.ball[1].x || state.suika.ball[0].y!=state.suika.ball[1].y);
    CASE();state.suika.ball[0].x=INT32_MAX;state.suika.ball[0].y=INT32_MIN;
    state.suika.ball[0].vx=INT32_MIN;state.suika.ball[0].vy=INT32_MAX;
    ds_suika_step(&state.suika);CHECK(state.suika.ball[0].x>=0 && state.suika.ball[0].x<=240*256);
    CHECK(state.suika.ball[0].y>=-64*256 && state.suika.ball[0].vy<=3072);
    CASE();state.suika.ball[0].level=255;ds_suika_step(&state.suika);CHECK(state.suika.over);
    CASE();memset(&state.suika,0,sizeof state.suika);state.suika.aim=120;
    for(unsigned i=0;i<DS_BALLS;++i){ds_ball *b=&state.suika.ball[i];b->used=1;b->level=5;
        b->x=(int32_t)(45+i%3*70)*256;b->y=(int32_t)(60+i/3*24)*256;}
    for(unsigned i=0;i<2000 && !state.suika.over;++i)ds_suika_step(&state.suika);
    CHECK(state.suika.over); /* ceiling overflow through actual solver, no drop/capacity shortcut */
    CASE();start();ds_key_event(&state,DS_TWO);state.suika.cooldown=0;
    for(unsigned i=0;i<DS_BALLS;++i)state.suika.ball[i].used=1;
    ds_key_event(&state,DS_DROP);CHECK(state.suika.over);ds_key_event(&state,DS_RESTART);CHECK(!state.suika.over);
    CASE();state.suika.aim=24;ds_key_event(&state,DS_LEFT);CHECK(state.suika.aim==24);
    state.suika.aim=216;ds_key_event(&state,DS_RIGHT);CHECK(state.suika.aim==216);
    CASE();start();ds_key_event(&state,DS_TWO);ds_key_event(&state,DS_TRACE);
    for(unsigned i=0;i<6;++i){ds_ball *b=&state.suika.ball[i];b->used=1;b->level=(uint8_t)i;
        b->x=(i%3*70+45)*256;b->y=(i/3*100+100)*256;}
    CHECK(!ds_render(&state,&surface));
    uint32_t bgr=image[211][127];CHECK(bgr==0x253bb6);
    ds_surface rgb=surface;rgb.rgbx=1;CHECK(!ds_render(&state,&rgb));
    CHECK(image[211][127]==((bgr&255)<<16 | (bgr&0xff00) | ((bgr>>16)&255)));
    CHECK(!ds_render(&state,&surface));if(argc==2)write_ppm(argv[1],"suika-host");
    CASE();start();first=state.fault;state.graphics_failed=1;
    memset(image,0xa5,sizeof image);CHECK(!ds_fallback_framebuffer(&state,&surface));
    CHECK(!memcmp(&first,&state.fault,sizeof first));
    for(unsigned y=0;y<480;++y)for(unsigned x=640;x<648;++x)CHECK(image[y][x]==0xa5a5a5a5);
    if(argc==2)write_ppm(argv[1],"ascii-fallback-host");
    CASE();bad=surface;bad.width=8;bad.height=8;CHECK(ds_surface_storage_valid(&bad));
    CHECK(!ds_surface_valid(&bad));CHECK(ds_fallback_framebuffer(&state,&bad)==-1);
    bad.pixels=0;CHECK(ds_fallback_framebuffer(&state,&bad)==-1);
    CASE();start();CHECK(ds_scan1(&state,0xe0)==DS_NONE);CHECK(ds_scan1(&state,0x4b)==DS_LEFT);
    CHECK(ds_scan1(&state,0xcb)==DS_NONE);CHECK(ds_scan1(&state,0xe0)==DS_NONE);CHECK(ds_scan1(&state,0x02)==DS_NONE);
    CHECK(ds_scan1(&state,0xe1)==DS_NONE);for(unsigned i=0;i<5;++i)CHECK(ds_scan1(&state,0x02)==DS_NONE);
    CHECK(ds_scan1(&state,0x02)==DS_ONE);CHECK(ds_serial_key('2')==DS_TWO && ds_serial_key(' ')==DS_DROP);
    CASE();start();ds_key_event(&state,DS_TWO);uint32_t rng=17;
    for(unsigned i=0;i<30000;++i){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;
        if(i%31==0)ds_key_event(&state,(enum ds_key)(DS_LEFT+rng%5));
        ds_tick(&state);if(state.suika.over)ds_key_event(&state,DS_RESTART);
        for(unsigned j=0;j<DS_BALLS;++j)if(state.suika.ball[j].used){ds_ball *b=&state.suika.ball[j];
            CHECK(b->level<6 && b->x>=0 && b->x<=240*256 && b->y>=-64*256 && b->y<=288*256);}
    }
    CASE();start();ds_key_event(&state,DS_ONE);
    for(unsigned i=0;i<10000;++i){ds_key_event(&state,(enum ds_key)(DS_LEFT+(i*7)%5));ds_tick(&state);
        if(state.tetris.over)ds_key_event(&state,DS_RESTART);
        CHECK(!state.graphics_failed);}
    printf("{\"status\":\"PASS\",\"cases\":%u,\"checks\":%u,\"native_execution\":false}\n",cases,checks);
    return 0;
}
