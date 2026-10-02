/* SPDX-License-Identifier: GPL-2.0-only
 * Include the actual WM/message/input implementations. Only kernel boundaries
 * (copy, allocator, IRQ, locks, clock, token binding and display) are mocked.
 * Portable subject authorization is real production account.c, linked below.
 * No scheduler, hardware, guest, Windows98 or trusted desktop executes here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../kernel64/gfx.h"
#include "../accounts/account.h"
static uint64_t host_irq_save(void){return 0;}
static void host_irq_restore(uint64_t f){(void)f;}
static uint64_t host_time_ns(void){return 100000000;}
#define irq_save host_irq_save
#define irq_restore host_irq_restore
#define shz_time_ns host_time_ns
#include "../kernel64/gfx_wm.c"
#include "../kernel64/gfx_msg.c"
#include "../kernel64/gfx_input.c"
static process_t people[4];static thread_t workers[4];static shz_subject subjects[4];
static thread_t *current;static unsigned checks,failures,copies,allocations;
static unsigned entries[4],takes;
static uint16_t titles[4][8];static uint32_t surfaces[4][400],back[128*32];
gfx_fb_t g_fb;
#define CHECK(x) do{++checks;if(!(x)){++failures;fprintf(stderr,"gfx assertion %u: %s\n",__LINE__,#x);}}while(0)
void mutex_lock(kmutex_t *m){(void)m;}void mutex_unlock(kmutex_t *m){(void)m;}
int copy_from_user(process_t *p,void *dst,uint64_t va,uint64_t n){(void)p;++copies;memcpy(dst,(const void *)(uintptr_t)va,(size_t)n);return 0;}
int copy_to_user(process_t *p,uint64_t va,const void *src,uint64_t n){(void)p;++copies;memcpy((void *)(uintptr_t)va,src,(size_t)n);return 0;}
void *gfx_pages_alloc(uint64_t n){void *p=calloc(1,(size_t)n);if(p)++allocations;return p;}
void gfx_pages_free(void *p,uint64_t n){(void)n;if(p){--allocations;free(p);}}
void *kmalloc(size_t n){return calloc(1,n);}void kfree(void *p){free(p);}
void *kzalloc(size_t n){return calloc(1,n);}
uint64_t ticks_now(void){return 100;}
thread_t *thread_current(void){return current;}
void thread_wake(thread_t *t){(void)t;}
void thread_block_current(void){abort();}
int current_thread_must_die(void){return 0;}
int k64_cmdline_has(const char *s){(void)s;return 0;}
void kprintf(const char *format,...){(void)format;}
void gfx_fb_present(int x,int y,int w,int h){(void)x;(void)y;(void)w;(void)h;}
void gfx_text(uint32_t *p,int stride,int w,int h,int x,int y,const uint16_t *s,unsigned n,uint32_t rgb,int a,int b,int c,int d)
{(void)p;(void)stride;(void)w;(void)h;(void)x;(void)y;(void)s;(void)n;(void)rgb;(void)a;(void)b;(void)c;(void)d;}
void ob_signal_event(kobject_t *o){o->signaled=1;}void ob_reset_event(kobject_t *o){o->signaled=0;}
void ob_deref(kobject_t *o){(void)o;}
kobject_t *ob_create(uint32_t type,const char *name){(void)type;(void)name;return NULL;}
kobject_t *handle_lookup(process_t *p,uint64_t h,uint32_t type){(void)p;(void)h;(void)type;return NULL;}
int32_t handle_insert(process_t *p,kobject_t *o,uint32_t access,uint32_t *h){(void)p;(void)o;(void)access;(void)h;return STATUS_NO_MEMORY;}
uint64_t gfx_pages_in_use(void){return 0;}uint64_t pmm_free_count(void){return 0;}
void gclip_window_gone(uint64_t h){(void)h;}void gclip_queue_gone(gqueue_t *q){(void)q;}
int shz_auth_process_access(process_t *a,process_t *b)
{
    unsigned i,j;for(i=0;i<4 && people+i!=a;i++){}for(j=0;j<4 && people+j!=b;j++){}
    return i<4 && j<4 && shz_subject_access(subjects+i,subjects+j);
}
int shz_auth_gui_take_entry(process_t *p)
{unsigned i;for(i=0;i<4;i++)if(people+i==p){if(entries[i]){entries[i]=0;++takes;return 1;}return 0;}return 0;}
static void setup(void)
{
    unsigned i;
    g_win=calloc(GFX_MAX_WINDOWS,sizeof *g_win);g_cls=calloc(GFX_MAX_CLASSES,sizeof *g_cls);
    CHECK(g_win && g_cls && !gq_tables_init() && !gin_tables_init());
    memset(people,0,sizeof people);memset(workers,0,sizeof workers);
    for(i=0;i<4;i++) {
        gqueue_t *q=g_queues+i;gwin_t *w=g_win+i+1;
        people[i].used=1;people[i].pid=10+(int)i;people[i].threads_alive=1;
        workers[i].id=100+i;workers[i].tid=200+i;workers[i].state=TS_RUNNING;workers[i].proc=people+i;
        q->used=1;q->thread=workers+i;q->thread_id=workers[i].id;q->proc=people+i;q->pid=(uint32_t)people[i].pid;
        q->cursor=-1;
        w->used=1;w->handle=(1ull<<12)|(i+2u);w->gen=1;w->q=q;w->pid=q->pid;w->tid=(uint32_t)workers[i].tid;
        w->parent=g_win;w->style=SHZ_WS_POPUP|SHZ_WS_VISIBLE;w->x=(int32_t)i*24;w->w=w->h=w->sw=w->sh=20;w->surf=surfaces[i];
        w->cls=g_cls+i;w->cls->used=1;w->cls->pid=q->pid;w->cls->name_len=1;w->cls->name[0]='X';w->title=titles[i];w->title_len=1;w->title[0]=(uint16_t)('A'+i);
        q->active=q->focus=w->handle;w->userdata=0xabc+i;
        subjects[i]=(shz_subject){0,0,0x2000,0,0,0,0x4e7};
    }
    subjects[2]=(shz_subject){UINT32_MAX,UINT32_MAX,0x4000,0,0,0,UINT64_MAX};
    subjects[3]=(shz_subject){1,1,0x2000,0,0,0,0x100000001ull};
    g_win[0].used=1;g_win[0].handle=0x1001;g_win[0].gen=1;g_win[0].w=128;g_win[0].h=32;g_win[0].style=SHZ_WS_VISIBLE;
    g_win[0].child=g_win+3;g_win[3].next=g_win+1;g_win[1].prev=g_win+3;g_win[1].next=g_win+2;g_win[2].prev=g_win+1;g_win[2].next=g_win+4;g_win[4].prev=g_win+2;
    g_fb.width=128;g_fb.height=32;g_fb.back=back;g_fg_q=g_queues+2;current=workers;
}
static void query_tests(void)
{
    shz_wnd_t q={0};shz_enum_t e={0};uint64_t list[8],hit=0;uint16_t output[8];unsigned i;
    q.hwnd=g_win[3].handle;q.what=SHZ_WQ_USERDATA;
    CHECK(sys_wquery(people,(uintptr_t)&q)==STATUS_ACCESS_DENIED && q.v0==0);
    q.what=SHZ_WQ_TEXT;q.buf=(uintptr_t)output;q.buf_len=8;memset(output,0xa5,sizeof output);
    CHECK(sys_wquery(people,(uintptr_t)&q)==STATUS_ACCESS_DENIED && output[0]==0xa5a5);
    q.hwnd=g_win[2].handle;q.what=SHZ_WQ_USERDATA;CHECK(!sys_wquery(people,(uintptr_t)&q) && q.v0==g_win[2].userdata);
    q.hwnd=g_win[1].handle;q.what=SHZ_WQ_GW;q.index=3;q.v0=0;
    CHECK(!sys_wquery(people,(uintptr_t)&q) && q.v0==0); /* previous sibling is protected */
    e.out=(uintptr_t)list;e.max=8;memset(list,0xa5,sizeof list);
    CHECK(!sys_enumwindows(people,(uintptr_t)&e) && e.count==2);
    for(i=0;i<e.count;i++)CHECK(list[i]==g_win[1].handle || list[i]==g_win[2].handle);
    CHECK(sys_hittest(people,g_win[3].x+1,1,(uintptr_t)&hit)==STATUS_ACCESS_DENIED && !hit);
    current=workers+2;CHECK(!sys_hittest(people+2,g_win[3].x+1,1,(uintptr_t)&hit) && hit==g_win[3].handle);current=workers;
    {static const uint32_t private_queries[]={SHZ_WQ_RECT,SHZ_WQ_POS,SHZ_WQ_RESTORE,SHZ_WQ_CLIENT,SHZ_WQ_CLIENT_ORG,
      SHZ_WQ_STYLE,SHZ_WQ_EXSTYLE,SHZ_WQ_ID,SHZ_WQ_USERDATA,SHZ_WQ_WNDPROC,SHZ_WQ_HINSTANCE,SHZ_WQ_PARENT,
      SHZ_WQ_OWNER,SHZ_WQ_THREAD,SHZ_WQ_TEXT,SHZ_WQ_CLASSNAME,SHZ_WQ_CLASS_ATOM,SHZ_WQ_VISIBLE,SHZ_WQ_ENABLED,
      SHZ_WQ_EXTRA,SHZ_WQ_GW,SHZ_WQ_ANCESTOR,SHZ_WQ_ISCHILD};
     for(i=0;i<sizeof private_queries/sizeof *private_queries;i++) {
        q=(shz_wnd_t){0};q.hwnd=g_win[3].handle;q.what=private_queries[i];q.buf=(uintptr_t)output;q.buf_len=8;
        CHECK(sys_wquery(people,(uintptr_t)&q)==STATUS_ACCESS_DENIED);
     }
     q.what=SHZ_WQ_EXISTS;CHECK(!sys_wquery(people,(uintptr_t)&q) && !q.v0);
     q.what=SHZ_WQ_DESKTOP;CHECK(sys_wquery(people,(uintptr_t)&q)==STATUS_ACCESS_DENIED);
     g_fg_q=NULL;CHECK(!sys_wquery(people,(uintptr_t)&q) && q.v0==g_win[0].handle);g_fg_q=g_queues+2;
    }
}
static void class_tests(void)
{
    shz_classop_t op={0};uint16_t output[8];uint64_t extra=0x55667788;
    op.hwnd=g_win[3].handle;op.op=SHZ_CLASS_GETLONG;op.index=-24;op.value=0xa5;
    CHECK(sys_classop(people,(uintptr_t)&op)==STATUS_ACCESS_DENIED && op.value==0xa5);
    op.op=SHZ_CLASS_GETNAME;op.buf=(uintptr_t)output;op.buf_len=8;memset(output,0xa5,sizeof output);
    CHECK(sys_classop(people,(uintptr_t)&op)==STATUS_ACCESS_DENIED && output[0]==0xa5a5);
    g_cls[2].cb_cls=8;g_cls[2].extra=(uint8_t *)&extra;op.op=SHZ_CLASS_GETLONG;op.index=0;
    CHECK(sys_classop(people,(uintptr_t)&op)==STATUS_ACCESS_DENIED);
    op.op=SHZ_CLASS_SETLONG;op.value=0xdead;
    CHECK(sys_classop(people,(uintptr_t)&op)==STATUS_ACCESS_DENIED && extra==0x55667788);
    g_cls[2].extra=NULL;g_cls[2].cb_cls=0;
    op.hwnd=g_win[2].handle;op.op=SHZ_CLASS_GETNAME;op.buf_len=8;
    CHECK(!sys_classop(people,(uintptr_t)&op) && output[0]=='X');
    op.op=SHZ_CLASS_SETLONG;op.index=-24;op.value=0xdead;
    CHECK(sys_classop(people,(uintptr_t)&op)==STATUS_ACCESS_DENIED && !g_cls[1].wndproc);
    op.hwnd=g_win[1].handle;op.value=0xdead;
    CHECK(!sys_classop(people,(uintptr_t)&op) && g_cls[0].wndproc==0xdead);
    g_cls[0].cb_cls=8;g_cls[0].extra=(uint8_t *)&extra;
    op.op=SHZ_CLASS_GETLONG;op.index=0;
    CHECK(!sys_classop(people,(uintptr_t)&op) && op.value==0x55667788);
    op.index=1;CHECK(sys_classop(people,(uintptr_t)&op)==STATUS_INVALID_PARAMETER);
    op.index=INT32_MAX;CHECK(sys_classop(people,(uintptr_t)&op)==STATUS_INVALID_PARAMETER);
    op.index=INT64_MAX;CHECK(sys_classop(people,(uintptr_t)&op)==STATUS_INVALID_PARAMETER && extra==0x55667788);
    op.op=SHZ_CLASS_SETLONG;op.value=0xabcdef;
    CHECK(sys_classop(people,(uintptr_t)&op)==STATUS_INVALID_PARAMETER && extra==0x55667788);
    op.index=0;CHECK(!sys_classop(people,(uintptr_t)&op) && extra==0xabcdef);
    g_cls[0].extra=NULL;g_cls[0].cb_cls=0;
}
static void message_present_tests(void)
{
    shz_send_t send={0};shz_threadop_t op={0};shz_focus_t focus={0};shz_present_t present={0};uint32_t *pixel=malloc(4);
    unsigned before=g_queues[2].nposted,read_before;
    CHECK(sys_postmessage(people,g_win[3].handle,0x123,0,0)==STATUS_ACCESS_DENIED && g_queues[2].nposted==before);
    CHECK(!sys_postmessage(people,g_win[2].handle,0x123,0,0) && g_queues[1].nposted==1);
    send.hwnd=g_win[3].handle;CHECK(sys_sendmessage(people,(uintptr_t)&send)==STATUS_ACCESS_DENIED);
    op.op=SHZ_TOP_POSTTHREAD;op.a=workers[2].tid;op.b=0x124;
    CHECK(sys_threadop(people,(uintptr_t)&op)==STATUS_ACCESS_DENIED && g_queues[2].nposted==before);
    focus.op=SHZ_FOCUS_SETFOREGROUND;focus.hwnd=g_win[3].handle;
    CHECK(sys_focus(people,(uintptr_t)&focus)==STATUS_ACCESS_DENIED && g_fg_q==g_queues+2);
    focus.hwnd=g_win[1].handle;CHECK(sys_focus(people,(uintptr_t)&focus)==STATUS_ACCESS_DENIED && g_fg_q==g_queues+2);
    focus.op=SHZ_FOCUS_SETACTIVE;CHECK(sys_focus(people,(uintptr_t)&focus)==STATUS_ACCESS_DENIED && g_fg_q==g_queues+2);
    {shz_show_t show={0};shz_setpos_t pos={0};show.hwnd=g_win[1].handle;show.cmd=SW_SHOW;
     CHECK(!sys_showwindow(people,(uintptr_t)&show) && !show.activated && g_fg_q==g_queues+2);
     pos.hwnd=g_win[1].handle;pos.flags=SWP_NOSIZE|SWP_NOMOVE;
     CHECK(!sys_setwindowpos(people,(uintptr_t)&pos) && !pos.prev_active && g_fg_q==g_queues+2);
    }
    *pixel=0x123456;present.hwnd=g_win[3].handle;present.bits=(uintptr_t)pixel;present.stride=80;present.surf_w=present.surf_h=20;present.w=present.h=1;
    read_before=copies;CHECK(gfx_syscall_present(people,(uintptr_t)&present)==STATUS_ACCESS_DENIED && surfaces[2][0]==0 && copies==read_before+1);
    present.hwnd=g_win[2].handle;CHECK(!gfx_syscall_present(people,(uintptr_t)&present) && surfaces[1][0]==*pixel);
    free(pixel);
}
static void input_tests(void)
{
    shz_input_t in={0};shz_rawrec_t rec={0},out;uint32_t id;unsigned before;
    in.op=SHZ_IN_GETASYNCKEYSTATE;in.a='A';g_pressed['A']=1;
    CHECK(gfx_syscall_input(people,(uintptr_t)&in)==STATUS_ACCESS_DENIED && g_pressed['A']==1);
    in.op=SHZ_IN_GETKEYSTATE;CHECK(!gfx_syscall_input(people,(uintptr_t)&in));
    g_hot[0]=(ghotkey_t){1,workers[0].id,g_win[1].handle,1,0,'A'};before=g_queues[0].nposted;
    CHECK(!hotkey_fire('A',0) && g_queues[0].nposted==before);memset(g_hot,0,sizeof g_hot);
    g_rawreg[0]=(grawreg_t){1,(uint32_t)people[0].pid,SHZ_RAW_KEYBOARD,RIDEV_INPUTSINK_,g_win[1].handle};
    rec.type=1;rec.kb_vkey='A';raw_post(SHZ_RAW_KEYBOARD,&rec);
    CHECK(g_queues[0].nposted==before);
    memset(g_rawreg,0,sizeof g_rawreg);g_rawreg[0]=(grawreg_t){1,(uint32_t)people[2].pid,SHZ_RAW_KEYBOARD,0,g_win[3].handle};
    raw_post(SHZ_RAW_KEYBOARD,&rec);id=g_raw_next-1;
    memset(&out,0xa5,sizeof out);in=(shz_input_t){0};in.op=SHZ_IN_RAWGET;in.a=id;in.buf=(uintptr_t)&out;in.buf_len=sizeof out;
    CHECK(gfx_syscall_input(people,(uintptr_t)&in)==STATUS_ACCESS_DENIED && out.kb_vkey==0xa5a5);
    current=workers+2;CHECK(!gfx_syscall_input(people+2,(uintptr_t)&in) && out.kb_vkey=='A');current=workers;
    ++g_queues[2].thread_id;CHECK(gfx_syscall_input(people+2,(uintptr_t)&in)==STATUS_ACCESS_DENIED);--g_queues[2].thread_id;
    gin_queue_gone(g_queues+2);CHECK(gfx_syscall_input(people+2,(uintptr_t)&in)==STATUS_INVALID_HANDLE);
    gin_queue_init(g_queues);CHECK(g_queues[0].keys['A']==0);
    g_fg_q=g_queues;current=workers+1;in=(shz_input_t){0};in.op=SHZ_IN_GETASYNCKEYSTATE;in.a='A';
    CHECK(!gfx_syscall_input(people+1,(uintptr_t)&in));
    {shz_inrec_t key={0};unsigned before_input=g_queues[0].nin;key.type=1;key.vk='B';
     in=(shz_input_t){0};in.op=SHZ_IN_SENDINPUT;in.a=1;in.buf=(uintptr_t)&key;
     CHECK(!gfx_syscall_input(people+1,(uintptr_t)&in) && g_queues[0].nin==before_input+1);
     current=workers+3;before_input=g_queues[0].nin;
     CHECK(gfx_syscall_input(people+3,(uintptr_t)&in)==STATUS_ACCESS_DENIED && g_queues[0].nin==before_input);
    }
    g_fg_q=NULL;current=workers;in=(shz_input_t){0};in.op=SHZ_IN_GETASYNCKEYSTATE;
    CHECK(gfx_syscall_input(people,(uintptr_t)&in)==STATUS_ACCESS_DENIED);
    g_fg_q=g_queues+2;
}
static void lifetime_tests(void)
{
    gqueue_t saved=g_queues[0];thread_t worker=workers[0];unsigned i;
    CHECK(gfx_auth_queue(people,g_queues));
    for(i=0;i<7;i++) {
        g_queues[0]=saved;workers[0]=worker;
        if(i==0)g_queues[0].used=0;
        if(i==1)g_queues[0].thread=NULL;
        if(i==2)g_queues[0].proc=people+1;
        if(i==3)g_queues[0].pid++;
        if(i==4)workers[0].id++;
        if(i==5)workers[0].state=TS_ZOMBIE;
        if(i==6)workers[0].proc=people+1;
        CHECK(!gfx_auth_queue(people,g_queues) && !gfx_auth_window(people,g_win+1));
    }
    g_queues[0]=saved;workers[0]=worker;
    people[0].terminated=1;CHECK(!gfx_auth_queue(people,g_queues));people[0].terminated=0;
}
static void composition_entry_tests(void)
{
    shz_focus_t f={0};shz_rect_t all={0,0,128,32},low={0,0,20,20};unsigned i,raw_id;shz_rawrec_t raw={0};
    for(i=0;i<400;i++){surfaces[0][i]=0x115522;surfaces[1][i]=0x225533;surfaces[2][i]=0x993344;surfaces[3][i]=0x3355aa;}
    memset(back,0xa5,sizeof back);g_fb.ready=1;g_fg_q=g_queues+2;wm_damage(&all);
    CHECK(back[1*128+1]==SHZ_DESKTOP_RGB && back[1*128+49]==0x993344 && back[1*128+73]==SHZ_DESKTOP_RGB);
    back[1*128+1]=0xdeadbeef;wm_damage(&low);CHECK(back[1*128+1]==SHZ_DESKTOP_RGB); /* denied opaque window cannot occlude background */
    CHECK(wm_input_hit(1,1)==NULL && wm_input_hit(49,1)==g_win+3);
    g_win[0].surf=gfx_pages_alloc(sizeof back);g_win[0].sw=128;g_win[0].sh=32;
    for(i=0;i<128*32;i++)g_win[0].surf[i]=0x887766;
    raw.type=1;raw.kb_vkey='Z';raw_post(SHZ_RAW_KEYBOARD,&raw);raw_id=g_raw_next-1;CHECK(g_raw_ids[raw_id%GIN_RAWRING]==raw_id);
    entries[3]=1;current=workers+3;f.op=SHZ_FOCUS_SETFOREGROUND;f.hwnd=g_win[4].handle;
    g_win[4].style&=~SHZ_WS_VISIBLE;
    CHECK(sys_focus(people+3,(uintptr_t)&f)==STATUS_UNSUCCESSFUL && entries[3]==1 && takes==0 && g_fg_q==g_queues+2);
    g_win[4].style|=SHZ_WS_VISIBLE;entries[3]=1;takes=0;
    CHECK(!sys_focus(people+3,(uintptr_t)&f) && g_fg_q==g_queues+3 && !entries[3] && takes==1);
    CHECK(back[1*128+49]==SHZ_DESKTOP_RGB && back[1*128+73]==0x3355aa && g_win[0].surf[0]==SHZ_DESKTOP_RGB);
    CHECK(!g_raw_ids[raw_id%GIN_RAWRING] && !g_clip_on && !g_pressed['A']);
    current=workers;entries[0]=1;f.hwnd=g_win[2].handle; /* foreign same-subject window cannot consume caller entry */
    CHECK(sys_focus(people,(uintptr_t)&f)==STATUS_ACCESS_DENIED && entries[0]==1 && takes==1);
    f.hwnd=0xdeaddead;CHECK(sys_focus(people,(uintptr_t)&f)==STATUS_INVALID_HANDLE && entries[0]==1 && takes==1);
    entries[0]=0;f.hwnd=g_win[1].handle;CHECK(sys_focus(people,(uintptr_t)&f)==STATUS_ACCESS_DENIED && g_fg_q==g_queues+3);
    entries[0]=1;CHECK(!sys_focus(people,(uintptr_t)&f) && g_fg_q==g_queues && takes==2);
    CHECK(back[1*128+49]==SHZ_DESKTOP_RGB && back[1*128+1]==0x115522 && back[1*128+25]==0x225533);
    subjects[1].integrity=0x1000;wm_damage(&all);
    CHECK(back[1*128+25]==SHZ_DESKTOP_RGB && wm_input_hit(25,1)==NULL); /* lower-IL overlay is hidden */
    subjects[1].integrity=0x2000;
    g_fb.ready=0;
}
static void cleanup(void)
{
    unsigned i;for(i=0;i<GFX_MAX_WINDOWS;i++)if(g_win[i].written)gfx_pages_free(g_win[i].written,shz_written_bytes(g_win[i].sw,g_win[i].sh));
    free(g_win);free(g_cls);gfx_pages_free(g_queues,sizeof(gqueue_t)*GFX_MAX_QUEUES);gfx_pages_free(g_msgs,sizeof(gmsg_t)*GFX_MAX_MSGS);
    gfx_pages_free(g_curs,sizeof(gcur_t)*GIN_CURSORS);gfx_pages_free(g_raw,sizeof(shz_rawrec_t)*GIN_RAWRING);CHECK(allocations==0);
}
int main(void)
{
    setup();query_tests();class_tests();message_present_tests();input_tests();lifetime_tests();composition_entry_tests();
    gfx_pages_free(g_win[0].surf,sizeof back);g_win[0].surf=NULL;cleanup();
    printf("%s: %u actual Kernel64 GUI authorization checks, %u failures; kernel boundaries mocked\n",failures?"FAIL":"PASS",checks,failures);
    return failures?1:0;
}
