/* SPDX-License-Identifier: GPL-2.0-only
 * Actual in-guest installer window. Disk writing stays in the portable SHZSETUP
 * core; this frontend only selects, confirms and reports its real results. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "interactive_ui.h"
#include "interactive_choice.h"
#include "shzcrt.h"

#define UI_DISKS 32
static void simple_progress(const char *value);
static HWND window;
static HINSTANCE instance;
static const plat_t *platform;
static shz_native_gui *native_ui;
static native_setup_target_v1_t native_reviewed;
static unsigned choices[UI_DISKS], count, selected, top;
static plat_disk_t reviewed;
static char confirmation[6], last_line[280];
static char progress_line[280];
static size_t progress_used;
static unsigned confirmation_len;
static char *answer_out;
static size_t answer_capacity;
static int stage, approved, done, failed, reserve_win98, installed, power;
/* 0 selection, 1 review, 2 installing, 3 result. */

static void text(HDC dc, int x, int y, const WCHAR *value)
{ int n = 0; while (value[n]) ++n; TextOutW(dc, x, y, value, n); }

static void narrow_text(HDC dc, int x, int y, const char *value)
{
    WCHAR w[300];
    unsigned i;
    for (i = 0; value[i] && i + 1 < sizeof w / sizeof w[0]; ++i) w[i] = (unsigned char)value[i];
    w[i] = 0; text(dc, x, y, w);
}

static void repaint(void)
{ if (window) { InvalidateRect(window, 0, TRUE); UpdateWindow(window); } }

static unsigned visible_rows(HWND hwnd)
{
    RECT rc;
    unsigned rows;
    GetClientRect(hwnd, &rc);
    rows = rc.bottom > 250 ? (unsigned)(rc.bottom - 250) / 25 : 1;
    return rows ? rows : 1;
}

static int eligible(unsigned index,plat_disk_t *out)
{
 if(native_ui){native_setup_target_v1_t t;
  if(shz_native_gui_review(native_ui,index,&t))return -1;
  *out=t.disk;return 0;
 }
 return setup_review_target(platform,index,out);
}

static void paint(HWND hwnd)
{
    PAINTSTRUCT ps;
    RECT rc;
    HDC dc = BeginPaint(hwnd, &ps);
    HBRUSH background = CreateSolidBrush(RGB(244, 246, 251));
    unsigned i, visible;
    char line[220];
    GetClientRect(hwnd, &rc); FillRect(dc, &rc, background); DeleteObject(background);
    visible = visible_rows(hwnd);
    if (selected < top) top = selected;
    if (selected >= top + visible) top = selected - visible + 1;
    SetBkMode(dc, TRANSPARENT); SetTextColor(dc, RGB(24, 34, 56));
    text(dc, 28, 24, L"ShizukuOS Setup");
    text(dc, 28, 52, L"Install with the built-in Shizuku installer");
    if (stage == 0) {
        text(dc, 28, 88, L"Choose a disk. Nothing is changed until you confirm.");
        if (!count) text(dc, 28, 128, native_ui ? L"No eligible disk for the prepared Windows 98 system." :
                                             L"No writable disk: need 256 MiB and 512-byte sectors.");
        for (i = top; i < count && i < top + visible; ++i) {
            plat_disk_t d;
            if (eligible(choices[i], &d)) continue;
            snprintf(line, sizeof line, "%c %s   %llu MiB%s", i == selected ? '>' : ' ', d.name,
                     (unsigned long long)(d.sectors / 2048), d.flags & PLAT_DISK_REMOVABLE ? "   removable" : "");
            narrow_text(dc, 34, 126 + (int)(i - top) * 25, line);
        }
        text(dc, 28, rc.bottom - 64, L"Up/Down or click: select    Enter: review    Esc: cancel");
        text(dc, 28, rc.bottom - 36, L"Confirming installation deletes every file on that disk.");
    } else if (stage == 1) {
        snprintf(line, sizeof line, "Target: %s   %llu MiB", reviewed.name,
                 (unsigned long long)(reviewed.sectors / 2048));
        narrow_text(dc, 28, 100, line);
        text(dc, 28, 144, L"Installation deletes ALL partitions and files on this target.");
        text(dc, 28, 176, L"Other disks are not selected. Esc returns without installing.");
        if (native_ui) text(dc, 28, 220, L"Install the prepared Windows 98 system on this disk.");
        else text(dc, 28, 220, reserve_win98 ? L"Windows 98 data partition: 512 MiB (F2 to change)" :
                                                      L"Windows 98 data partition: none (F2 to change)");
        if (!native_ui) text(dc, 28, 252, L"Your own Windows 98 files are separate; they are not bundled.");
        text(dc, 28, 302, L"Type ERASE, then press Enter to install:");
        narrow_text(dc, 28, 344, confirmation);
    } else if (stage == 2) {
        text(dc, 28, 112, L"Installing and checking the written system...");
        text(dc, 28, 152, L"Keep the machine on until verification finishes.");
        narrow_text(dc, 28, 216, last_line);
    } else {
        text(dc, 28, 112, installed ? L"Installation and file verification finished." : L"Installation failed.");
        narrow_text(dc, 28, 168, last_line);
        text(dc, 28, 236, installed ? L"Remove the installation medium before starting the installed disk." :
                                              L"The failure is recorded in the console. Review the target before retrying.");
        text(dc, 28, 310, L"R: restart    S: shut down    Esc: close");
    }
    EndPaint(hwnd, &ps);
}

static void review(void)
{
    if (!count) return;
    if(native_ui){
        if(shz_native_gui_review(native_ui,choices[selected],&native_reviewed))return;
        reviewed=native_reviewed.disk;
    }else if(setup_review_target(platform,choices[selected],&reviewed))return;
    reserve_win98 = reviewed.sectors >= 768ull * 2048;
    confirmation[0] = 0; confirmation_len = 0; stage = 1;
    printf("SHZ-SETUP UI review target=%s sectors=%llu\n", reviewed.name, (unsigned long long)reviewed.sectors);
    repaint();
}

static LRESULT CALLBACK procedure(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_PAINT) { paint(hwnd); return 0; }
    if (msg == WM_GETMINMAXINFO) {
        MINMAXINFO *limits = (MINMAXINFO *)(uintptr_t)lp;
        limits->ptMinTrackSize.x = 600; limits->ptMinTrackSize.y = 440;
        return 0;
    }
    if (msg == WM_SIZING) {
        RECT *bounds = (RECT *)(uintptr_t)lp;
        if (bounds->right - bounds->left < 600) {
            if (wp == WMSZ_LEFT || wp == WMSZ_TOPLEFT || wp == WMSZ_BOTTOMLEFT)
                bounds->left = bounds->right - 600;
            else bounds->right = bounds->left + 600;
        }
        if (bounds->bottom - bounds->top < 440) {
            if (wp == WMSZ_TOP || wp == WMSZ_TOPLEFT || wp == WMSZ_TOPRIGHT)
                bounds->top = bounds->bottom - 440;
            else bounds->bottom = bounds->top + 440;
        }
        return TRUE;
    }
    if (msg == WM_CLOSE) {
        if (stage != 2) done = 1;
        return 0;
    }
    if (msg == WM_KEYDOWN) {
        if (wp == VK_ESCAPE && stage != 2) {
            if (stage == 1) { stage = 0; confirmation_len = 0; confirmation[0] = 0; repaint(); }
            else done = 1;
        } else if (stage == 0 && count) {
            if (wp == VK_UP) { if (selected) --selected; repaint(); }
            else if (wp == VK_DOWN) { if (selected + 1 < count) ++selected; repaint(); }
            else if (wp == VK_RETURN) review();
        } else if (stage == 1 && wp == VK_RETURN) {
            plat_disk_t current;
            int accepted = native_ui ? !shz_native_gui_confirm(native_ui,&native_reviewed,confirmation) :
                !setup_review_target(platform, choices[selected], &current) &&
                !memcmp(&current, &reviewed, sizeof current) &&
                !setup_build_interactive_answer(&current, confirmation, reserve_win98, answer_out, answer_capacity);
            if (accepted) {
                if(native_ui)current=native_reviewed.disk;
                approved = 1; stage = 2;
                printf("SHZ-SETUP UI confirmed target=%s\n", current.name);
                repaint();
            }
        } else if (stage == 1 && !native_ui && wp == VK_F2 && confirmation_len == 0) {
            if (reviewed.sectors >= 768ull * 2048) reserve_win98 = !reserve_win98;
            repaint();
        } else if (stage == 3) {
            if (wp == 'R') { power = SETUP_POWER_REBOOT; done = 1; }
            else if (wp == 'S') { power = SETUP_POWER_SHUTDOWN; done = 1; }
        }
        return 0;
    }
    if (msg == WM_CHAR && stage == 1) {
        if (wp == '\b') { if (confirmation_len) confirmation[--confirmation_len] = 0; }
        else if (((wp >= 'A' && wp <= 'Z') || (wp >= 'a' && wp <= 'z')) && confirmation_len < 5) {
            if (wp >= 'a' && wp <= 'z') wp -= 'a' - 'A';
            confirmation[confirmation_len++] = (char)wp; confirmation[confirmation_len] = 0;
        }
        repaint(); return 0;
    }
    if (msg == WM_LBUTTONDOWN && stage == 0) {
        int y = (short)((lp >> 16) & 0xffff);
        int x = (short)(lp & 0xffff);
        RECT rc;
        GetClientRect(hwnd, &rc);
        if (x >= 28 && x < rc.right - 28 && y >= 120 && y < 120 + (int)visible_rows(hwnd) * 25) {
            unsigned row = top + (unsigned)(y - 120) / 25;
            if (row < count) { selected = row; repaint(); }
        }
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static int messages(int selection)
{
    MSG msg;
    int rc;
    while (!done && !(selection && approved)) {
        rc = GetMessageW(&msg, 0, 0, 0);
        if (rc <= 0) { if (rc < 0) failed = 1; done = 1; break; }
        TranslateMessage(&msg); DispatchMessageW(&msg);
    }
    return failed ? -1 : approved ? 0 : 1;
}

static void close_ui(void)
{
    if (window) DestroyWindow(window);
    window = 0; UnregisterClassW(L"ShizukuSetupWindow", instance);
}

static int choose(const plat_t *p, char *answer, size_t capacity,shz_native_gui *native)
{
    WNDCLASSEXW wc;
    unsigned i;
    int rc, width = GetSystemMetrics(SM_CXSCREEN), height = GetSystemMetrics(SM_CYSCREEN);
    if (!p || (!answer&&!native) || width < 640 || height < 480) return -1;
    platform = p; native_ui = native; answer_out = answer; answer_capacity = capacity;
    count = selected = top = confirmation_len = 0; stage = approved = done = failed = installed = power = reserve_win98 = 0;
    progress_used = 0; progress_line[0] = last_line[0] = 0;
    for (i = 0; i < p->disk_count(p->ctx) && count < UI_DISKS; ++i) {
        plat_disk_t target;
        if (!eligible(i, &target)) choices[count++] = i;
    }
    instance = GetModuleHandleW(0);
    memset(&wc, 0, sizeof wc); wc.cbSize = sizeof wc; wc.lpfnWndProc = procedure;
    wc.hInstance = instance; wc.lpszClassName = L"ShizukuSetupWindow";
    if (!RegisterClassExW(&wc)) return -1;
    { int w = width < 792 ? width - 32 : 760, h = height < 612 ? height - 32 : 580;
      window = CreateWindowExW(0, wc.lpszClassName, L"ShizukuOS Setup", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                               (width - w) / 2, (height - h) / 2, w, h, 0, 0, instance, 0); }
    if (!window) { close_ui(); return -1; }
    SetForegroundWindow(window); SetFocus(window); repaint();
    printf("SHZ-SETUP UI ready candidates=%u writes=0\n", count);
    rc = messages(1);
    if (rc) close_ui();
    return rc;
}

int setup_ui_choose(const plat_t *p,char *answer,size_t capacity)
{ return choose(p,answer,capacity,0); }
int setup_ui_choose_native(const plat_t *p,shz_native_gui *native)
{ if(!native||!native->prepared)return -1;return choose(p,0,0,native); }

void setup_ui_progress(const char *value)
{
    size_t i, j;
    simple_progress(value);
    if (!window || !value) return;
    /* The portable writer emits each line in several out() calls. Keep the
     * actual assembled line visible when the final call is just a newline. */
    for (i = 0; value[i]; ++i) {
        if (value[i] == '\r') continue;
        if (value[i] == '\n') {
            progress_used = 0;
            continue;
        }
        if (progress_used + 1 < sizeof progress_line) progress_line[progress_used++] = value[i];
        progress_line[progress_used] = 0;
        for (j = 0; j <= progress_used; ++j) last_line[j] = progress_line[j];
    }
    repaint();
}

void setup_ui_finish(setup_result_t *result)
{
    MSG msg;
    if (!window || !result) return;
    /* Input pressed while the writer was busy must not trigger a restart. */
    while (PeekMessageW(&msg, window, WM_KEYFIRST, WM_KEYLAST, PM_REMOVE)) {}
    installed = result->ok; stage = 3; done = 0;
    progress_used = 0;
    setup_ui_progress(result->ok ? "SETUP-RESULT: OK" : result->reason);
    messages(0); result->power = power; close_ui();
}

/* Public five-screen flow in the existing SHZSETUP executable. The private
 * sealed-input compatibility entry above remains unchanged. */
#include "ui_strings.h"
#include "shz_text_diag.h"
#define SIMPLE_DISKS 32u
#define SIMPLE_LOG_BYTES (256u*1024u)
#define SIMPLE_TIMER 71u
#define SIMPLE_ROW 72
#define SIMPLE_NONE ((unsigned)-1)
enum { SIMPLE_WELCOME, SIMPLE_TARGET, SIMPLE_SUMMARY, SIMPLE_PROGRESS, SIMPLE_COMPLETE };
enum { JOB_SCAN=1, JOB_PLAN, JOB_INSTALL };
enum { B_KO=1,B_EN,B_NEXT,B_BACK,B_EXIT,B_INSTALL,B_DETAILS,B_CANCEL,B_RESTART,B_SHUTDOWN,B_SAVELOG };
typedef struct simple_disk {
    setup_target_t target;
    char reason[160];
    int allowed;
} simple_disk_t;
typedef struct simple_button { RECT rect; int id,enabled,primary; const WCHAR *label; } simple_button_t;
typedef struct simple_state {
    HWND hwnd; HINSTANCE module; const plat_t *p; const setup_ui_backend_t *backend;
    char *answer; size_t answer_cap; const char *answer_path,*payload;
    HANDLE worker; int job,screen,done,details,focus,claimed;
    unsigned selected,count,top,language;
    volatile LONG cancel,dirty;
    CRITICAL_SECTION lock;
    simple_disk_t disks[SIMPLE_DISKS];
    setup_image_t image,job_image; setup_plan_t plan,job_plan; setup_event_t event;
    simple_disk_t job_disks[SIMPLE_DISKS]; unsigned job_count; int job_image_ok,job_plan_ok;
    setup_result_t result,job_result;
    int image_ok,plan_ok;
    char *log; size_t log_used; char line[280],status[280]; size_t line_used;
    simple_button_t buttons[6]; unsigned button_count;
    int width,height,scale,body,title;
    DWORD last_error; int fatal_error;
} simple_state_t;
static simple_state_t U;
static int simple_active;

static const WCHAR *tr(enum setup_string id) { return setup_string(U.language,id); }
static void simple_repaint(void) { if(U.hwnd)InvalidateRect(U.hwnd,0,FALSE); }
static int units(const WCHAR *s) { int n=0;while(s[n])++n;return n; }
static void ascii(WCHAR *dst,unsigned cap,const char *src)
{
    int n;
    if(!cap)return;
    n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,src,-1,dst,(int)cap);
    if(!n){unsigned i;for(i=0;src[i]&&i+1<cap;++i)dst[i]=(unsigned char)src[i];dst[i]=0;}
}
static void fill(HDC dc,RECT r,COLORREF c)
{ HBRUSH b=CreateSolidBrush(c);if(b){FillRect(dc,&r,b);DeleteObject(b);} }
static int measure(const WCHAR *s,int n,int px)
{ SIZE z;if(!ShzTextMeasurePxExW(s,n,px,&z,0,0))return -1;return z.cx; }
/* Real proportional wrapping, clipped to the supplied body area. No bitmap
 * fallback is permitted, and UTF-16 pairs never split at a line boundary. */
static int paragraph(HDC dc,RECT r,const WCHAR *s,int px,COLORREF color,int center)
{
    int n=units(s),start=0,y=r.top,saved=SaveDC(dc),line_h=px+8;
    if(!saved||IntersectClipRect(dc,r.left,r.top,r.right,r.bottom)==ERROR){if(saved)RestoreDC(dc,saved);return y;}
    while(start<n&&y+px<=r.bottom){
        int end=start,last_space=-1,width=0;
        while(end<n&&s[end]!='\n'){
            int next=end+1,w;
            if(s[end]>=0xd800&&s[end]<=0xdbff&&next<n&&s[next]>=0xdc00&&s[next]<=0xdfff)++next;
            w=measure(s+start,next-start,px);if(w<0)break;
            if(w>r.right-r.left&&end>start)break;
            width=w;end=next;if(s[end-1]==' ')last_space=end;
            if(w>r.right-r.left)break;
        }
        if(end==start)break;
        if(end<n&&s[end]!='\n'&&last_space>start){end=last_space;width=measure(s+start,end-start,px);}
        ShzTextDrawPxW(dc,center?r.left+(r.right-r.left-width)/2:r.left,y,s+start,end-start,color,px);
        y+=line_h;start=end;if(start<n&&s[start]=='\n')++start;
        while(start<n&&s[start]==' ')++start;
    }
    RestoreDC(dc,saved);return y;
}
static void label(HDC dc,int x,int y,int w,const WCHAR *s,int px,COLORREF c)
{ RECT r={x,y,x+w,y+px+8};paragraph(dc,r,s,px,c,0); }
static void value(HDC dc,int x,int y,int w,const char *s,COLORREF c)
{ WCHAR text_value[300];ascii(text_value,300,s);label(dc,x,y,w,text_value,U.body,c); }
static void line_pair(HDC dc,int y,const WCHAR *caption,const char *actual)
{
    RECT left={36*U.scale,y,U.width/2-8,y+U.body+8};WCHAR v[300];ascii(v,300,actual);
    paragraph(dc,left,caption,U.body,RGB(105,105,112),0);
    {RECT right={U.width/2,y,U.width-36*U.scale,y+U.body+8};paragraph(dc,right,v,U.body,RGB(29,29,31),0);}
}
static void add_button(int id,const WCHAR *label_value,int enabled,int primary,int x,int y,int w)
{
    simple_button_t *b;
    if(U.button_count>=6)return;
    b=&U.buttons[U.button_count++];
    b->id=id;b->label=label_value;b->enabled=enabled;b->primary=primary;
    b->rect.left=x;b->rect.top=y;b->rect.right=x+w;b->rect.bottom=y+38*U.scale;
}
static unsigned rows(void)
{ int h=U.height-240*U.scale;return h>SIMPLE_ROW*U.scale?(unsigned)(h/(SIMPLE_ROW*U.scale)):1; }
static void geometry(void)
{
    RECT r;int gap=10*U.scale,bw=116*U.scale,y;
    GetClientRect(U.hwnd,&r);U.width=r.right;U.height=r.bottom;
    U.body=16*U.scale;U.title=30*U.scale;
    if(U.height<440*U.scale){U.body=14*U.scale;U.title=26*U.scale;}
    U.button_count=0;y=U.height-56*U.scale;
    if(U.screen==SIMPLE_WELCOME){
        add_button(B_KO,L"한국어",1,0,36*U.scale,204*U.scale,bw);
        add_button(B_EN,L"English",1,0,36*U.scale+bw+gap,204*U.scale,bw);
        add_button(B_EXIT,tr(UI_EXIT),1,0,36*U.scale,y,bw);
        add_button(B_DETAILS,tr(U.details?UI_HIDE_DETAILS:UI_DETAILS),1,0,36*U.scale+bw+gap,y,bw);
        add_button(B_NEXT,tr(UI_CONTINUE),!U.worker&&U.image_ok,1,U.width-36*U.scale-bw,y,bw);
    }else if(U.screen==SIMPLE_TARGET){
        add_button(B_BACK,tr(UI_BACK),!U.worker,0,36*U.scale,y,bw);
        add_button(B_NEXT,tr(UI_CONTINUE),!U.worker&&U.selected<U.count&&U.disks[U.selected].allowed,1,U.width-36*U.scale-bw,y,bw);
    }else if(U.screen==SIMPLE_SUMMARY){
        add_button(B_BACK,tr(UI_BACK),!U.worker,0,36*U.scale,y,bw);
        add_button(B_INSTALL,tr(UI_ERASE_INSTALL),U.plan_ok&&!U.worker,1,U.width-36*U.scale-bw-24*U.scale,y,bw+24*U.scale);
    }else if(U.screen==SIMPLE_PROGRESS){
        add_button(B_DETAILS,tr(U.details?UI_HIDE_DETAILS:UI_DETAILS),1,0,36*U.scale,y,bw);
        unsigned cancellable;
        EnterCriticalSection(&U.lock);cancellable=U.event.cancellable;LeaveCriticalSection(&U.lock);
        add_button(B_CANCEL,tr(UI_CANCEL),cancellable&&!InterlockedCompareExchange(&U.cancel,0,0),0,U.width-36*U.scale-bw,y,bw);
    }else{
        add_button(B_DETAILS,tr(U.details?UI_HIDE_DETAILS:UI_DETAILS),1,0,36*U.scale,y,bw);
        add_button(B_SAVELOG,tr(UI_SAVE_LOG),1,0,36*U.scale+bw+gap,y,bw);
        if(U.result.ok){
            add_button(B_SHUTDOWN,tr(UI_SHUTDOWN),1,0,U.width-36*U.scale-2*bw-gap,y,bw);
            add_button(B_RESTART,tr(UI_RESTART),1,1,U.width-36*U.scale-bw,y,bw);
        }else add_button(B_EXIT,tr(UI_EXIT),1,1,U.width-36*U.scale-bw,y,bw);
    }
    if(U.focus>=(int)U.button_count)U.focus=0;
}
static void draw_button(HDC dc,unsigned i)
{
    simple_button_t *b=&U.buttons[i];RECT inner=b->rect,text_rect=b->rect;
    COLORREF face=b->primary?RGB(30,111,216):RGB(255,255,255);
    COLORREF ink=b->primary?RGB(255,255,255):RGB(29,29,31);
    if(!b->enabled){face=RGB(226,226,231);ink=RGB(140,140,147);}
    fill(dc,b->rect,U.focus==(int)i?RGB(28,96,190):RGB(210,210,216));
    inner.left+=2;inner.top+=2;inner.right-=2;inner.bottom-=2;fill(dc,inner,face);
    text_rect.top+=8*U.scale;paragraph(dc,text_rect,b->label,U.body,ink,1);
}
static const WCHAR *phase_text(unsigned p)
{
    switch(p){case SETUP_PHASE_ESP:return tr(UI_COPY_ESP);case SETUP_PHASE_ESP_VERIFY:return tr(UI_VERIFY_ESP);
    case SETUP_PHASE_SYSTEM:return tr(UI_COPY_SYSTEM);case SETUP_PHASE_SYSTEM_VERIFY:return tr(UI_VERIFY_SYSTEM);
    case SETUP_PHASE_GPT:return tr(UI_PARTITIONS);case SETUP_PHASE_LOG:case SETUP_PHASE_DONE:return tr(UI_FINALIZE);
    default:return tr(UI_PREFLIGHT);}
}
static void paint_simple(HWND hwnd)
{
    PAINTSTRUCT ps;HDC dc=BeginPaint(hwnd,&ps);RECT background,card,body;unsigned i;
    char v[280];setup_event_t e;char status[280];
    geometry();GetClientRect(hwnd,&background);fill(dc,background,RGB(245,245,247));
    card=(RECT){20*U.scale,18*U.scale,U.width-20*U.scale,U.height-76*U.scale};fill(dc,card,RGB(255,255,255));
    body=(RECT){36*U.scale,38*U.scale,U.width-36*U.scale,U.height-92*U.scale};
    paragraph(dc,(RECT){body.left,body.top,body.right,body.top+U.title+10},
       tr(U.screen==SIMPLE_WELCOME?UI_WELCOME:U.screen==SIMPLE_TARGET?UI_TARGET:U.screen==SIMPLE_SUMMARY?UI_SUMMARY:
          U.screen==SIMPLE_PROGRESS?UI_PROGRESS:U.result.ok?UI_COMPLETE:UI_FAILURE),U.title,RGB(29,29,31),1);
    EnterCriticalSection(&U.lock);e=U.event;memcpy(status,U.status,sizeof status);LeaveCriticalSection(&U.lock);
    if(U.screen==SIMPLE_WELCOME){
        paragraph(dc,(RECT){body.left,92*U.scale,body.right,160*U.scale},tr(UI_WELCOME_BODY),U.body,RGB(83,83,90),1);
        label(dc,body.left,174*U.scale,body.right-body.left,tr(UI_LANGUAGE),U.body,RGB(105,105,112));
        if(!U.worker&&U.image_ok){line_pair(dc,250*U.scale,tr(UI_IMAGE),U.image.product);
            snprintf(v,sizeof v,"%llu MiB",(unsigned long long)((U.image.required_bytes+1048575)/1048576));
            line_pair(dc,280*U.scale,tr(UI_REQUIRED),v);
        }else if(U.worker)label(dc,body.left,270*U.scale,body.right-body.left,tr(UI_SCANNING),U.body,RGB(105,105,112));
        else value(dc,body.left,250*U.scale,body.right-body.left,U.job_result.reason,RGB(150,40,40));
        paragraph(dc,(RECT){body.left,310*U.scale,body.right,body.bottom},tr(UI_US_KEYBOARD),U.body,RGB(105,105,112),0);
    }else if(U.screen==SIMPLE_TARGET){
        unsigned shown=rows();int row_y=128*U.scale;
        paragraph(dc,(RECT){body.left,90*U.scale,body.right,126*U.scale},tr(UI_TARGET_BODY),U.body,RGB(83,83,90),0);
        if(U.selected<U.count){if(U.selected<U.top)U.top=U.selected;if(U.selected>=U.top+shown)U.top=U.selected-shown+1;}
        for(i=U.top;i<U.count&&i<U.top+shown;++i){simple_disk_t *d=&U.disks[i];char id[33];unsigned j;
            RECT row={body.left,row_y,body.right,row_y+SIMPLE_ROW*U.scale-4*U.scale};
            fill(dc,row,i==U.selected?RGB(226,237,255):RGB(248,248,250));
            for(j=0;j<16;++j){static const char hexv[]="0123456789abcdef";id[j*2]=hexv[d->target.whole_id[j]>>4];id[j*2+1]=hexv[d->target.whole_id[j]&15];}id[32]=0;
            snprintf(v,sizeof v,"%s   %llu MiB",d->target.disk.name,
                 (unsigned long long)(d->target.disk.sectors*d->target.disk.sector_size/1048576));
            value(dc,row.left+10*U.scale,row_y+3*U.scale,row.right-row.left-20*U.scale,v,d->allowed?RGB(29,29,31):RGB(110,110,117));
            label(dc,row.right-118*U.scale,row_y+3*U.scale,108*U.scale,
              tr(d->target.disk.flags&PLAT_DISK_REMOVABLE?UI_REMOVABLE:UI_FIXED),U.body-2*U.scale,RGB(90,90,97));
            snprintf(v,sizeof v,"%.16s [%s]",d->target.disk.serial,id);
            {WCHAR actual_id[300];ascii(actual_id,300,v);
             label(dc,row.left+10*U.scale,row_y+27*U.scale,row.right-row.left-20*U.scale,actual_id,U.body-2*U.scale,RGB(90,90,97));}
            if(!d->allowed){enum setup_string why=UI_DISK_EXCLUDED;
             if(d->target.disk.flags&PLAT_DISK_PARTITION)why=UI_DISK_PARTITION;
             else if(d->target.disk.flags&PLAT_DISK_READONLY)why=UI_DISK_RO;
             else if(d->target.disk.flags&PLAT_DISK_REMOVABLE)why=UI_DISK_REMOVABLE_UNSUPPORTED;
             else if(d->target.disk.sector_size!=512)why=UI_DISK_SECTOR;
             else if(!strcmp(d->reason,"Insufficient installation space"))why=UI_DISK_SPACE;
             label(dc,row.left+10*U.scale,row_y+48*U.scale,row.right-row.left-20*U.scale,tr(why),U.body-2*U.scale,RGB(155,50,45));}
            row_y+=SIMPLE_ROW*U.scale;
        }
        if(!U.count)label(dc,body.left,row_y,body.right-body.left,tr(UI_NO_TARGET),U.body,RGB(105,105,112));
        if(U.worker)label(dc,body.left,body.bottom-U.body-8,body.right-body.left,tr(UI_SCANNING),U.body,RGB(105,105,112));
        else label(dc,body.left,body.bottom-U.body-8,body.right-body.left,tr(UI_SELECT_EXPLICIT),U.body,RGB(105,105,112));
    }else if(U.screen==SIMPLE_SUMMARY){
        setup_plan_t *p=&U.plan;
        {char actual_id[33];unsigned j;static const char hx[]="0123456789abcdef";
         for(j=0;j<16;++j){actual_id[j*2]=hx[p->target.whole_id[j]>>4];actual_id[j*2+1]=hx[p->target.whole_id[j]&15];}actual_id[32]=0;
         snprintf(v,sizeof v,"%s  %llu MiB  [%s]",p->target.disk.name,
          (unsigned long long)(p->target.disk.sectors*p->target.disk.sector_size/1048576),actual_id);}
        value(dc,body.left,98*U.scale,body.right-body.left,v,RGB(29,29,31));
        line_pair(dc,132*U.scale,tr(UI_IMAGE),p->image.product);
        snprintf(v,sizeof v,"%llu MiB (%llu payload bytes)",(unsigned long long)((p->required_bytes+1048575)/1048576),(unsigned long long)p->image.payload_bytes);
        line_pair(dc,163*U.scale,tr(UI_REQUIRED),v);
        paragraph(dc,(RECT){body.left,201*U.scale,body.right,267*U.scale},tr(UI_DESTRUCTIVE),U.body,RGB(163,48,43),0);
        paragraph(dc,(RECT){body.left,273*U.scale,body.right,331*U.scale},tr(UI_BOOT_CHANGE),U.body,RGB(83,83,90),0);
        label(dc,body.left,335*U.scale,body.right-body.left,tr(UI_NO_OTHER_DISKS),U.body,RGB(83,83,90));
    }else if(U.screen==SIMPLE_PROGRESS){
        label(dc,body.left,105*U.scale,body.right-body.left,phase_text(e.phase),U.body,RGB(29,29,31));
        snprintf(v,sizeof v,"%llu",(unsigned long long)e.io_bytes);line_pair(dc,147*U.scale,tr(UI_BYTES),v);
        snprintf(v,sizeof v,"%llu / %llu",(unsigned long long)e.files_done,(unsigned long long)e.files_total);line_pair(dc,182*U.scale,tr(UI_FILES),v);
        /* Fraction is actual verified files only. Other phases are indeterminate. */
        {RECT track={body.left,221*U.scale,body.right,227*U.scale};fill(dc,track,RGB(230,230,235));
         if(e.phase==SETUP_PHASE_SYSTEM_VERIFY&&e.files_total&&e.files_done<=e.files_total){RECT actual=track;actual.right=actual.left+(int)((uint64_t)(track.right-track.left)*e.files_done/e.files_total);fill(dc,actual,RGB(30,111,216));}}
        paragraph(dc,(RECT){body.left,245*U.scale,body.right,305*U.scale},
          tr(InterlockedCompareExchange(&U.cancel,0,0)?UI_CANCEL_REQUESTED:e.cancellable?UI_CANCEL_SAFE:UI_NONCANCEL),U.body,RGB(105,105,112),0);
    }else{
        if(U.result.ok){
            paragraph(dc,(RECT){body.left,107*U.scale,body.right,171*U.scale},tr(UI_REMOVE_MEDIA),U.body,RGB(83,83,90),0);
            snprintf(v,sizeof v,"%llu / %llu",(unsigned long long)e.files_done,(unsigned long long)e.files_total);
            line_pair(dc,190*U.scale,tr(UI_VERIFIED_FILES),v);
        }else{
            value(dc,body.left,110*U.scale,body.right-body.left,U.result.reason,RGB(155,50,45));
            if(e.destructive)paragraph(dc,(RECT){body.left,165*U.scale,body.right,260*U.scale},tr(UI_PARTIAL),U.body,RGB(155,50,45),0);
            else label(dc,body.left,168*U.scale,body.right-body.left,tr(UI_NO_OTHER_DISKS),U.body,RGB(83,83,90));
        }
    }
    if(U.details){RECT detail={body.left,308*U.scale,body.right,body.bottom};fill(dc,detail,RGB(248,248,250));value(dc,detail.left+8,detail.top+8,detail.right-detail.left-16,status,RGB(83,83,90));}
    for(i=0;i<U.button_count;++i)draw_button(dc,i);
    EndPaint(hwnd,&ps);
}
static int ui_cancelled(void *ctx){(void)ctx;return InterlockedCompareExchange(&U.cancel,0,0)!=0;}
static int ui_check(void *ctx,const setup_plan_t *plan)
{(void)ctx;return U.backend&&U.backend->check?U.backend->check(U.backend->ctx,plan):-1;}
static void ui_event(void *ctx,const setup_event_t *event)
{(void)ctx;EnterCriticalSection(&U.lock);U.event=*event;LeaveCriticalSection(&U.lock);InterlockedExchange(&U.dirty,1);}
static void simple_progress(const char *text_value)
{
    unsigned i;
    if(!simple_active||!text_value)return;
    EnterCriticalSection(&U.lock);
    for(i=0;text_value[i];++i){char c=text_value[i];
        if(U.log_used+1<SIMPLE_LOG_BYTES)U.log[U.log_used++]=c;
        if(c=='\r')continue;
        if(c=='\n'){U.line_used=0;continue;}
        if(U.line_used+1<sizeof U.line)U.line[U.line_used++]=c;
        U.line[U.line_used]=0;memcpy(U.status,U.line,U.line_used+1);
    }
    U.log[U.log_used]=0;LeaveCriticalSection(&U.lock);InterlockedExchange(&U.dirty,1);
}
static DWORD WINAPI simple_worker(void *unused)
{
    unsigned i;setup_control_t control={0,ui_check,ui_cancelled,ui_event};(void)unused;
    memset(&U.job_result,0,sizeof U.job_result);
    if(U.job==JOB_SCAN){
        if(!U.backend||!U.backend->prepare||U.backend->prepare(U.backend->ctx,U.payload)){
            strcpy(U.job_result.reason,"Kernel installer source/target authority is unavailable");
            U.job_image_ok=0;U.job_count=0;return 0;
        }
        U.job_image_ok=!setup_image_inspect(U.p,U.payload,&U.job_image,&U.job_result);U.job_count=0;
        for(i=0;i<U.p->disk_count(U.p->ctx)&&U.job_count<SIMPLE_DISKS;++i){simple_disk_t *d=&U.job_disks[U.job_count];
            memset(d,0,sizeof *d);d->target.index=i;
            if(U.p->disk_info(U.p->ctx,i,&d->target.disk))continue;
            if(U.backend&&U.backend->review)d->allowed=!U.backend->review(U.backend->ctx,i,&d->target,d->reason,sizeof d->reason);
            else strcpy(d->reason,"Kernel target authority unavailable");
            if(d->allowed&&d->target.disk.sectors*d->target.disk.sector_size<U.job_image.required_bytes){d->allowed=0;strcpy(d->reason,"Insufficient installation space");}
            ++U.job_count;
        }
    }else if(U.job==JOB_PLAN){
        setup_target_t actual;
        char reason[160];
        U.job_plan_ok=0;
        if(U.selected>=U.count||!U.backend||!U.backend->review||
           U.backend->review(U.backend->ctx,U.disks[U.selected].target.index,&actual,reason,sizeof reason)||
           memcmp(&actual,&U.disks[U.selected].target,sizeof actual)){
            strcpy(U.job_result.reason,"Selected disk changed; choose it again");
        }else U.job_plan_ok=!setup_plan_build(U.p,U.payload,&actual,U.language,&U.job_plan,&U.job_result);
    }else{
        setup_run_planned(U.p,U.answer_path,U.payload,&U.plan,&control,&U.job_result);
        if(U.backend->release(U.backend->ctx)){
            U.job_result.ok=0;strcpy(U.job_result.reason,"Target authority release or final flush failed");
        }
        U.claimed=0;
    }
    return 0;
}
static int start_job(int job)
{
    if(U.worker)return -1;
    U.job=job;
    U.worker=CreateThread(0,0,simple_worker,0,0,0);
    if(!U.worker){U.last_error=GetLastError();return -1;}
    simple_repaint();return 0;
}
static void save_log(void)
{
    HANDLE f;DWORD wrote=0;int ok;
    CreateDirectoryW(L"C:\\TEMP",0);
    f=CreateFileW(L"C:\\TEMP\\SHZSETUP.LOG",GENERIC_WRITE,0,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
    if(f==INVALID_HANDLE_VALUE){simple_progress(U.language==1?"Log save failed\n":"Log save failed\n");return;}
    EnterCriticalSection(&U.lock);
    ok=WriteFile(f,U.log,(DWORD)U.log_used,&wrote,0)&&wrote==U.log_used&&FlushFileBuffers(f);
    LeaveCriticalSection(&U.lock);if(!CloseHandle(f))ok=0;
    U.last_error=ok?0:GetLastError();
    simple_progress(ok?"Diagnostic log saved to C:\\TEMP\\SHZSETUP.LOG; volatile until restart\n":"Diagnostic log write/flush failed\n");
}
static void activate(int id)
{
    unsigned i;
    if(id==B_KO||id==B_EN){U.language=id==B_KO?1:2;simple_repaint();return;}
    if(id==B_DETAILS){U.details=!U.details;simple_repaint();return;}
    if(id==B_SAVELOG){save_log();simple_repaint();return;}
    if(id==B_CANCEL){EnterCriticalSection(&U.lock);i=U.event.cancellable;LeaveCriticalSection(&U.lock);if(i)InterlockedExchange(&U.cancel,1);simple_repaint();return;}
    if(U.worker)return;
    if(id==B_EXIT){U.done=1;return;}
    if(id==B_RESTART||id==B_SHUTDOWN){U.result.power=id==B_RESTART?SETUP_POWER_REBOOT:SETUP_POWER_SHUTDOWN;U.done=1;return;}
    if(id==B_BACK){U.screen=U.screen==SIMPLE_SUMMARY?SIMPLE_TARGET:SIMPLE_WELCOME;U.focus=0;U.plan_ok=0;simple_repaint();return;}
    if(id==B_NEXT&&U.screen==SIMPLE_WELCOME&&U.image_ok){U.screen=SIMPLE_TARGET;U.focus=-1;simple_repaint();return;}
    if(id==B_NEXT&&U.screen==SIMPLE_TARGET&&U.selected<U.count&&U.disks[U.selected].allowed){
        if(start_job(JOB_PLAN)){U.result.ok=0;strcpy(U.result.reason,"Unable to start planning worker");U.screen=SIMPLE_COMPLETE;}return;
    }
    if(id==B_INSTALL&&U.plan_ok&&U.screen==SIMPLE_SUMMARY){
        int n;
        if(!U.backend||!U.backend->claim||!U.backend->check||!U.backend->release||U.backend->claim(U.backend->ctx,&U.plan)){
            U.plan_ok=0;U.screen=SIMPLE_TARGET;U.selected=SIMPLE_NONE;
            simple_progress("Target authority changed or claim refused; no disk writes\n");simple_repaint();return;
        }
        U.claimed=1;
        n=snprintf(U.answer,U.answer_cap,
          "[Setup]\r\nSchema=1\r\nConfirm=ERASE-TARGET\r\nReboot=none\r\n[Target]\r\nSelect=name\r\nName=%s\r\nAllowNonEmpty=yes\r\n[Layout]\r\nSystemMiB=0\r\nWin98MiB=0\r\nWin98HybridMBR=no\r\nBiosBootCode=yes\r\n[System]\r\nHostname=SHIZUKUOS\r\n[Drivers]\r\nInstall=all\r\n",U.plan.target.disk.name);
        if(n<0||(size_t)n>=U.answer_cap){U.backend->release(U.backend->ctx);U.claimed=0;return;}
        InterlockedExchange(&U.cancel,0);U.screen=SIMPLE_PROGRESS;U.focus=0;U.details=0;
        if(start_job(JOB_INSTALL)){U.backend->release(U.backend->ctx);U.claimed=0;U.screen=SIMPLE_COMPLETE;U.result.ok=0;strcpy(U.result.reason,"Unable to start installation worker");}
        simple_repaint();
    }
}
static void poll_worker(void)
{
    DWORD observed;
    if(!U.worker)return;
    observed=WaitForSingleObject(U.worker,0);
    if(observed==WAIT_FAILED){U.last_error=GetLastError();U.fatal_error=1;InterlockedExchange(&U.cancel,1);U.done=1;return;}
    if(observed!=WAIT_OBJECT_0)return;
    CloseHandle(U.worker);U.worker=0;
    if(U.job==JOB_SCAN){U.image=U.job_image;U.image_ok=U.job_image_ok;U.count=U.job_count;memcpy(U.disks,U.job_disks,sizeof U.disks);
        if(!U.image_ok)simple_progress(U.job_result.reason);}
    else if(U.job==JOB_PLAN){
        U.plan=U.job_plan;U.plan_ok=U.job_plan_ok;
        if(U.plan_ok){U.screen=SIMPLE_SUMMARY;U.focus=0;
            printf("SHZ-SETUP UI plan ready target=%s whole_id=%02x%02x%02x%02x generation=%llu writes=0\n",U.plan.target.disk.name,
                U.plan.target.whole_id[0],U.plan.target.whole_id[1],U.plan.target.whole_id[2],U.plan.target.whole_id[3],(unsigned long long)U.plan.target.generation);
        }else{U.selected=SIMPLE_NONE;simple_progress(U.job_result.reason);}
    }else if(U.job==JOB_INSTALL){
        MSG m;U.result=U.job_result;U.screen=SIMPLE_COMPLETE;U.focus=0;U.details=!U.result.ok;
        while(PeekMessageW(&m,U.hwnd,WM_KEYFIRST,WM_KEYLAST,PM_REMOVE)){}
    }
    simple_repaint();
}
static LRESULT CALLBACK simple_proc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp)
{
    if(msg==WM_NCCREATE)U.hwnd=hwnd;
    if(msg==WM_PAINT){paint_simple(hwnd);return 0;}
    if(msg==WM_TIMER&&wp==SIMPLE_TIMER){poll_worker();
        if(InterlockedExchange(&U.dirty,0))simple_repaint();
        return 0;}
    if(msg==WM_SIZE){simple_repaint();return 0;}
    if(msg==WM_CLOSE){if(!U.worker&&U.screen!=SIMPLE_PROGRESS)U.done=1;return 0;}
    if(msg==WM_KEYDOWN){
        /* A held Enter never confirms a second screen. WM_CHAR is not a button
         * activation route, so KEYDOWN/CHAR cannot duplicate destructive input. */
        if(lp&((LPARAM)1<<30))return 0;
        geometry();
        if(wp==VK_TAB){
            int dir=GetKeyState(VK_SHIFT)&0x8000?-1:1;
            U.focus+=dir;if(U.focus>=(int)U.button_count)U.focus=U.screen==SIMPLE_TARGET?-1:0;
            if(U.focus<(U.screen==SIMPLE_TARGET?-1:0))U.focus=(int)U.button_count-1;
            simple_repaint();return 0;
        }
        if(wp==VK_ESCAPE){if(U.screen==SIMPLE_SUMMARY||U.screen==SIMPLE_TARGET)activate(B_BACK);else if(!U.worker&&U.screen!=SIMPLE_PROGRESS)activate(B_EXIT);return 0;}
        if(U.screen==SIMPLE_TARGET&&!U.worker&&(wp==VK_UP||wp==VK_DOWN||wp==VK_HOME||wp==VK_END||wp==VK_PRIOR||wp==VK_NEXT)){
            if(U.count){
                if(U.selected>=U.count)U.selected=wp==VK_UP?U.count-1:0;
                else if(wp==VK_HOME)U.selected=0;else if(wp==VK_END)U.selected=U.count-1;
                else if(wp==VK_UP&&U.selected) --U.selected;
                else if(wp==VK_DOWN&&U.selected+1<U.count)++U.selected;
                else if(wp==VK_PRIOR)U.selected=U.selected>rows()?U.selected-rows():0;
                else if(wp==VK_NEXT)U.selected=U.selected+rows()<U.count?U.selected+rows():U.count-1;
                U.focus=-1;simple_repaint();
            }return 0;
        }
        if((wp==VK_RETURN||wp==VK_SPACE)&&U.focus>=0&&(unsigned)U.focus<U.button_count&&U.buttons[U.focus].enabled){activate(U.buttons[U.focus].id);return 0;}
        if(wp==VK_RETURN&&U.screen==SIMPLE_TARGET&&U.focus==-1){activate(B_NEXT);return 0;}
        if(wp=='L'&&U.screen==SIMPLE_COMPLETE){activate(B_SAVELOG);return 0;}
        return 0;
    }
    if(msg==WM_LBUTTONDOWN){
        POINT p={(short)(lp&0xffff),(short)((lp>>16)&0xffff)};unsigned i;
        geometry();
        for(i=0;i<U.button_count;++i)if(PtInRect(&U.buttons[i].rect,p)){U.focus=(int)i;if(U.buttons[i].enabled)activate(U.buttons[i].id);simple_repaint();return 0;}
        if(U.screen==SIMPLE_TARGET&&!U.worker&&p.x>=36*U.scale&&p.x<U.width-36*U.scale&&p.y>=128*U.scale){
            unsigned r=(unsigned)(p.y-128*U.scale)/(SIMPLE_ROW*U.scale);
            if(r<rows()&&U.top+r<U.count){U.selected=U.top+r;U.focus=-1;simple_repaint();}
        }return 0;
    }
    return DefWindowProcW(hwnd,msg,wp,lp);
}
int setup_ui_run(const plat_t *p,const setup_ui_backend_t *backend,char *answer,size_t capacity,
                 const char *answer_path,const char *payload,setup_result_t *result)
{
    WNDCLASSEXW wc;MSG m;DWORD win32;int font_status,width,height,w,h,rc=1;HDC dc;
    if(!p||!answer||!capacity||!answer_path||!payload||!result)return -1;
    memset(&U,0,sizeof U);memset(result,0,sizeof *result);U.p=p;U.backend=backend;
    U.answer=answer;U.answer_cap=capacity;U.answer_path=answer_path;U.payload=payload;
    U.language=SETUP_LANGUAGE_KO;U.selected=SIMPLE_NONE;U.screen=SIMPLE_WELCOME;U.focus=4;
    U.log=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,SIMPLE_LOG_BYTES);if(!U.log)return -1;
    InitializeCriticalSection(&U.lock);simple_active=1;
    if(!ShzTextFontInit(&win32,&font_status)){
        printf("SHZ-SETUP Noto unavailable error=%u status=%d writes=0\n",(unsigned)win32,font_status);rc=-1;goto closed;
    }
    width=GetSystemMetrics(SM_CXSCREEN);height=GetSystemMetrics(SM_CYSCREEN);
    if(width<640||height<480){rc=-1;goto closed;}
    U.scale=1;dc=GetDC(0);if(dc){int dpi=GetDeviceCaps(dc,LOGPIXELSX);if(dpi>=144&&width>=1280&&height>=960)U.scale=2;ReleaseDC(0,dc);}
    w=800*U.scale;h=560*U.scale;if(w>width-16)w=width-16;if(h>height-16)h=height-16;
    U.module=GetModuleHandleW(0);memset(&wc,0,sizeof wc);wc.cbSize=sizeof wc;
    wc.lpfnWndProc=simple_proc;wc.hInstance=U.module;wc.lpszClassName=L"ShizukuSetupWindow";
    if(!RegisterClassExW(&wc)){rc=-1;goto closed;}
    U.hwnd=CreateWindowExW(0,wc.lpszClassName,L"ShizukuOS",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_VISIBLE,
                       (width-w)/2,(height-h)/2,w,h,0,0,U.module,0);
    if(!U.hwnd){rc=-1;goto closed;}
    SetForegroundWindow(U.hwnd);SetFocus(U.hwnd);
    if(!SetTimer(U.hwnd,SIMPLE_TIMER,100,0)||start_job(JOB_SCAN)){rc=-1;goto closed;}
    printf("SHZ-SETUP UI ready flow=welcome-target-plan-progress-verified writes=0 keyboard=US ime=none\n");
    while(!U.done){int got=GetMessageW(&m,0,0,0);if(got<=0){rc=-1;break;}TranslateMessage(&m);DispatchMessageW(&m);}
    *result=U.result;
    if(U.fatal_error)rc=-1;
    else if(rc!=-1)rc=U.screen==SIMPLE_COMPLETE?0:1;
closed:
    /* Window destruction cannot abandon a running disk writer. A message-loop
     * failure requests cooperative cancellation and waits for real cleanup. */
    if(U.worker){InterlockedExchange(&U.cancel,1);WaitForSingleObject(U.worker,INFINITE);CloseHandle(U.worker);U.worker=0;}
    if(U.claimed&&U.backend&&U.backend->release)U.backend->release(U.backend->ctx);
    if(U.backend&&U.backend->finish&&U.backend->finish(U.backend->ctx)){
        result->ok=0;strcpy(result->reason,"Installer source authority cleanup failed");rc=-1;
    }
    if(U.hwnd){KillTimer(U.hwnd,SIMPLE_TIMER);DestroyWindow(U.hwnd);}
    UnregisterClassW(L"ShizukuSetupWindow",U.module);simple_active=0;
    DeleteCriticalSection(&U.lock);HeapFree(GetProcessHeap(),0,U.log);ShzTextFontShutdown();return rc;
}
