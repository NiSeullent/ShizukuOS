/* SPDX-License-Identifier: LGPL-2.1-or-later
 * ShizukuOS native local search. The prepared file index is bounded and built
 * by an actual Win32 worker; typing never enumerates a filesystem. Command
 * records are shared with Start/Run and document activation uses real APIs.
 */
#include "shzcrt.h"
#include "search.h"
#include "catalog.h"
#include "fileops.h"
#include "layout.h"
#include <limits.h>

#define SEARCH_CLASS L"ShizukuSearch"
#define SEARCH_QUERY 128
#define SEARCH_FILES 512
#define SEARCH_DIRS 64
#define SEARCH_HITS 96
#define SEARCH_TIMER 19
enum { HIT_COMMAND, HIT_FILE, HIT_WINDOW, HIT_CALC };
typedef struct { WCHAR path[SHZ_MAX_PATH]; DWORD attrs; } INDEX_FILE;
typedef struct { WCHAR path[SHZ_MAX_PATH]; unsigned depth; } INDEX_DIR;
typedef struct {
    INDEX_FILE files[SEARCH_FILES]; INDEX_DIR dirs[SEARCH_DIRS];
    unsigned count, ndirs; DWORD error; BOOL limited, cancelled;
} FILE_INDEX;
typedef struct { int kind; unsigned id; HWND window; WCHAR label[SHZ_MAX_PATH]; } HIT;
static HWND search_window;
static WCHAR query[SEARCH_QUERY], calc_text[64];
static HIT hits[SEARCH_HITS];
static int hit_count, selected, scroll;
static FILE_INDEX *published, *pending;
static HANDLE worker;
static volatile LONG cancelled;
static BOOL refresh_needed, closing;
static DWORD last_refresh, generation;
static DWORD index_error;
static DWORD seen_file_generation;

static WCHAR Fold(WCHAR c) { return c >= L'A' && c <= L'Z' ? c + 32 : c; }
static BOOL Contains(const WCHAR *s, const WCHAR *needle)
{
    if (!*needle) return TRUE;
    for (; *s; ++s) {
        const WCHAR *a=s, *b=needle;
        while (*a && *b && Fold(*a)==Fold(*b)) { ++a; ++b; }
        if (!*b) return TRUE;
    }
    return FALSE;
}
static BOOL AppendPath(WCHAR *out, const WCHAR *parent, const WCHAR *name)
{
    SIZE_T n=ShzWcsLen(parent);
    return ShzWcsCopy(out,SHZ_MAX_PATH,parent) &&
        (!n || parent[n-1]==L'\\' || ShzWcsCat(out,SHZ_MAX_PATH,L"\\")) &&
        ShzWcsCat(out,SHZ_MAX_PATH,name);
}
static BOOL Cancelled(void) { return InterlockedCompareExchange(&cancelled,0,0)!=0; }
static DWORD WINAPI IndexWorker(void *parameter)
{
    FILE_INDEX *idx=parameter;
    if (!ShzFileResolveDocumentsW(idx->dirs[0].path,FALSE)) { idx->error=GetLastError(); return 0; }
    DWORD attrs=GetFileAttributesW(idx->dirs[0].path);
    if (attrs==INVALID_FILE_ATTRIBUTES) { idx->error=GetLastError(); return 0; }
    if (!(attrs&FILE_ATTRIBUTE_DIRECTORY)) { idx->error=ERROR_DIRECTORY; return 0; }
    if (attrs&FILE_ATTRIBUTE_REPARSE_POINT) { idx->error=ERROR_NOT_SUPPORTED; return 0; }
    idx->ndirs=1;
    for (unsigned d=0; d<idx->ndirs; ++d) {
        WCHAR pattern[SHZ_MAX_PATH]; WIN32_FIND_DATAW data;
        HANDLE find;
        if (Cancelled()) { idx->cancelled=TRUE; return 0; }
        if (!AppendPath(pattern,idx->dirs[d].path,L"*")) {
            idx->limited=TRUE; continue;
        }
        find=FindFirstFileW(pattern,&data);
        if (find==INVALID_HANDLE_VALUE) {
            DWORD e=GetLastError();
            if (e!=ERROR_FILE_NOT_FOUND && e!=ERROR_NO_MORE_FILES && !idx->error) idx->error=e;
            continue;
        }
        do {
            if (Cancelled()) { idx->cancelled=TRUE; break; }
            if (!data.cFileName[0] || !lstrcmpW(data.cFileName,L".") ||
                !lstrcmpW(data.cFileName,L"..") || !lstrcmpW(data.cFileName,L".ShizukuTrash")) continue;
            /* Links are indexed as entries but never traversed. */
            if (idx->count>=SEARCH_FILES) { idx->limited=TRUE; break; }
            INDEX_FILE *f=&idx->files[idx->count];
            if (!AppendPath(f->path,idx->dirs[d].path,data.cFileName)) { idx->limited=TRUE; continue; }
            f->attrs=data.dwFileAttributes; ++idx->count;
            if ((data.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) &&
                !(data.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)) {
                if (idx->ndirs>=SEARCH_DIRS || idx->dirs[d].depth>=8) idx->limited=TRUE;
                else {
                    INDEX_DIR *next=&idx->dirs[idx->ndirs++];
                    ShzWcsCopy(next->path,SHZ_MAX_PATH,f->path);
                    next->depth=idx->dirs[d].depth+1;
                }
            }
        } while (FindNextFileW(find,&data));
        if (!idx->limited && !idx->cancelled) {
            DWORD e=GetLastError();
            if (e!=ERROR_NO_MORE_FILES && e!=ERROR_FILE_NOT_FOUND && !idx->error) idx->error=e;
        }
        if (!FindClose(find) && !idx->error) idx->error=GetLastError();
        if (idx->cancelled || idx->count>=SEARCH_FILES) break;
    }
    return 0;
}
static void BeginIndex(void)
{
    if (worker || !refresh_needed || closing) return;
    pending=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof *pending);
    if (!pending) { index_error=ERROR_NOT_ENOUGH_MEMORY; refresh_needed=FALSE; return; }
    InterlockedExchange(&cancelled,0);
    worker=CreateThread(NULL,0,IndexWorker,pending,0,NULL);
    refresh_needed=FALSE;
    last_refresh=GetTickCount();
    if (!worker) { index_error=GetLastError(); HeapFree(GetProcessHeap(),0,pending); pending=NULL; }
}

/* Small integer expression provider: checked arithmetic, no eval/script,
 * float approximations or host service. Units/timezones are not claimed. */
typedef struct { const WCHAR *p; unsigned depth; BOOL bad; } EXPR;
static void Space(EXPR *e) { while (*e->p==L' ' || *e->p==L'\t') ++e->p; }
static long long Sum(EXPR *e);
static long long Value(EXPR *e)
{
    long long value=0; BOOL neg=FALSE; unsigned digits=0;
    Space(e);
    if (++e->depth>16) { e->bad=TRUE; --e->depth; return 0; }
    if (*e->p==L'+' || *e->p==L'-') { neg=*e->p==L'-'; ++e->p; Space(e); }
    if (*e->p==L'(') {
        ++e->p; value=Sum(e); Space(e);
        if (*e->p!=L')') e->bad=TRUE; else ++e->p;
    } else {
        while (*e->p>=L'0' && *e->p<=L'9') {
            long long tmp;
            if (__builtin_mul_overflow(value,10LL,&tmp) ||
                __builtin_add_overflow(tmp,(long long)(*e->p-L'0'),&value)) e->bad=TRUE;
            ++e->p; ++digits;
        }
        if (!digits) e->bad=TRUE;
    }
    if (neg && __builtin_sub_overflow(0LL,value,&value)) e->bad=TRUE;
    --e->depth; return value;
}
static long long Product(EXPR *e)
{
    long long value=Value(e); Space(e);
    while (*e->p==L'*' || *e->p==L'/' || *e->p==L'%') {
        WCHAR op=*e->p++; long long right=Value(e), next=0;
        if (op==L'*') { if (__builtin_mul_overflow(value,right,&next)) e->bad=TRUE; }
        else if (!right || (value==LLONG_MIN && right==-1)) e->bad=TRUE;
        else next=op==L'/'?value/right:value%right;
        value=next; Space(e);
    }
    return value;
}
static long long Sum(EXPR *e)
{
    long long value=Product(e); Space(e);
    while (*e->p==L'+' || *e->p==L'-') {
        WCHAR op=*e->p++; long long right=Product(e), next;
        if (op==L'+') { if (__builtin_add_overflow(value,right,&next)) e->bad=TRUE; }
        else if (__builtin_sub_overflow(value,right,&next)) e->bad=TRUE;
        value=next; Space(e);
    }
    return value;
}
static BOOL Calculate(const WCHAR *text, WCHAR *out)
{
    EXPR e={text,0,FALSE}; long long result; WCHAR magnitude[32];
    Space(&e); if (*e.p==L'=') ++e.p;
    if (!*e.p) return FALSE;
    result=Sum(&e); Space(&e);
    if (e.bad || *e.p) return FALSE;
    ShzFormatU64(result<0?0ULL-(unsigned long long)result:(unsigned long long)result,magnitude,32);
    ShzWcsCopy(out,64,result<0?L"= -":L"= "); ShzWcsCat(out,64,magnitude); return TRUE;
}
static void AddHit(int kind,unsigned id,HWND window,const WCHAR *label)
{
    if (hit_count>=SEARCH_HITS) return;
    HIT *h=&hits[hit_count++]; h->kind=kind; h->id=id; h->window=window;
    ShzWcsCopy(h->label,SHZ_MAX_PATH,label);
}
static void Filter(void)
{
    hit_count=0; selected=0; scroll=0;
    if (Calculate(query,calc_text)) AddHit(HIT_CALC,0,NULL,calc_text);
    for (unsigned i=0; i<ShzCommandCount(); ++i) {
        const SHZ_COMMAND_INFO *c=ShzCommandAt(i);
        if (Contains(c->name,query) || Contains(c->keywords,query)) AddHit(HIT_COMMAND,c->id,NULL,c->name);
    }
    ShzTasksRefresh();
    for (int i=0; i<g_shell.ntasks; ++i) {
        SHZ_TASK *t=&g_shell.tasks[i];
        if (t->hwnd!=search_window && t->title[0] && Contains(t->title,query))
            AddHit(HIT_WINDOW,0,t->hwnd,t->title);
    }
    if (published) for (unsigned i=0; i<published->count; ++i)
        if (Contains(published->files[i].path,query)) AddHit(HIT_FILE,i,NULL,published->files[i].path);
    printf("SHZ-SEARCH filter generation=%u query-units=%u hits=%u indexing=%u\n",
        (unsigned)generation,(unsigned)ShzWcsLen(query),(unsigned)hit_count,worker?1u:0u);
    if (search_window) InvalidateRect(search_window,NULL,FALSE);
}
static void Collect(void)
{
    if (!worker || WaitForSingleObject(worker,0)!=WAIT_OBJECT_0) return;
    if (!CloseHandle(worker)) { index_error=GetLastError(); return; }
    worker=NULL;
    if (!pending->cancelled) {
        if (published) HeapFree(GetProcessHeap(),0,published);
        published=pending; pending=NULL;
        index_error=published->error; ++generation; last_refresh=GetTickCount();
        printf("SHZ-SEARCH index generation=%u entries=%u dirs=%u limited=%u error=%u\n",
            (unsigned)generation,published->count,published->ndirs,published->limited?1u:0u,(unsigned)index_error);
        Filter();
    } else { HeapFree(GetProcessHeap(),0,pending); pending=NULL; }
    if (!closing) BeginIndex();
}
void ShzSearchInvalidateFiles(void)
{
    refresh_needed=TRUE;
    if (search_window) BeginIndex();
}
static void Geometry(const RECT *c,RECT *edit,RECT *list,RECT *status,int *row)
{
    *row=ShzPx(44);
    *edit=(RECT){ShzPx(16),ShzPx(16),c->right-ShzPx(16),ShzPx(54)};
    *list=(RECT){ShzPx(16),ShzPx(72),c->right-ShzPx(16),c->bottom-ShzPx(58)};
    *status=(RECT){ShzPx(16),c->bottom-ShzPx(52),c->right-ShzPx(16),c->bottom-ShzPx(8)};
    if (list->bottom<list->top) list->bottom=list->top;
}
static void ClampScroll(HWND hwnd)
{
    RECT c,e,l,s; int row,visible;
    GetClientRect(hwnd,&c); Geometry(&c,&e,&l,&s,&row);
    visible=(l.bottom-l.top)/row; if (visible<1) visible=1;
    if (selected<scroll) scroll=selected;
    if (selected>=scroll+visible) scroll=selected-visible+1;
    if (scroll<0) scroll=0;
}
static void Activate(void)
{
    BOOL ok=FALSE;
    if (selected<0 || selected>=hit_count) {
        /* A typed local path is also a real document request, not a command. */
        if (query[0] && query[1]==L':' && query[2]==L'\\') ok=ShzOpenDocument(query);
        if (!ok) ShzUserMessage(L"검색 결과를 선택하세요.",0);
        return;
    }
    HIT h=hits[selected];
    if (h.kind==HIT_COMMAND) {
        if (h.id==SHZ_CMD_SEARCH) { SetFocus(search_window); return; }
        if (h.id==SHZ_CMD_EXIT) { ShzUserMessage(L"세션 종료는 시작 메뉴에서 실행하세요.",0); return; }
        ok=ShzCommandInvoke((SHZ_COMMAND)h.id);
    } else if (h.kind==HIT_FILE) ok=ShzOpenDocument(h.label);
    else if (h.kind==HIT_WINDOW) {
        if (IsWindow(h.window)) {
            if (IsIconic(h.window)) ShowWindow(h.window,SW_RESTORE);
            ok=SetForegroundWindow(h.window) && GetForegroundWindow()==h.window;
            if (!ok) ShzUserMessage(L"창을 활성화할 수 없습니다.",GetLastError());
        } else { Filter(); ShzUserMessage(L"선택한 창이 닫혔습니다.",0); }
    } else { ShzClipboardWriteText(search_window,h.label+2); return; }
    if (ok && search_window) ShowWindow(search_window,SW_HIDE);
}
static void Paint(HWND hwnd)
{
    PAINTSTRUCT ps; HDC dc=BeginPaint(hwnd,&ps); RECT c,e,l,s,t; int row,visible;
    if (!dc) return;
    GetClientRect(hwnd,&c); Geometry(&c,&e,&l,&s,&row);
    ShzFill(dc,&c,TC(TH()->background_panel_face));
    ShzFill(dc,&e,TC(TH()->background_input_bg));
    ShzFrame(dc,&e,TC(TH()->border_focus),1);
    t=e; t.left+=ShzPx(10); t.right-=ShzPx(10);
    SetTextColor(dc,TC(TH()->background_surface_text));
    WCHAR display[SEARCH_QUERY+2]; ShzWcsCopy(display,SEARCH_QUERY+2,query);
    ShzWcsCat(display,SEARCH_QUERY+2,L"|");
    ShzDrawText(dc,query[0]?display:L"앱, 문서, 설정, 열린 창 검색",&t,DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS);
    visible=(l.bottom-l.top)/row;
    for (int n=0; n<visible && scroll+n<hit_count; ++n) {
        HIT *h=&hits[scroll+n];
        t=(RECT){l.left,l.top+n*row,l.right,l.top+(n+1)*row};
        if (scroll+n==selected) ShzFill(dc,&t,TC(TH()->selection_top));
        SetTextColor(dc,TC(scroll+n==selected?TH()->selection_text:TH()->background_panel_text));
        RECT badge=t; badge.right=badge.left+ShzPx(60);
        const WCHAR *kind=h->kind==HIT_COMMAND?L"앱":h->kind==HIT_FILE?L"파일":h->kind==HIT_WINDOW?L"창":L"계산";
        ShzDrawText(dc,kind,&badge,DT_SINGLELINE|DT_VCENTER|DT_CENTER);
        t.left=badge.right+ShzPx(6); t.right-=ShzPx(6);
        ShzDrawText(dc,h->label,&t,DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS);
    }
    if (!hit_count) {
        t=l; t.bottom=t.top+ShzPx(54);
        SetTextColor(dc,TC(TH()->background_panel_text));
        ShzDrawText(dc,L"일치하는 항목이 없습니다. 다른 이름이나 전체 경로를 입력하세요.",&t,DT_WORDBREAK);
    }
    WCHAR footer[192], count[24], error[24];
    if (closing) ShzWcsCopy(footer,192,L"인덱싱 취소 중… 작업이 끝나면 창을 닫습니다.");
    else if (worker) ShzWcsCopy(footer,192,L"문서 인덱스 갱신 중 · 앱과 열린 창은 바로 검색할 수 있습니다.");
    else if (index_error) {
        ShzFormatU64(index_error,error,24);
        ShzWcsCopy(footer,192,L"문서 검색 범위에 접근할 수 없습니다. 오류 "); ShzWcsCat(footer,192,error);
        ShzWcsCat(footer,192,L" · 문서 폴더 · F5 재시도");
    } else {
        ShzFormatU64(published?published->count:0,count,24);
        ShzWcsCopy(footer,192,L"문서 "); ShzWcsCat(footer,192,count);
        ShzWcsCat(footer,192,published && published->limited?L"개 · 범위 상한 도달 · F5 갱신":L"개 · ↑↓ 선택 · Enter 열기 · F5 갱신");
    }
    SetTextColor(dc,TC(TH()->background_panel_text)); ShzDrawText(dc,footer,&s,DT_WORDBREAK);
    EndPaint(hwnd,&ps);
}
static LRESULT CALLBACK SearchProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        if (!SetTimer(hwnd,SEARCH_TIMER,100,NULL)) return -1;
        return 0;
    case WM_PAINT: Paint(hwnd); return 0;
    case WM_TIMER:
        if (wp!=SEARCH_TIMER) break;
        if (seen_file_generation!=ShzFileOpsGeneration()) {
            seen_file_generation=ShzFileOpsGeneration();refresh_needed=TRUE;
        }
        Collect();
        if (closing && !worker) { DestroyWindow(hwnd); return 0; }
        if (!worker && !refresh_needed && (DWORD)(GetTickCount()-last_refresh)>30000) refresh_needed=TRUE;
        BeginIndex(); return 0;
    case WM_CHAR: {
        if (closing || GetKeyState(VK_CONTROL)<0) return 0;
        SIZE_T n=ShzWcsLen(query);
        if (wp==VK_BACK) {
            if (n) { query[--n]=0; if (n && query[n-1]>=0xd800 && query[n-1]<=0xdbff) query[n-1]=0; }
        } else if (wp>=32 && wp!=127) {
            if (n+1>=SEARCH_QUERY) { ShzUserMessage(L"검색어가 너무 깁니다.",0); return 0; }
            query[n]=(WCHAR)wp; query[n+1]=0;
        } else return 0;
        Filter(); return 0;
    }
    case WM_KEYDOWN:
        if (wp==VK_ESCAPE) { SendMessageW(hwnd,WM_CLOSE,0,0); return 0; }
        if (closing) return 0;
        if (wp==VK_RETURN) { Activate(); return 0; }
        if (wp==L'C' && GetKeyState(VK_CONTROL)<0) {
            if (selected>=0 && selected<hit_count) {
                HIT *h=&hits[selected];
                ShzClipboardWriteText(hwnd,h->kind==HIT_CALC?h->label+2:h->label);
            }
            return 0;
        }
        if (wp==VK_UP && selected>0) --selected;
        else if (wp==VK_DOWN && selected+1<hit_count) ++selected;
        else if (wp==VK_F5) { refresh_needed=TRUE; BeginIndex(); }
        else if (wp==L'A' && GetKeyState(VK_CONTROL)<0) { query[0]=0; Filter(); }
        else { ShzGlobalKey((UINT)wp); return 0; }
        ClampScroll(hwnd); InvalidateRect(hwnd,NULL,FALSE); return 0;
    case WM_LBUTTONDOWN: {
        RECT c,e,l,s; int row; GetClientRect(hwnd,&c); Geometry(&c,&e,&l,&s,&row);
        int x=(short)LOWORD(lp),y=(short)HIWORD(lp);
        if (x>=l.left && x<l.right && y>=l.top && y<l.bottom) {
            int n=scroll+(y-l.top)/row;
            if (n<hit_count) { selected=n; InvalidateRect(hwnd,NULL,FALSE); }
        }
        SetFocus(hwnd); return 0;
    }
    case WM_LBUTTONDBLCLK: {
        RECT c,e,l,s; int row; GetClientRect(hwnd,&c); Geometry(&c,&e,&l,&s,&row);
        int x=(short)LOWORD(lp),y=(short)HIWORD(lp);
        if (!closing && x>=l.left && x<l.right && y>=l.top && y<l.bottom &&
            scroll+(y-l.top)/row<hit_count) Activate();
        return 0;
    }
    case WM_SIZE: ClampScroll(hwnd); InvalidateRect(hwnd,NULL,FALSE); return 0;
    case WM_CLOSE:
        closing=TRUE; refresh_needed=FALSE; InterlockedExchange(&cancelled,1);
        Collect(); if (!worker) DestroyWindow(hwnd); else InvalidateRect(hwnd,NULL,FALSE);
        return 0;
    case WM_DESTROY: KillTimer(hwnd,SEARCH_TIMER); search_window=NULL; closing=FALSE; return 0;
    default: break;
    }
    return DefWindowProcW(hwnd,msg,wp,lp);
}
BOOL ShzSearchRegister(void)
{
    WNDCLASSEXW wc; ZeroMemory(&wc,sizeof wc); wc.cbSize=sizeof wc;
    wc.style=CS_DBLCLKS; wc.lpfnWndProc=SearchProc; wc.hInstance=g_shell.inst;
    wc.hCursor=LoadCursorW(NULL,IDC_ARROW); wc.lpszClassName=SEARCH_CLASS;
    return RegisterClassExW(&wc)!=0;
}
HWND ShzSearchOpen(void)
{
    if (!search_window) {
        int sw=GetSystemMetrics(SM_CXSCREEN),sh=GetSystemMetrics(SM_CYSCREEN);
        int w=ShzClamp(ShzPx(700),240,sw>32?sw-32:240),h=ShzClamp(ShzPx(490),180,sh>80?sh-80:180);
        closing=FALSE;
        search_window=CreateWindowExW(0,SEARCH_CLASS,L"검색 — ShizukuOS",WS_OVERLAPPEDWINDOW,
            (sw-w)/2,(sh-h)/2,w,h,NULL,NULL,g_shell.inst,NULL);
        if (!search_window) { ShzUserMessage(L"검색창을 만들 수 없습니다.",GetLastError()); return NULL; }
    }
    query[0]=0; refresh_needed=TRUE; BeginIndex(); Filter();
    ShowWindow(search_window,SW_SHOW); SetForegroundWindow(search_window); SetFocus(search_window);
    printf("SHZ-SEARCH open local-only=1 worker=%u\n",worker?1u:0u);
    return search_window;
}
BOOL ShzSearchCanExit(void)
{
    Collect();
    if (!worker) return TRUE;
    ShzUserMessage(L"검색 인덱싱을 취소한 후 세션을 종료하세요.",0);
    if (search_window) { ShowWindow(search_window,SW_SHOW); SetForegroundWindow(search_window); }
    return FALSE;
}
void ShzSearchClose(void)
{
    if (search_window) SendMessageW(search_window,WM_CLOSE,0,0);
    Collect();
    if (!worker && published) { HeapFree(GetProcessHeap(),0,published); published=NULL; }
}
void ShzSearchRelayout(void)
{ if (search_window) { ClampScroll(search_window); InvalidateRect(search_window,NULL,FALSE); } }
