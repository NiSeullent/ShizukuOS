/*
 * ShizukuOS shell candidate: "Files" top-level window (directory browser over real Win32 file APIs).
 *
 * Role adapted from ReactOS Explorer's file-browsing top-level window (pinned commit
 * ce41f2e98e0450ce624c5fc6155fb671af7cc3b5, base/shell/explorer: explorer launches the shell folder browser as
 * an ordinary top-level window which then becomes a task via CTrayWindow::IsTaskWnd, traywnd.cpp 2300-2316).
 * ReactOS uses the COM IShellBrowser/IShellView namespace; that is NOT implemented here. This window lists a
 * directory with FindFirstFileW/FindNextFileW and shows the real attribute bits and size. Namespace
 * extensions and drag and drop are absent. File-type association is routed
 * through the existing shell's shared native application dispatcher;
 * folder/drive/document icons are painted by the native vector helper.
 * Original ShizukuOS code with the structural attribution above; LGPL-2.1-or-later (see COPYING.LIB).
 *
 * Bounds: SHZ_MAX_FILES entries per listing (rest counted as truncated and reported), SHZ_MAX_PATH wide
 * characters per path including NUL. A path that would not fit is rejected and counted, never cut short.
 */
#include "shzcrt.h"
#include "shell.h"
#include "layout.h"
#include "icons.h"
#include "fileops.h"
#include "editor.h"
#include "catalog.h"
#include "search.h"


#define ROW_H  ShzPx(TH()->files_row_height)
#define FOOT_H ShzPx(TH()->files_footer_height)

typedef struct ENTRY {
    WCHAR name[SHZ_MAX_PATH];
    DWORD attrs;
    unsigned long long size;
    BOOL is_drive;
} ENTRY;

typedef struct LISTING {
    ENTRY e[SHZ_MAX_FILES];
    int n;
    BOOL truncated;
    int skipped_long;
    BOOL enum_error;
    DWORD enum_err;                 /* GetLastError captured immediately after the failing FindNextFileW */
} LISTING;

#define SHZ_HIST 8                  /* history entries per window */
#define SHZ_FILES_JOB_TIMER 71
#define SHZ_FILES_WATCH_TIMER 72
#define SHZ_FILES_CHANGED (WM_APP + 111)
enum { EDIT_RENAME=1, EDIT_MKDIR, EDIT_SEARCH };
enum { ACT_DOCUMENT, ACT_FOLDER, ACT_COPY, ACT_CUT, ACT_PASTE,
       ACT_TRASH, ACT_TRASH_VIEW, ACT_RESTORE, ACT_SEARCH, ACT_COUNT };

typedef struct FILESWND {
    WCHAR dir[SHZ_MAX_PATH];        /* "" = computer view, else always ends with '\' */
    LISTING *cur, *alt, *all;       /* actual directory cache -> bounded filtered view; no separate namespace */
    int sel, top;
    BOOL renaming;
    WCHAR edit[SHZ_MAX_PATH];
    int editlen;
    WCHAR msg[SHZ_STATUS_CHARS];    /* last error shown in this window's footer */
    WCHAR want[SHZ_MAX_PATH];       /* entry name to reselect after the next successful Navigate (consumed there) */
    BOOL wanthit;                   /* last Navigate found 'want' */
    WCHAR hist[SHZ_HIST][SHZ_MAX_PATH]; /* per-window back/forward list of directories visited (real paths only) */
    int hn, hpos;
    BOOL histmove;                  /* Navigate called from Alt+Left/Right: do not record */
    WCHAR ta[16]; int talen; DWORD tatick;   /* type-ahead prefix and time of last key */
    int edit_kind;
    BOOL edit_select;
    WCHAR filter[SHZ_MAX_PATH];
    BOOL actions;
    int action_sel, action_top;
    SHZ_FILE_JOB *job;
    SHZ_FILE_OPERATION job_op;
    WCHAR job_source[SHZ_MAX_PATH];
    DWORD file_generation;
} FILESWND;

static const WCHAR g_roots[3] = { L'E', L'C', L'D' };      /* required navigation roots, in this button order */
/* Files-local transfer selection, shared by these real browser windows.
 * This is not presented as the OS clipboard or as multi-file selection. */
static WCHAR g_transfer[SHZ_MAX_PATH];
static BOOL g_transfer_cut;
static const WCHAR *const action_names[ACT_COUNT] = {
    L"새 문서  Ctrl+N", L"새 폴더  Ctrl+Shift+N", L"복사  Ctrl+C", L"잘라내기  Ctrl+X",
    L"붙여넣기  Ctrl+V", L"휴지통으로 이동  Delete", L"휴지통 열기  Ctrl+T",
    L"원래 위치로 복원  Ctrl+R", L"이 폴더에서 찾기  Ctrl+F"
};

static void SetMsg(FILESWND *w, int id, DWORD err)
{
    ShzSetStatus(id, err);
    ShzWcsCopy(w->msg, SHZ_STATUS_CHARS, g_shell.status);
}

static BOOL AppendSlash(WCHAR *s)
{
    SIZE_T n = ShzWcsLen(s);
    if (n == 0 || s[n - 1] == L'\\') return TRUE;
    return ShzWcsCat(s, SHZ_MAX_PATH, L"\\");
}

static WCHAR Fold(WCHAR c) { return (c >= L'a' && c <= L'z') ? (WCHAR)(c - 32) : c; }
static BOOL EqI(const WCHAR *a, const WCHAR *b)
{
    while (*a && Fold(*a) == Fold(*b)) { ++a; ++b; }
    return *a == *b;
}
static BOOL PrefixI(const WCHAR *s, const WCHAR *p, int n)    /* first n chars of s equal p (case-insensitive) */
{
    int i;
    for (i = 0; i < n; ++i) if (!s[i] || Fold(s[i]) != Fold(p[i])) return FALSE;
    return TRUE;
}

static BOOL BadNameChar(WCHAR c)
{
    return c < 32 || c == L'\\' || c == L'/' || c == L':' || c == L'*' || c == L'?' || c == L'"' || c == L'<' || c == L'>' || c == L'|';
}

static void SwapDirsFirst(LISTING *l)       /* stable partition: folders first, order otherwise as returned */
{
    static ENTRY tmp[SHZ_MAX_FILES];        /* UI thread only; avoids a 70 KiB stack frame */
    int i, k = 0;
    for (i = 0; i < l->n; ++i) if (l->e[i].attrs & FILE_ATTRIBUTE_DIRECTORY) tmp[k++] = l->e[i];
    for (i = 0; i < l->n; ++i) if (!(l->e[i].attrs & FILE_ATTRIBUTE_DIRECTORY)) tmp[k++] = l->e[i];
    for (i = 0; i < l->n; ++i) l->e[i] = tmp[i];
}

static BOOL ReadDrives(LISTING *l)
{
    DWORD mask = GetLogicalDrives();
    int i;
    if (mask == 0) return FALSE;
    for (i = 0; i < 26; ++i) {
        if (!(mask & (1u << i))) continue;
        if (l->n >= SHZ_MAX_FILES) { l->truncated = TRUE; break; }
        l->e[l->n].name[0] = (WCHAR)(L'A' + i); l->e[l->n].name[1] = L':'; l->e[l->n].name[2] = L'\\'; l->e[l->n].name[3] = 0;
        l->e[l->n].attrs = FILE_ATTRIBUTE_DIRECTORY;
        l->e[l->n].size = GetDriveTypeW(l->e[l->n].name);       /* DRIVE_* code shown as the "size" column */
        l->e[l->n].is_drive = TRUE;
        l->n++;
    }
    return TRUE;
}

/* Fills 'l' from 'dir' (trailing backslash). Returns FALSE with *err set if the directory cannot be listed. */
static BOOL ReadDir(const WCHAR *dir, LISTING *l, DWORD *err)
{
    WCHAR pat[SHZ_MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    SIZE_T dlen = ShzWcsLen(dir);
    l->n = 0; l->truncated = FALSE; l->skipped_long = 0; l->enum_error = FALSE; l->enum_err = 0;
    if (!ShzWcsCopy(pat, SHZ_MAX_PATH, dir) || !ShzWcsCat(pat, SHZ_MAX_PATH, L"*")) { *err = ERROR_FILENAME_EXCED_RANGE; return FALSE; }
    h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        *err = GetLastError();
        if (*err == ERROR_FILE_NOT_FOUND) { *err = 0; return TRUE; }     /* empty directory */
        return FALSE;
    }
    do {
        SIZE_T nlen;
        if (fd.cFileName[0] == L'.' && (fd.cFileName[1] == 0 || (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0))) continue;
        nlen = ShzWcsLen(fd.cFileName);
        if (dlen + nlen >= SHZ_MAX_PATH) { l->skipped_long++; continue; }   /* a child path we could not hold: count, do not truncate */
        if (l->n >= SHZ_MAX_FILES) { l->truncated = TRUE; continue; }       /* keep counting nothing more, flag once */
        ShzWcsCopy(l->e[l->n].name, SHZ_MAX_PATH, fd.cFileName);
        l->e[l->n].attrs = fd.dwFileAttributes;
        l->e[l->n].size = ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        l->e[l->n].is_drive = FALSE;
        l->n++;
    } while (FindNextFileW(h, &fd));
    {   DWORD e = GetLastError();         /* read before FindClose can overwrite it */
        if (e != ERROR_NO_MORE_FILES) { l->enum_error = TRUE; l->enum_err = e; }
    }
    *err = 0;
    FindClose(h);
    SwapDirsFirst(l);
    return TRUE;
}

static void Reload(HWND hwnd, FILESWND *w);
static void EnsureVisibleFwd(HWND hwnd, FILESWND *w);

static BOOL ContainsI(const WCHAR *name, const WCHAR *needle)
{
    size_t n=ShzWcsLen(needle),i;
    if(!n)return TRUE;
    for(i=0;name[i];i++)if(PrefixI(name+i,needle,(int)n))return TRUE;
    return FALSE;
}
static void ApplyFilter(FILESWND *w)
{
    int i;
    w->cur->n=0;w->cur->truncated=w->all->truncated;w->cur->skipped_long=w->all->skipped_long;
    w->cur->enum_error=w->all->enum_error;w->cur->enum_err=w->all->enum_err;
    for(i=0;i<w->all->n;i++)if(ContainsI(w->all->e[i].name,w->filter))w->cur->e[w->cur->n++]=w->all->e[i];
    w->sel=0;w->top=0;
}

/* Navigate to 'dir' ("" = computer view). On failure the old listing stays and the error is shown. */
static BOOL Navigate(HWND hwnd, FILESWND *w, const WCHAR *dir)
{
    WCHAR d[SHZ_MAX_PATH];
    DWORD err = 0;
    LISTING *t;
    w->alt->n = 0; w->alt->truncated = FALSE; w->alt->skipped_long = 0; w->alt->enum_error = FALSE;
    if (!ShzWcsCopy(d, SHZ_MAX_PATH, dir) || !AppendSlash(d)) { SetMsg(w, IDS_ERR_PATH_LONG, 0); return FALSE; }
    if (d[0] == 0) {
        if (!ReadDrives(w->alt)) { SetMsg(w, IDS_ERR_DRIVE, GetLastError()); return FALSE; }
    } else if (!ReadDir(d, w->alt, &err)) {
        SetMsg(w, d[1] == L':' && ShzWcsLen(d) == 3 ? IDS_ERR_DRIVE : IDS_ERR_ENUM, err);
        return FALSE;
    }
    t = w->all; w->all = w->alt; w->alt = t;
    w->filter[0]=0;ApplyFilter(w);
    ShzWcsCopy(w->dir, SHZ_MAX_PATH, d);
    w->sel = 0; w->top = 0; w->renaming = FALSE; w->msg[0] = 0; w->talen = 0;
    w->wanthit = FALSE;
    if (w->want[0]) {                                /* keep the focus on the entry the user came from / just renamed */
        int i;
        for (i = 0; i < w->cur->n; ++i) if (EqI(w->cur->e[i].name, w->want)) { w->sel = i; w->wanthit = TRUE; break; }
        w->want[0] = 0;
    }
    if (!w->histmove && !(w->hn > 0 && EqI(w->hist[w->hpos], d))) {
        if (w->hn > 0) w->hn = w->hpos + 1;          /* a new branch drops the forward list */
        if (w->hn == SHZ_HIST) { int k; for (k = 1; k < SHZ_HIST; ++k) ShzWcsCopy(w->hist[k-1], SHZ_MAX_PATH, w->hist[k]); w->hn--; }
        ShzWcsCopy(w->hist[w->hn++], SHZ_MAX_PATH, d);
        w->hpos = w->hn - 1;
    }
    if (w->cur->enum_error) SetMsg(w, IDS_ERR_ENUM, w->cur->enum_err);
    else if (w->cur->skipped_long) SetMsg(w, IDS_ERR_PATH_LONG, 0);
    else if (w->cur->truncated) SetMsg(w, IDS_ERR_TRUNC, 0);
    SetWindowTextW(hwnd, w->dir[0] ? w->dir : ShzStr(IDS_COMPUTER));
    InvalidateRect(hwnd, NULL, FALSE);
    printf("SHZ-FILES listing count=%d truncated=%d error=%u\n",w->all->n,w->all->truncated,(unsigned)err);
    return TRUE;
}

static void Reload(HWND hwnd, FILESWND *w)          /* F5 */
{
    WCHAR d[SHZ_MAX_PATH];
    int keep = w->sel;WCHAR filter[SHZ_MAX_PATH];
    ShzWcsCopy(filter,SHZ_MAX_PATH,w->filter);
    ShzWcsCopy(d, SHZ_MAX_PATH, w->dir);
    w->want[0] = 0;
    if (keep >= 0 && keep < w->cur->n) ShzWcsCopy(w->want, SHZ_MAX_PATH, w->cur->e[keep].name);
    if (Navigate(hwnd, w, d) && !w->wanthit) w->sel = keep < w->cur->n ? keep : (w->cur->n ? w->cur->n - 1 : 0);
    if(filter[0]){ShzWcsCopy(w->filter,SHZ_MAX_PATH,filter);ApplyFilter(w);}
    w->want[0] = 0;
    ShzTasksRefresh();
}

static void GoParent(HWND hwnd, FILESWND *w)         /* Bksp */
{
    WCHAR d[SHZ_MAX_PATH];
    SIZE_T n = ShzWcsLen(w->dir);
    if (n == 0) return;
    ShzWcsCopy(d, SHZ_MAX_PATH, w->dir);
    d[n - 1] = 0;                                    /* drop trailing '\' */
    {   SIZE_T k = n - 1;                            /* remember the folder we leave so it is selected in the parent */
        while (k > 0 && d[k - 1] != L'\\') --k;
        w->want[0] = 0;
        if (k == 0 || d[k - 1] == L':') ShzWcsCopy(w->want, SHZ_MAX_PATH, w->dir);   /* drive root -> computer view entry "X:\\" */
        else ShzWcsCopy(w->want, SHZ_MAX_PATH, d + k);
    }
    while (n > 1 && d[n - 2] != L'\\' && d[n - 2] != L':') { d[n - 2] = 0; --n; }
    if (n > 1 && d[n - 2] == L':') d[0] = 0;   /* "X:\" had no parent folder: computer view */
    Navigate(hwnd, w, d);
    w->want[0] = 0;
}

static void GoHistory(HWND hwnd, FILESWND *w, int delta)   /* Alt+Left / Alt+Right */
{
    WCHAR d[SHZ_MAX_PATH];
    int np = w->hpos + delta;
    if (np < 0 || np >= w->hn) return;
    ShzWcsCopy(d, SHZ_MAX_PATH, w->hist[np]);
    w->histmove = TRUE;
    if (Navigate(hwnd, w, d)) w->hpos = np;         /* on failure position and the old listing stay, error shown */
    w->histmove = FALSE;
}

static void TypeAhead(HWND hwnd, FILESWND *w, WCHAR ch)  /* typing a name selects the next matching entry */
{
    DWORD now = GetTickCount();
    int i, n = w->cur->n, start;
    if (now - w->tatick > 1000 || w->talen >= 15) w->talen = 0;
    w->tatick = now;
    w->ta[w->talen++] = ch; w->ta[w->talen] = 0;
    start = w->sel >= 0 ? w->sel : 0;
    if (w->talen > 1 && w->sel < n && PrefixI(w->cur->e[w->sel].name, w->ta, w->talen)) return;
    for (i = 0; i < n; ++i) {
        int k = (start + (w->talen > 1 ? 0 : 1) + i) % n;
        if (PrefixI(w->cur->e[k].name, w->ta, w->talen)) { w->sel = k; EnsureVisibleFwd(hwnd, w); InvalidateRect(hwnd, NULL, FALSE); return; }
    }
}

static void OpenSelected(HWND hwnd, FILESWND *w)     /* Enter */
{
    WCHAR full[SHZ_MAX_PATH];
    ENTRY *e;
    if (w->sel < 0 || w->sel >= w->cur->n) return;
    e = &w->cur->e[w->sel];
    if (e->is_drive) { Navigate(hwnd, w, e->name); return; }
    if (!ShzWcsCopy(full, SHZ_MAX_PATH, w->dir) || !ShzWcsCat(full, SHZ_MAX_PATH, e->name)) { SetMsg(w, IDS_ERR_PATH_LONG, 0); return; }
    if (e->attrs & FILE_ATTRIBUTE_DIRECTORY) { Navigate(hwnd, w, full); return; }
    if(!ShzOpenDocument(full))ShzWcsCopy(w->msg,SHZ_STATUS_CHARS,g_shell.status);
}

static void LocalMessage(FILESWND *w,const WCHAR *text,DWORD error)
{
    WCHAR number[24];ShzWcsCopy(w->msg,SHZ_STATUS_CHARS,text);
    if(error){ShzFormatU64(error,number,24);ShzWcsCat(w->msg,SHZ_STATUS_CHARS,L" (오류 ");
        ShzWcsCat(w->msg,SHZ_STATUS_CHARS,number);ShzWcsCat(w->msg,SHZ_STATUS_CHARS,L")");}
}
static BOOL SelectedPath(FILESWND *w,WCHAR out[SHZ_MAX_PATH])
{
    if(!w->dir[0]||w->sel<0||w->sel>=w->cur->n||w->cur->e[w->sel].is_drive){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    return ShzWcsCopy(out,SHZ_MAX_PATH,w->dir)&&ShzWcsCat(out,SHZ_MAX_PATH,w->cur->e[w->sel].name)&&ShzFilePathValidW(out);
}
static BOOL StartFileJob(HWND hwnd,FILESWND *w,SHZ_FILE_OPERATION op,const WCHAR *src,const WCHAR *dst)
{
    if(w->job){LocalMessage(w,L"다른 파일 작업이 진행 중입니다. Esc로 취소할 수 있습니다.",ERROR_IO_PENDING);return FALSE;}
    w->job=ShzFileJobStart(op,src,dst,NULL,0,FALSE);
    if(!w->job){LocalMessage(w,L"파일 작업을 시작하지 못했습니다.",GetLastError());return FALSE;}
    if(!SetTimer(hwnd,SHZ_FILES_JOB_TIMER,100,NULL)){
        DWORD e=GetLastError();ShzFileJobRelease(w->job);w->job=NULL;LocalMessage(w,L"파일 작업을 시작하지 못했습니다.",e);return FALSE;
    }
    ShzFileJobSetOwner(w->job,hwnd);w->job_op=op;
    if(src)ShzWcsCopy(w->job_source,SHZ_MAX_PATH,src);else w->job_source[0]=0;
    LocalMessage(w,L"파일 작업 중... Esc 취소",0);InvalidateRect(hwnd,NULL,FALSE);return TRUE;
}
static BOOL CALLBACK NotifyFilesEnum(HWND hwnd,LPARAM except)
{
    WCHAR cls[32];DWORD owner=0;
    if(hwnd!=(HWND)except&&GetWindowThreadProcessId(hwnd,&owner)&&owner==GetCurrentProcessId()&&
       GetClassNameW(hwnd,cls,32)>0&&EqI(cls,SHZ_CLASS_FILES))PostMessageW(hwnd,SHZ_FILES_CHANGED,0,0);
    return TRUE;
}
void ShzFilesRefreshAll(void){EnumWindows(NotifyFilesEnum,0);}
static void PollFileJob(HWND hwnd,FILESWND *w)
{
    SHZ_FILE_RESULT r;WCHAR n[24],path[SHZ_MAX_PATH];
    if(!w->job)return;
    ShzFileJobPoll(w->job,&r);
    if(r.state==SHZ_FILE_RUNNING){
        ShzWcsCopy(w->msg,SHZ_STATUS_CHARS,L"파일 작업 중... ");ShzFormatU64(r.completed_bytes,n,24);ShzWcsCat(w->msg,SHZ_STATUS_CHARS,n);
        ShzWcsCat(w->msg,SHZ_STATUS_CHARS,L" / ");ShzFormatU64(r.total_bytes,n,24);ShzWcsCat(w->msg,SHZ_STATUS_CHARS,n);
        ShzWcsCat(w->msg,SHZ_STATUS_CHARS,L" 바이트  Esc 취소");InvalidateRect(hwnd,NULL,FALSE);return;
    }
    ShzFileJobRelease(w->job);w->job=NULL;KillTimer(hwnd,SHZ_FILES_JOB_TIMER);
    if(r.namespace_committed){Reload(hwnd,w);w->file_generation=ShzFileOpsGeneration();EnumWindows(NotifyFilesEnum,(LPARAM)hwnd);ShzSearchInvalidateFiles();}
    if(r.state==SHZ_FILE_DONE){
        LocalMessage(w,L"파일 작업을 완료했습니다.",0);
        if(g_transfer_cut&&w->job_op==SHZ_FILE_MOVE&&EqI(g_transfer,w->job_source))g_transfer[0]=0;
        if(r.result_path[0]&&ShzWcsCopy(path,SHZ_MAX_PATH,r.result_path)){
            size_t k=ShzWcsLen(path);while(k&&path[k-1]!=L'\\')k--;
            for(int i=0;i<w->cur->n;i++)if(EqI(w->cur->e[i].name,path+k)){w->sel=i;break;}
        }
    }else if(r.state==SHZ_FILE_CANCELLED)LocalMessage(w,L"작업을 취소했습니다. 원본을 유지했습니다.",r.error);
    else if(r.state==SHZ_FILE_PARTIAL){LocalMessage(w,L"파일은 변경됐지만 저장 또는 정리를 완료하지 못했습니다.",r.error);
        if(r.recovery_path[0]){ShzWcsCat(w->msg,SHZ_STATUS_CHARS,L" 복구 파일: ");ShzWcsCat(w->msg,SHZ_STATUS_CHARS,r.recovery_path);}}
    else LocalMessage(w,L"파일 작업을 완료하지 못했습니다. 원본을 확인하세요.",r.error);
    printf("SHZ-FILES job state=%u error=%u cleanup=%u committed=%d bytes=%llu/%llu\n",
           (unsigned)r.state,(unsigned)r.error,(unsigned)r.cleanup_error,r.namespace_committed,
           (unsigned long long)r.completed_bytes,(unsigned long long)r.total_bytes);
    EnsureVisibleFwd(hwnd,w);InvalidateRect(hwnd,NULL,FALSE);
}
static void FilesAction(HWND hwnd,FILESWND *w,int action)
{
    WCHAR from[SHZ_MAX_PATH],to[SHZ_MAX_PATH];w->actions=FALSE;
    if(action==ACT_DOCUMENT){if(!ShzEditorOpen(NULL))LocalMessage(w,L"문서를 열지 못했습니다.",GetLastError());return;}
    if(action==ACT_SEARCH){w->renaming=TRUE;w->edit_kind=EDIT_SEARCH;w->edit_select=TRUE;ShzWcsCopy(w->edit,SHZ_MAX_PATH,w->filter);w->editlen=(int)ShzWcsLen(w->edit);return;}
    if(action==ACT_FOLDER){if(!w->dir[0]){LocalMessage(w,L"새 폴더를 만들 위치를 먼저 여세요.",0);return;}
        w->renaming=TRUE;w->edit_kind=EDIT_MKDIR;w->edit_select=FALSE;w->editlen=0;w->edit[0]=0;return;}
    if(action==ACT_TRASH_VIEW){
        if(!w->dir[0]||!ShzWcsCopy(from,SHZ_MAX_PATH,w->dir)||!ShzWcsCat(from,SHZ_MAX_PATH,L"unused")||!ShzFileTrashDirectoryW(from,to))
            LocalMessage(w,L"휴지통 위치를 열지 못했습니다.",GetLastError());
        else Navigate(hwnd,w,to);
        return;
    }
    if(action==ACT_PASTE){size_t k=ShzWcsLen(g_transfer);
        if(!k||!w->dir[0]){LocalMessage(w,L"복사할 파일과 대상 폴더를 선택하세요.",0);return;}
        while(k&&g_transfer[k-1]!=L'\\')k--;
        if(!ShzWcsCopy(to,SHZ_MAX_PATH,w->dir)||!ShzWcsCat(to,SHZ_MAX_PATH,g_transfer+k)){LocalMessage(w,L"경로가 너무 깁니다.",ERROR_FILENAME_EXCED_RANGE);return;}
        StartFileJob(hwnd,w,g_transfer_cut?SHZ_FILE_MOVE:SHZ_FILE_COPY,g_transfer,to);return;
    }
    if(!SelectedPath(w,from)){LocalMessage(w,L"파일을 선택하세요.",GetLastError());return;}
    if(w->cur->e[w->sel].attrs&FILE_ATTRIBUTE_DIRECTORY){LocalMessage(w,L"이 작업은 현재 일반 파일만 지원합니다.",ERROR_NOT_SUPPORTED);return;}
    if(action==ACT_COPY||action==ACT_CUT){ShzWcsCopy(g_transfer,SHZ_MAX_PATH,from);g_transfer_cut=action==ACT_CUT;
        LocalMessage(w,action==ACT_CUT?L"다른 폴더에서 붙여넣으면 이동합니다.":L"다른 폴더에서 붙여넣으면 복사합니다.",0);return;}
    if(action==ACT_TRASH)StartFileJob(hwnd,w,SHZ_FILE_TRASH,from,NULL);
    else if(action==ACT_RESTORE)StartFileJob(hwnd,w,SHZ_FILE_RESTORE,from,NULL);
}

static void CommitRename(HWND hwnd, FILESWND *w)     /* Enter while renaming (after F2) */
{
    WCHAR from[SHZ_MAX_PATH], to[SHZ_MAX_PATH];
    int i;
    for (i = 0; i < w->editlen; ++i) if (BadNameChar(w->edit[i])) { SetMsg(w, IDS_ERR_RENAME, ERROR_INVALID_NAME); return; }
    if (w->editlen == 0) { SetMsg(w, IDS_ERR_RENAME, ERROR_INVALID_NAME); return; }
    if (!ShzWcsCopy(from, SHZ_MAX_PATH, w->dir) || !ShzWcsCat(from, SHZ_MAX_PATH, w->cur->e[w->sel].name) ||
        !ShzWcsCopy(to, SHZ_MAX_PATH, w->dir) || !ShzWcsCat(to, SHZ_MAX_PATH, w->edit)) { SetMsg(w, IDS_ERR_PATH_LONG, 0); return; }
    {   const WCHAR *x = from, *y = to; while (*x && *x == *y) { ++x; ++y; }
        if (*x == *y) { w->renaming = FALSE; w->msg[0] = 0; return; } }   /* unchanged name */
    if (!StartFileJob(hwnd,w,SHZ_FILE_RENAME,from,to)) return;
    w->renaming = FALSE;
}
static void CommitEdit(HWND hwnd,FILESWND *w)
{
    if(w->edit_kind==EDIT_RENAME){CommitRename(hwnd,w);return;}
    if(w->edit_kind==EDIT_SEARCH){ShzWcsCopy(w->filter,SHZ_MAX_PATH,w->edit);ApplyFilter(w);w->renaming=FALSE;return;}
    if(w->edit_kind==EDIT_MKDIR){WCHAR path[SHZ_MAX_PATH];
        if(!w->editlen){LocalMessage(w,L"폴더 이름을 입력하세요.",ERROR_INVALID_NAME);return;}
        if(!ShzWcsCopy(path,SHZ_MAX_PATH,w->dir)||!ShzWcsCat(path,SHZ_MAX_PATH,w->edit)||!ShzFilePathValidW(path)){
            LocalMessage(w,L"폴더 이름이나 경로를 사용할 수 없습니다.",GetLastError());return;}
        if(StartFileJob(hwnd,w,SHZ_FILE_MKDIR,NULL,path))w->renaming=FALSE;
    }
}

static SHZ_FILES_LAYOUT Geometry(HWND hwnd)
{
    RECT c; GetClientRect(hwnd, &c);
    return ShzFilesLayout(c.right, c.bottom, ShzUiScale(), TH()->files_bar_height, TH()->files_row_height, TH()->files_footer_height);
}
static void EnsureVisible(HWND hwnd, FILESWND *w)
{
    SHZ_FILES_LAYOUT g = Geometry(hwnd); int vis = ShzVisibleRows(&g);
    if (vis < 1) vis = 1;
    if (w->sel < w->top) w->top = w->sel;
    if (w->sel >= w->top+vis) w->top = w->sel-vis+1;
}
static void EnsureVisibleFwd(HWND hwnd, FILESWND *w) { EnsureVisible(hwnd, w); }
static void DriveRect(int i, RECT *r)
{
    int bar = ShzPx(TH()->files_bar_height), h = ShzPx(32);
    if (h > bar-ShzPx(4)) h=bar-ShzPx(4);
    r->left = ShzPx(130)+i*ShzPx(56); r->right = r->left+ShzPx(48);
    r->top = (bar-h)/2; r->bottom = r->top+h;
}
static void UpRect(RECT *r) { DriveRect(0,r); r->left=ShzPx(10); r->right=ShzPx(58); }
static void RefreshRect(RECT *r) { UpRect(r); r->left=ShzPx(66); r->right=ShzPx(114); }
static BOOL ActionsRect(HWND hwnd,RECT *r)
{
    RECT c;GetClientRect(hwnd,&c);RefreshRect(r);
    r->right=c.right-ShzPx(10);r->left=r->right-ShzPx(105);
    return r->left>=ShzPx(305);
}
static int ActionRows(HWND hwnd)
{
    SHZ_FILES_LAYOUT g=Geometry(hwnd);int n=(g.list_bottom-g.list_top)/ShzPx(30);
    if(n<1)n=1;
    if(n>ACT_COUNT)n=ACT_COUNT;
    return n;
}
static void ActionVisible(HWND hwnd,FILESWND *w)
{
    int n=ActionRows(hwnd);
    if(w->action_sel<w->action_top)w->action_top=w->action_sel;
    if(w->action_sel>=w->action_top+n)w->action_top=w->action_sel-n+1;
}
static void ActionRowRect(HWND hwnd,int row,RECT *r)
{
    RECT c;SHZ_FILES_LAYOUT g=Geometry(hwnd);GetClientRect(hwnd,&c);
    r->right=c.right-ShzPx(12);r->left=r->right-ShzPx(310);
    if(r->left<ShzPx(8))r->left=ShzPx(8);
    r->top=g.list_top+row*ShzPx(30);r->bottom=r->top+ShzPx(30);
}
static int SideBase(void) { return ShzPx(TH()->files_bar_height)+ShzPx(38); }   /* top of the navigation pane = toolbar+address */
static void SideRect(int i, RECT *r, int sidebar)
{
    r->left=ShzPx(8); r->right=sidebar-ShzPx(8); r->top=SideBase()+ShzPx(36)+i*ShzPx(34); r->bottom=r->top+ShzPx(30);
}

/* Column x-extents shared by header and rows so both stay aligned (details = kind and size columns shown). */
static void ColX(int width, int sidebar, BOOL details, int *name_l, int *name_r, int *kind_l, int *kind_r, int *size_l, int *size_r)
{
    *name_l = sidebar+ShzPx(46); *name_r = width-ShzPx(details?250:16);
    *kind_l = width-ShzPx(240); *kind_r = width-ShzPx(132);
    *size_l = width-ShzPx(124); *size_r = width-ShzPx(16);
}

/* Breadcrumb of the real current path. Each crumb maps to an existing directory prefix of w->dir (computer view
 * for the first). Width is an estimate (the text engine's measure call is private to ui.c); drawing ellipsizes. */
#define CRUMB_MAX 64
typedef struct CRUMB { RECT r; int pre; int ts, tl; BOOL ell; } CRUMB;   /* ts<0: computer label; ell: overflow chip */

static void AddrRect(const SHZ_FILES_LAYOUT *g, int width, RECT *r)
{
    r->left=ShzPx(10); r->right=width-ShzPx(10); r->top=g->toolbar; r->bottom=g->toolbar+g->address-ShzPx(6);
}
static int CrumbW(const WCHAR *s, int n)
{
    int i, px = ShzPx(TH()->typography_size), wd = ShzPx(14);
    for (i = 0; i < n; ++i) wd += s[i] >= 0x1100 ? px : (px*55)/100 + 1;
    return wd;
}
static int Crumbs(const FILESWND *w, const RECT *addr, CRUMB *out)
{
    int all_s[CRUMB_MAX], all_l[CRUMB_MAX], all_p[CRUMB_MAX], wd[CRUMB_MAX];
    int n = 1, i = 0, skip = 0, comps = 0, k, first, x, avail, sep = ShzPx(16), total;
    RECT in;
    in.left = addr->left+ShzPx(40); in.right = addr->right-ShzPx(8); in.top = addr->top+ShzPx(3); in.bottom = addr->bottom-ShzPx(3);
    all_s[0] = -1; all_l[0] = 0; all_p[0] = 0;
    while (w->dir[i]) { int j = i; while (w->dir[j] && w->dir[j] != L'\\') ++j; ++comps; i = w->dir[j] ? j+1 : j; }
    if (comps > CRUMB_MAX-1) skip = comps-(CRUMB_MAX-1);
    for (i = 0, k = 0; w->dir[i]; ) {
        int j = i; while (w->dir[j] && w->dir[j] != L'\\') ++j;
        if (k++ >= skip) { all_s[n] = i; all_l[n] = j-i; all_p[n] = w->dir[j] ? j+1 : j; ++n; }
        i = w->dir[j] ? j+1 : j;
    }
    for (k = 0; k < n; ++k) wd[k] = k ? CrumbW(w->dir+all_s[k], all_l[k]) : CrumbW(ShzStr(IDS_COMPUTER), (int)ShzWcsLen(ShzStr(IDS_COMPUTER)));
    avail = in.right-in.left;
    for (first = 0; first < n-1; ++first) {
        total = first ? ShzPx(28)+sep : 0;
        for (k = first; k < n; ++k) total += wd[k] + (k > first ? sep : 0);
        if (total <= avail) break;
    }
    x = in.left; i = 0;
    if (first) {
        out[i].r.left = x; out[i].r.right = x+ShzPx(28); out[i].r.top = in.top; out[i].r.bottom = in.bottom;
        out[i].pre = all_p[first-1]; out[i].ts = -1; out[i].tl = 0; out[i].ell = TRUE; ++i; x += ShzPx(28)+sep;
    }
    for (k = first; k < n; ++k) {
        int cw = wd[k]; if (x+cw > in.right) cw = in.right-x;
        if (cw <= 0) break;
        out[i].r.left = x; out[i].r.right = x+cw; out[i].r.top = in.top; out[i].r.bottom = in.bottom;
        out[i].pre = all_p[k]; out[i].ts = all_s[k]; out[i].tl = all_l[k]; out[i].ell = FALSE; ++i;
        x += cw+sep;
    }
    return i;
}

static void AttrString(DWORD a, WCHAR *s)
{
    s[0] = (a & FILE_ATTRIBUTE_DIRECTORY) ? L'D' : L'-'; s[1] = (a & FILE_ATTRIBUTE_READONLY) ? L'R' : L'-';
    s[2] = (a & FILE_ATTRIBUTE_HIDDEN) ? L'H' : L'-';    s[3] = (a & FILE_ATTRIBUTE_SYSTEM) ? L'S' : L'-';
    s[4] = (a & FILE_ATTRIBUTE_ARCHIVE) ? L'A' : L'-';   s[5] = 0;
}

/* Compact size: exact digits below 10,000,000 (<=7 cells), else value in K/M/G/T/P/E (1024 steps, <=8 cells with suffix). */
static void FormatSize(unsigned long long v, WCHAR out[24])
{
    static const WCHAR suf[] = L"KMGTPE";
    int k = -1;
    while (v >= 10000000ULL && k < 5) { v >>= 10; ++k; }
    ShzFormatU64(v, out, 22);
    if (k >= 0) { SIZE_T n = ShzWcsLen(out); out[n] = suf[k]; out[n + 1] = 0; }
}

/* BrowseUI CShellBrowser::RepositionBars separates toolbar/address/status
 * from the view before layout. CDefView::UpdateStatusbar derives counts from
 * real enumeration/selection. Both roles are adapted here without COM bands,
 * fake shell namespaces or replacing the existing Win32 file operations.
 * ReactOS pinned ce41f2e98e0450ce624c5fc6155fb671af7cc3b5, browseui/shellbrowser.cpp
 * Copyright 2009 Andrew Hill; CDefView.cpp Copyright 1998,1999 Juergen Schmied,
 * 2022 Russell Johnson. Both LGPL-2.1-or-later, see COPYING.LIB. */
static void OnPaint(HWND hwnd, FILESWND *w)
{
    PAINTSTRUCT ps; RECT c, r, icon, area;
    unsigned gen = (unsigned)ShzThemeGeneration();   /* captured before painting */
    HDC dc = BeginPaint(hwnd, &ps);
    const SHZ_THEME *th = TH(); SHZ_FILES_LAYOUT g = Geometry(hwnd);
    DWORD present = GetLogicalDrives(); int i, row, vis = ShzVisibleRows(&g);
    BOOL details; int nl,nr,kl,kr,sl,sr;
    WCHAR status[128] = L"";
    if (!dc) return;
    GetClientRect(hwnd, &c); ShzFill(dc, &c, TC(th->background_surface));
    details = c.right - g.sidebar >= ShzPx(480);
    r=c; r.bottom=g.toolbar+g.address;
    ShzFillGradientV(dc, &r, TC(th->files_bar_top), TC(th->files_bar_bottom));
    UpRect(&r); ShzFillGradientV(dc,&r,TC(th->buttons_normal_top),TC(th->buttons_normal_bottom)); ShzFrame(dc,&r,TC(th->border_light),1);
    icon=r; icon.left+=ShzPx(12); icon.right-=ShzPx(12); icon.top+=ShzPx(4); icon.bottom-=ShzPx(4);
    ShzDrawIcon(dc,&icon,SHZ_ICON_UP,TC(th->buttons_text));
    RefreshRect(&r); ShzFillGradientV(dc,&r,TC(th->buttons_normal_top),TC(th->buttons_normal_bottom)); ShzFrame(dc,&r,TC(th->border_light),1);
    icon=r; icon.left+=ShzPx(12); icon.right-=ShzPx(12); icon.top+=ShzPx(4); icon.bottom-=ShzPx(4);
    ShzDrawIcon(dc,&icon,SHZ_ICON_REFRESH,TC(th->buttons_text));
    for(i=0;i<3;i++) {
        WCHAR name[3]={g_roots[i],L':',0}; BOOL has=(present>>(g_roots[i]-L'A'))&1;
        DriveRect(i,&r); ShzFillGradientV(dc,&r,TC(has?th->buttons_normal_top:th->border_inactive),TC(has?th->buttons_normal_bottom:th->border_inactive)); if(has) ShzFrame(dc,&r,TC(th->border_light),1);
        SetTextColor(dc,TC(th->buttons_text)); ShzDrawText(dc,name,&r,DT_SINGLELINE|DT_VCENTER|DT_CENTER);
    }
    if(ActionsRect(hwnd,&r)){
        ShzFillGradientV(dc,&r,TC(th->buttons_normal_top),TC(th->buttons_normal_bottom));ShzFrame(dc,&r,TC(th->border_light),1);
        SetTextColor(dc,TC(th->buttons_text));ShzDrawText(dc,L"작업 (F10)",&r,DT_SINGLELINE|DT_VCENTER|DT_CENTER);
    }
    /* Address band becomes a bounded input for real mkdir/current-folder search. */
    {   CRUMB cr[CRUMB_MAX+1]; int nc, k; RECT ar;
        AddrRect(&g,c.right,&ar); r=ar;
        ShzFill(dc,&r,TC(th->background_input_bg)); ShzFrame(dc,&r,TC(th->background_input_border),1);
        icon=r; icon.left+=ShzPx(8); icon.top+=ShzPx(4); icon.right=icon.left+ShzPx(24); icon.bottom=icon.top+ShzPx(24);
        ShzDrawIcon(dc,&icon,w->dir[0]?SHZ_ICON_FOLDER:SHZ_ICON_COMPUTER,TC(th->menu_header_text));
        if(w->renaming&&w->edit_kind!=EDIT_RENAME){
            WCHAR text[SHZ_MAX_PATH+40];
            ShzWcsCopy(text,SHZ_MAX_PATH+40,w->edit_kind==EDIT_SEARCH?L"이 폴더에서 찾기: ":L"새 폴더 이름: ");
            ShzWcsCat(text,SHZ_MAX_PATH+40,w->edit);ShzWcsCat(text,SHZ_MAX_PATH+40,L"_  [Enter / Esc]");
            area=ar;area.left+=ShzPx(40);area.right-=ShzPx(5);SetTextColor(dc,TC(th->background_surface_text));
            ShzDrawText(dc,text,&area,DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS|DT_NOPREFIX);nc=0;
        }else nc=Crumbs(w,&ar,cr);
        for(k=0;k<nc;k++) {
            WCHAR t[SHZ_MAX_PATH]; BOOL last=(k==nc-1);
            area=cr[k].r;
            if(cr[k].ell) { SetTextColor(dc,TC(th->background_panel_text)); ShzDrawText(dc,L"\u2026",&area,DT_SINGLELINE|DT_VCENTER|DT_CENTER); }
            else {
                if(cr[k].ts<0) ShzWcsCopy(t,SHZ_MAX_PATH,ShzStr(IDS_COMPUTER));
                else { int m=cr[k].tl<SHZ_MAX_PATH-1?cr[k].tl:SHZ_MAX_PATH-1; int q; for(q=0;q<m;q++) t[q]=w->dir[cr[k].ts+q]; t[m]=0; }
                area.left+=ShzPx(7); SetTextColor(dc,TC(last?th->background_surface_text:th->background_panel_text));
                ShzDrawText(dc,t,&area,DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS|DT_NOPREFIX);
            }
            if(!last) {       /* chevron separator in the gap before the next crumb */
                RECT sp=cr[k].r; sp.left=cr[k].r.right; sp.right=cr[k+1].r.left;
                SetTextColor(dc,TC(th->background_surface_dim_text)); ShzDrawText(dc,L"\u203A",&sp,DT_SINGLELINE|DT_VCENTER|DT_CENTER);
            }
        }
    }
    if(g.sidebar) {
        int base=SideBase();
        r.left=0; r.right=g.sidebar; r.top=g.toolbar+g.address; r.bottom=g.list_bottom; ShzFill(dc,&r,TC(th->background_panel_face));
        r.left=g.sidebar-1; ShzFill(dc,&r,TC(th->border_light));                      /* divider against the list */
        r.left=ShzPx(16); r.right=g.sidebar-ShzPx(8); r.top=base+ShzPx(6); r.bottom=base+ShzPx(32); SetTextColor(dc,TC(th->menu_header_text));
        ShzDrawText(dc,L"\uC704\uCE58",&r,DT_SINGLELINE|DT_VCENTER);
        for(i=0;i<4;i++) {
            WCHAR root[4]={i ? g_roots[i-1] : 0,L':',L'\\',0}; const WCHAR *name=i?root:ShzStr(IDS_COMPUTER);
            BOOL selected=i ? (w->dir[0] && Fold(w->dir[0])==root[0]) : !w->dir[0];
            BOOL has=!i || ((present>>(root[0]-L'A'))&1); SideRect(i,&r,g.sidebar);
            if(selected) {
                ShzFillGradientV(dc,&r,TC(th->selection_inactive_top),TC(th->selection_inactive_bottom));
                ShzFrame(dc,&r,TC(th->selection_border),1);
            }
            icon=r; icon.left+=ShzPx(10); icon.top+=ShzPx(3); icon.right=icon.left+ShzPx(24); icon.bottom=icon.top+ShzPx(24);
            ShzDrawIcon(dc,&icon,i?SHZ_ICON_DRIVE:SHZ_ICON_COMPUTER,TC(th->menu_header_text));
            r.left+=ShzPx(42); SetTextColor(dc,TC(selected?th->selection_inactive_text:has?th->background_panel_text:th->background_surface_dim_text));
            ShzDrawText(dc,name,&r,DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS);
        }
    }
    /* Shared geometry keeps the column header outside the selectable rows; columns come from ColX like the rows. */
    ColX(c.right,g.sidebar,details,&nl,&nr,&kl,&kr,&sl,&sr);
    r.left=g.sidebar; r.right=c.right; r.top=g.toolbar+g.address; r.bottom=g.list_top;
    ShzFill(dc,&r,TC(th->background_panel_face));
    {   RECT ln=r; ln.top=r.bottom-1; ShzFill(dc,&ln,TC(th->border_light)); }                 /* header bottom rule */
    SetTextColor(dc,TC(th->background_panel_text));
    area=r; area.left=nl; area.right=nr;
    ShzDrawText(dc,L"\uC774\uB984",&area,DT_SINGLELINE|DT_VCENTER);
    if (details) {
        RECT sep=r; int xs[2]; int q; xs[0]=kl-ShzPx(8); xs[1]=sl-ShzPx(8);
        sep.top+=ShzPx(5); sep.bottom-=ShzPx(5);
        for(q=0;q<2;q++) { sep.left=xs[q]; sep.right=xs[q]+1; ShzFill(dc,&sep,TC(th->border_light)); }   /* column dividers */
        area.left=kl; area.right=kr; ShzDrawText(dc,L"\uC885\uB958",&area,DT_SINGLELINE|DT_VCENTER);
        area.left=sl; area.right=sr; ShzDrawText(dc,L"\uD06C\uAE30",&area,DT_SINGLELINE|DT_VCENTER|DT_RIGHT);
    }
    for(row=0;row<vis && w->top+row<w->cur->n;row++) {
        ENTRY *e=&w->cur->e[w->top+row]; WCHAR size[24]; BOOL selected=w->top+row==w->sel;
        BOOL focus=GetForegroundWindow()==hwnd;
        r.left=g.sidebar+ShzPx(8); r.right=c.right-ShzPx(8); r.top=g.list_top+row*g.row; r.bottom=r.top+g.row;
        if(selected) { ShzFillGradientV(dc,&r,TC(focus?th->selection_top:th->selection_inactive_top),TC(focus?th->selection_bottom:th->selection_inactive_bottom));
                       ShzFrame(dc,&r,TC(th->selection_border),1); }
        else if(row&1) ShzFill(dc,&r,ShzTint(TC(th->background_surface),TC(th->background_panel_face),38));
        icon=r; icon.left+=ShzPx(8); icon.top+=(g.row-ShzPx(24))/2; icon.right=icon.left+ShzPx(24); icon.bottom=icon.top+ShzPx(24);
        ShzDrawIcon(dc,&icon,e->is_drive?SHZ_ICON_DRIVE:e->attrs&FILE_ATTRIBUTE_DIRECTORY?SHZ_ICON_FOLDER:SHZ_ICON_DOCUMENT,
                    TC(e->is_drive?th->icons_glyph_computer:e->attrs&FILE_ATTRIBUTE_DIRECTORY?th->icons_glyph_files:th->icons_glyph_run));
        SetTextColor(dc,TC(selected?(focus?th->selection_text:th->selection_inactive_text):th->background_surface_text));
        area=r; area.left=nl; area.right=nr;
        ShzDrawText(dc,selected&&w->renaming&&w->edit_kind==EDIT_RENAME?w->edit:e->name,&area,DT_SINGLELINE|DT_VCENTER|DT_NOPREFIX|DT_END_ELLIPSIS);
        if (details) {
            area.left=kl; area.right=kr;
            ShzDrawText(dc,e->is_drive?L"\uB4DC\uB77C\uC774\uBE0C":ShzStr(e->attrs&FILE_ATTRIBUTE_DIRECTORY?IDS_DIR:IDS_FILE),&area,DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS);
            if(!(e->attrs&FILE_ATTRIBUTE_DIRECTORY)) {
                FormatSize(e->size,size); area.left=sl; area.right=sr;
                ShzDrawText(dc,size,&area,DT_SINGLELINE|DT_VCENTER|DT_RIGHT|DT_END_ELLIPSIS);
            }
        }
    }
    if(!w->cur->n) {
        r.left=g.sidebar+ShzPx(24); r.right=c.right-ShzPx(24); r.top=g.list_top+ShzPx(24); r.bottom=r.top+ShzPx(100);
        SetTextColor(dc,TC(th->background_surface_dim_text));
        if(w->msg[0]) ShzDrawText(dc,w->msg,&r,DT_WORDBREAK|DT_NOPREFIX);
        else {
            r.bottom=r.top+ShzPx(34);
            ShzDrawText(dc,w->filter[0]?L"이 폴더 목록에 일치하는 파일이 없습니다.":w->dir[0]?L"\uC774 \uD3F4\uB354\uB294 \uBE44\uC5B4 \uC788\uC2B5\uB2C8\uB2E4.":L"\uB4DC\uB77C\uC774\uBE0C\uB97C \uC120\uD0DD\uD558\uC138\uC694.",&r,DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS);
            r.top=r.bottom; r.bottom+=ShzPx(34);
            ShzDrawText(dc,L"\uC704\uCE58 \uBAA9\uB85D \uB610\uB294 \uC0C1\uB2E8 \uBC84\uD2BC\uC73C\uB85C \uC774\uB3D9\uD560 \uC218 \uC788\uC2B5\uB2C8\uB2E4.",&r,DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS);
        }
    }
    r=c; r.top=g.list_bottom; ShzFillGradientV(dc,&r,TC(th->files_footer_top),TC(th->files_footer_bottom));
    { RECT ln=r; ln.bottom=ln.top+1; ShzFill(dc,&ln,TC(th->border_light)); }      /* footer top rule */
    r.left+=ShzPx(14); r.right-=ShzPx(14);
    if(w->msg[0]) { SetTextColor(dc,TC(th->files_error_text)); ShzDrawText(dc,w->msg,&r,DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS); }
    else {
        ShzFormatU64((unsigned long long)w->cur->n,status,128); ShzWcsCat(status,128,L"\uAC1C \uD56D\uBAA9");
        if(w->sel>=0 && w->sel<w->cur->n) {
            ENTRY *e=&w->cur->e[w->sel]; WCHAR size[24];
            ShzWcsCat(status,128,L"  |  \uC120\uD0DD: "); ShzWcsCat(status,128,e->name);
            if(!(e->attrs&FILE_ATTRIBUTE_DIRECTORY) && !e->is_drive) { FormatSize(e->size,size); ShzWcsCat(status,128,L"  "); ShzWcsCat(status,128,size); }
        }
        ShzWcsCat(status,128,L"  |  F10 작업");
        if(w->filter[0])ShzWcsCat(status,128,L"  |  폴더 내 필터 적용");
        SetTextColor(dc,TC(th->background_panel_text)); ShzDrawText(dc,status,&r,DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS);
    }
    if(w->actions){
        int n=ActionRows(hwnd),k;ActionVisible(hwnd,w);
        for(k=0;k<n&&w->action_top+k<ACT_COUNT;k++){
            ActionRowRect(hwnd,k,&r);
            ShzFillGradientV(dc,&r,TC(w->action_top+k==w->action_sel?th->selection_top:th->background_panel_face),
                                      TC(w->action_top+k==w->action_sel?th->selection_bottom:th->background_panel_face));
            ShzFrame(dc,&r,TC(th->border_light),1);r.left+=ShzPx(8);r.right-=ShzPx(8);
            SetTextColor(dc,TC(w->action_top+k==w->action_sel?th->selection_text:th->background_panel_text));
            ShzDrawText(dc,action_names[w->action_top+k],&r,DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS|DT_NOPREFIX);
        }
    }
    if (EndPaint(hwnd,&ps)) {
        static unsigned long long last_h; static unsigned last_gen; static int last_fg = -1;   /* suppress identical repaints */
        unsigned long long h = (unsigned long long)(ULONG_PTR)hwnd; int fg = GetForegroundWindow() == hwnd ? 1 : 0;
        if (last_fg < 0 || last_h != h || last_fg != fg || last_gen != gen) {
            last_h = h; last_fg = fg; last_gen = gen;
            printf("SHZ-SHELL UI files hwnd=%llu foreground=%d gen=%u\n", h, fg, gen);
        }
    }
}

static void OnKey(HWND hwnd, FILESWND *w, UINT vk, BOOL alt)
{
    SHZ_FILES_LAYOUT geometry = Geometry(hwnd); int vis = ShzVisibleRows(&geometry);
    BOOL ctrl=(GetKeyState(VK_CONTROL)&0x8000)!=0;
    if (vis < 1) vis = 1;
    if (ShzGlobalKey(vk) && vk != VK_F5) return;
    if(w->renaming&&ctrl&&vk=='A'){w->edit_select=TRUE;InvalidateRect(hwnd,NULL,FALSE);return;}
    if(w->actions){
        if(vk==VK_UP&&w->action_sel>0)w->action_sel--;
        else if(vk==VK_DOWN&&w->action_sel+1<ACT_COUNT)w->action_sel++;
        else if(vk==VK_HOME)w->action_sel=0;
        else if(vk==VK_END)w->action_sel=ACT_COUNT-1;
        else if(vk==VK_RETURN)FilesAction(hwnd,w,w->action_sel);
        else if(vk==VK_ESCAPE||vk==VK_F10)w->actions=FALSE;
        ActionVisible(hwnd,w);InvalidateRect(hwnd,NULL,FALSE);return;
    }
    if(!w->renaming&&ctrl){
        int action=-1;
        if(vk=='N')action=(GetKeyState(VK_SHIFT)&0x8000)?ACT_FOLDER:ACT_DOCUMENT;
        else if(vk=='C')action=ACT_COPY;else if(vk=='X')action=ACT_CUT;else if(vk=='V')action=ACT_PASTE;
        else if(vk=='T')action=ACT_TRASH_VIEW;else if(vk=='R')action=ACT_RESTORE;else if(vk=='F')action=ACT_SEARCH;
        if(action>=0){FilesAction(hwnd,w,action);InvalidateRect(hwnd,NULL,FALSE);return;}
    }
    if (alt && !w->renaming) {
        if (vk == VK_LEFT) { GoHistory(hwnd, w, -1); EnsureVisible(hwnd, w); InvalidateRect(hwnd, NULL, FALSE); return; }
        if (vk == VK_RIGHT) { GoHistory(hwnd, w, 1); EnsureVisible(hwnd, w); InvalidateRect(hwnd, NULL, FALSE); return; }
        if (vk == VK_UP) { GoParent(hwnd, w); EnsureVisible(hwnd, w); InvalidateRect(hwnd, NULL, FALSE); return; }
    }
    switch (vk) {
    case VK_F10: if(!w->renaming){w->actions=TRUE;w->action_sel=0;w->action_top=0;}break;
    case VK_DELETE: if(!w->renaming)FilesAction(hwnd,w,ACT_TRASH);break;
    case VK_F2:
        if (!w->job && w->sel >= 0 && w->sel < w->cur->n && !w->cur->e[w->sel].is_drive && !(w->cur->e[w->sel].attrs&FILE_ATTRIBUTE_DIRECTORY)) {
            ShzWcsCopy(w->edit, SHZ_MAX_PATH, w->cur->e[w->sel].name);
            w->editlen = (int)ShzWcsLen(w->edit); w->renaming = TRUE;w->edit_kind=EDIT_RENAME;w->edit_select=TRUE; w->msg[0] = 0;
        }
        break;
    case VK_ESCAPE:
        if(w->renaming)w->renaming=FALSE;
        else if(w->job){ShzFileJobCancel(w->job);LocalMessage(w,L"취소를 요청했습니다. 완료된 변경은 결과에서 확인하세요.",0);}
        else if(w->filter[0]){w->filter[0]=0;ApplyFilter(w);}
        else w->msg[0]=0;
        w->talen=0;break;
    case VK_RETURN: if (w->renaming) CommitEdit(hwnd, w); else OpenSelected(hwnd, w); break;
    case VK_BACK: if (!w->renaming) GoParent(hwnd, w); break;      /* while renaming, WM_CHAR handles Backspace */
    case VK_F5: Reload(hwnd, w); break;
    case VK_LEFT: if (!w->renaming && !alt) GoParent(hwnd, w); break;      /* Explorer-style: Left = up one level */
    case VK_RIGHT: if (!w->renaming && !alt && w->sel >= 0 && w->sel < w->cur->n && (w->cur->e[w->sel].attrs & FILE_ATTRIBUTE_DIRECTORY)) OpenSelected(hwnd, w); break;
    case VK_UP: if (!w->renaming && w->sel > 0) w->sel--; break;
    case VK_DOWN: if (!w->renaming && w->sel + 1 < w->cur->n) w->sel++; break;
    case VK_PRIOR: if (!w->renaming) { w->sel -= vis; if (w->sel < 0) w->sel = 0; } break;
    case VK_NEXT: if (!w->renaming) { w->sel += vis; if (w->sel >= w->cur->n) w->sel = w->cur->n ? w->cur->n - 1 : 0; } break;
    case VK_HOME: if (!w->renaming) w->sel = 0; break;
    case VK_END: if (!w->renaming) w->sel = w->cur->n ? w->cur->n - 1 : 0; break;
    default: return;
    }
    EnsureVisible(hwnd, w);
    InvalidateRect(hwnd, NULL, FALSE);
}

static void OnClick(HWND hwnd, FILESWND *w, int x, int y, BOOL dbl)
{
    RECT r; POINT p; int i;
    p.x = x; p.y = y;
    if(w->actions){
        int n=ActionRows(hwnd);
        for(i=0;i<n&&w->action_top+i<ACT_COUNT;i++){
            ActionRowRect(hwnd,i,&r);
            if(PtInRect(&r,p)){FilesAction(hwnd,w,w->action_top+i);InvalidateRect(hwnd,NULL,FALSE);return;}
        }
        w->actions=FALSE;InvalidateRect(hwnd,NULL,FALSE);return;
    }
    if(ActionsRect(hwnd,&r)&&PtInRect(&r,p)){
        w->actions=TRUE;w->action_top=0;w->action_sel=0;InvalidateRect(hwnd,NULL,FALSE);return;
    }
    if(w->renaming)return;
    for (i = 0; i < 3; ++i) {
        DriveRect(i, &r);
        if (PtInRect(&r, p)) {
            WCHAR root[4]; root[0] = g_roots[i]; root[1] = L':'; root[2] = L'\\'; root[3] = 0;
            if (!((GetLogicalDrives() >> (g_roots[i] - L'A')) & 1)) { SetMsg(w, IDS_ERR_DRIVE, ERROR_PATH_NOT_FOUND); InvalidateRect(hwnd, NULL, FALSE); }
            else Navigate(hwnd, w, root);
            return;
        }
    }
    UpRect(&r);
    if(PtInRect(&r,p)) { GoParent(hwnd,w); return; }
    RefreshRect(&r);
    if(PtInRect(&r,p)) { Reload(hwnd,w); return; }
    { SHZ_FILES_LAYOUT g=Geometry(hwnd);
      {   CRUMB cr[CRUMB_MAX+1]; RECT ar, cl; int nc, k;     /* breadcrumb: jump to the real directory prefix */
          GetClientRect(hwnd,&cl); AddrRect(&g,cl.right,&ar);
          if(PtInRect(&ar,p)) {
              nc=Crumbs(w,&ar,cr);
              for(k=0;k<nc;k++) if(PtInRect(&cr[k].r,p)) {
                  WCHAR d[SHZ_MAX_PATH]; int m=cr[k].pre;
                  if(m>=SHZ_MAX_PATH) return;
                  { int q; for(q=0;q<m;q++) d[q]=w->dir[q]; d[m]=0; }
                  Navigate(hwnd,w,d); InvalidateRect(hwnd,NULL,FALSE); return;
              }
              return;
          }
      }
      if(g.sidebar) for(i=0;i<4;i++) {
          SideRect(i,&r,g.sidebar);
          if(PtInRect(&r,p) && p.y<g.list_bottom) {
              WCHAR root[4]={i?g_roots[i-1]:0,L':',L'\\',0};
              if(i && !((GetLogicalDrives()>>(root[0]-L'A'))&1)) SetMsg(w,IDS_ERR_DRIVE,ERROR_PATH_NOT_FOUND);
              else Navigate(hwnd,w,root);
              InvalidateRect(hwnd,NULL,FALSE); return;
          }
      }
      GetClientRect(hwnd,&r); i=ShzListHit(&g,r.right,x,y,w->top,w->cur->n);
      if(i>=0) { w->sel=i; w->renaming=FALSE; if(dbl) OpenSelected(hwnd,w); InvalidateRect(hwnd,NULL,FALSE); }
    }

}

static LRESULT CALLBACK FilesProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    FILESWND *w = (FILESWND *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    switch (msg) {
    case WM_TIMER:
        if(w&&wp==SHZ_FILES_JOB_TIMER){PollFileJob(hwnd,w);return 0;}
        if(w&&wp==SHZ_FILES_WATCH_TIMER){
            DWORD gen=ShzFileOpsGeneration();
            if(gen!=w->file_generation&&!w->renaming&&!w->job){
                WCHAR keep[SHZ_STATUS_CHARS];ShzWcsCopy(keep,SHZ_STATUS_CHARS,w->msg);
                Reload(hwnd,w);if(!w->cur->enum_error)ShzWcsCopy(w->msg,SHZ_STATUS_CHARS,keep);
                w->file_generation=gen;
            }
            return 0;
        }
        break;
    case SHZ_FILES_CHANGED:
        if(w&&!w->renaming){WCHAR keep[SHZ_STATUS_CHARS];ShzWcsCopy(keep,SHZ_STATUS_CHARS,w->msg);
            Reload(hwnd,w);if(!w->cur->enum_error)ShzWcsCopy(w->msg,SHZ_STATUS_CHARS,keep);}
        return 0;
    case SHZ_FILEOPS_EXIT_BLOCKED:
        if(w){LocalMessage(w,L"파일 작업 중에는 종료할 수 없습니다. 완료를 기다리거나 Esc로 취소하세요.",ERROR_BUSY);InvalidateRect(hwnd,NULL,FALSE);}
        return 0;
    case WM_PAINT: if (w) OnPaint(hwnd, w); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_SIZE: if (w) { EnsureVisible(hwnd, w); InvalidateRect(hwnd, NULL, FALSE); } return 0;
    case WM_KEYDOWN: case WM_SYSKEYDOWN: if (w) OnKey(hwnd, w, (UINT)wp, msg == WM_SYSKEYDOWN); break;
    case WM_CHAR:
        if (w && !w->renaming && !w->actions && !(GetKeyState(VK_CONTROL)&0x8000) && wp > 32 && w->cur->n > 0) { TypeAhead(hwnd, w, (WCHAR)wp); return 0; }
        if (w && w->renaming && wp != VK_RETURN && wp != VK_ESCAPE) {
            if(w->edit_select&&(wp==VK_BACK||wp>=32)){w->editlen=0;w->edit[0]=0;w->edit_select=FALSE;}
            if (wp == VK_BACK) { if (w->editlen > 0) {
                WCHAR last=w->edit[--w->editlen];w->edit[w->editlen]=0;
                if(last>=0xdc00&&last<=0xdfff&&w->editlen>0&&w->edit[w->editlen-1]>=0xd800&&w->edit[w->editlen-1]<0xdc00)w->edit[--w->editlen]=0;
            } }
            else if (wp >= 32) {
                if (w->editlen + 1 >= SHZ_MAX_PATH) SetMsg(w, IDS_ERR_PATH_LONG, 0);
                else { w->edit[w->editlen++] = (WCHAR)wp; w->edit[w->editlen] = 0; }
            }
            InvalidateRect(hwnd, NULL, FALSE);
        }
        return 0;
    case WM_LBUTTONDOWN: if (w) OnClick(hwnd, w, (short)LOWORD(lp), (short)HIWORD(lp), FALSE); SetFocus(hwnd); return 0;
    case WM_LBUTTONDBLCLK: if (w) OnClick(hwnd, w, (short)LOWORD(lp), (short)HIWORD(lp), TRUE); return 0;
    case WM_MOUSEWHEEL:
        if(w&&w->actions){int d=(short)HIWORD(wp)>0?-1:1;w->action_sel+=d;
            if(w->action_sel<0)w->action_sel=0;
            if(w->action_sel>=ACT_COUNT)w->action_sel=ACT_COUNT-1;
            ActionVisible(hwnd,w);InvalidateRect(hwnd,NULL,FALSE);return 0;}
        if (w) { int d = (short)HIWORD(wp) > 0 ? -3 : 3; w->top += d; if (w->top < 0) w->top = 0; if (w->top >= w->cur->n) w->top = w->cur->n ? w->cur->n - 1 : 0; InvalidateRect(hwnd, NULL, FALSE); }
        return 0;
    case WM_NCDESTROY:
        if (w) {
            KillTimer(hwnd,SHZ_FILES_WATCH_TIMER);
            if(w->job){ShzFileJobSetOwner(w->job,NULL);ShzFileJobRelease(w->job);w->job=NULL;KillTimer(hwnd,SHZ_FILES_JOB_TIMER);}
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            HeapFree(GetProcessHeap(), 0, w->cur); HeapFree(GetProcessHeap(), 0, w->alt); HeapFree(GetProcessHeap(), 0, w->all);HeapFree(GetProcessHeap(), 0, w);
            if (g_shell.files_windows > 0) g_shell.files_windows--;
        }
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* Theme reload: every live Files window re-clamps scroll for the new row height (WM_SIZE path) and repaints. */
static BOOL CALLBACK RelayoutEnum(HWND hwnd, LPARAM lp)
{
    WCHAR cls[24]; DWORD owner = 0;
    (void)lp;
    if (!GetWindowThreadProcessId(hwnd, &owner) || owner != GetCurrentProcessId()) return TRUE;
    if (GetClassNameW(hwnd, cls, 24) > 0) {
        const WCHAR *want = SHZ_CLASS_FILES; int k = 0;
        while (cls[k] && want[k] && cls[k] == want[k]) ++k;
        if (!cls[k] && !want[k]) SendMessageW(hwnd, WM_SIZE, 0, 0);
    }
    return TRUE;
}

void ShzFilesRelayoutAll(void)
{
    if (g_shell.files_windows > 0 && !EnumWindows(RelayoutEnum, 0)) ShzSetStatus(IDS_ERR_ENUM, GetLastError());
}

BOOL ShzFilesRegister(void)
{
    WNDCLASSEXW wc;
    wc.cbSize = sizeof wc; wc.style = CS_DBLCLKS; wc.lpfnWndProc = FilesProc; wc.cbClsExtra = wc.cbWndExtra = 0;
    wc.hInstance = g_shell.inst; wc.hIcon = NULL; wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = NULL; wc.lpszMenuName = NULL; wc.lpszClassName = SHZ_CLASS_FILES; wc.hIconSm = NULL;
    if (!RegisterClassExW(&wc)) { ShzSetStatus(IDS_ERR_CLASS, GetLastError()); return FALSE; }
    return TRUE;
}

HWND ShzFilesOpen(const WCHAR *path)
{
    FILESWND *w;
    HWND h;
    int off = g_shell.files_windows * ShzPx(24);
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    int width = ShzPx(940), height = ShzPx(640), x, y;
    if (width > sw-ShzPx(32)) width=sw-ShzPx(32);
    if (height > sh-ShzPx(TH()->taskbar_height)-ShzPx(48)) height=sh-ShzPx(TH()->taskbar_height)-ShzPx(48);
    if (width<320 || height<240) { ShzSetStatus(IDS_ERR_WINDOW, ERROR_INVALID_PARAMETER); return NULL; }
    x=(sw-width)/2+off; y=(sh-ShzPx(TH()->taskbar_height)-height)/2+off;
    if (x+width>sw) x=sw-width;
    if (y+height>sh-ShzPx(TH()->taskbar_height)) y=sh-ShzPx(TH()->taskbar_height)-height;
    if (g_shell.files_windows >= SHZ_MAX_FILES_WINDOWS) { ShzSetStatus(IDS_ERR_FILES_LIMIT, 0); return NULL; }
    w = (FILESWND *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *w);
    if (!w) { ShzSetStatus(IDS_ERR_WINDOW, ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    w->cur = (LISTING *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LISTING));
    w->alt = (LISTING *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LISTING));
    w->all = (LISTING *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LISTING));
    if (!w->cur || !w->alt || !w->all) {
        HeapFree(GetProcessHeap(), 0, w->cur); HeapFree(GetProcessHeap(), 0, w->alt);HeapFree(GetProcessHeap(),0,w->all); HeapFree(GetProcessHeap(), 0, w);
        ShzSetStatus(IDS_ERR_WINDOW, ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    h = CreateWindowExW(0, SHZ_CLASS_FILES, ShzStr(IDS_FILES_TITLE), WS_OVERLAPPEDWINDOW, x, y, width, height,
                        NULL, NULL, g_shell.inst, w);
    if (!h) {                                           /* ownership is adopted only after creation succeeded (below) */
        DWORD e = GetLastError();
        HeapFree(GetProcessHeap(), 0, w->cur); HeapFree(GetProcessHeap(), 0, w->alt);HeapFree(GetProcessHeap(),0,w->all); HeapFree(GetProcessHeap(), 0, w);
        ShzSetStatus(IDS_ERR_WINDOW, e);
        return NULL;
    }
    SetLastError(0);                                    /* SetWindowLongPtrW returns the old value (0): only the error tells failure */
    if (SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)w) == 0 && GetLastError() != 0) {
        DWORD e = GetLastError();
        DestroyWindow(h);                               /* userdata not set, so WM_NCDESTROY does not free w */
        HeapFree(GetProcessHeap(), 0, w->cur); HeapFree(GetProcessHeap(), 0, w->alt);HeapFree(GetProcessHeap(),0,w->all); HeapFree(GetProcessHeap(), 0, w);
        ShzSetStatus(IDS_ERR_WINDOW, e);
        return NULL;
    }                                                   /* from here WM_NCDESTROY owns and frees w */
    g_shell.files_windows++;
    w->file_generation=ShzFileOpsGeneration();
    if (!path || !Navigate(h, w, path)) {
        if (path) ShzWcsCopy(w->msg, SHZ_STATUS_CHARS, g_shell.status);      /* keep failure visible, then show computer view */
        { WCHAR keep[SHZ_STATUS_CHARS]; ShzWcsCopy(keep, SHZ_STATUS_CHARS, w->msg);
          Navigate(h, w, L""); ShzWcsCopy(w->msg, SHZ_STATUS_CHARS, keep); }
    }
    ShowWindow(h, SW_SHOW);
    if(!SetTimer(h,SHZ_FILES_WATCH_TIMER,500,NULL))LocalMessage(w,L"자동 새로 고침을 시작하지 못했습니다. F5로 다시 읽을 수 있습니다.",GetLastError());
    if (!SetForegroundWindow(h)) ShzSetStatus(IDS_ERR_FOCUS, GetLastError());
    SetFocus(h);
    UpdateWindow(h);
    ShzTasksRefresh();
    ShzTaskbarInvalidate();
    return h;
}
