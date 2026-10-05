/* SPDX-License-Identifier: LGPL-2.1-or-later
 * One native command catalogue for Start, search, Run and file associations.
 * External commands are the actual shipped executables, never placeholders.
 */
#include "shzcrt.h"
#include "catalog.h"
#include "editor.h"
#include "search.h"
#include "fileops.h"

static const SHZ_COMMAND_INFO commands[] = {
    {SHZ_CMD_FILES, L"파일", L"files explorer 탐색기 폴더",L"files"},
    {SHZ_CMD_DOCUMENTS, L"문서", L"documents 홈 저장 파일",L"documents"},
    {SHZ_CMD_TEXT, L"텍스트 편집기", L"editor text notepad 메모 문서 새 파일",L"editor"},
    {SHZ_CMD_SETTINGS, L"설정", L"settings personalization theme 테마 개인 설정",L"settings"},
    {SHZ_CMD_SEARCH, L"검색", L"search find 검색 파일 창 앱",L"search"},
    {SHZ_CMD_RUN, L"실행", L"run command 실행 명령",L"run"},
    {SHZ_CMD_SAPPHIRE, L"Sapphire", L"image photo 그림 사진",L"sapphire"},
    {SHZ_CMD_MUZIK, L"Muzik", L"music wav 음악 소리",L"muzik"},
    {SHZ_CMD_GAMES, L"게임", L"games mines 지뢰 찾기",L"games"},
    {SHZ_CMD_EXIT, L"세션 종료", L"exit logout 종료",L"exit"}
};
unsigned ShzCommandCount(void) { return sizeof commands/sizeof commands[0]; }
const SHZ_COMMAND_INFO *ShzCommandAt(unsigned i)
{ return i<ShzCommandCount()?&commands[i]:NULL; }

void ShzUserMessage(const WCHAR *text, DWORD error)
{
    WCHAR code[24];
    ShzWcsCopy(g_shell.status, SHZ_STATUS_CHARS, text);
    if(error) {
        ShzFormatU64(error, code, 24);
        ShzWcsCat(g_shell.status, SHZ_STATUS_CHARS, L" (오류 ");
        ShzWcsCat(g_shell.status, SHZ_STATUS_CHARS, code);
        ShzWcsCat(g_shell.status, SHZ_STATUS_CHARS, L")");
    }
    g_shell.status_tick=GetTickCount();
    ShzTaskbarInvalidate();
}

BOOL ShzClipboardWriteText(HWND owner, const WCHAR *text)
{
    SIZE_T units=text?ShzWcsLen(text):0;
    if (!text || units>32767) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    HGLOBAL memory=GlobalAlloc(GMEM_MOVEABLE,(units+1)*sizeof(WCHAR));
    if (!memory) { ShzUserMessage(L"클립보드 메모리를 준비할 수 없습니다.",GetLastError()); return FALSE; }
    WCHAR *dst=GlobalLock(memory);
    if (!dst) { DWORD error=GetLastError();GlobalFree(memory);ShzUserMessage(L"클립보드 메모리에 접근할 수 없습니다.",error);return FALSE; }
    for (SIZE_T i=0;i<=units;++i) dst[i]=text[i];
    SetLastError(0);
    if (!GlobalUnlock(memory) && GetLastError()) {
        DWORD error=GetLastError();GlobalFree(memory);ShzUserMessage(L"클립보드 준비에 실패했습니다.",error);return FALSE;
    }
    if (!OpenClipboard(owner)) {
        DWORD error=GetLastError();GlobalFree(memory);ShzUserMessage(L"다른 앱이 클립보드를 사용 중입니다.",error);return FALSE;
    }
    if (!EmptyClipboard() || !SetClipboardData(CF_UNICODETEXT,memory)) {
        DWORD error=GetLastError();CloseClipboard();GlobalFree(memory);ShzUserMessage(L"클립보드에 복사할 수 없습니다.",error);return FALSE;
    }
    /* Successful SetClipboardData transfers ownership to the real backend. */
    if (!CloseClipboard()) { ShzUserMessage(L"복사됐지만 클립보드 닫기에 실패했습니다.",GetLastError());return FALSE; }
    ShzUserMessage(L"클립보드에 복사했습니다.",0);return TRUE;
}
static BOOL LaunchFile(const WCHAR *exe, const WCHAR *prefix, const WCHAR *path)
{
    WCHAR line[SHZ_MAX_PATH];
    /* Paths originate in the real file namespace. A quote is never an accepted
     * file-name scalar here; refusing it prevents command argument injection. */
    for(const WCHAR *s=exe;*s;++s) if(*s==L'"' || *s<32) {
        SetLastError(ERROR_INVALID_NAME);ShzUserMessage(L"프로그램 경로를 사용할 수 없습니다.",ERROR_INVALID_NAME);return FALSE;
    }
    for(const WCHAR *s=path;*s;++s) if(*s==L'"' || *s<32) {
        SetLastError(ERROR_INVALID_NAME);ShzUserMessage(L"파일 경로를 사용할 수 없습니다.",ERROR_INVALID_NAME);return FALSE;
    }
    if(!ShzWcsCopy(line,SHZ_MAX_PATH,L"\"") || !ShzWcsCat(line,SHZ_MAX_PATH,exe) ||
       !ShzWcsCat(line,SHZ_MAX_PATH,L"\"") ||
       ((path[0] || prefix) && (!ShzWcsCat(line,SHZ_MAX_PATH,L" ") ||
        (prefix && !ShzWcsCat(line,SHZ_MAX_PATH,prefix)) ||
        !ShzWcsCat(line,SHZ_MAX_PATH,L"\"") || !ShzWcsCat(line,SHZ_MAX_PATH,path) ||
        !ShzWcsCat(line,SHZ_MAX_PATH,L"\"")))) {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);ShzUserMessage(L"실행할 파일 경로가 너무 깁니다.",ERROR_FILENAME_EXCED_RANGE);return FALSE;
    }
    return ShzLaunch(line,L"C:\\SHZ\\SYS64");
}
static WCHAR Fold(WCHAR c) {return c>=L'A' && c<=L'Z'?c+32:c;}
static BOOL Extension(const WCHAR *path,const WCHAR *ext)
{
    const WCHAR *dot=NULL;
    for(const WCHAR *s=path;*s;++s) {if(*s==L'\\' || *s==L'/')dot=NULL;else if(*s==L'.')dot=s;}
    if(!dot)return FALSE;
    while(*dot && *ext && Fold(*dot)==Fold(*ext)){++dot;++ext;}
    return !*dot && !*ext;
}
BOOL ShzOpenDocument(const WCHAR *path)
{
    DWORD attrs;
    if(!path || !path[0] || ShzWcsLen(path)>=SHZ_MAX_PATH) {
        SetLastError(ERROR_INVALID_NAME);return FALSE;
    }
    attrs=GetFileAttributesW(path);
    if(attrs==INVALID_FILE_ATTRIBUTES) {ShzUserMessage(L"파일을 찾거나 열 수 없습니다.",GetLastError());return FALSE;}
    if(attrs & FILE_ATTRIBUTE_DIRECTORY)return ShzFilesOpen(path)!=NULL;
    if(Extension(path,L".txt") || Extension(path,L".md") || Extension(path,L".log") || Extension(path,L".ini"))
        return ShzEditorOpen(path)!=NULL;
    if(Extension(path,L".png") || Extension(path,L".bmp") || Extension(path,L".ppm"))
        return LaunchFile(L"C:\\SHZ\\SYS64\\SAPPHIRE.EXE",NULL,path);
    if(Extension(path,L".wav"))
        return LaunchFile(L"C:\\SHZ\\SYS64\\MUZIK.EXE",L"play --max-ms 60000 ",path);
    if(Extension(path,L".exe"))return LaunchFile(path,NULL,L"");
    SetLastError(ERROR_NOT_SUPPORTED);
    ShzUserMessage(L"이 파일 형식에 연결된 앱이 없습니다.",0);return FALSE;
}
BOOL ShzCommandInvoke(SHZ_COMMAND id)
{
    switch(id) {
    case SHZ_CMD_FILES:return ShzFilesOpen(NULL)!=NULL;
    case SHZ_CMD_DOCUMENTS: {
        WCHAR path[SHZ_FILE_PATH_CAP];
        if (!ShzFileDocumentsPathW(path)) { ShzUserMessage(L"문서 폴더 경로를 확인할 수 없습니다.",GetLastError());return FALSE; }
        return ShzFilesOpen(path)!=NULL;
    }
    case SHZ_CMD_TEXT:return ShzEditorOpen(NULL)!=NULL;
    case SHZ_CMD_SETTINGS:return ShzSettingsOpen()!=NULL;
    case SHZ_CMD_SEARCH:return ShzSearchOpen()!=NULL;
    case SHZ_CMD_RUN:ShzRunDialogOpen();return g_shell.runwnd!=NULL;
    case SHZ_CMD_SAPPHIRE:return LaunchFile(L"C:\\SHZ\\SYS64\\SAPPHIRE.EXE",NULL,L"C:\\SHZ\\SYS64\\SAPPHIRE-SAMPLE.PNG");
    case SHZ_CMD_MUZIK:return LaunchFile(L"C:\\SHZ\\SYS64\\MUZIK.EXE",L"play --max-ms 8000 ",L"C:\\SHZ\\MEDIA\\ShizukuStartup.wav");
    case SHZ_CMD_GAMES:return ShzLaunch(L"\"C:\\SHZ\\SYS64\\GAMES.EXE\"",L"C:\\SHZ\\SYS64");
    case SHZ_CMD_EXIT:
        if(!ShzEditorCanExit())return FALSE;
        if(!ShzFileOpsCanExit())return FALSE;
        if(!ShzSearchCanExit())return FALSE;
        g_shell.quit_requested=TRUE;DestroyWindow(g_shell.tray);return TRUE;
    default:SetLastError(ERROR_NOT_SUPPORTED);return FALSE;
    }
}

BOOL ShzRunInput(const WCHAR *text)
{
    WCHAR input[SHZ_MAX_PATH];
    if (!text || !ShzWcsCopy(input,SHZ_MAX_PATH,text)) {
        ShzUserMessage(L"명령이 너무 깁니다.",ERROR_FILENAME_EXCED_RANGE); return FALSE;
    }
    WCHAR *start=input;
    while (*start==L' ' || *start==L'\t') ++start;
    SIZE_T n=ShzWcsLen(start);
    while (n && (start[n-1]==L' ' || start[n-1]==L'\t')) start[--n]=0;
    if (!n) { ShzUserMessage(L"명령이나 파일 경로를 입력하세요.",0); return FALSE; }
    for (unsigned i=0; i<ShzCommandCount(); ++i) {
        const WCHAR *a=start,*b=commands[i].verb;
        while (*a && *b && Fold(*a)==Fold(*b)) { ++a; ++b; }
        if (!*a && !*b) {
            if (commands[i].id==SHZ_CMD_RUN) return FALSE;
            return ShzCommandInvoke(commands[i].id);
        }
    }
    BOOL open_verb=Fold(start[0])==L'o' && Fold(start[1])==L'p' &&
        Fold(start[2])==L'e' && Fold(start[3])==L'n' && (start[4]==L' ' || start[4]==L'\t');
    if (open_verb) { start+=5; while (*start==L' ' || *start==L'\t') ++start; }
    n=ShzWcsLen(start);
    if (n>=2 && start[0]==L'"' && start[n-1]==L'"') { ++start; start[n-2]=0; }
    if (open_verb || (start[0] && start[1]==L':' && start[2]==L'\\' &&
        GetFileAttributesW(start)!=INVALID_FILE_ATTRIBUTES)) return ShzOpenDocument(start);
    /* Existing process launch retains SAW's exact native parser and ordinary
     * CreateProcess argument semantics. No shell expansion/eval is introduced. */
    return ShzLaunch(text,NULL);
}
