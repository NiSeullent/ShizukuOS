/* Native, bounded KernelEx mode guard for the frozen latest-NPP private lab.
 * Copyright (C) 2026 Win98-Modern contributors. GPL-2.0-only.
 * No wildcard/default setting is changed. Existing exact values are refused.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define CONFIG_KEY "Software\\KernelEx\\AppSettings\\Configs"
#define FLAGS_KEY "Software\\KernelEx\\AppSettings\\Flags"
#define APP_PATH "C:\\NPPLAB\\APP\\NPP.EXE"
#define CONFIG "WINXP"
#define LOG_PATH "C:\\NPPLAB\\MODE.LOG"

static HANDLE log_file;
static unsigned length(const char *s) { unsigned n=0; while(s[n]) ++n; return n; }
static char upper(char c) { return c>='a'&&c<='z'?(char)(c-'a'+'A'):c; }
static BOOL same(const char *a,const char *b)
{
    while(*a&&*b) if(upper(*a++)!=upper(*b++)) return FALSE;
    return !*a&&!*b;
}
static void output(const char *s)
{
    DWORD written; HANDLE h=GetStdHandle(STD_OUTPUT_HANDLE); DWORD n=length(s);
    if(h&&h!=INVALID_HANDLE_VALUE) WriteFile(h,s,n,&written,NULL);
    if(log_file&&log_file!=INVALID_HANDLE_VALUE) WriteFile(log_file,s,n,&written,NULL);
}
static void number(const char *tag,DWORD value)
{
    char digits[16]; unsigned n=sizeof(digits)-1; digits[n]=0;
    do { digits[--n]=(char)('0'+value%10); value/=10; } while(value);
    output(tag); output(digits+n); output("\r\n");
}
static const char *action(void)
{
    const char *s=GetCommandLineA(); BOOL quote=FALSE;
    while(*s) {
        if(*s=='"') quote=!quote;
        else if(!quote&&(*s==' '||*s=='\t')) break;
        ++s;
    }
    while(*s==' '||*s=='\t') ++s;
    return s;
}
static BOOL command(const char *s,const char *wanted)
{
    while(*wanted) if(upper(*s++)!=upper(*wanted++)) return FALSE;
    while(*s==' '||*s=='\t') ++s;
    return !*s;
}
static LONG read_config(HKEY key,char *value,BOOL *present)
{
    DWORD type=0,bytes=64; LONG rc=RegQueryValueExA(key,APP_PATH,NULL,&type,(BYTE *)value,&bytes);
    *present=FALSE;
    if(rc==ERROR_FILE_NOT_FOUND) return ERROR_SUCCESS;
    if(rc!=ERROR_SUCCESS) return rc;
    if(type!=REG_SZ||!bytes||bytes>64||value[bytes-1]!=0||length(value)+1!=bytes) return ERROR_INVALID_DATA;
    *present=TRUE; return ERROR_SUCCESS;
}
static LONG read_flags(HKEY key,DWORD *value,BOOL *present)
{
    DWORD type=0,bytes=sizeof(*value); LONG rc=RegQueryValueExA(key,APP_PATH,NULL,&type,(BYTE *)value,&bytes);
    *present=FALSE;
    if(rc==ERROR_FILE_NOT_FOUND) return ERROR_SUCCESS;
    if(rc!=ERROR_SUCCESS) return rc;
    if(type!=REG_DWORD||bytes!=sizeof(*value)) return ERROR_INVALID_DATA;
    *present=TRUE; return ERROR_SUCCESS;
}
static BOOL absent_after_rollback(HKEY configs,HKEY flags)
{
    char config[64]; DWORD value=0; BOOL cp=FALSE,fp=FALSE;
    LONG cr=RegDeleteValueA(configs,APP_PATH),fr=RegDeleteValueA(flags,APP_PATH);
    LONG cf=RegFlushKey(configs),ff=RegFlushKey(flags);
    number("ROLLBACK_CONFIG_DELETE=",(DWORD)cr); number("ROLLBACK_FLAGS_DELETE=",(DWORD)fr);
    number("ROLLBACK_CONFIG_FLUSH=",(DWORD)cf); number("ROLLBACK_FLAGS_FLUSH=",(DWORD)ff);
    return (cr==ERROR_SUCCESS||cr==ERROR_FILE_NOT_FOUND)&&(fr==ERROR_SUCCESS||fr==ERROR_FILE_NOT_FOUND)&&
        cf==ERROR_SUCCESS&&ff==ERROR_SUCCESS&&read_config(configs,config,&cp)==ERROR_SUCCESS&&
        read_flags(flags,&value,&fp)==ERROR_SUCCESS&&!cp&&!fp;
}
static void finish(DWORD code,HKEY configs,HKEY flags)
{
    number("EXIT=",code);
    if(configs) RegCloseKey(configs);
    if(flags) RegCloseKey(flags);
    if(log_file&&log_file!=INVALID_HANDLE_VALUE) { FlushFileBuffers(log_file); CloseHandle(log_file); }
    ExitProcess(code);
}
void __cdecl mainCRTStartup(void)
{
    const char *mode=action(); BOOL inspect=command(mode,"inspect"),apply=command(mode,"apply");
    HKEY configs=NULL,flags=NULL; char config[64]; DWORD flag=0; BOOL cp=FALSE,fp=FALSE;
    LONG rc; DWORD access=KEY_QUERY_VALUE|(apply?KEY_SET_VALUE:0);
    if(!inspect&&!apply) { output("USAGE: NPPMODE.EXE inspect|apply\r\n"); ExitProcess(2); }
    log_file=CreateFileA(LOG_PATH,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(log_file==INVALID_HANDLE_VALUE) { number("LOG_ERROR=",GetLastError()); ExitProcess(3); }
    output("NPP-MODE native exact-app guard\r\nAPP=" APP_PATH "\r\n"); number("NATIVE_VERSION=",GetVersion());
    rc=RegOpenKeyExA(HKEY_LOCAL_MACHINE,CONFIG_KEY,0,access,&configs);
    if(rc!=ERROR_SUCCESS) { number("OPEN_CONFIG_ERROR=",(DWORD)rc); finish(3,configs,flags); }
    rc=RegOpenKeyExA(HKEY_LOCAL_MACHINE,FLAGS_KEY,0,access,&flags);
    if(rc!=ERROR_SUCCESS) { number("OPEN_FLAGS_ERROR=",(DWORD)rc); finish(3,configs,flags); }
    rc=read_config(configs,config,&cp);
    if(rc!=ERROR_SUCCESS) { number("READ_CONFIG_ERROR=",(DWORD)rc); finish(3,configs,flags); }
    rc=read_flags(flags,&flag,&fp);
    if(rc!=ERROR_SUCCESS) { number("READ_FLAGS_ERROR=",(DWORD)rc); finish(3,configs,flags); }
    number("OLD_CONFIG_PRESENT=",cp); if(cp) { output("OLD_CONFIG=");output(config);output("\r\n"); }
    number("OLD_FLAGS_PRESENT=",fp); if(fp) number("OLD_FLAGS=",flag);
    if(inspect) finish(0,configs,flags);
    if(cp||fp) { output("GUARD_REJECTED: exact application values already exist\r\n"); finish(4,configs,flags); }
    flag=0;
    rc=RegSetValueExA(configs,APP_PATH,0,REG_SZ,(const BYTE *)CONFIG,sizeof(CONFIG));
    if(rc==ERROR_SUCCESS) rc=RegSetValueExA(flags,APP_PATH,0,REG_DWORD,(const BYTE *)&flag,sizeof(flag));
    if(rc==ERROR_SUCCESS) rc=RegFlushKey(configs);
    if(rc==ERROR_SUCCESS) rc=RegFlushKey(flags);
    if(rc==ERROR_SUCCESS) rc=read_config(configs,config,&cp);
    if(rc==ERROR_SUCCESS) rc=read_flags(flags,&flag,&fp);
    if(rc!=ERROR_SUCCESS||!cp||!fp||!same(config,CONFIG)||flag!=0) {
        number("APPLY_ERROR=",(DWORD)(rc==ERROR_SUCCESS?ERROR_INVALID_DATA:rc));
        number("ROLLBACK_ABSENT_VERIFIED=",absent_after_rollback(configs,flags)); finish(5,configs,flags);
    }
    output("APPLIED_CONFIG=WINXP\r\nAPPLIED_FLAGS=0\r\nREADBACK_VERIFIED=1\r\n"); finish(0,configs,flags);
}
