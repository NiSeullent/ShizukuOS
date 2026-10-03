/* SPDX-License-Identifier: GPL-2.0-only
 * Exercise the production native backend + real transaction through modeled
 * Win32 boundaries. No host registry, colors, executable launch or VM. */
#include "native_backend.h"
#include <stdio.h>
#include <string.h>

static unsigned checks,failures;
#define CHECK(x) do { ++checks;if(!(x)){++failures;fprintf(stderr,"FAIL %u: %s\n",(unsigned)__LINE__,#x);} } while(0)
static struct fixture {
    shz_theme_value values[2];uint32_t colors[SHZ_THEME_COLORS];
    unsigned version_ok,platform,major,minor,mutex_ok,locked;
    unsigned waits,releases,closes,reads,writes,sets,flushes,path_calls,mutex_calls;
    unsigned read_denied,query_race,oversized,close_error,release_error,write_run_error,flush_error;
    DWORD wait,error,path_length,last_timeout;
    const char *path;
} f;
static void reset(void)
{
    unsigned i;memset(&f,0,sizeof f);f.version_ok=f.mutex_ok=1;
    f.platform=1;f.major=4;f.minor=10;f.error=ERROR_ACCESS_DENIED;
    f.path="C:\\Shizuku Settings\\SHZPERS.EXE";
    for(i=0;i<SHZ_THEME_COLORS;++i)f.colors[i]=i*0x010101u;
}
DWORD GetLastError(void){return f.error;}
BOOL GetVersionExA(OSVERSIONINFOA *out)
{
    CHECK(out->dwOSVersionInfoSize==sizeof(*out));
    if(!f.version_ok)return 0;
    out->dwPlatformId=f.platform;out->dwMajorVersion=f.major;out->dwMinorVersion=f.minor;return 1;
}
DWORD GetModuleFileNameA(HANDLE module,char *out,DWORD size)
{
    size_t n=strlen(f.path);++f.path_calls;CHECK(!module && size==MAX_PATH);
    if(n>=size){memcpy(out,f.path,size);return size;}
    memcpy(out,f.path,n+1);return f.path_length?f.path_length:(DWORD)n;
}
HANDLE CreateMutexA(void *attributes,BOOL owner,const char *name)
{
    ++f.mutex_calls;CHECK(!attributes && !owner && !strcmp(name,"ShizukuOS.Win98.ThemeSelector.v1"));
    return f.mutex_ok?(HANDLE)(uintptr_t)3:NULL;
}
DWORD WaitForSingleObject(HANDLE handle,DWORD timeout)
{
    ++f.waits;f.last_timeout=timeout;CHECK(handle==(HANDLE)(uintptr_t)3 && (timeout==0 || timeout==5000));
    if(f.wait==WAIT_OBJECT_0 || f.wait==WAIT_ABANDONED){CHECK(!f.locked);f.locked=1;}
    return f.wait;
}
BOOL ReleaseMutex(HANDLE handle)
{
    ++f.releases;CHECK(handle==(HANDLE)(uintptr_t)3 && f.locked);
    if(f.release_error)return 0;
    f.locked=0;return 1;
}
BOOL CloseHandle(HANDLE handle)
{++f.closes;CHECK(handle==(HANDLE)(uintptr_t)3);f.locked=0;return 1;}
DWORD GetSysColor(int index)
{CHECK(f.locked && index>=0 && index<25);return f.colors[index];}
BOOL SetSysColors(int count,const int *indices,const COLORREF *colors)
{
    int i;++f.sets;CHECK(f.locked && count==25);
    for(i=0;i<count;++i){CHECK(indices[i]==i);f.colors[i]=colors[i];}return 1;
}
static unsigned target(HKEY key,const char *name)
{
    unsigned n=(unsigned)(uintptr_t)key-10u;
    CHECK(f.locked && n<2);CHECK(!strcmp(name,n?"ShizukuOSTheme":"Profile"));return n;
}
static unsigned key_target(HKEY root,const char *path,DWORD reserved,DWORD access)
{
    CHECK(f.locked && root==HKEY_CURRENT_USER && reserved==0);
    CHECK(access==KEY_QUERY_VALUE || access==KEY_SET_VALUE);
    if(!strcmp(path,"Software\\ShizukuOS\\Theme"))return 0;
    CHECK(!strcmp(path,"Software\\Microsoft\\Windows\\CurrentVersion\\Run"));return 1;
}
LONG RegOpenKeyExA(HKEY root,const char *path,DWORD reserved,DWORD access,HKEY *out)
{
    unsigned n=key_target(root,path,reserved,access);
    if(f.read_denied)return ERROR_ACCESS_DENIED;
    *out=(HKEY)(uintptr_t)(10u+n);return ERROR_SUCCESS;
}
LONG RegCreateKeyExA(HKEY root,const char *path,DWORD reserved,char *class_name,
                    DWORD options,DWORD access,void *security,HKEY *out,DWORD *disposition)
{
    unsigned n=key_target(root,path,reserved,access);
    CHECK(!class_name && !security && options==REG_OPTION_NON_VOLATILE);
    *out=(HKEY)(uintptr_t)(10u+n);*disposition=1;return ERROR_SUCCESS;
}
LONG RegQueryValueExA(HKEY key,const char *name,DWORD *reserved,DWORD *type,unsigned char *data,DWORD *bytes)
{
    shz_theme_value *v=&f.values[target(key,name)];++f.reads;CHECK(!reserved);
    if(!v->present)return ERROR_FILE_NOT_FOUND;
    if(!data){*type=v->type;*bytes=f.oversized?SHZ_THEME_VALUE_BYTES+1u:v->bytes;return ERROR_SUCCESS;}
    CHECK(*bytes>=v->bytes);memcpy(data,v->data,v->bytes);*bytes=v->bytes;*type=v->type;
    if(f.query_race){f.query_race=0;*type^=1u;}return ERROR_SUCCESS;
}
LONG RegSetValueExA(HKEY key,const char *name,DWORD reserved,DWORD type,const unsigned char *data,DWORD bytes)
{
    unsigned n=target(key,name);shz_theme_value *v=&f.values[n];++f.writes;
    CHECK(!reserved && bytes<=SHZ_THEME_VALUE_BYTES);memset(v,0,sizeof(*v));
    v->present=1;v->type=type;v->bytes=bytes;memcpy(v->data,data,bytes);
    if(n && f.write_run_error){f.write_run_error=0;return ERROR_ACCESS_DENIED;}
    return ERROR_SUCCESS;
}
LONG RegDeleteValueA(HKEY key,const char *name)
{++f.writes;memset(&f.values[target(key,name)],0,sizeof(shz_theme_value));return ERROR_SUCCESS;}
LONG RegFlushKey(HKEY key)
{
    ++f.flushes;CHECK(f.locked && ((uintptr_t)key==10 || (uintptr_t)key==11));
    if(f.flush_error){f.flush_error=0;return ERROR_ACCESS_DENIED;}return ERROR_SUCCESS;
}
LONG RegCloseKey(HKEY key)
{
    CHECK(f.locked && ((uintptr_t)key==10 || (uintptr_t)key==11));
    if(f.close_error){f.close_error=0;return ERROR_ACCESS_DENIED;}return ERROR_SUCCESS;
}
static void profile(uint32_t style)
{
    shz_theme_profile p;CHECK(shz_theme_make(style,f.colors,&p));
    f.values[0].present=1;f.values[0].type=SHZ_THEME_REG_BINARY;f.values[0].bytes=SHZ_THEME_PROFILE_BYTES;
    CHECK(shz_theme_encode(&p,f.values[0].data));
}
static void platform_and_path_admission(void)
{
    shz_theme_native n;uint32_t error;
    reset();f.version_ok=0;CHECK(!shz_theme_native_open(&n,&error) && error==5);
    CHECK(!f.path_calls && !f.mutex_calls && !f.reads && !f.sets);
    reset();f.platform=2;CHECK(!shz_theme_native_open(&n,&error) && error==50);
    reset();f.minor=0;CHECK(!shz_theme_native_open(&n,&error) && error==50);
    reset();f.major=5;CHECK(!shz_theme_native_open(&n,&error) && error==50);
    reset();f.path="\\\\server\\share\\settings.exe";CHECK(!shz_theme_native_open(&n,&error) && error==13);
    CHECK(!f.mutex_calls && !f.reads && !f.sets);
    reset();f.path="C:\\unsafe\"name.exe";CHECK(!shz_theme_native_open(&n,&error) && error==13);
    reset();f.path_length=MAX_PATH;CHECK(!shz_theme_native_open(&n,&error) && error==13);
    reset();f.mutex_ok=0;CHECK(!shz_theme_native_open(&n,&error) && error==5);
    reset();CHECK(shz_theme_native_open(&n,&error) && !error);
    CHECK(!strcmp((char *)n.startup.data,"\"C:\\Shizuku Settings\\SHZPERS.EXE\" /restore"));
    CHECK(!f.reads && !f.writes && !f.sets && !f.waits);
    CHECK(shz_theme_native_close(&n) && !n.mutex && f.closes==1);
}
static void baseline_and_transactions(void)
{
    shz_theme_native n,second;shz_theme_result r;shz_theme_snapshot s;shz_theme_profile p;
    uint32_t error,original[SHZ_THEME_COLORS];shz_theme_value run;unsigned sets,writes;
    reset();memcpy(original,f.colors,sizeof original);CHECK(shz_theme_native_open(&n,&error));
    CHECK(!shz_theme_native_apply(&n,1,&r) && !f.sets && !f.writes);
    CHECK(shz_theme_native_snapshot(&n,&s,&r) && !s.saved && s.current==SHZ_THEME_CURRENT_CLASSIC);
    CHECK(f.last_timeout==0);
    CHECK(!f.sets && !f.writes && !f.locked);
    CHECK(shz_theme_native_apply(&n,SHZ_THEME_SHIZUKUOS,&r));
    CHECK(f.last_timeout==0);
    CHECK(shz_theme_decode(f.values[0].data,f.values[0].bytes,&p));
    CHECK(!memcmp(p.baseline,original,sizeof original) && p.style==1);
    CHECK(!memcmp(&f.values[1],&n.startup,sizeof n.startup));
    CHECK(shz_theme_native_open(&second,&error));
    CHECK(shz_theme_native_snapshot(&second,&s,&r) && s.saved && s.saved_style==1 && s.current==SHZ_THEME_CURRENT_SHIZUKUOS);
    CHECK(!memcmp(second.baseline,original,sizeof original));
    CHECK(shz_theme_native_apply(&second,SHZ_THEME_CLASSIC,&r));
    CHECK(!memcmp(f.colors,original,sizeof original));
    sets=f.sets;writes=f.writes;run=f.values[1];f.colors[4]^=0x1234;
    CHECK(shz_theme_native_restore(&n,&r) && f.sets==sets+1 && f.writes==writes);
    CHECK(f.last_timeout==5000);
    CHECK(!memcmp(f.colors,original,sizeof original) && !memcmp(&run,&f.values[1],sizeof run));
    CHECK(shz_theme_native_close(&n) && shz_theme_native_close(&second));

    reset();memcpy(original,f.colors,sizeof original);CHECK(shz_theme_native_open(&n,&error));
    CHECK(shz_theme_native_snapshot(&n,&s,&r));f.write_run_error=1;
    CHECK(!shz_theme_native_apply(&n,1,&r) && r.rollback_attempted && !r.rollback_failed);
    CHECK(!f.values[0].present && !f.values[1].present && !memcmp(f.colors,original,sizeof original));
    CHECK(!f.locked);CHECK(shz_theme_native_close(&n));
    reset();memcpy(original,f.colors,sizeof original);CHECK(shz_theme_native_open(&n,&error));
    CHECK(shz_theme_native_snapshot(&n,&s,&r));f.flush_error=1;
    CHECK(!shz_theme_native_apply(&n,1,&r) && r.rollback_attempted && !r.rollback_failed);
    CHECK(!f.values[0].present && !memcmp(f.colors,original,sizeof original));
    CHECK(shz_theme_native_close(&n));
}
static void corrupt_and_unavailable_state(void)
{
    unsigned mode;shz_theme_native n;shz_theme_result r;shz_theme_snapshot s;uint32_t error;
    for(mode=0;mode<6;++mode){
        reset();profile(0);CHECK(shz_theme_native_open(&n,&error));
        if(mode==0)f.values[0].data[0]^=1;
        if(mode==1)f.values[0].type=1;
        if(mode==2)f.read_denied=1;
        if(mode==3)f.query_race=1;
        if(mode==4)f.oversized=1;
        if(mode==5)f.close_error=1;
        CHECK(!shz_theme_native_snapshot(&n,&s,&r));
        CHECK(!n.baseline_captured && !f.writes && !f.sets && !f.locked);
        CHECK(shz_theme_native_close(&n));
    }
    reset();CHECK(shz_theme_native_open(&n,&error));
    CHECK(!shz_theme_native_restore(&n,&r) && !f.sets && !f.writes);
    CHECK(shz_theme_native_close(&n));
    reset();profile(0);CHECK(shz_theme_native_open(&n,&error));
    f.colors[1]=0xff000000u;CHECK(!shz_theme_native_snapshot(&n,&s,&r));
    CHECK(!n.baseline_captured && !f.writes && !f.sets);CHECK(shz_theme_native_close(&n));
    reset();profile(0);CHECK(shz_theme_native_open(&n,&error));
    CHECK(shz_theme_native_snapshot(&n,&s,&r));f.values[0].data[0]^=1;
    CHECK(!shz_theme_native_apply(&n,1,&r) && !f.sets && !f.writes);
    CHECK(shz_theme_native_close(&n));
}
static void locking_failures(void)
{
    shz_theme_native n;shz_theme_result r;shz_theme_snapshot s;uint32_t error;unsigned waits;
    reset();CHECK(shz_theme_native_open(&n,&error));f.wait=WAIT_TIMEOUT;
    CHECK(!shz_theme_native_snapshot(&n,&s,&r) && r.error==ERROR_TIMEOUT);
    CHECK(f.last_timeout==0);
    CHECK(!f.reads && !f.writes && !f.sets && !f.releases);CHECK(shz_theme_native_close(&n));
    reset();CHECK(shz_theme_native_open(&n,&error));f.wait=WAIT_FAILED;
    CHECK(!shz_theme_native_restore(&n,&r) && r.error==5 && !f.reads && f.last_timeout==5000);CHECK(shz_theme_native_close(&n));
    reset();CHECK(shz_theme_native_open(&n,&error));f.wait=WAIT_ABANDONED;
    CHECK(!shz_theme_native_snapshot(&n,&s,&r) && r.error==13 && f.releases==1 && n.poisoned);
    waits=f.waits;f.wait=WAIT_OBJECT_0;
    CHECK(!shz_theme_native_restore(&n,&r) && f.waits==waits && !f.sets && !f.writes);
    CHECK(shz_theme_native_close(&n));
    reset();CHECK(shz_theme_native_open(&n,&error));CHECK(shz_theme_native_snapshot(&n,&s,&r));
    f.release_error=1;CHECK(!shz_theme_native_apply(&n,1,&r));
    CHECK(n.poisoned && r.status==SHZ_THEME_FAILED && r.colors_attempted && r.profile_attempted && r.run_attempted);
    CHECK(f.sets==1 && f.values[0].present && f.values[1].present);
    waits=f.waits;CHECK(!shz_theme_native_apply(&n,0,&r) && f.waits==waits);
    CHECK(shz_theme_native_close(&n));
}
int main(void)
{
    platform_and_path_admission();baseline_and_transactions();corrupt_and_unavailable_state();locking_failures();
    if(failures)return 1;
    printf("PASS: %u production Win98 theme backend boundary checks (host model only)\n",checks);return 0;
}
