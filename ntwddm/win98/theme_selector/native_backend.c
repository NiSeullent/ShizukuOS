/* SPDX-License-Identifier: GPL-2.0-only
 * Shared actual Windows 98 palette/profile boundary. Both native settings
 * executables use this backend and the same checked transaction and mutex.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400
#include "native_backend.h"

static const char profile_key[]="Software\\ShizukuOS\\Theme";
static const char run_key[]="Software\\Microsoft\\Windows\\CurrentVersion\\Run";
static const char profile_name[]="Profile";
static const char run_name[]="ShizukuOSTheme";
static const char mutex_name[]="ShizukuOS.Win98.ThemeSelector.v1";
static void clear(void *memory,SIZE_T size)
{ unsigned char *p=memory;SIZE_T i;for(i=0;i<size;++i)p[i]=0; }
static int same_colors(const uint32_t *a,const uint32_t *b)
{ unsigned i;for(i=0;i<SHZ_THEME_COLORS;++i)if(a[i]!=b[i])return 0;return 1; }
static int key_names(unsigned target,const char **key,const char **name,uint32_t *error)
{
    if(target>SHZ_THEME_RUN_VALUE){*error=ERROR_INVALID_PARAMETER;return 0;}
    *key=target==SHZ_THEME_PROFILE_VALUE?profile_key:run_key;
    *name=target==SHZ_THEME_PROFILE_VALUE?profile_name:run_name;return 1;
}
static int close_key(HKEY key,LONG result,uint32_t *error)
{
    LONG closed=RegCloseKey(key);
    if(result==ERROR_SUCCESS)result=closed;
    if(result!=ERROR_SUCCESS){*error=(uint32_t)result;return 0;}return 1;
}
static int read_registry(void *context,unsigned target,shz_theme_value *out,uint32_t *error)
{
    HKEY key;const char *path,*name;LONG result;DWORD type=0,bytes=0,read_type,read_bytes;
    (void)context;clear(out,sizeof(*out));
    if(!key_names(target,&path,&name,error))return 0;
    result=RegOpenKeyExA(HKEY_CURRENT_USER,path,0,KEY_QUERY_VALUE,&key);
    if(result==ERROR_FILE_NOT_FOUND || result==ERROR_PATH_NOT_FOUND)return 1;
    if(result!=ERROR_SUCCESS){*error=(uint32_t)result;return 0;}
    result=RegQueryValueExA(key,name,NULL,&type,NULL,&bytes);
    if(result==ERROR_FILE_NOT_FOUND)return close_key(key,ERROR_SUCCESS,error);
    if(result!=ERROR_SUCCESS)return close_key(key,result,error);
    if(bytes>SHZ_THEME_VALUE_BYTES)return close_key(key,ERROR_MORE_DATA,error);
    read_type=type;read_bytes=bytes;
    result=RegQueryValueExA(key,name,NULL,&read_type,out->data,&read_bytes);
    if(result==ERROR_SUCCESS && (read_type!=type || read_bytes!=bytes))result=ERROR_INVALID_DATA;
    if(result==ERROR_SUCCESS){out->present=1;out->type=type;out->bytes=bytes;}
    return close_key(key,result,error);
}
static int write_registry(void *context,unsigned target,const shz_theme_value *value,uint32_t *error)
{
    HKEY key;const char *path,*name;LONG result;DWORD disposition;
    (void)context;
    if(!key_names(target,&path,&name,error))return 0;
    if(value->bytes>SHZ_THEME_VALUE_BYTES || value->present>1){*error=ERROR_INVALID_PARAMETER;return 0;}
    if(value->present){
        result=RegCreateKeyExA(HKEY_CURRENT_USER,path,0,NULL,REG_OPTION_NON_VOLATILE,KEY_SET_VALUE,NULL,&key,&disposition);
        if(result!=ERROR_SUCCESS){*error=(uint32_t)result;return 0;}
        result=RegSetValueExA(key,name,0,value->type,value->data,value->bytes);
    }else{
        result=RegOpenKeyExA(HKEY_CURRENT_USER,path,0,KEY_SET_VALUE,&key);
        if(result==ERROR_FILE_NOT_FOUND || result==ERROR_PATH_NOT_FOUND)return 1;
        if(result!=ERROR_SUCCESS){*error=(uint32_t)result;return 0;}
        result=RegDeleteValueA(key,name);
        if(result==ERROR_FILE_NOT_FOUND)result=ERROR_SUCCESS;
    }
    return close_key(key,result,error);
}
static int flush_registry(void *context,unsigned target,uint32_t *error)
{
    HKEY key;const char *path,*name;LONG result;(void)context;
    if(!key_names(target,&path,&name,error))return 0;
    (void)name;
    result=RegOpenKeyExA(HKEY_CURRENT_USER,path,0,KEY_QUERY_VALUE,&key);
    if(result==ERROR_FILE_NOT_FOUND || result==ERROR_PATH_NOT_FOUND)return 1;
    if(result!=ERROR_SUCCESS){*error=(uint32_t)result;return 0;}
    return close_key(key,RegFlushKey(key),error);
}
static int get_system_colors(void *context,uint32_t *colors,uint32_t *error)
{
    unsigned i;(void)context;
    for(i=0;i<SHZ_THEME_COLORS;++i){colors[i]=(uint32_t)GetSysColor((int)i);
        if(colors[i]&0xff000000u){*error=ERROR_INVALID_DATA;return 0;}}
    return 1;
}
static int set_system_colors(void *context,const uint32_t *colors,uint32_t *error)
{
    int indices[SHZ_THEME_COLORS];COLORREF values[SHZ_THEME_COLORS];unsigned i;
    (void)context;
    for(i=0;i<SHZ_THEME_COLORS;++i){indices[i]=(int)i;values[i]=(COLORREF)colors[i];}
    if(!SetSysColors(SHZ_THEME_COLORS,indices,values)){*error=GetLastError();return 0;}return 1;
}
static const shz_theme_ops operations={NULL,get_system_colors,set_system_colors,read_registry,write_registry,flush_registry};

static int refused(shz_theme_result *out,enum shz_theme_phase phase,uint32_t error)
{
    clear(out,sizeof(*out));out->status=SHZ_THEME_FAILED;out->phase=phase;
    out->error=error?error:ERROR_GEN_FAILURE;return 0;
}
static int acquire(shz_theme_native *native,DWORD timeout,shz_theme_result *result)
{
    DWORD wait;
    if(!native || !native->mutex || native->poisoned)
        return refused(result,SHZ_THEME_PHASE_ARGUMENT,ERROR_INVALID_HANDLE);
    /* UI callers must not block while a peer holding this mutex broadcasts
     * SetSysColors synchronously to their windows. Windowless startup restore
     * may wait; UI snapshots and selections fail promptly if another owner runs. */
    wait=WaitForSingleObject(native->mutex,timeout);
    if(wait==WAIT_OBJECT_0)return 1;
    if(wait==WAIT_ABANDONED){
        /* An interrupted transaction has no durable completion marker. Refuse
         * it for this instance rather than declaring the old state valid. */
        native->poisoned=1;ReleaseMutex(native->mutex);
        return refused(result,SHZ_THEME_PHASE_PROFILE_SNAPSHOT,ERROR_INVALID_DATA);
    }
    return refused(result,SHZ_THEME_PHASE_PROFILE_SNAPSHOT,
                   wait==WAIT_TIMEOUT?ERROR_TIMEOUT:GetLastError());
}
static int release(shz_theme_native *native,int success,shz_theme_result *result)
{
    if(!ReleaseMutex(native->mutex)){
        native->poisoned=1;
        if(success){
            /* Preserve the transaction's mutation flags. The state may already
             * have been applied; do not call this a pre-write refusal. */
            result->status=SHZ_THEME_FAILED;result->phase=SHZ_THEME_PHASE_NONE;
            result->error=GetLastError();if(!result->error)result->error=ERROR_GEN_FAILURE;
        }
        return 0;
    }
    return success;
}
int shz_theme_native_open(shz_theme_native *native,uint32_t *error)
{
    OSVERSIONINFOA version;char module[MAX_PATH];DWORD length;
    if(!native || !error)return 0;
    clear(native,sizeof(*native));clear(&version,sizeof(version));
    version.dwOSVersionInfoSize=sizeof(version);
    if(!GetVersionExA(&version)){*error=GetLastError();return 0;}
    if(version.dwPlatformId!=VER_PLATFORM_WIN32_WINDOWS ||
       version.dwMajorVersion!=4 || version.dwMinorVersion!=10){*error=ERROR_NOT_SUPPORTED;return 0;}
    length=GetModuleFileNameA(NULL,module,MAX_PATH);
    if(!length || length>=MAX_PATH || module[length] ||
       !shz_theme_startup_value(module,length,&native->startup)){
        *error=ERROR_INVALID_DATA;return 0;
    }
    native->mutex=CreateMutexA(NULL,FALSE,mutex_name);
    if(!native->mutex){*error=GetLastError();return 0;}
    *error=0;return 1;
}
int shz_theme_native_close(shz_theme_native *native)
{
    if(!native || !native->mutex)return 1;
    if(!CloseHandle(native->mutex))return 0;
    clear(native,sizeof(*native));return 1;
}
int shz_theme_native_snapshot(shz_theme_native *native,shz_theme_snapshot *snapshot,shz_theme_result *result)
{
    shz_theme_value value;shz_theme_profile profile,modern;
    uint32_t colors[SHZ_THEME_COLORS],error=0;unsigned i;int success=0;
    if(!snapshot || !result)return 0;
    clear(snapshot,sizeof(*snapshot));clear(result,sizeof(*result));
    if(!acquire(native,0,result))return 0;
    if(!read_registry(NULL,SHZ_THEME_PROFILE_VALUE,&value,&error))
        refused(result,SHZ_THEME_PHASE_PROFILE_SNAPSHOT,error);
    else if(value.present && (value.type!=SHZ_THEME_REG_BINARY || !shz_theme_decode(value.data,value.bytes,&profile)))
        refused(result,SHZ_THEME_PHASE_PROFILE_INVALID,ERROR_INVALID_DATA);
    else if(!get_system_colors(NULL,colors,&error))
        refused(result,SHZ_THEME_PHASE_COLORS_SNAPSHOT,error);
    else {
        if(value.present){
            for(i=0;i<SHZ_THEME_COLORS;++i)native->baseline[i]=profile.baseline[i];
            native->baseline_captured=1;
        }else if(!native->baseline_captured){
            for(i=0;i<SHZ_THEME_COLORS;++i)native->baseline[i]=colors[i];
            native->baseline_captured=1;
        }
        snapshot->saved=value.present;snapshot->saved_style=value.present?profile.style:SHZ_THEME_CLASSIC;
        if(same_colors(colors,native->baseline))snapshot->current=SHZ_THEME_CURRENT_CLASSIC;
        else if(shz_theme_make(SHZ_THEME_SHIZUKUOS,native->baseline,&modern) && same_colors(colors,modern.selected))
            snapshot->current=SHZ_THEME_CURRENT_SHIZUKUOS;
        else snapshot->current=SHZ_THEME_CURRENT_CUSTOM;
        result->status=SHZ_THEME_OK;success=1;
    }
    return release(native,success,result);
}
int shz_theme_native_apply(shz_theme_native *native,uint32_t style,shz_theme_result *result)
{
    int success;
    if(!result)return 0;
    if(!native || !native->baseline_captured)return refused(result,SHZ_THEME_PHASE_ARGUMENT,ERROR_INVALID_DATA);
    if(!acquire(native,0,result))return 0;
    success=shz_theme_apply(&operations,native->baseline,style,&native->startup,result);
    return release(native,success,result);
}
int shz_theme_native_restore(shz_theme_native *native,shz_theme_result *result)
{
    int success;
    if(!result)return 0;
    if(!acquire(native,5000,result))return 0;
    success=shz_theme_restore(&operations,result);
    return release(native,success,result);
}
