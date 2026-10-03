/* SPDX-License-Identifier: GPL-2.0-only
 * Real Windows 98 SetupX16 display-class caller. Compile with the privately
 * acquired original Win98 INC16 SDK; do not redistribute SDK headers.
 * C:\GPREQ.INI must come from the owned disk preparation operator. This tool
 * reports installation/readback, never GPU activation or cold-boot success.
 */
#include <windows.h>
#include <setupx.h>
#include <stdio.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>
#include <share.h>
#include <sys/stat.h>
#include "sha256.h"
#include "native_gop_gate.h"
#include "gop_live_contract.h"

#define REQUEST "C:\\GPREQ.INI"
typedef RETERR (WINAPI *GetDevices)(LPLPDEVICE_INFO,LPCSTR,HWND,int);
typedef RETERR (WINAPI *DeviceOp)(LPDEVICE_INFO);
typedef RETERR (WINAPI *ClassOp)(DI_FUNCTION,LPDEVICE_INFO);
typedef RETERR (WINAPI *GetPath)(LOGDISKID,LPSTR);
typedef RETERR (WINAPI *SetPath)(LOGDISKID,LPCSTR);
typedef DWORD (WINAPI *RegInit)(void);
typedef DWORD (WINAPI *RegOpen)(HKEY,LPCSTR,HKEY FAR*);
typedef DWORD (WINAPI *RegClose)(HKEY);
typedef DWORD (WINAPI *RegQuery)(HKEY,LPCSTR,DWORD FAR*,DWORD FAR*,LPSTR,DWORD FAR*);
typedef DWORD (WINAPI *RegSave)(HKEY,LPCSTR,LPVOID);
static RegOpen regopen;
static RegClose regclose;
static RegQuery regquery;
static RegSave regsave;
static FILE *logfile;
static char buffer[1024];

static int field(const char *name,char *out,unsigned size)
{
    unsigned n=GetPrivateProfileString("GOP",name,"",out,size,REQUEST);
    return n>0 && n<size-1;
}
static int hash_file(const char *path,const char *expected)
{
    FILE *f; sha256_ctx ctx; unsigned n; unsigned char digest[32];
    char hex[65]; unsigned i;
    if(strlen(expected)!=64) return 0;
    for(i=0;i<64;++i) if(!((expected[i]>='0'&&expected[i]<='9') ||
                           (expected[i]>='a'&&expected[i]<='f'))) return 0;
    f=fopen(path,"rb"); if(!f) return 0;
    sha256_init(&ctx);
    while((n=fread(buffer,1,sizeof buffer,f))!=0) sha256_update(&ctx,buffer,n);
    if(ferror(f)) {fclose(f);return 0;}
    fclose(f); sha256_final(&ctx,digest);sha256_hex(digest,hex);
    return !strcmp(hex,expected);
}
static int query_string(HKEY key,const char *name,char *out,unsigned maximum)
{
    DWORD size=maximum,type=0;
    memset(out,0,maximum);
    if(regquery(key,name,NULL,&type,out,&size)!=0 || type!=REG_SZ ||
       size==0 || size>maximum || out[size-1]!=0) return 0;
    return strlen(out)+1==size;
}
static int absent(const char *path)
{
    OFSTRUCT of; return OpenFile(path,&of,OF_EXIST)==HFILE_ERROR;
}
static int save_key(const char *key,const char *file)
{
    HKEY h; DWORD rc;
    if(!absent(file) || regopen(HKEY_LOCAL_MACHINE,key,&h)!=0) return 0;
    rc=regsave(h,file,NULL);regclose(h);
    if(rc!=0 || absent(file)) return 0;
    fprintf(logfile,"backup=%s:%s\n",key,file);fflush(logfile);return 1;
}
static int driver_class(const char *enumkey,char *classkey,unsigned size)
{
    HKEY h; char value[256]; int okay;
    if(regopen(HKEY_LOCAL_MACHINE,enumkey,&h)!=0) return 0;
    okay=query_string(h,"Driver",value,sizeof value);regclose(h);
    if(!okay || strnicmp(value,"Display\\",8)!=0 || strlen(value)!=12 ||
       value[8]<'0'||value[8]>'9'||value[9]<'0'||value[9]>'9'||
       value[10]<'0'||value[10]>'9'||value[11]<'0'||value[11]>'9') return 0;
    if(size<strlen(value)+strlen("System\\CurrentControlSet\\Services\\Class\\")+1) return 0;
    strcpy(classkey,"System\\CurrentControlSet\\Services\\Class\\");strcat(classkey,value);
    return 1;
}
int PASCAL WinMain(HINSTANCE self,HINSTANCE prev,LPSTR cmd,int show)
{
    HINSTANCE sx=0; GetDevices getdev; DeviceOp build,destroy;
    ClassOp install; GetPath getpath; SetPath setpath; RegInit init;
    LPDEVICE_INFO list=NULL,di,selected=NULL; LPDRIVER_NODE dn,winner=NULL;
    char enumkey[256],devicekey[256],classkey[256],defaultkey[270];
    char expected[4][66],system[256],path[270],oldsource[MAX_PATH_LEN],atomname[256];
    char drv[64],vxd[64]; HKEY h; unsigned i,count; ATOM atom=0,oldatom=0;
    int locks[5]={-1,-1,-1,-1,-1},logfd;
    int code=1,source_changed=0; RETERR installed;
    char provider_hex[66];unsigned char provider[32],snapshot[SHZGOP_PROBE_BYTES];
    const char *names[3]={"SHZGOP.DRV","SHZGOP.VXD","SHZGOP.INF"};
    const char *pins[4]={"DRV_SHA256","VXD_SHA256","INF_SHA256","SETUPX_SHA256"};
    (void)self;(void)prev;(void)show;
    /* Explicit operation is required; RunOnce staging alone is not success. */
    if(strcmp(cmd,"/install")!=0) return 2;
    locks[4]=sopen(REQUEST,O_RDONLY|O_BINARY,SH_DENYWR);
    if(locks[4]<0) return 2;
    if(!field("EnumKey",enumkey,sizeof enumkey) ||
       strnicmp(enumkey,"Enum\\",5)!=0 || strstr(enumkey,"..")) {code=3;goto early;}
    for(i=0;i<4;++i) if(!field(pins[i],expected[i],66)) {code=4;goto early;}
    if(!field("LIVE_PROVIDER_SHA256",provider_hex,sizeof provider_hex) || strlen(provider_hex)!=64) {code=4;goto early;}
    for(i=0;i<32;++i) {
        unsigned a,b;char ca=provider_hex[2*i],cb=provider_hex[2*i+1];
        if(!((ca>='0'&&ca<='9')||(ca>='a'&&ca<='f')) ||
           !((cb>='0'&&cb<='9')||(cb>='a'&&cb<='f'))) {code=4;goto early;}
        a=ca<='9'?ca-'0':ca-'a'+10;b=cb<='9'?cb-'0':cb-'a'+10;
        provider[i]=(unsigned char)(a*16+b);
    }
    for(i=0;i<3;++i) {
        strcpy(path,"C:\\");strcat(path,names[i]);
        locks[i]=sopen(path,O_RDONLY|O_BINARY,SH_DENYWR);
        if(locks[i]<0 || !hash_file(path,expected[i])) {code=5;goto early;}
    }
    count=GetSystemDirectory(system,sizeof system);
    if(count==0 || count>=sizeof system-16) {code=6;goto early;}
    strcpy(path,system);strcat(path,"\\SETUPX.DLL");
    locks[3]=sopen(path,O_RDONLY|O_BINARY,SH_DENYWR);
    if(locks[3]<0 || !hash_file(path,expected[3])) {code=7;goto early;}
    logfd=sopen("C:\\GOPINST.LOG",O_WRONLY|O_CREAT|O_EXCL|O_TEXT,SH_DENYRW,S_IREAD|S_IWRITE);
    if(logfd<0) {code=8;goto early;}
    logfile=fdopen(logfd,"w");
    if(!logfile) {close(logfd);code=9;goto early;}
    fprintf(logfile,"schema=shizukuos.win98-setupx-install.v1\nGPU_active=false\ncold_boot_verified=false\n");
    fflush(logfile);
    sx=LoadLibrary(path);if((UINT)sx<32) {sx=0;goto done;}
#define RESOLVE(var,type,name) var=(type)GetProcAddress(sx,name);if(!var) goto done
    RESOLVE(getdev,GetDevices,"DiGetClassDevs");
    RESOLVE(build,DeviceOp,"DiBuildCompatDrvList");
    RESOLVE(destroy,DeviceOp,"DiDestroyDeviceInfoList");
    RESOLVE(install,ClassOp,"DiCallClassInstaller");
    RESOLVE(getpath,GetPath,"CtlGetLddPath");RESOLVE(setpath,SetPath,"CtlSetLddPath");
    RESOLVE(init,RegInit,"SURegInit");RESOLVE(regopen,RegOpen,"SURegOpenKey");
    RESOLVE(regclose,RegClose,"SURegCloseKey");RESOLVE(regquery,RegQuery,"SURegQueryValueEx");
    RESOLVE(regsave,RegSave,"SURegSaveKey");
    if(init()!=0) goto done;
    if(getdev(&list,"Display",NULL,DIGCF_PRESENT|DIGCF_PROFILE)!=OK) goto cleanup;
    count=0;
    for(di=list;di;di=di->lpNextDi) {
        if(++count>256 || di->cbSize!=sizeof(DEVICE_INFO)) goto cleanup;
        if(!memchr(di->szRegSubkey,0,sizeof di->szRegSubkey) ||
           !memchr(di->szClassName,0,sizeof di->szClassName)) goto cleanup;
        if(di->hRegKey!=HKEY_LOCAL_MACHINE) continue;
        strcpy(devicekey,di->szRegSubkey);
        if(!stricmp(devicekey,enumkey) && !stricmp(di->szClassName,"Display") && di->dnDevnode) {
            if(selected) goto cleanup;selected=di;
        }
    }
    if(!selected || !driver_class(enumkey,classkey,sizeof classkey)) goto cleanup;
    atom=GlobalAddAtom("C:\\SHZGOP.INF");if(!atom) goto cleanup;
    oldatom=selected->atDriverPath;selected->atDriverPath=atom;selected->Flags|=DI_ENUMSINGLEINF;
    if(build(selected)!=OK) goto cleanup;
    count=0;
    for(dn=selected->lpCompatDrvList;dn;dn=dn->lpNextDN) {
        if(++count>256) goto cleanup;
        if(!dn->lpszSectionName || stricmp(dn->lpszSectionName,"Driver.Install") ||
           (dn->Flags&(DNF_OLDDRIVER|DNF_NODRIVER))) continue;
        if(!GlobalGetAtomName(dn->atInfFileName,atomname,sizeof atomname) ||
           (stricmp(atomname,"SHZGOP.INF") && stricmp(atomname,"C:\\SHZGOP.INF"))) continue;
        if(!dn->lpszInfPath || stricmp(dn->lpszInfPath,"C:\\")) continue;
        if(winner) goto cleanup;winner=dn;
    }
    memset(oldsource,0,sizeof oldsource);
    if(!winner || getpath(LDID_SRCPATH,oldsource)!=OK ||
       !memchr(oldsource,0,sizeof oldsource)) goto cleanup;
    if(!shz_gop_current_boot_ready(provider,snapshot,sizeof snapshot)) {
        fprintf(logfile,"native_current_boot_probe=FAIL_INSTALL_REFUSED\n");
        goto cleanup;
    }
    /* Fresh key backups are mandatory BEFORE the class installer mutates state.
       The owner must separately retain the original full disk clone. */
    if(!save_key(enumkey,"C:\\GOPBAK\\ENUM.BAK") ||
       !save_key(classkey,"C:\\GOPBAK\\CLASS.BAK")) goto cleanup;
    for(i=0;i<3;++i) {strcpy(path,"C:\\");strcat(path,names[i]);
        if(!hash_file(path,expected[i])) goto cleanup;}
    if(!shz_gop_current_boot_ready(provider,snapshot,sizeof snapshot)) goto cleanup;
    fprintf(logfile,"native_current_boot_query=PASS\nSupervisor_epoch_verified=false\nprovider_identity_sha256=%s\nsnapshot_hex=",provider_hex);
    for(i=0;i<sizeof snapshot;++i) fprintf(logfile,"%02x",(unsigned)snapshot[i]);
    fprintf(logfile,"\n");
    if(fflush(logfile)!=0 || ferror(logfile)) goto cleanup;
    if(setpath(LDID_SRCPATH,"C:\\")!=OK) goto cleanup;
    source_changed=1;selected->lpSelectedDriver=winner;
    installed=install(DIF_INSTALLDEVICE,selected);
    fprintf(logfile,"class_install_result=%u\nrestart_needed=%u\nreboot_needed=%u\n",
            installed,!!(selected->Flags&DI_NEEDRESTART),!!(selected->Flags&DI_NEEDREBOOT));
    if(installed!=OK || !driver_class(enumkey,classkey,sizeof classkey)) goto cleanup;
    strcpy(defaultkey,classkey);strcat(defaultkey,"\\DEFAULT");
    if(regopen(HKEY_LOCAL_MACHINE,defaultkey,&h)!=0) goto cleanup;
    i=query_string(h,"drv",drv,sizeof drv)&&query_string(h,"minivdd",vxd,sizeof vxd);
    regclose(h);if(!i || stricmp(drv,"SHZGOP.DRV") || stricmp(vxd,"SHZGOP.VXD")) goto cleanup;
    for(i=0;i<2;++i) {strcpy(path,system);strcat(path,"\\");strcat(path,names[i]);
        if(!hash_file(path,expected[i])) goto cleanup;}
    code=0;
cleanup:
    if(source_changed && setpath(LDID_SRCPATH,oldsource)!=OK) code=1;
    if(selected && atom) selected->atDriverPath=oldatom;
    if(list && destroy(list)!=OK) code=1;
    if(atom) GlobalDeleteAtom(atom);
done:
    fprintf(logfile,"registration_and_file_readback=%s\nGPU_active=false\ncold_boot_verified=false\n",
            code==0?"PASS":"FAIL");
    if(fflush(logfile)!=0 || ferror(logfile)) code=1;
    if(fclose(logfile)!=0) code=1;
    if(sx) FreeLibrary(sx);
early:
    for(i=0;i<5;++i) if(locks[i]>=0) close(locks[i]);
    return code;
}
