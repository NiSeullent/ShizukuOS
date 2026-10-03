/* SPDX-License-Identifier: GPL-2.0-only */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_IE 0x0400
#include <windows.h>
#include <shlobj.h>
#include <string.h>
#include "profile.h"

static int append(char *out,const char *base,const char *leaf,size_t reserve)
{
    size_t a=0,b=0;
    while(a<MAX_PATH && base[a])++a;
    while(b<MAX_PATH && leaf[b])++b;
    if(a+b+2+reserve>MAX_PATH){SetLastError(ERROR_BUFFER_OVERFLOW);return 0;}
    memcpy(out,base,a);out[a]='\\';memcpy(out+a+1,leaf,b+1);return 1;
}
int pz98_profile_paths(pz98_paths *out)
{
    char base[MAX_PATH]={0},directory[MAX_PATH];pz98_paths candidate={0};
    char drive[4];size_t length=0;DWORD attributes,type;
    if(!out){SetLastError(ERROR_INVALID_PARAMETER);return 0;}
    /* CSIDL_APPDATA follows the Windows shell's current profile. An inherited
     * environment variable or an executable location cannot select an account. */
    if(!SHGetSpecialFolderPathA(NULL,base,CSIDL_APPDATA,TRUE)){
        SetLastError(ERROR_PATH_NOT_FOUND);return 0;
    }
    while(length<MAX_PATH && base[length])++length;
    if(length==MAX_PATH){SetLastError(ERROR_BUFFER_OVERFLOW);return 0;}
    /* Local drive paths only: the verified wallpaper/store contract is local.
     * Do not route settings into an unexpected network share. */
    if(length<3 || !((base[0]>='A' && base[0]<='Z') || (base[0]>='a' && base[0]<='z')) ||
       base[1]!=':' || base[2]!='\\'){
        SetLastError(ERROR_INVALID_DATA);return 0;
    }
    drive[0]=base[0];drive[1]=':';drive[2]='\\';drive[3]=0;
    type=GetDriveTypeA(drive);
    if(type!=DRIVE_FIXED && type!=DRIVE_REMOVABLE && type!=DRIVE_RAMDISK){
        SetLastError(ERROR_NOT_SUPPORTED);return 0;
    }
    /* store.c adds .lck, .tmp and .bak. Reserve their four bytes before making
     * the directory, so successful initialization can use the store protocol. */
    if(!append(directory,base,"Shizuku-Personalization",0) ||
       !append(candidate.preferences,directory,"preferences.pz",4) ||
       !append(candidate.bitmap,directory,"wallpaper.bmp",4) ||
       !append(candidate.html,directory,"wallpaper.htm",4))return 0;
    if(!CreateDirectoryA(directory,NULL) && GetLastError()!=ERROR_ALREADY_EXISTS)return 0;
    attributes=GetFileAttributesA(directory);
    if(attributes==INVALID_FILE_ATTRIBUTES)return 0;
    if(!(attributes&FILE_ATTRIBUTE_DIRECTORY)){
        SetLastError(ERROR_INVALID_DATA);return 0;
    }
    *out=candidate;return 1;
}
