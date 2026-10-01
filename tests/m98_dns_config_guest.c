/* SPDX-License-Identifier: GPL-2.0-only
 * Native GUI-subsystem probe; writes a CREATE_NEW DOS8.3 log, no networking.
 * An external observer must retain the full child exit and input hashes.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "m98_dns_config.h"
typedef DWORD (WINAPI *query_fn)(uint32_t,DWORD,const WCHAR *,void *,void *,DWORD *);
typedef DWORD (WINAPI *network_fn)(void *,ULONG *);
static HANDLE log_file=INVALID_HANDLE_VALUE;static unsigned checks;
static void text(const char *s){DWORD n=0,w=0;while(s[n])++n;
    if(log_file==INVALID_HANDLE_VALUE||!WriteFile(log_file,s,n,&w,NULL)||w!=n)ExitProcess(2);
}
static void number(DWORD n){char s[11];unsigned i=10;s[i]=0;do{s[--i]=(char)('0'+n%10);n/=10;}while(n);text(s+i);}
static void hex_string(const char *s){const char digits[]="0123456789abcdef";char byte[3];DWORD i;
    byte[2]=0;for(i=0;s[i];++i){BYTE c=(BYTE)s[i];byte[0]=digits[c>>4];byte[1]=digits[c&15];text(byte);}}
static void die(const char *s){text("FAIL: ");text(s);text("\r\n");CloseHandle(log_file);ExitProcess(1);}
#define C(c,s) do{++checks;if(!(c))die(s);}while(0)
static DWORD len(const char *s,DWORD cap){DWORD i;for(i=0;i<cap;++i)if(!s[i])return i;return cap;}
static int same(const void *a,const void *b,DWORD n){const BYTE *x=a,*y=b;DWORD i;for(i=0;i<n;++i)if(x[i]!=y[i])return 0;return 1;}
static char lower(char c){return c>='A'&&c<='Z'?(char)(c+32):c;}
static int same_path(const char *a,const char *b){DWORD i=0;while(a[i]&&b[i]&&lower(a[i])==lower(b[i]))++i;return !a[i]&&!b[i];}
static DWORD rd(const BYTE *b){return b[0]|((DWORD)b[1]<<8)|((DWORD)b[2]<<16)|((DWORD)b[3]<<24);}
static uint32_t decode(void *unused,const char *a,uint32_t n,uint16_t *w,uint32_t cap){
    int count;(void)unused;if(!n){w[0]=0;return 0;}
    count=MultiByteToWideChar(CP_ACP,0,a,n,(WCHAR *)w,cap-1);if(count<=0)return 13;w[count]=0;return 0;
}
static const char *nonce(void){const char *p=GetCommandLineA(),*start;DWORD n;
    while(*p==' ')++p;
    if(*p=='"'){++p;while(*p&&*p!='"')++p;if(*p)++p;}
    else while(*p&&*p!=' ')++p;
    while(*p==' ')++p;
    start=p;
    for(n=0;p[n];++n){char c=p[n];if(n==48||!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'))return NULL;}
    return n?start:NULL;
}
/* Independent expected string bytes from the directly captured provider,
 * using native ACP conversion and a separate codepoint-width UTF8 encoder. */
static DWORD expected_string(const void *fixed,DWORD config,BYTE *out){
    const char *host=fixed,*domain=host+132,*source;char a[264];WCHAR w[264];
    DWORD h=len(host,132),d=len(domain,132),i,n,kind;int count;
    BOOL full=config>=15,is_domain=config<=2;
    C(h<132&&d<132,"independent direct string bounds");
    source=is_domain?domain:host;n=is_domain?d:h;
    if(!is_domain&&!full)for(n=0;n<h&&host[n]!='.';++n){}
    for(i=0;i<n;++i)a[i]=source[i];
    for(i=0;i<h&&host[i]!='.';++i){}
    if(full&&h&&d&&i==h){a[n++]='.';for(i=0;i<d;++i)a[n++]=domain[i];}a[n]=0;
    kind=config<=2?config:full?config-15:config-12;
    if(kind==1){for(i=0;i<=n;++i)out[i]=(BYTE)a[i];return n+1;}
    count=MultiByteToWideChar(CP_ACP,0,a,-1,w,264);C(count>0,"independent native UTF16 conversion");
    if(kind==0){for(i=0;i<(DWORD)count;++i){out[2*i]=(BYTE)w[i];out[2*i+1]=(BYTE)(w[i]>>8);}return 2*(DWORD)count;}
    n=0;
    for(i=0;i+1<(DWORD)count;++i){DWORD value=w[i],width,j;BYTE encoded[4];
        if(value>=0xd800&&value<=0xdbff){C(i+2<(DWORD)count&&w[i+1]>=0xdc00&&w[i+1]<=0xdfff,"independent surrogate pair");value=(value-0xd800)*1024+(w[++i]-0xdc00)+65536;}
        else C(value<0xdc00||value>0xdfff,"independent scalar validation");
        width=value<128?1:value<2048?2:value<65536?3:4;
        for(j=width;j>1;--j){encoded[j-1]=(BYTE)(128+value%64);value/=64;}
        encoded[0]=(BYTE)(value+(width==1?0:width==2?192:width==3?224:240));
        for(j=0;j<width;++j)out[n++]=encoded[j];
    }out[n++]=0;return n;
}
void mainCRTStartup(void){
    const char *trial=nonce();OSVERSIONINFOA os={sizeof(os),0,0,0,0,{0}};
    HMODULE dll,ip;query_fn query;network_fn network;char path[MAX_PATH],module[MAX_PATH];
    DWORD n,status,i,size,required;void *allocated=NULL,*fixed;BYTE output[1056],expected[1056],sentinel[16];m98_dns_snapshot snapshot={0};
    static const DWORD configs[]={0,1,2,6,12,13,14,15,16,17};
    if(!trial)ExitProcess(3);
    log_file=CreateFileA("DNSCF.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(log_file==INVALID_HANDLE_VALUE)ExitProcess(4);
    text("M98DNS_CONFIG_PROBE=1\r\nNONCE=");text(trial);text("\r\n");
    C(GetVersionExA(&os),"read OS identity");text("OS_PLATFORM=");number(os.dwPlatformId);
    text("\r\nOS_MAJOR=");number(os.dwMajorVersion);text("\r\nOS_MINOR=");number(os.dwMinorVersion);
    text("\r\nOS_BUILD_LOW=");number(os.dwBuildNumber&65535);text("\r\n");
    C(os.dwPlatformId==1&&os.dwMajorVersion==4&&os.dwMinorVersion==10&&(os.dwBuildNumber&65535)==2222,"require real Win98 SE 4.10.2222");
    text("WIN98_IDENTIFIED=1\r\n");
    n=GetModuleFileNameA(NULL,path,sizeof(path));C(n&&n<sizeof(path),"probe executable identity");
    while(n&&path[n-1]!='\\')--n;
    C(n&&n<MAX_PATH-11,"probe adjacent provider path");
    {const char *name="M98DNS.DLL";DWORD j=0;do{path[n+j]=name[j];}while(name[j++]);}
    dll=LoadLibraryA(path);C(dll,"load absolute adjacent opt-in provider");
    n=GetModuleFileNameA(dll,module,sizeof(module));C(n&&n<sizeof(module),"provider module identity");
    C(same_path(path,module),"tested DLL is exact adjacent frozen input");
    text("MODULE_PATH=");text(module);text("\r\n");
    query=(query_fn)(void *)GetProcAddress(dll,"DnsQueryConfig");C(query,"resolve exact named export");
    n=GetSystemDirectoryA(path,sizeof(path));C(n&&n<MAX_PATH-14,"actual system provider path");
    {const char *suffix="\\IPHLPAPI.DLL";DWORD j=0;do{path[n+j]=suffix[j];}while(suffix[j++]);}
    ip=LoadLibraryA(path);C(ip,"load installed IP Helper independently");
    network=(network_fn)(void *)GetProcAddress(ip,"GetNetworkParams");C(network,"resolve actual configuration reader");
    size=0;C(network(NULL,&size)==ERROR_BUFFER_OVERFLOW&&size>=584&&size<=65536,"bounded actual snapshot sizing");
    fixed=LocalAlloc(LMEM_FIXED,size);C(fixed,"own snapshot allocation");
    required=size;C(network(fixed,&required)==0&&required>=584&&required<=size,"capture actual installed configuration");
    C(m98_dns_parse_fixed4(fixed,required,(uint32_t)(uintptr_t)fixed,decode,NULL,&snapshot)==0,"validate direct configuration ownership");
    text("HOSTNAME_ACP_HEX=");hex_string(snapshot.host_a);text("\r\nDOMAIN_ACP_HEX=");hex_string(snapshot.domain_a);
    text("\r\nREAL_DNS_SERVER_COUNT=");number(snapshot.server_count);text("\r\n");
    for(i=0;i<snapshot.server_count;++i){DWORD j;text("REAL_DNS_SERVER=");for(j=0;j<4;++j){if(j)text(".");number(snapshot.servers[i][j]);}text("\r\n");}
    n=0;C(query(6,0,NULL,NULL,NULL,&n)==0&&n==4+4*snapshot.server_count,"actual IP4_ARRAY byte sizing");
    size=sizeof(output);C(query(6,0,NULL,NULL,output,&size)==0&&rd(output)==snapshot.server_count,"real DNS count");
    C(size==n&&same(output+4,snapshot.servers,4*snapshot.server_count),"actual DNS order and bytes");
    if(!snapshot.server_count)text("EMPTY_DNS_SETTINGS=1\r\n");
    size=sizeof(output);n=expected_string(fixed,13,expected);
    C(query(13,0,NULL,NULL,output,&size)==0&&size==n&&same(output,expected,size),"actual host ACP bytes");
    size=sizeof(output);C(query(1,0,NULL,NULL,output,&size)==0&&size==len(snapshot.domain_a,132)+1&&same(output,snapshot.domain_a,size),"actual domain ACP bytes");
    for(i=0;i<sizeof(configs)/sizeof(configs[0]);++i){DWORD needed=0,expected_size;
        status=query(configs[i],0,NULL,NULL,NULL,&needed);
        C(status==(configs[i]==6?0:122)&&needed>0&&needed<=sizeof(output),"size negotiation status");
        for(n=0;n<sizeof(sentinel);++n)sentinel[n]=0xa5;
        size=needed-1;status=query(configs[i],0,NULL,NULL,sentinel,&size);
        C(status==(configs[i]==6?234:122)&&size==needed,"short buffer byte count");
        for(n=0;n<sizeof(sentinel);++n)C(sentinel[n]==0xa5,"short buffer unchanged");
        size=sizeof(output);C(query(configs[i],0,NULL,NULL,output,&size)==0&&size==needed,"successful caller buffer");
        if(configs[i]!=6){n=expected_string(fixed,configs[i],expected);C(size==n&&same(output,expected,n),"independent provider string bytes");}
        expected_size=size;size=0xdeadbeef;allocated=(void *)(uintptr_t)0x1234;
        C(query(configs[i],1,NULL,NULL,&allocated,&size)==0&&allocated&&allocated!=(void *)(uintptr_t)0x1234&&size==expected_size,"actual LocalAlloc ownership");
        C(same(allocated,output,size),"allocation matches caller result");
        C(!LocalFree(allocated),"caller LocalFree ownership");allocated=NULL;
    }
    size=77;output[0]=0xa5;C(query(6,2,NULL,NULL,output,&size)==87&&size==77&&output[0]==0xa5,"invalid flags preserve output");
    C(query(6,0,NULL,output,output,&size)==87&&size==77,"reserved preserve output");
    C(query(7,0,NULL,NULL,output,&size)==50&&size==77,"unsupported search list explicit");
    C(query(6,0,L"adapter",NULL,output,&size)==50&&size==77,"adapter scope explicit");
    C(query(6,0,NULL,NULL,output,NULL)==87,"missing size explicit");
    C(!LocalFree(fixed),"direct snapshot release");C(FreeLibrary(ip),"direct provider release");C(FreeLibrary(dll),"configuration module release");
    text("NO_DNS_TRANSACTIONS=1\r\nCHECKS=");number(checks);text("\r\nPASS: native configuration and LocalFree ownership\r\n");
    C(FlushFileBuffers(log_file),"flush native receipt");C(CloseHandle(log_file),"close native receipt");ExitProcess(0);
}
