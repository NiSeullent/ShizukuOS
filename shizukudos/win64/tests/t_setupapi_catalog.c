/* SPDX-License-Identifier: GPL-2.0-only
 * Actual SetupAPI comparison with the kernel's independently queried PnP
 * catalog. No driver, USB device or symbolic link is fabricated by this test.
 * A genuinely empty registered graph is reported explicitly, not substituted.
 */
#include "k32test.h"
#include "nt.h"
#include <setupapi.h>
#include "../../abi/shz_pnp_catalog.h"

static const GUID property_guid={0xa45c254e,0xdf1c,0x4efd,{0x80,0x20,0x67,0xd1,0x46,0xa8,0x50,0xe0}};
static const GUID instance_guid={0x78c34fc8,0x104a,0x4aca,{0x9e,0xa4,0x52,0x4d,0x52,0x99,0x6e,0x57}};
static int equal(const WCHAR *a,const uint16_t *b)
{
    while(*a&&*b){unsigned x=*a++,y=*b++;if(x>='A'&&x<='Z')x+=32;if(y>='A'&&y<='Z')y+=32;if(x!=y)return 0;}
    return !*a&&!*b;
}
static unsigned length(const uint16_t *s) { unsigned n=0;while(s[n])++n;return n; }
static shz_pnp_row_t *node(shz_pnp_catalog_t *catalog,DWORD id)
{
    shz_pnp_row_t *rows=(shz_pnp_row_t *)(catalog+1);unsigned i;
    for(i=0;i<catalog->count;++i)if(rows[i].kind==SHZ_PNP_NODE&&rows[i].node_id==id)return &rows[i];
    return NULL;
}
int main(void)
{
    shz_pnp_catalog_t *catalog=NULL;
    shz_pnp_row_t *rows,*row;
    ULONG needed=0,returned=0;
    DWORD expected_nodes=0,expected_interfaces=0,index,count=0,bytes;
    HDEVINFO set,empty,other,interfaces;
    SP_DEVINFO_DATA device={.cbSize=sizeof device},opened={.cbSize=sizeof opened};
    SP_DEVICE_INTERFACE_DATA iface={.cbSize=sizeof iface},copied={.cbSize=sizeof copied};
    DEVPROPKEY property={instance_guid,256};DEVPROPTYPE type;
    WCHAR value[256];GUID guid;HKEY registry,direct;
    WCHAR path[320];unsigned i,j,n;
    struct { DWORD cbSize; WCHAR DevicePath[160]; } detail;
    NTSTATUS status=NtQuerySystemInformation(SHZ_PNP_CATALOG_CLASS,NULL,0,&needed);
    CHECK(status==(NTSTATUS)0xc0000004u&&needed>=16&&needed<=16+1024u*1424u,
          "real kernel supplies bounded registered-PnP catalog required bytes");
    if(status!=(NTSTATUS)0xc0000004u||needed<16||needed>16+1024u*1424u)return 1;
    catalog=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,needed);
    CHECK(catalog!=NULL,"actual user buffer allocated for kernel catalog");
    if(!catalog)return 1;
    status=NtQuerySystemInformation(SHZ_PNP_CATALOG_CLASS,catalog,needed,&returned);
    CHECK(status==0&&
          catalog->version==1&&catalog->row_size==1424&&catalog->count<=1024&&
          returned==16+catalog->count*1424u,"actual kernel snapshot has exact version/header/row/count ABI");
    if(status||catalog->row_size!=1424||catalog->count>1024||returned!=16+catalog->count*1424u){HeapFree(GetProcessHeap(),0,catalog);return 1;}
    rows=(shz_pnp_row_t *)(catalog+1);
    for(i=0;i<catalog->count;++i){if(rows[i].kind==SHZ_PNP_NODE)++expected_nodes;else if(rows[i].kind==SHZ_PNP_INTERFACE)++expected_interfaces;}
    printf("Actual registered PnP snapshot: %lu devnodes, %lu interfaces; unregistered PCI/USB inventory is outside this provider\n",
           (unsigned long)expected_nodes,(unsigned long)expected_interfaces);
    empty=SetupDiCreateDeviceInfoList(NULL,NULL);
    CHECK(empty!=INVALID_HANDLE_VALUE,"genuine initially empty information set created");
    CHECK(!SetupDiEnumDeviceInfo(empty,0,&device)&&GetLastError()==ERROR_NO_MORE_ITEMS,"new information set contains no invented device");
    CHECK(SetupDiDestroyDeviceInfoList(empty),"owned empty information set destroyed");
    CHECK(!SetupDiDestroyDeviceInfoList(empty)&&GetLastError()==ERROR_INVALID_HANDLE,"stale destroyed set token rejected");
    set=SetupDiGetClassDevsW(NULL,NULL,NULL,DIGCF_ALLCLASSES|DIGCF_PRESENT);
    CHECK(set!=INVALID_HANDLE_VALUE,"SetupAPI obtains actual registered present devnode graph");
    if(set==INVALID_HANDLE_VALUE){HeapFree(GetProcessHeap(),0,catalog);return 1;}
    other=SetupDiCreateDeviceInfoList(NULL,NULL);
    for(index=0;SetupDiEnumDeviceInfo(set,index,&device);++index){
        row=node(catalog,device.DevInst);
        CHECK(row!=NULL,"SetupAPI DevInst corresponds to independently queried actual PDO");
        if(!row)continue;
        bytes=0;
        CHECK(!SetupDiGetDevicePropertyW(set,&device,&property,&type,NULL,0,&bytes,0)&&
              GetLastError()==ERROR_INSUFFICIENT_BUFFER&&type==DEVPROP_TYPE_STRING&&bytes==(length(row->instance)+1)*2,
              "actual instance-ID property negotiates exact UTF-16 bytes");
        CHECK(SetupDiGetDevicePropertyW(set,&device,&property,&type,(BYTE *)value,sizeof value,&bytes,0)&&equal(value,row->instance),
              "property value equals actual kernel registered instance identity");
        CHECK(!SetupDiGetDevicePropertyW(other,&device,&property,&type,(BYTE *)value,sizeof value,NULL,0)&&GetLastError()==ERROR_INVALID_PARAMETER,
              "device token from another set is rejected");
        CHECK(SetupDiOpenDeviceInfoW(other,(WCHAR *)row->instance,NULL,0,&opened)&&opened.DevInst==device.DevInst&&opened.Reserved!=device.Reserved,
              "actual existing instance opens into separate owned set with distinct item generation");
        {
            DEVPROPKEY cls={property_guid,10};
            if(!row->class_guid[0])CHECK(!SetupDiGetDevicePropertyW(set,&device,&cls,&type,(BYTE *)&guid,sizeof guid,NULL,0)&&GetLastError()==ERROR_NOT_FOUND,
                                      "missing actual setup class does not become fictitious GUID property");
        }
        /* OpenDevRegKey returns the genuine existing hardware parameters key
         * or exactly the direct registry failure. Neither path creates keys. */
        n=0;
        {const WCHAR *prefix=L"System\\CurrentControlSet\\Enum\\";for(j=0;prefix[j];++j)path[n++]=prefix[j];}
        for(j=0;row->instance[j];++j)path[n++]=row->instance[j];
        {const WCHAR *suffix=L"\\Device Parameters";for(j=0;suffix[j];++j)path[n++]=suffix[j];}path[n]=0;
        status=RegOpenKeyExW(HKEY_LOCAL_MACHINE,path,0,KEY_READ,&direct);
        registry=SetupDiOpenDevRegKey(set,&device,DICS_FLAG_GLOBAL,0,DIREG_DEV,KEY_READ);
        CHECK((status==0&&registry!=(HKEY)INVALID_HANDLE_VALUE)||(status!=0&&registry==(HKEY)INVALID_HANDLE_VALUE&&GetLastError()==(DWORD)status),
              "device registry-key open follows actual registry provider result");
        if(!status)RegCloseKey(direct);
        if(registry!=(HKEY)INVALID_HANDLE_VALUE)CHECK(RegCloseKey(registry)==0,"actual opened device registry handle closes normally");
    }
    CHECK(GetLastError()==ERROR_NO_MORE_ITEMS&&index==expected_nodes,"SetupAPI enumeration count equals actual registered kernel devnode count");
    CHECK(!SetupDiOpenDeviceInfoW(set,L"SHZ-NONEXISTENT\\DEVICE\\NOTREGISTERED",NULL,0,NULL)&&GetLastError()==ERROR_NO_SUCH_DEVINST,
          "unregistered device identity is not fabricated");
    for(i=0;i<catalog->count;++i)if(rows[i].kind==SHZ_PNP_INTERFACE){
        row=&rows[i];memcpy(&guid,row->interface_guid,16);
        for(j=0;j<i;++j)if(rows[j].kind==SHZ_PNP_INTERFACE&&rows[j].node_id==row->node_id&&!memcmp(rows[j].interface_guid,&guid,16))break;
        if(j<i)continue; /* enumerate each real node/interface-class group once */
        interfaces=SetupDiGetClassDevsW(&guid,(WCHAR *)row->instance,NULL,DIGCF_DEVICEINTERFACE);
        CHECK(interfaces!=INVALID_HANDLE_VALUE,"actual registered interface class and instance form genuine information set");
        if(interfaces==INVALID_HANDLE_VALUE)continue;
        for(index=0;SetupDiEnumDeviceInterfaces(interfaces,NULL,&guid,index,&iface);++index){
            bytes=0;
            CHECK(!SetupDiGetDeviceInterfaceDetailW(interfaces,&iface,NULL,0,&bytes,&opened)&&GetLastError()==ERROR_INSUFFICIENT_BUFFER&&opened.DevInst==row->node_id,
                  "real interface detail negotiates bytes and identifies actual supporting node");
            memset(&detail,0,sizeof detail);detail.cbSize=sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
            CHECK(bytes<=sizeof detail&&SetupDiGetDeviceInterfaceDetailW(interfaces,&iface,(void *)&detail,sizeof detail,&bytes,&opened),
                  "actual registered interface path returned within caller buffer");
            {
                DWORD matched=0;
                for(j=0;j<catalog->count;++j)if(rows[j].kind==SHZ_PNP_INTERFACE&&rows[j].node_id==row->node_id&&!memcmp(rows[j].interface_guid,&guid,16)){
                    WCHAR expected[160];unsigned k;
                    for(k=0;rows[j].link[k];++k)expected[k]=rows[j].link[k];
                    expected[k]=0;
                    if(k>=4&&expected[0]=='\\'&&expected[1]=='?'&&expected[2]=='?'&&expected[3]=='\\'){expected[1]='\\';expected[2]='?';}
                    if(equal(detail.DevicePath,(uint16_t *)expected)&&iface.Flags==(rows[j].enabled?SPINT_ACTIVE:0))++matched;
                }
                CHECK(matched==1,"interface detail preserves unique actual symbolic-link identity and enabled state");
                CHECK(SetupDiOpenDeviceInterfaceW(other,detail.DevicePath,0,&copied),"actual registered interface opens into another owned set");
            }
            ++count;
        }
        CHECK(GetLastError()==ERROR_NO_MORE_ITEMS,"interface enumeration ends with genuine no-more-items status");
        CHECK(SetupDiDestroyDeviceInfoList(interfaces),"actual interface information set destroyed");
    }
    CHECK(count==expected_interfaces,"SetupAPI interface observations equal independently queried registered interface count");
    if(!expected_interfaces){
        const GUID absent={0x10293847,0x5647,0x1029,{1,2,3,4,5,6,7,8}};
        interfaces=SetupDiGetClassDevsW(&absent,NULL,NULL,DIGCF_DEVICEINTERFACE|DIGCF_PRESENT);
        CHECK(interfaces!=INVALID_HANDLE_VALUE&&!SetupDiEnumDeviceInterfaces(interfaces,NULL,&absent,0,&iface)&&GetLastError()==ERROR_NO_MORE_ITEMS,
              "independently empty kernel interface graph yields truthful empty query");
        CHECK(SetupDiDestroyDeviceInfoList(interfaces),"actual empty interface set destroyed");
    }
    printf("Interface observations: %lu; real registered device-path opening remains a separate provider boundary\n",(unsigned long)count);
    CHECK(SetupDiGetClassDevsW(NULL,NULL,NULL,DIGCF_ALLCLASSES|DIGCF_PROFILE)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_NOT_SUPPORTED,
          "unavailable hardware-profile provider fails explicitly");
    CHECK(SetupDiDestroyDeviceInfoList(other)&&SetupDiDestroyDeviceInfoList(set),"all actual information sets release owned storage");
    CHECK(!SetupDiEnumDeviceInfo(set,0,&device)&&GetLastError()==ERROR_INVALID_HANDLE,"destroyed populated set cannot reuse stale token");
    HeapFree(GetProcessHeap(),0,catalog);
    return k32t_finish("T_SETUPAPI_CATALOG");
}
