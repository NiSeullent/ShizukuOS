/* SPDX-License-Identifier: GPL-2.0-only
 * Hosted populated-catalog/registry injection. These are dependency and
 * lifecycle tests, not evidence that guest hardware or Chromium is working.
 */
#include <stdio.h>
#include <pthread.h>
#include "setupapi_host_contract.h"
#define SHZ_SETUP_HOST_TEST 1
#include "../dlls/setupapi/setupapi_catalog.c"

static struct { shz_pnp_catalog_t header; shz_pnp_row_t rows[4]; } fixture;
static NTSTATUS catalog_failure;
static unsigned checks, registry_opened, registry_closed;
static int registry_failure;
static unsigned registry_value_mode;
static REGSAM opened_access;
static WCHAR opened_path[320];
static const GUID class_one={0x12345678,0x1234,0x5678,{0x90,0xab,0xcd,0xef,0,1,2,3}};
static const GUID class_two={0x11111111,0x2222,0x3333,{0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb}};
static const GUID interface_one={0x87654321,0x4321,0x8765,{0xab,0x90,0xef,0xcd,3,2,1,0}};
#define VERIFY(x) do { ++checks;if(!(x)){fprintf(stderr,"FAIL line %u: %s (error %u)\n",__LINE__,#x,GetLastError());exit(1);} } while(0)
static void wide(uint16_t *output,const WCHAR *input)
{ unsigned i;for(i=0;input[i];++i)output[i]=input[i];output[i]=0; }
static void populate(void)
{
    memset(&fixture,0,sizeof fixture);
    fixture.header.version=1;fixture.header.row_size=sizeof(shz_pnp_row_t);fixture.header.count=4;
    fixture.rows[0].kind=SHZ_PNP_NODE;fixture.rows[0].node_id=3;fixture.rows[0].started=1;
    wide(fixture.rows[0].instance,L"PCI\\VEN_1234&DEV_5678\\B00D03F0");
    wide(fixture.rows[0].class_guid,L"{12345678-1234-5678-90ab-cdef00010203}");
    wide(fixture.rows[0].driver_key,L"{12345678-1234-5678-90ab-cdef00010203}\\0000");
    wide(fixture.rows[0].description,L"Hosted actual-row fixture");
    wide(fixture.rows[0].manufacturer,L"Fixture vendor");
    memcpy(fixture.rows[0].service,"fixture-driver",15);
    fixture.rows[1]=fixture.rows[0];fixture.rows[1].kind=SHZ_PNP_INTERFACE;fixture.rows[1].enabled=1;
    memcpy(fixture.rows[1].interface_guid,&interface_one,16);
    wide(fixture.rows[1].link,L"\\??\\PCI#VEN_1234&DEV_5678#B00D03F0#{87654321-4321-8765-ab90-efcd03020100}");
    fixture.rows[2]=fixture.rows[0];fixture.rows[2].node_id=4;fixture.rows[2].started=0;
    wide(fixture.rows[2].instance,L"ROOT\\REAL_REGISTERED\\0000");
    fixture.rows[2].class_guid[0]=fixture.rows[2].manufacturer[0]=fixture.rows[2].driver_key[0]=0;
    fixture.rows[3]=fixture.rows[1];fixture.rows[3].node_id=4;fixture.rows[3].enabled=0;
    wide(fixture.rows[3].instance,L"ROOT\\REAL_REGISTERED\\0000");
    wide(fixture.rows[3].link,L"\\??\\ROOT#REAL_REGISTERED#0000#{87654321-4321-8765-ab90-efcd03020100}");
}
static NTSTATUS NtQuerySystemInformation(ULONG cls,void *output,ULONG size,ULONG *required)
{
    DWORD bytes=sizeof(fixture.header)+fixture.header.count*sizeof(shz_pnp_row_t);
    if(catalog_failure)return catalog_failure;
    if(cls!=SHZ_PNP_CATALOG_CLASS)return (NTSTATUS)0xc0000003u;
    if(required)*required=bytes;
    if(size<bytes)return (NTSTATUS)0xc0000004u;
    if(bytes>sizeof fixture) return (NTSTATUS)0xc0000004u;
    memcpy(output,&fixture,bytes);return 0;
}
static LONG RegOpenKeyExW(HKEY root,PCWSTR path,DWORD flags,REGSAM access,HKEY *output)
{
    unsigned i;(void)flags;
    if(root!=HKEY_LOCAL_MACHINE)return ERROR_INVALID_HANDLE;
    if(registry_failure)return registry_failure;
    for(i=0;path[i];++i)opened_path[i]=path[i];opened_path[i]=0;opened_access=access;
    *output=malloc(1);if(!*output)return ERROR_NOT_ENOUGH_MEMORY;
    ++registry_opened;return 0;
}
static LONG RegQueryValueExW(HKEY key,PCWSTR name,DWORD *reserved,DWORD *type,BYTE *buffer,DWORD *size)
{
    const WCHAR *value;DWORD bytes;(void)key;(void)reserved;
    if(equal(name,L"HardwareID")){static const WCHAR ids[]=L"PCI\\VEN_1234&DEV_5678\0PCI\\VEN_1234\0";value=ids;bytes=sizeof ids;*type=REG_MULTI_SZ;}
    else if(equal(name,L"Class")){value=L"Net";bytes=8;*type=REG_SZ;}
    else return ERROR_FILE_NOT_FOUND;
    if(registry_value_mode==2&&*type==REG_SZ)bytes=7; /* odd UTF16 size */
    if(registry_value_mode==3&&*type==REG_SZ)bytes=6; /* no string terminator */
    if(registry_value_mode==4&&*type==REG_MULTI_SZ)bytes-=2; /* missing final double NUL */
    if(registry_value_mode==5&&*type==REG_MULTI_SZ){static const WCHAR malformed[]=L"A\0\0B\0";value=malformed;bytes=sizeof malformed;}
    if(!buffer){*size=bytes;return 0;}if(*size<bytes){*size=bytes;return ERROR_MORE_DATA;}
    if(registry_value_mode==1)*type=REG_BINARY; /* type changed after size query */
    if(registry_value_mode==6){*size=bytes+2;return ERROR_MORE_DATA;}
    memcpy(buffer,value,bytes);*size=bytes;return 0;
}
static LONG RegCloseKey(HKEY key) { free(key);++registry_closed;return 0; }
static void *worker(void *unused)
{
    unsigned i;(void)unused;
    for(i=0;i<1000;++i){HDEVINFO set=SetupDiGetClassDevsW(NULL,NULL,NULL,DIGCF_ALLCLASSES|DIGCF_PRESENT);
        SP_DEVINFO_DATA data={.cbSize=sizeof data};BYTE bytes[128];DEVPROPTYPE type;
        DEVPROPKEY key={instance_property_guid,256};
        if(set==INVALID_HANDLE_VALUE||!SetupDiEnumDeviceInfo(set,0,&data)||
           !SetupDiGetDevicePropertyW(set,&data,&key,&type,bytes,sizeof bytes,NULL,0)||
           type!=DEVPROP_TYPE_STRING||!SetupDiDestroyDeviceInfoList(set))abort();}
    return NULL;
}
int main(void)
{
    HDEVINFO all,filtered,other,created,interfaces,active;
    SP_DEVINFO_DATA data={.cbSize=sizeof data},node={.cbSize=sizeof node},foreign={.cbSize=sizeof foreign};
    SP_DEVICE_INTERFACE_DATA iface={.cbSize=sizeof iface},invalid={.cbSize=sizeof invalid};
    BYTE storage[512],property_buffer[256];PSP_DEVICE_INTERFACE_DETAIL_DATA_W detail=(void *)storage;
    DEVPROPKEY key;DEVPROPTYPE type;DWORD size;HKEY reg;pthread_t threads[4];unsigned i;
    populate();
    VERIFY(sizeof(shz_pnp_row_t)==1424&&sizeof(shz_pnp_catalog_t)==16);
    created=SetupDiCreateDeviceInfoList(NULL,NULL);VERIFY(created!=INVALID_HANDLE_VALUE);
    VERIFY(!SetupDiEnumDeviceInfo(created,0,&data)&&GetLastError()==ERROR_NO_MORE_ITEMS);
    VERIFY(SetupDiDestroyDeviceInfoList(created));
    VERIFY(!SetupDiDestroyDeviceInfoList(created)&&GetLastError()==ERROR_INVALID_HANDLE);
    VERIFY(SetupDiGetClassDevsW(NULL,NULL,NULL,0)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_INVALID_PARAMETER);
    VERIFY(SetupDiGetClassDevsW(NULL,NULL,NULL,DIGCF_ALLCLASSES|DIGCF_PROFILE)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_NOT_SUPPORTED);
    VERIFY(SetupDiGetClassDevsW(NULL,NULL,NULL,0x8000)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_INVALID_FLAGS);
    VERIFY(SetupDiGetClassDevsW(NULL,L"{enumerator-guid}",NULL,DIGCF_ALLCLASSES)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_NOT_SUPPORTED);
    all=SetupDiGetClassDevsW(NULL,NULL,NULL,DIGCF_ALLCLASSES|DIGCF_PRESENT);VERIFY(all!=INVALID_HANDLE_VALUE);
    VERIFY(SetupDiEnumDeviceInfo(all,0,&data)&&data.DevInst==3&&same_guid(&data.ClassGuid,&class_one));
    VERIFY(SetupDiEnumDeviceInfo(all,1,&node)&&node.DevInst==4);
    VERIFY(!SetupDiEnumDeviceInfo(all,2,&node)&&GetLastError()==ERROR_NO_MORE_ITEMS);
    node.cbSize=0;VERIFY(!SetupDiEnumDeviceInfo(all,0,&node)&&GetLastError()==ERROR_INVALID_USER_BUFFER);node.cbSize=sizeof node;
    filtered=SetupDiGetClassDevsW(&class_one,L"pci",NULL,DIGCF_PRESENT);VERIFY(filtered!=INVALID_HANDLE_VALUE);
    VERIFY(SetupDiEnumDeviceInfo(filtered,0,&foreign)&&foreign.DevInst==3);
    VERIFY(!SetupDiEnumDeviceInfo(filtered,1,&node)&&GetLastError()==ERROR_NO_MORE_ITEMS);
    other=SetupDiCreateDeviceInfoList(&class_two,NULL);VERIFY(other!=INVALID_HANDLE_VALUE);
    VERIFY(!SetupDiOpenDeviceInfoW(other,(WCHAR *)fixture.rows[0].instance,NULL,0,&node)&&GetLastError()==ERROR_CLASS_MISMATCH);
    VERIFY(!SetupDiOpenDeviceInfoW(other,L"MISSING\\DEVICE\\0000",NULL,0,&node)&&GetLastError()==ERROR_NO_SUCH_DEVINST);
    key.fmtid=instance_property_guid;key.pid=256;
    VERIFY(!SetupDiGetDevicePropertyW(filtered,&data,&key,&type,property_buffer,sizeof property_buffer,NULL,0)&&GetLastError()==ERROR_INVALID_PARAMETER);
    VERIFY(!SetupDiGetDevicePropertyW(all,&data,&key,&type,NULL,0,&size,0)&&GetLastError()==ERROR_INSUFFICIENT_BUFFER&&type==DEVPROP_TYPE_STRING&&size==sizeof(L"PCI\\VEN_1234&DEV_5678\\B00D03F0"));
    VERIFY(SetupDiGetDevicePropertyW(all,&data,&key,&type,property_buffer,sizeof property_buffer,&size,0)&&equal((WCHAR *)property_buffer,(WCHAR *)fixture.rows[0].instance));
    key.fmtid=device_property_guid;key.pid=10;
    VERIFY(SetupDiGetDevicePropertyW(all,&data,&key,&type,property_buffer,sizeof property_buffer,&size,0)&&type==DEVPROP_TYPE_GUID&&size==16&&same_guid((GUID *)property_buffer,&class_one));
    VERIFY(SetupDiEnumDeviceInfo(all,1,&node));
    VERIFY(!SetupDiGetDevicePropertyW(all,&node,&key,&type,property_buffer,sizeof property_buffer,&size,0)&&GetLastError()==ERROR_NOT_FOUND);
    key.pid=13;VERIFY(!SetupDiGetDevicePropertyW(all,&node,&key,&type,property_buffer,sizeof property_buffer,NULL,0)&&GetLastError()==ERROR_NOT_FOUND);
    key.pid=6;VERIFY(SetupDiGetDevicePropertyW(all,&data,&key,&type,property_buffer,sizeof property_buffer,NULL,0)&&equal((WCHAR *)property_buffer,L"fixture-driver"));
    key.pid=3;VERIFY(SetupDiGetDevicePropertyW(all,&data,&key,&type,property_buffer,sizeof property_buffer,&size,0)&&type==DEVPROP_TYPE_STRING_LIST&&registry_opened==registry_closed);
    key.pid=9;VERIFY(SetupDiGetDevicePropertyW(all,&data,&key,&type,property_buffer,sizeof property_buffer,NULL,0)&&equal((WCHAR *)property_buffer,L"Net"));
    for(i=1;i<=5;++i){registry_value_mode=i;key.pid=i>=4?3:9;
        memset(property_buffer,0xa5,sizeof property_buffer);
        VERIFY(!SetupDiGetDevicePropertyW(all,&data,&key,&type,property_buffer,sizeof property_buffer,&size,0)&&GetLastError()==ERROR_INVALID_DATA);
        VERIFY(property_buffer[0]==0xa5&&registry_opened==registry_closed);}
    registry_value_mode=6;key.pid=9;
    VERIFY(!SetupDiGetDevicePropertyW(all,&data,&key,&type,NULL,0,&size,0)&&GetLastError()==ERROR_INSUFFICIENT_BUFFER&&size==10&&registry_opened==registry_closed);
    registry_value_mode=0;
    key.pid=14;VERIFY(!SetupDiGetDevicePropertyW(all,&data,&key,&type,property_buffer,sizeof property_buffer,NULL,0)&&GetLastError()==ERROR_NOT_FOUND);
    key.pid=999;VERIFY(!SetupDiGetDevicePropertyW(all,&data,&key,&type,property_buffer,sizeof property_buffer,NULL,0)&&GetLastError()==ERROR_NOT_FOUND);
    VERIFY(!SetupDiGetDevicePropertyW(all,&data,&key,&type,property_buffer,sizeof property_buffer,NULL,1)&&GetLastError()==ERROR_INVALID_FLAGS);
    interfaces=SetupDiGetClassDevsW(&interface_one,NULL,NULL,DIGCF_DEVICEINTERFACE);VERIFY(interfaces!=INVALID_HANDLE_VALUE);
    VERIFY(SetupDiEnumDeviceInterfaces(interfaces,NULL,&interface_one,0,&iface)&&(iface.Flags&SPINT_ACTIVE));
    VERIFY(!SetupDiGetDeviceInterfaceDetailW(interfaces,&iface,NULL,0,&size,&node)&&GetLastError()==ERROR_INSUFFICIENT_BUFFER&&node.DevInst==3);
    memset(storage,0xcc,sizeof storage);detail->cbSize=sizeof *detail;
    VERIFY(SetupDiGetDeviceInterfaceDetailW(interfaces,&iface,detail,size,&size,&node)&&equal(detail->DevicePath,L"\\\\?\\PCI#VEN_1234&DEV_5678#B00D03F0#{87654321-4321-8765-ab90-efcd03020100}"));
    VERIFY(storage[size]==0xcc); /* no write beyond exact negotiated bytes */
    VERIFY(!SetupDiGetDeviceInterfaceDetailW(all,&iface,detail,sizeof storage,NULL,NULL)&&GetLastError()==ERROR_INVALID_PARAMETER);
    VERIFY(!SetupDiGetDeviceInterfaceDetailW(interfaces,&iface,NULL,8,NULL,NULL)&&GetLastError()==ERROR_INVALID_USER_BUFFER);
    detail->cbSize=6;
    VERIFY(!SetupDiGetDeviceInterfaceDetailW(interfaces,&iface,detail,sizeof storage,NULL,NULL)&&GetLastError()==ERROR_INVALID_USER_BUFFER);
    detail->cbSize=sizeof *detail;
    VERIFY(!SetupDiGetDeviceInterfaceDetailW(interfaces,&iface,detail,size-1,&size,NULL)&&GetLastError()==ERROR_INSUFFICIENT_BUFFER);
    VERIFY(!SetupDiEnumDeviceInterfaces(interfaces,NULL,NULL,0,&invalid)&&GetLastError()==ERROR_INVALID_PARAMETER);
    VERIFY(SetupDiEnumDeviceInterfaces(interfaces,NULL,&interface_one,1,&invalid)&&invalid.Flags==0);
    VERIFY(!SetupDiEnumDeviceInterfaces(interfaces,&node,&interface_one,1,&invalid)&&GetLastError()==ERROR_NO_MORE_ITEMS);
    active=SetupDiGetClassDevsW(&interface_one,NULL,NULL,DIGCF_DEVICEINTERFACE|DIGCF_PRESENT);VERIFY(active!=INVALID_HANDLE_VALUE);
    VERIFY(SetupDiEnumDeviceInterfaces(active,NULL,&interface_one,0,&invalid));
    VERIFY(!SetupDiEnumDeviceInterfaces(active,NULL,&interface_one,1,&invalid)&&GetLastError()==ERROR_NO_MORE_ITEMS);
    created=SetupDiCreateDeviceInfoList(NULL,NULL);VERIFY(created!=INVALID_HANDLE_VALUE&&created!=(HDEVINFO)all);
    VERIFY(!SetupDiOpenDeviceInterfaceW(created,detail->DevicePath,DIODI_NO_ADD,&invalid)&&GetLastError()==ERROR_NO_SUCH_DEVICE_INTERFACE);
    VERIFY(SetupDiOpenDeviceInfoW(created,(WCHAR *)fixture.rows[0].instance,NULL,0,&node));
    VERIFY(SetupDiOpenDeviceInterfaceW(created,detail->DevicePath,DIODI_NO_ADD,&invalid));
    invalid.cbSize=0;
    VERIFY(!SetupDiOpenDeviceInterfaceW(created,(WCHAR *)fixture.rows[3].link,0,&invalid)&&GetLastError()==ERROR_INVALID_USER_BUFFER);
    invalid.cbSize=sizeof invalid;VERIFY(SetupDiEnumDeviceInfo(created,1,&node)&&node.DevInst==4);
    VERIFY(!SetupDiOpenDeviceInfoW(created,L"",NULL,0,NULL)&&GetLastError()==ERROR_NOT_SUPPORTED);
    VERIFY(!SetupDiOpenDeviceInfoW(created,(WCHAR *)fixture.rows[0].instance,NULL,DIOD_CANCEL_REMOVE,NULL)&&GetLastError()==ERROR_NOT_SUPPORTED);
    reg=SetupDiOpenDevRegKey(all,&data,DICS_FLAG_GLOBAL,123,DIREG_DEV,KEY_READ);
    VERIFY(reg!=INVALID_HANDLE_VALUE&&opened_access==KEY_READ&&equal(opened_path,L"System\\CurrentControlSet\\Enum\\PCI\\VEN_1234&DEV_5678\\B00D03F0\\Device Parameters"));RegCloseKey(reg);
    reg=SetupDiOpenDevRegKey(all,&data,DICS_FLAG_GLOBAL,0,DIREG_DRV,KEY_QUERY_VALUE);
    VERIFY(reg!=INVALID_HANDLE_VALUE&&equal(opened_path,L"System\\CurrentControlSet\\Control\\Class\\{12345678-1234-5678-90ab-cdef00010203}\\0000"));RegCloseKey(reg);
    VERIFY(SetupDiOpenDevRegKey(all,&data,DICS_FLAG_CONFIGSPECIFIC,0,DIREG_DEV,KEY_READ)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_NOT_SUPPORTED);
    registry_failure=ERROR_ACCESS_DENIED;
    VERIFY(SetupDiOpenDevRegKey(all,&data,DICS_FLAG_GLOBAL,0,DIREG_DEV,KEY_READ)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_ACCESS_DENIED);registry_failure=0;
    fixture.rows[1].enabled=0;
    VERIFY(SetupDiOpenDeviceInterfaceW(created,detail->DevicePath,0,&invalid)&&invalid.Flags==0);fixture.rows[1].enabled=1;
    fixture.header.count=0;
    key.fmtid=instance_property_guid;key.pid=256;
    VERIFY(!SetupDiGetDevicePropertyW(all,&data,&key,&type,property_buffer,sizeof property_buffer,NULL,0)&&GetLastError()==ERROR_NO_SUCH_DEVINST);
    VERIFY(!SetupDiGetDeviceInterfaceDetailW(interfaces,&iface,NULL,0,&size,NULL)&&GetLastError()==ERROR_NO_SUCH_DEVICE_INTERFACE);
    populate();fixture.header.row_size=1;
    VERIFY(SetupDiGetClassDevsW(NULL,NULL,NULL,DIGCF_ALLCLASSES)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_INVALID_DATA);populate();
    fixture.rows[3].node_id=999;
    VERIFY(SetupDiGetClassDevsW(NULL,NULL,NULL,DIGCF_ALLCLASSES)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_INVALID_DATA);populate();
    fixture.rows[2].node_id=3;
    VERIFY(SetupDiGetClassDevsW(NULL,NULL,NULL,DIGCF_ALLCLASSES)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_INVALID_DATA);populate();
    fixture.header.count=1025;
    VERIFY(SetupDiGetClassDevsW(NULL,NULL,NULL,DIGCF_ALLCLASSES)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_INVALID_DATA);populate();
    memset(fixture.rows[0].instance,'x',sizeof fixture.rows[0].instance);
    VERIFY(SetupDiGetClassDevsW(NULL,NULL,NULL,DIGCF_ALLCLASSES)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_INVALID_DATA);populate();
    catalog_failure=(NTSTATUS)0xc0000003u;
    VERIFY(SetupDiGetClassDevsW(NULL,NULL,NULL,DIGCF_ALLCLASSES)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_NOT_SUPPORTED);catalog_failure=0;
    allocation_fail=0;
    VERIFY(SetupDiGetClassDevsW(NULL,NULL,NULL,DIGCF_ALLCLASSES)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_NOT_ENOUGH_MEMORY);allocation_fail=-1;
    for(i=1;i<5;++i){allocation_fail=(int)i;
        VERIFY(SetupDiGetClassDevsW(NULL,NULL,NULL,DIGCF_ALLCLASSES|DIGCF_DEVICEINTERFACE)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_NOT_ENOUGH_MEMORY);
        allocation_fail=-1;}
    VERIFY(SetupDiDestroyDeviceInfoList(all)&&SetupDiDestroyDeviceInfoList(filtered)&&SetupDiDestroyDeviceInfoList(other)&&
           SetupDiDestroyDeviceInfoList(interfaces)&&SetupDiDestroyDeviceInfoList(active)&&SetupDiDestroyDeviceInfoList(created));
    VERIFY(!SetupDiEnumDeviceInfo(all,0,&data)&&GetLastError()==ERROR_INVALID_HANDLE);
    for(i=0;i<4;++i)VERIFY(pthread_create(&threads[i],NULL,worker,NULL)==0);
    for(i=0;i<4;++i)VERIFY(pthread_join(threads[i],NULL)==0);
    VERIFY(sets==NULL&&registry_opened==registry_closed);
    printf("SETUPAPI-HOST: %u checks and 4000 concurrent populated-catalog query lifecycles passed; hosted fixture only\n",checks);
    return 0;
}
