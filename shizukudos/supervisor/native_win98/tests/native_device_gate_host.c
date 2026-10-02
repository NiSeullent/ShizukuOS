/* SPDX-License-Identifier: GPL-2.0-only
 * Real C policy/fw_cfg/UART/PCI control with modeled ports and host authority.
 * The constructor mode mocks only gate/VGA/storage/VMX call boundaries. */
#include "../native_device_gate.h"
#ifndef W98_GATE_CONSTRUCTOR
#include "../l1_vga.h"
#include "../persistence_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#pragma weak w98_native_device_gate_with_io
#pragma weak w98_gate_sha256
static unsigned checks;
#define CHECK(x) do{++checks;if(!(x)){fprintf(stderr,"FAIL line%u: %s\n",__LINE__,#x);exit(2);}}while(0)
typedef struct {
    uint8_t directory[132],policy[256],challenge[48],grant[272],report[304],rom[65536];
    uint32_t pci[2][10],address;
    uint64_t ticks;
    unsigned selector,offset,rx,tx,dlab,ier,dll,dlh,writes,reads,forbidden,case_id,pci_calls,fifo_init;
} model_t;
static model_t m;
static w98_vga_config_t vga;
static w98_persist_config_t disk;
static shz_info_t info;
static shz_caps_t caps;
static w98_native_gate_t gate;
static void le16(uint8_t *p,unsigned n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void le32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(n>>(i*8));}
static void le64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(n>>(i*8));}
static void be32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(n>>(24-i*8));}
static void entry(uint8_t *p){be32(p,256);p[4]=0;p[5]=0x20;memcpy(p+8,W98_GATE_POLICY_NAME,sizeof W98_GATE_POLICY_NAME);}
static void hash(const void *p,unsigned n,uint8_t *out){CHECK(!w98_gate_sha256(p,n,out));}
static int read_port(void *ctx,uint16_t port,unsigned bytes,uint32_t *value)
{
    model_t *f=ctx;++f->reads;
    if(f->case_id==13)f->ticks=10000100;
    if(f->case_id==23)gate.deadline++;
    if(port==0x511 && bytes==1){
        unsigned at=f->offset++;*value=0;
        if(f->selector==0){if(at<4)*value=((const uint8_t *)"QEMU")[at];}
        else if(f->selector==0x19){if(at<sizeof f->directory)*value=f->directory[at];}
        else if(f->selector==0x20 && at<256)*value=f->policy[at];
        if(f->case_id==1 && f->selector==0)*value=0;
        return 0;
    }
    if(port==0xcf8 && bytes==4){*value=f->address;return 0;}
    if(port==0xcfc && bytes==4){unsigned bdf=(f->address>>8)&255,off=f->address&252;
        CHECK((bdf==16 || bdf==24) && off<=36);*value=f->pci[bdf==16?0:1][off/4];++f->pci_calls;
        if(f->case_id==11 && f->pci_calls==21)*value^=0x1000;
        return 0;}
    if(port==W98_GATE_COM2+5 && bytes==1){*value=0x20;
        if(f->case_id!=10 && f->tx>=48 && (f->rx<48 || f->tx==304)) *value|=1;
        if(f->case_id==12)*value|=2;
        return 0;}
    if(port==W98_GATE_COM2 && bytes==1){
        CHECK(f->fifo_init && f->tx>=48);
        if(f->rx<48)*value=f->challenge[f->rx++];
        else{CHECK(f->tx==304 && f->rx<320);*value=f->grant[f->rx++-48];}
        return 0;
    }
    ++f->forbidden;return -1;
}
static int write_port(void *ctx,uint16_t port,unsigned bytes,uint32_t value)
{
    model_t *f=ctx;++f->writes;
    if(port==0x510 && bytes==2){f->selector=value;f->offset=0;return 0;}
    if(port==0xcf8 && bytes==4){f->address=value;return 0;}
    if(port>=W98_GATE_COM2 && port<=W98_GATE_COM2+4 && bytes==1){
        if(port==W98_GATE_COM2+3)f->dlab=value&128;
        /* Offset1 selects IER only when DLAB is clear; inherited firmware
         * can leave both DLAB1 and IRQs enabled. Model the real banks. */
        if(port==W98_GATE_COM2+1){if(f->dlab)f->dlh=value;else f->ier=value;}
        if(port==W98_GATE_COM2 && f->dlab)f->dll=value;
        if(port==W98_GATE_COM2+2){CHECK(value==0xc7);CHECK(!f->dlab && f->ier==0 && f->dll==1 && f->dlh==0);f->fifo_init=1;f->rx=f->tx=0;}
        if(port==W98_GATE_COM2 && !f->dlab){CHECK(f->fifo_init && f->ier==0 && f->tx<304);f->report[f->tx++]=(uint8_t)value;
            if(f->tx==48){static const uint8_t h[16]={0x57,0x44,0x45,0x31,1,0,4,0,48};CHECK(!memcmp(f->report,h,16) && !memcmp(f->report+16,f->policy+16,32));}
            if(f->tx==304){le32(f->grant,W98_EPOCH_MAGIC);le16(f->grant+4,1);le16(f->grant+6,3);le32(f->grant+8,272);le32(f->grant+12,f->report[48+12]);memcpy(f->grant+16,f->report+48,256);if(f->case_id==9)f->grant[16+48]^=1;
                if(f->case_id==21)f->rom[123]^=1;
                if(f->case_id==22)info.blobs[0].base+=8;
                if(f->case_id==24)gate.config[0][20]^=1;}}
        return 0;
    }
    ++f->forbidden;return -1;
}
static uint64_t now(void *ctx){return ((model_t *)ctx)->ticks;}
static void idle(void *ctx){++((model_t *)ctx)->ticks;}
static w98_gate_port_io_t ports={&m,read_port,write_port,now,idle};
static void blob(unsigned slot,const char *name,const void *p,unsigned bytes)
{strcpy(info.blobs[slot].name,name);info.blobs[slot].base=(uintptr_t)p;info.blobs[slot].size=bytes;}
static void fixture(unsigned roles,unsigned id)
{
    memset(&m,0,sizeof m);memset(&info,0,sizeof info);memset(&caps,0,sizeof caps);memset(&gate,0,sizeof gate);
    memset(&vga,0,sizeof vga);memset(&disk,0,sizeof disk);m.ticks=100;m.case_id=id;m.dlab=128;m.ier=0x0f;m.dll=m.dlh=0xaa;
    info.magic=SHZ_INFO_MAGIC;info.version=SHZ_INFO_VERSION;info.size=sizeof info;info.loader_flags=SHZ_LOADER_NATIVE_WIN98;info.tsc_hz=1000000;caps.hypervisor_bit=1;
    vga.magic=W98_VGA_MAGIC;vga.version=1;vga.bytes=136;vga.flags=1;vga.bdf=16;vga.lfb_base=0xe0000000;vga.lfb_bytes=16u<<20;
    memset(vga.source_sha256,1,32);memset(vga.config_sha256,2,32);memset(m.rom,0x5a,sizeof m.rom);hash(m.rom,sizeof m.rom,vga.rom_sha256);
    disk.magic=W98_PERSIST_CONFIG_MAGIC;disk.version=1;disk.bdf=24;disk.vendor=0x1af4;disk.device=0x1042;disk.esp_bytes=2304ull<<20;disk.member_bytes=2ull<<30;disk.volume_id=0x53485739;
    disk.bar[4]=(w98_persist_bar_t){0xfe000000,4096,W98_PERSIST_BAR_MEM64,0};
    m.pci[0][0]=0x11111234;m.pci[0][1]=3;m.pci[0][2]=0x03000001;m.pci[0][4]=0xe0000008;
    m.pci[1][0]=0x10421af4;m.pci[1][1]=0x00100006;m.pci[1][2]=0x01000001;m.pci[1][8]=0xfe000004;
    be32(m.directory,1);entry(m.directory+4);
    le32(m.policy,W98_GATE_POLICY_MAGIC);le16(m.policy+4,1);le16(m.policy+6,256);le32(m.policy+8,roles);
    memset(m.policy+16,0x7d,32);le64(m.policy+144,123456789000ull);le32(m.policy+152,10000);le16(m.policy+156,W98_GATE_COM2);
    if(roles&1){blob(0,"VGACFG.BIN",&vga,136);blob(1,"VGAROM.BIN",m.rom,65536);hash(&vga,136,m.policy+48);memcpy(m.policy+112,vga.rom_sha256,32);le16(m.policy+160,16);for(unsigned b=0;b<6;b++)le32(m.policy+168+b*4,m.pci[0][b+4]);}
    if(roles&2){blob(2,"W98PERS.BIN",&disk,192);hash(&disk,192,m.policy+80);le16(m.policy+162,24);for(unsigned b=0;b<6;b++)le32(m.policy+192+b*4,m.pci[1][b+4]);}
    le32(m.challenge,W98_EPOCH_MAGIC);le16(m.challenge+4,1);le16(m.challenge+6,1);le32(m.challenge+8,48);memcpy(m.challenge+16,m.policy+16,32);
}
static void refuse(unsigned id)
{CHECK(w98_native_device_gate_with_io(&gate,&info,&caps,&ports)==-1);CHECK(!gate.admitted && !gate.protocol.protocol_admitted && gate.attempted);CHECK(!m.forbidden);printf("refusal%u ",id);}
static void golden(unsigned n,const char *expected)
{uint8_t out[32];char hex[65];memset(m.rom,n==65536?'Z':'a',n);CHECK(!w98_gate_sha256(m.rom,n,out));for(unsigned i=0;i<32;i++)sprintf(hex+i*2,"%02x",out[i]);CHECK(!strcmp(hex,expected));}
int main(void)
{
    CHECK(w98_native_device_gate_with_io!=NULL && w98_gate_sha256!=NULL);
    uint8_t digest[32];static const uint8_t abc[32]={0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    CHECK(!w98_gate_sha256((const uint8_t *)"abc",3,digest) && !memcmp(digest,abc,32));CHECK(w98_gate_sha256(NULL,1,digest)==-1 && w98_gate_sha256(m.rom,65537,digest)==-1);
    golden(0,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    golden(55,"9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
    golden(56,"b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
    golden(64,"ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
    golden(65,"635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0");
    golden(136,"6f0e44b9ce4ea61d52a3479c10f60ef916937f799f11964b7f1c7771063905c4");
    golden(192,"7cee24628d290c16183532716cc5a8a889bc951b4b0a1507c32b8e29cee01052");
    golden(65536,"944044fe482bc4e91085c15c5a923a1b9e02eac98d3bce04997d6dbecd2a5b8d");
    fixture(0,0);CHECK(!w98_native_device_gate_with_io(&gate,&info,&caps,NULL) && !m.reads && !m.writes && !gate.attempted);
    for(unsigned roles=1;roles<=3;roles++){fixture(roles,0);CHECK(!w98_native_device_gate_with_io(&gate,&info,&caps,&ports));CHECK(gate.admitted && gate.protocol.protocol_admitted && !m.forbidden);CHECK(gate.host_deadline_ns==123456789000ull && gate.deadline==10000100);
        if(roles&1){CHECK(gate.snapshots[0].base==(uintptr_t)gate.config[0] && gate.snapshots[1].base==(uintptr_t)gate.rom);CHECK(!memcmp(gate.config[0],&vga,136) && !memcmp(gate.rom,m.rom,65536));m.rom[0]^=1;CHECK(gate.rom[0]!=m.rom[0]);}
        if(roles&2){CHECK(gate.snapshots[2].base==(uintptr_t)gate.config[1] && !memcmp(gate.config[1],&disk,192));}
        CHECK(w98_native_device_gate_with_io(&gate,&info,&caps,&ports)==-1 && !gate.admitted && !gate.protocol.protocol_admitted);}
    for(unsigned id=1;id<=13;id++){fixture(3,id);
        if(id==2)be32(m.directory,129);
        if(id==3){be32(m.directory,2);entry(m.directory+68);}
        if(id==4)m.policy[216]=1;
        if(id==5)((uint8_t *)&vga)[8]^=1;
        if(id==6)m.rom[123]^=1;
        if(id==7)m.policy[168]^=16;
        if(id==8)m.challenge[16]^=1;
        refuse(id);
    }
    fixture(3,0);info.blobs[3]=info.blobs[2];refuse(14);CHECK(!m.reads && !m.writes);
    fixture(3,0);info.blobs[1].size--;refuse(15);CHECK(!m.reads && !m.writes);
    fixture(3,0);caps.hypervisor_bit=0;refuse(16);CHECK(!m.reads && !m.writes);
    fixture(2,0);m.policy[48]=1;refuse(17);
    fixture(3,0);le32(m.policy+192+4*4,0xfe001004);refuse(18);
    fixture(3,0);le64(m.policy+144,0);refuse(19);
    fixture(3,0);le32(m.policy+152,10001);refuse(20);
    for(unsigned id=21;id<=24;id++){fixture(3,id);refuse(id);}
    fixture(3,0);m.directory[12]='X';refuse(25);
    printf("\nPASS %u actual C controls; ports/QMP/nonce authority modeled, no hardware/VM\n",checks);return 0;
}
#else
/* Reuse retained constructor fixture definitions. Its original main is not
 * executed here; real constructor ordering is exercised with new boundaries. */
#define main retained_constructor_main
#define w98_native_device_gate mock_epoch_gate
#define w98_native_device_gate_blob mock_gate_blob
#define w98_l1_vga_init mock_vga_attach
int mock_epoch_gate(const shz_info_t *,const shz_caps_t *);
const shz_blob_t *mock_gate_blob(const char *);
#include "persistence_integration_host.c"
#undef main
#undef w98_native_device_gate
#undef w98_native_device_gate_blob
#undef w98_l1_vga_init
static unsigned gate_calls,vga_calls;
static int gate_failure;
const shz_blob_t *mock_gate_blob(const char *name)
{CHECK(gate_calls==1 && !gate_failure);for(unsigned b=0;b<SHZ_MAX_BLOBS;b++)if(!strcmp(G.info->blobs[b].name,name))return &G.info->blobs[b];return NULL;}
int mock_epoch_gate(const shz_info_t *i,const shz_caps_t *c)
{++gate_calls;CHECK(i==G.info && c && !vmcs_calls && !attach_calls && !vga_calls && ata.status==0x50 && g_dom[SHZ_DOM_WIN98].state!=SHZ_DS_RUNNABLE);return gate_failure?-1:0;}
int mock_vga_attach(w98_l1_vga_t *s,const w98_vga_config_t *c,uint64_t n,const uint8_t *r,uint64_t nr,const w98_vga_ops_t *ops)
{(void)s;(void)c;(void)r;CHECK(gate_calls==1 && !gate_failure && !vmcs_calls && !attach_calls && n==136 && nr==65536 && ops);++vga_calls;return 0;}
int main(int argc,char **argv)
{
    CHECK(argc==2);group=(unsigned)strtoul(argv[1],NULL,10);CHECK(group<=2);
    shz_info_t i={0};shz_caps_t c={0};uint8_t *ram=aligned_alloc(4096,128u<<20),*bios=aligned_alloc(4096,256u<<10),*rom2=aligned_alloc(4096,65536);
    uint8_t *disk2=mmap(0,2ull<<30,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);CHECK(ram && bios && rom2 && disk2!=MAP_FAILED);
    memset(bios,0,256u<<10);i.loader_flags=SHZ_LOADER_NATIVE_WIN98;i.guest_ram_base=(uintptr_t)ram;i.guest_ram_size=128ull<<20;i.disk_base=(uintptr_t)disk2;i.disk_size=2ull<<30;i.tsc_hz=1000000000;c.hypervisor_bit=1;
    strcpy(i.blobs[0].name,"SEABIOS.BIN");i.blobs[0].base=(uintptr_t)bios;i.blobs[0].size=256u<<10;
    w98_vga_config_t v={.magic=W98_VGA_MAGIC,.version=1,.bytes=136,.flags=1,.bdf=16,.lfb_base=0xe0000000,.lfb_bytes=16u<<20};memset(v.rom_sha256,1,32);memset(v.source_sha256,2,32);memset(v.config_sha256,3,32);
    uint8_t p[192] __attribute__((aligned(8)))={0};
    if(group){strcpy(i.blobs[1].name,"VGACFG.BIN");i.blobs[1].base=(uintptr_t)&v;i.blobs[1].size=136;strcpy(i.blobs[2].name,"VGAROM.BIN");i.blobs[2].base=(uintptr_t)rom2;i.blobs[2].size=65536;strcpy(i.blobs[3].name,"W98PERS.BIN");i.blobs[3].base=(uintptr_t)p;i.blobs[3].size=192;}
    G.info=g_info=&i;g_tsc_hz=i.tsc_hz;gate_failure=group==1;
    int rc=win98_domain_create(&i,&c);
    if(group==1){CHECK(rc==-1 && gate_calls==1 && !vga_calls && !vmcs_calls && !attach_calls && g_dom[SHZ_DOM_WIN98].state!=SHZ_DS_RUNNABLE);}
    else{CHECK(!rc && gate_calls==1 && vmcs_calls==1 && attach_calls==(group==2) && vga_calls==(group==2) && g_dom[SHZ_DOM_WIN98].state==SHZ_DS_RUNNABLE);}
    munmap(disk2,2ull<<30);free(rom2);free(bios);free(ram);printf("PASS %u actual constructor ordering controls group%u; physical boundaries mocked\n",checks,group);return 0;
}
#endif
