/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "../win98.c"
#undef G
static unsigned checks,map_calls,vmcs_calls;static int map_failure,vmcs_failure,allocation_failure=-1;static uint8_t pages[5][4096] __attribute__((aligned(4096)));static unsigned page_count;
static unsigned generic_reads,native_activations;
domain_t g_dom[SHZ_MAX_DOMAINS];guest_t G;shz_info_t *g_info;uint64_t g_tsc_hz;volatile int dev_a20_dirty;void (*dev_uart_tx_hook)(uint8_t);
#define CHECK(v) do{++checks;if(!(v)){fprintf(stderr,"FAIL line%d: %s\n",__LINE__,#v);exit(2);}}while(0)
void kprintf(const char *format,...){(void)format;}
void log_capture(char *out,unsigned capacity,const char *format,...){(void)format;if(capacity)out[0]='x';}
void serial_putc(char c){(void)c;}
void dev_irq_raise(unsigned n){CHECK(n==14);}
void dev_init(uint64_t hz,uint64_t bytes){CHECK(hz==1000000000ull && bytes==(128ull<<20));}
void dev_native_win98_enable(void){++native_activations;}
const dev_native_observation_t *dev_native_observation(void){return NULL;}
int dev_a20_get(void){return 1;}
uint8_t *dom_gpa_ptr(domain_t *d,uint64_t gpa,uint64_t size){if(gpa>d->ram_size || size>d->ram_size-gpa)return NULL;return (uint8_t *)(uintptr_t)(d->ram_base+gpa);}
int dev_pio_in(uint16_t port,int bytes,uint32_t *value){++generic_reads;if(port==0x40 && bytes==1){*value=0x35;return 1;}return 0;}
void *pool_alloc_pages(unsigned n){CHECK(n==1 && page_count<5);if((int)page_count==allocation_failure)return 0;return pages[page_count++];}
int ept_init(ept_t *e){memset(e,0,sizeof *e);return 0;}
int ept_map(ept_t *e,uint64_t gpa,uint64_t hpa,uint64_t size,uint64_t flags,int four)
{(void)e;++map_calls;CHECK(four==1);if(map_calls==1){CHECK(gpa==0 && hpa==G.info->guest_ram_base && size==(128ull<<20) && flags==(EPT_RWX|EPT_WB));}else if(map_calls==2)CHECK(gpa==0xfffc0000ull && hpa==rom->base && size==(256u<<10) && flags==(EPT_R|EPT_X|EPT_WB));else {CHECK(map_calls==3 && gpa==0xfee00000ull && size==4096 && flags==(EPT_R|EPT_UC));for(unsigned n=0;n<4096;++n)CHECK(((uint8_t *)(uintptr_t)hpa)[n]==255);}return map_calls==(unsigned)map_failure?-1:0;}
uint64_t ept_pointer(const ept_t *e){(void)e;return 0x1234501e;}
int vmx_vcpu_init(vcpu_t *v,shz_info_t *info,const shz_caps_t *caps,const vmx_cfg_t *cfg)
{(void)v;(void)info;(void)caps;++vmcs_calls;CHECK(cfg->mode==VMODE_REAL && cfg->vpid==SHZ_DOM_WIN98 && cfg->cs_sel==0xf000 && cfg->rip==0xfff0 && cfg->rsp==0 && !cfg->cr3 && cfg->eptp==0x1234501e);CHECK(cfg->vmcs && cfg->io_bitmap_a && cfg->io_bitmap_b && cfg->msr_bitmap);return vmcs_failure?-1:0;}
int main(void)
{
 shz_info_t info;shz_caps_t caps;uint8_t *ram=aligned_alloc(4096,128u<<20),*bios=aligned_alloc(4096,256u<<10);
 uint8_t *disk=mmap(0,2ull<<30,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);CHECK(ram && bios && disk!=MAP_FAILED);
 for(unsigned n=0;n<256u<<10;++n)bios[n]=(uint8_t)(n*37+11);
 memset(&info,0,sizeof info);memset(&caps,0,sizeof caps);info.loader_flags=SHZ_LOADER_NATIVE_WIN98;info.guest_ram_base=(uintptr_t)ram;info.guest_ram_size=128ull<<20;info.disk_base=(uintptr_t)disk;info.disk_size=2ull<<30;info.tsc_hz=1000000000ull;memcpy(info.blobs[0].name,"SEABIOS.BIN",12);info.blobs[0].base=(uintptr_t)bios;info.blobs[0].size=256u<<10;G.info=&info;
 w98_config_t config={W98_CONFIG_MAGIC,1,128,0};CHECK(w98_config_valid(&config,sizeof config));CHECK(!w98_config_valid(NULL,sizeof config));config.version=2;CHECK(!w98_config_valid(&config,sizeof config));config.version=1;config.reserved=1;CHECK(!w98_config_valid(&config,sizeof config));config.reserved=0;CHECK(!w98_config_valid(&config,15));
 CHECK(last_render==0);CHECK(win98_domain_create(&info,&caps)==0 && vmcs_calls==1 && map_calls==3);CHECK(native_activations==1);domain_t *d=&g_dom[SHZ_DOM_WIN98];CHECK(d->id==5 && d->kind==DK_WIN98 && d->state==SHZ_DS_RUNNABLE && info.domains[5].state==SHZ_DS_RUNNABLE && d->generation==1);
 CHECK(!memcmp(ram+0xc0000,bios,0x40000));
 CHECK(ram[0xbffff]==0 && ram[0x100000]==0);
 CHECK(!memcmp(ram+0xdf790,bios+0x1f790,64));
 CHECK(!memcmp(ram+0xe0000,bios+0x20000,0x20000));CHECK(ram[0x7000]==0 && ram[0x7001]==0 && ram[0x400]==0);CHECK(ata.disk==disk && ata.bytes==2ull<<30 && ata.sectors==4194304u);CHECK(ata.raise_irq==ata_irq);CHECK(d->fx[0]==0x7f && d->fx[1]==3 && d->fx[24]==0x80 && d->fx[25]==0x1f);
 /* The modeled memory reader agrees with the exact read-only EPT bus window. */
 CHECK(physical(d,0xfee00000u,4096,0)==absent_lapic);
 CHECK(physical(d,0xfee00fffu,1,0)==absent_lapic+4095 && absent_lapic[4095]==255);
 CHECK(physical(d,0xfee00030u,4,0)==absent_lapic+0x30);
 CHECK(!physical(d,0xfee00000u,1,1));CHECK(!physical(d,0xfee00fffu,2,0));
 CHECK(!physical(d,0xfee00000u,4097,0));CHECK(!physical(d,0xfee00000u,0,0));
 CHECK(!physical(d,0xfedfffffu,1,0));CHECK(!physical(d,0xfee01000u,1,0));
 CHECK(!physical(d,0xfec00000u,4,0));CHECK(!physical(d,0xffffffffu,2,0));
 CHECK(physical(d,0xfffc0000u,1,0)==bios && !physical(d,0xfffc0000u,1,1));
 CHECK(physical(d,0x7000u,1,1)==ram+0x7000);
 /* Only the configured 8-bit debug signature changes; wider/other ports and ATA remain exact. */
 uint32_t value=0;unsigned old_reads=generic_reads,old_unhandled=info.io_unhandled;
 CHECK(input(d,0x402,1,&value)==1 && value==0xe9 && generic_reads==old_reads && info.io_unhandled==old_unhandled);
 for(unsigned width=2;width<=4;width+=2){CHECK(input(d,0x402,width,&value)==1 && value==0xffffffffu);++old_reads;++old_unhandled;CHECK(generic_reads==old_reads && info.io_unhandled==old_unhandled);}
 CHECK(input(d,0x403,1,&value)==1 && value==0xffffffffu);++old_reads;++old_unhandled;CHECK(generic_reads==old_reads && info.io_unhandled==old_unhandled);
 CHECK(input(d,0x40,1,&value)==1 && value==0x35);++old_reads;CHECK(generic_reads==old_reads && info.io_unhandled==old_unhandled);
 uint32_t ata_status=0;CHECK(w98_ata_in(&ata,0x1f7,1,&ata_status)==1);
 CHECK(input(d,0x1f7,1,&value)==1 && value==ata_status && generic_reads==old_reads && info.io_unhandled==old_unhandled);
 /* Invalid declared memory/ROM/configuration never constructs or publishes a new VMCS. */
 for(unsigned n=0;n<8;++n){shz_info_t bad=info;unsigned old=vmcs_calls;
  if(n==0)bad.loader_flags=0;else if(n==1)bad.disk_size--;else if(n==2)bad.guest_ram_size=64ull<<20;else if(n==3)bad.guest_ram_base++;else if(n==4)bad.blobs[0].size--;else if(n==5)bad.blobs[0].name[0]='X';else if(n==6)bad.blobs[0].base++;else bad.tsc_hz=999999;
  CHECK(win98_domain_create(&bad,&caps)==-1 && vmcs_calls==old);
 }
 for(unsigned fail=1;fail<=3;++fail){page_count=map_calls=0;map_failure=(int)fail;CHECK(win98_domain_create(&info,&caps)==-1 && vmcs_calls==1);}map_failure=0;
 for(int fail=0;fail<5;++fail){page_count=map_calls=0;allocation_failure=fail;CHECK(win98_domain_create(&info,&caps)==-1 && vmcs_calls==1);}allocation_failure=-1;
 page_count=map_calls=0;vmcs_failure=1;CHECK(win98_domain_create(&info,&caps)==-1 && g_dom[5].state!=SHZ_DS_RUNNABLE);vmcs_failure=0;
 munmap(disk,2ull<<30);free(bios);free(ram);printf("PASS %u exact constructor/config/ROM/absent-page/debugcon host checks (VMX mocked, no VM)\n",checks);return 0;
}
