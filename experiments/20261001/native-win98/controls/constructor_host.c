/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "constructor-body.c"
#undef G
static unsigned checks,map_calls,vmcs_calls;static int map_failure,vmcs_failure;static uint8_t pages[4][4096] __attribute__((aligned(4096)));static unsigned page_count;
domain_t g_dom[SHZ_MAX_DOMAINS];guest_t G;shz_info_t *g_info;uint64_t g_tsc_hz;volatile int dev_a20_dirty;void (*dev_uart_tx_hook)(uint8_t);
#define CHECK(v) do{++checks;if(!(v)){fprintf(stderr,"FAIL line%d: %s\n",__LINE__,#v);exit(2);}}while(0)
void kprintf(const char *format,...){(void)format;}
void log_capture(char *out,unsigned capacity,const char *format,...){(void)format;if(capacity)out[0]='x';}
void serial_putc(char c){(void)c;}
void dev_irq_raise(unsigned n){CHECK(n==14);}
void dev_init(uint64_t hz,uint64_t bytes){CHECK(hz==1000000000ull && bytes==(128ull<<20));}
void *pool_alloc_pages(unsigned n){CHECK(n==1 && page_count<4);return pages[page_count++];}
int ept_init(ept_t *e){memset(e,0,sizeof *e);return 0;}
int ept_map(ept_t *e,uint64_t gpa,uint64_t hpa,uint64_t size,uint64_t flags,int four)
{(void)e;++map_calls;CHECK(four==1);if(map_calls==1){CHECK(gpa==0 && hpa==G.info->guest_ram_base && size==(128ull<<20) && flags==(EPT_RWX|EPT_WB));}else CHECK(gpa==0xfffc0000ull && hpa==rom->base && size==(256u<<10) && flags==(EPT_R|EPT_X|EPT_WB));return map_failure?-1:0;}
uint64_t ept_pointer(const ept_t *e){(void)e;return 0x1234501e;}
int vmx_vcpu_init(vcpu_t *v,shz_info_t *info,const shz_caps_t *caps,const vmx_cfg_t *cfg)
{(void)v;(void)info;(void)caps;++vmcs_calls;CHECK(cfg->mode==VMODE_REAL && cfg->vpid==SHZ_DOM_WIN98 && cfg->cs_sel==0xf000 && cfg->rip==0xfff0 && cfg->rsp==0 && !cfg->cr3 && cfg->eptp==0x1234501e);CHECK(cfg->vmcs && cfg->io_bitmap_a && cfg->io_bitmap_b && cfg->msr_bitmap);return vmcs_failure?-1:0;}
int main(void)
{
 shz_info_t info;shz_caps_t caps;uint8_t *ram=aligned_alloc(4096,128u<<20),*bios=aligned_alloc(4096,256u<<10);
 uint8_t *disk=mmap(0,2ull<<30,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);CHECK(ram && bios && disk!=MAP_FAILED);
 for(unsigned n=0;n<256u<<10;++n)bios[n]=(uint8_t)(n*37+11);
 memset(&info,0,sizeof info);memset(&caps,0,sizeof caps);info.loader_flags=SHZ_LOADER_NATIVE_WIN98;info.guest_ram_base=(uintptr_t)ram;info.guest_ram_size=128ull<<20;info.disk_base=(uintptr_t)disk;info.disk_size=2ull<<30;info.tsc_hz=1000000000ull;memcpy(info.blobs[0].name,"SEABIOS.BIN",12);info.blobs[0].base=(uintptr_t)bios;info.blobs[0].size=256u<<10;G.info=&info;
 w98_config_t config={W98_CONFIG_MAGIC,1,128,0};CHECK(w98_config_valid(&config,sizeof config));config.version=2;CHECK(!w98_config_valid(&config,sizeof config));config.version=1;config.reserved=1;CHECK(!w98_config_valid(&config,sizeof config));config.reserved=0;CHECK(!w98_config_valid(&config,15));
 CHECK(last_render==0);CHECK(win98_domain_create(&info,&caps)==0 && vmcs_calls==1 && map_calls==2);domain_t *d=&g_dom[SHZ_DOM_WIN98];CHECK(d->id==5 && d->kind==DK_WIN98 && d->state==SHZ_DS_RUNNABLE && info.domains[5].state==SHZ_DS_RUNNABLE && d->generation==1);
 CHECK(!memcmp(ram+0xe0000,bios+0x20000,0x20000));CHECK(ram[0x7000]==0 && ram[0x7001]==0 && ram[0x400]==0);CHECK(ata.disk==disk && ata.bytes==2ull<<30 && ata.sectors==4194304u);CHECK(ata.raise_irq==ata_irq);CHECK(d->fx[0]==0x7f && d->fx[1]==3 && d->fx[24]==0x80 && d->fx[25]==0x1f);
 /* Invalid declared memory/ROM/configuration never constructs or publishes a new VMCS. */
 for(unsigned n=0;n<7;++n){shz_info_t bad=info;unsigned old=vmcs_calls;
  if(n==0)bad.loader_flags=0;else if(n==1)bad.disk_size--;else if(n==2)bad.guest_ram_size=64ull<<20;else if(n==3)bad.guest_ram_base++;else if(n==4)bad.blobs[0].size--;else if(n==5)bad.blobs[0].name[0]='X';else bad.blobs[0].base++;
  CHECK(win98_domain_create(&bad,&caps)==-1 && vmcs_calls==old);
 }
 page_count=map_calls=0;map_failure=1;CHECK(win98_domain_create(&info,&caps)==-1 && vmcs_calls==1);map_failure=0;
 page_count=map_calls=0;vmcs_failure=1;CHECK(win98_domain_create(&info,&caps)==-1 && g_dom[5].state!=SHZ_DS_RUNNABLE);vmcs_failure=0;
 munmap(disk,2ull<<30);free(bios);free(ram);printf("PASS %u exact constructor/config/ROM-mapping host checks (VMX mocked, no VM)\n",checks);return 0;
}
