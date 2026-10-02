/* SPDX-License-Identifier: GPL-2.0-only
 * Actual native I/O/physical/A20 and renderer bodies. Privileged instructions
 * reach bounded callback fixtures; no host device, VM or Windows is executed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#define SHZ_CPU_H
static uint64_t host_rdtsc(void);
static uint64_t host_rdmsr(uint32_t);
static uint8_t host_inb(uint16_t);
static uint16_t host_inw(uint16_t);
static uint32_t host_inl(uint16_t);
static void host_outb(uint16_t,uint8_t);
static void host_outw(uint16_t,uint16_t);
static void host_outl(uint16_t,uint32_t);
static uint64_t injected_qual;
static uint64_t host_vmread(uint64_t f) {return f==0x6400?injected_qual:0;}
#define rdtsc host_rdtsc
#define rdmsr host_rdmsr
#define inb host_inb
#define inw host_inw
#define inl host_inl
#define outb host_outb
#define outw host_outw
#define outl host_outl
#define vmread host_vmread
#include "../win98.c"
#include "../../src/video.c"
#include "vga_fixture.h"
guest_t G;domain_t g_dom[SHZ_MAX_DOMAINS];shz_info_t *g_info;
uint64_t g_tsc_hz;volatile int dev_a20_dirty;void (*dev_uart_tx_hook)(uint8_t);
static unsigned checks,writes,reads,cf8_writes,cfc_writes,owner_seen,map_count;
static int a20=1,uc_failure,map_failure,disable_failure;
static uint32_t selector;static uint16_t dispi_index,dispi_enable=1;
static uint8_t cfg[256],ram[2u<<20],aperture[0x20000];
static uint32_t pixels[640*400],last_out;
static shz_info_t info;static domain_t domain;
static shz_blob_t system_rom;static uint64_t mapped_hpa[32],mapped_flags[32];
static unsigned rip_advances;
static w98_vga_config_t test_binding;
static uint8_t pool_pages[8][4096] __attribute__((aligned(4096)));static unsigned pool_used,vmcs_calls;
static struct {uint32_t g;uint64_t h,p;} mappings[65536];static unsigned mapping_count;
#define CHECK(v) do {++checks;if(!(v)){fprintf(stderr,"FAIL %u: %s\n",__LINE__,#v);return 2;}}while(0)
static uint64_t host_rdtsc(void){return 1000000000ull;}
static uint64_t host_rdmsr(uint32_t n){(void)n;return 0x0007040600070406ull;}
static uint8_t host_inb(uint16_t p){++reads;(void)p;return 0x5a;}
static uint16_t host_inw(uint16_t p){++reads;return p==0x1cf?(dispi_index==4?dispi_enable:dispi_index==0?0xb0c5:256):0xa55a;}
static uint32_t host_inl(uint16_t p){
 if(p==0xcf8)return selector;
 if(p==0xcfc){unsigned bdf=(selector>>8)&0xffff,off=selector&0xfc;
  if(!(selector&0x80000000u)||bdf!=8)return 0xffffffffu;
  return (uint32_t)cfg[off]|(uint32_t)cfg[off+1]<<8|(uint32_t)cfg[off+2]<<16|(uint32_t)cfg[off+3]<<24;}
 ++reads;return 0x12345678;
}
static void host_outb(uint16_t p,uint8_t v){++writes;last_out=(uint32_t)p<<16|v;}
static void host_outw(uint16_t p,uint16_t v){++writes;last_out=(uint32_t)p<<16|v;
 if(p==0x1ce)dispi_index=v;
 if(p==0x1cf&&dispi_index==4&&!disable_failure)dispi_enable=v;
 /* Device programming can only happen after actual global renderer exclusion. */
 if(p==0x1cf){uint32_t before=pixels[0];video_render();if(pixels[0]==before)++owner_seen;}
}
static void host_outl(uint16_t p,uint32_t v){if(p==0xcf8){++cf8_writes;selector=v;}else if(p>=0xcfc&&p<=0xcff)++cfc_writes;else{++writes;last_out=v;}}
void kprintf(const char *f,...){(void)f;}
void log_capture(char *s,unsigned n,const char *f,...){(void)f;if(n)s[0]='x';}
void serial_putc(char c){(void)c;}
void dom_fail(domain_t *d,const char *f,...){(void)f;d->state=SHZ_DS_FAILED;}
void dom_advance_rip(void){++rip_advances;}
void vmx_inject_exception(uint8_t v,int h,uint32_t e){(void)v;(void)h;(void)e;}
void dev_irq_raise(unsigned n){(void)n;}
void dev_init(uint64_t hz,uint64_t n){(void)hz;(void)n;a20=1;}
void dev_native_win98_enable(void){}
void *pool_alloc_pages(unsigned n){if(n!=1||pool_used==8)return NULL;return pool_pages[pool_used++];}
int ept_init(ept_t *e){memset(e,0,sizeof *e);return 0;}
int ept_map(ept_t *e,uint64_t g,uint64_t h,uint64_t n,uint64_t f,int four){(void)e;(void)g;(void)h;(void)n;(void)f;return four==1?0:-1;}
uint64_t ept_pointer(const ept_t *e){(void)e;return 0x1234501e;}
int vmx_vcpu_init(vcpu_t *v,shz_info_t *i,const shz_caps_t *c,const vmx_cfg_t *p){(void)v;(void)i;(void)c;if(p->vpid!=5||p->mode!=VMODE_REAL||p->rip!=0xfff0)return -1;++vmcs_calls;return 0;}
int dev_a20_get(void){return a20;}
const dev_native_observation_t *dev_native_observation(void){return NULL;}
int dev_pio_in(uint16_t p,int n,uint32_t *v){(void)p;(void)n;*v=0xffffffffu;return 1;}
int dev_pio_out(uint16_t p,int n,uint32_t v){(void)p;(void)n;(void)v;return 1;}
void dev_poll(uint64_t n){(void)n;}
int dev_irq_pending(void){return 0;}
uint8_t *dom_gpa_ptr(domain_t *d,uint64_t g,uint64_t n){return g<=d->ram_size&&n<=d->ram_size-g?(uint8_t *)(uintptr_t)(d->ram_base+g):NULL;}
int platform_vga_uc(uint64_t b,uint64_t n){return uc_failure||b!=0xe0000000ull||n!=(16u<<20)?-1:0;}
int ept_remap_page(ept_t *e,uint64_t g,uint64_t h,uint64_t p){(void)e;++map_count;
 if(mapping_count<65536){mappings[mapping_count].g=(uint32_t)g;mappings[mapping_count].h=h;mappings[mapping_count++].p=p;}
 if(g>=0xa0000&&g<0xc0000){mapped_hpa[(g-0xa0000)>>12]=h;mapped_flags[(g-0xa0000)>>12]=p;}
 if(map_failure)return -1;
 return 0;}
void ept_invalidate(void){}
static int setup(void){
 memset(&info,0,sizeof info);memset(&domain,0,sizeof domain);memset(cfg,0,sizeof cfg);
 memset(pixels,0xcc,sizeof pixels);memset(ram,0,sizeof ram);
 cfg[0]=0x34;cfg[1]=0x12;cfg[2]=0x11;cfg[3]=0x11;cfg[4]=3;cfg[0x0b]=3;
 cfg[0x10]=8;cfg[0x13]=0xe0;
 domain.kind=DK_WIN98;domain.id=5;domain.ram_base=(uintptr_t)ram;domain.ram_size=sizeof ram;domain.state=SHZ_DS_RUNNABLE;
 G.info=&info;G.ram_base=domain.ram_base;G.ram_size=domain.ram_size;G.vc=&domain.vc;G.tsc_hz=1000000000ull;
 info.fb_base=(uintptr_t)pixels;info.fb_size=sizeof pixels;info.fb_width=640;info.fb_height=400;info.fb_pitch_pixels=640;info.fb_format=1;
 system_rom.base=(uintptr_t)ram;system_rom.size=0x40000;rom=&system_rom;w98=&domain;
 video_init();
#ifdef SHZ_L1_VGA_H
 test_binding=(w98_vga_config_t){.magic=W98_VGA_MAGIC,.version=1,.bytes=sizeof test_binding,.flags=1,.bdf=8,.lfb_base=0xe0000000ull,.lfb_bytes=16u<<20};
 memcpy(test_binding.rom_sha256,fixture_sha256,32);memset(test_binding.source_sha256,1,32);memset(test_binding.config_sha256,2,32);
 memcpy(info.blobs[0].name,"VGACFG.BIN",11);info.blobs[0].base=(uintptr_t)&test_binding;info.blobs[0].size=sizeof test_binding;
 memcpy(info.blobs[1].name,"VGAROM.BIN",11);info.blobs[1].base=(uintptr_t)fixture_rom;info.blobs[1].size=sizeof fixture_rom;
 shz_caps_t caps={.hypervisor_bit=1};
 CHECK(win98_vga_init(&domain,&info,&caps)==0);
 /* Only the host physical pointer is translated to fixture RAM. Production
  * EPT addresses remain literal L1 A0000; no host I/O is executed. */
 vga.aperture_pointer=aperture;
#endif
 return 0;
}
static int test_ports(void){CHECK(setup()==0);unsigned old=writes;CHECK(output(&domain,0x3c4,2,0x1202)==1);CHECK(writes==old+1&&last_out==0x03c41202u);uint32_t n;CHECK(input(&domain,0x3da,1,&n)==1&&n==0x5a);old=writes;output(&domain,0x3df,2,0xabcd);CHECK(writes==old);output(&domain,0x3c0,4,0x1234);CHECK(writes==old);CHECK(cfc_writes==0);return 0;}
static int test_aperture(void){CHECK(setup()==0);CHECK(physical(&domain,0xa0000,1,1)==aperture);CHECK(physical(&domain,0xbffff,1,0)==aperture+0x1ffff);CHECK(!physical(&domain,0xbffff,2,1));CHECK(!physical(&domain,0x9ffff,2,1));CHECK(physical(&domain,0x9ffff,1,1)==ram+0x9ffff);for(unsigned i=0;i<32;++i){CHECK(mapped_hpa[i]==0xa0000u+(i<<12));CHECK(mapped_flags[i]==(EPT_R|EPT_W|EPT_UC));}return 0;}
static int test_a20(void){CHECK(setup()==0);a20=0;CHECK(physical(&domain,0x1a0000,1,1)==aperture);dev_a20_dirty=1;win98_housekeeping();CHECK(physical(&domain,0x1bffff,1,0)==aperture+0x1ffff);return 0;}
static int test_renderer(void){CHECK(setup()==0);uint32_t before=pixels[0];video_render();CHECK(pixels[0]==before);CHECK(dispi_enable==0&&owner_seen);return 0;}
int main(int argc,char **argv){if(argc!=2)return 3;int n=atoi(argv[1]),rc=n==0?test_ports():n==1?test_aperture():n==2?test_a20():test_renderer();if(!rc)printf("PASS %u native VGA hook checks, no VM\n",checks);return rc;}
