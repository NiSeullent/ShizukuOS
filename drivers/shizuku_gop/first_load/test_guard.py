#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run actual guard C with modeled HC14/map services; no VM/runtime proof."""
import ctypes,json,shutil,struct,subprocess,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
from test_contract import descriptor,anchor
HARNESS=r'''
#include <stdint.h>
#include <stdio.h>
#include "guard.c"
unsigned char ntwv_text_begin[1],ntwv_text_last[1],ntwv_data_begin[1],ntwv_data_last[1];
static unsigned char model_rom[65536],model_descriptor[4096];
static uint32_t model_words[40],model_fail,model_change,model_calls,model_maps,model_signature=1;
void ntwv_cpuid(uint32_t leaf,uint32_t r[4]){r[0]=r[1]=r[2]=r[3]=0;if(!model_signature)return;
 if(leaf==1)r[2]=0x80000000u;else{r[1]=0x5a485353;r[2]=0x4d4d5675;r[3]=0x30312d76;}}
int32_t ntwv_vmcall(uint32_t op,uint32_t index,uint32_t version,uint32_t *word,uint32_t *n){
 model_calls++;if(op!=14 || index>=40 || version!=1 || model_fail)return -3;
 *word=model_words[index];*n=40;if(model_change && model_calls>40 && index==16)*word^=1;return 0;}
uint32_t ntwv_vmm_map_phys(uint32_t at,uint32_t n,uint32_t flags){model_maps++;if(flags)return 0;
 if(at==0xf0000 && n==65536)return (uint32_t)(uintptr_t)model_rom;
 if(at==0x800000 && n==4096)return (uint32_t)(uintptr_t)model_descriptor;return 0;}
uint32_t ntwv_vmm_check(uint32_t a,uint32_t b,uint32_t c){(void)a;(void)b;(void)c;return 0;}
uint32_t ntwv_vmm_lock(uint32_t a,uint32_t b,uint32_t c){(void)a;(void)b;(void)c;return 0;}
uint32_t ntwv_vmm_unlock(uint32_t a,uint32_t b,uint32_t c){(void)a;(void)b;(void)c;return 0;}
uint32_t ntwv_vmm_ptes(uint32_t a,uint32_t b,uint32_t*c,uint32_t d){(void)a;(void)b;(void)c;(void)d;return 0;}
uint32_t ntwv_irq_enter(void *p){(void)p;return 0;}void ntwv_irq_leave(void*p,uint32_t n){(void)p;(void)n;}
int main(void){return 0;}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='shzguard-controls-') as tmp:
        w=Path(tmp);lane=w/'first_load';lane.mkdir()
        for n in ('guard.c','contract.h'):shutil.copyfile(HERE/n,lane/n)
        shutil.copyfile(HERE.parent/'gop_contract.h',w/'gop_contract.h')
        (lane/'provider.h').write_text('static const unsigned char shzguard_provider[32]={1};\n')
        # Non-PIE executable keeps modeled static addresses representable by
        # the real Win9x32-bit MapPhysToLinear return ABI. No alias writes tested.
        raw=HARNESS+'''\nint observe(const unsigned char *r,const unsigned char *d,const uint32_t *words,uint32_t fail,uint32_t change,uint32_t sig){
 copy(model_rom,r,65536);copy(model_descriptor,d,96);copy(model_words,words,160);
 model_fail=fail;model_change=change;model_signature=sig;model_calls=model_maps=0;
 rom=descriptor=0;descriptor_address=0;unsigned char out[352];return snapshot(out);
}\n'''
        # Build executable harness with fixture inputs per case; production
        # snapshot source is identical and stubs model only external services.
        d=descriptor(location=0x10000000);r=bytearray(65536);r[4096:4144]=anchor(d)
        words=[0x31455047,1,40,5,1,0,3,16,0x11111234,0x030000]+[0xe0000008,0,0,0,0,0]+[0x7d7d7d7d]*24
        fixtures='\nstatic const unsigned char test_rom[]={'+','.join(map(str,r))+'};\nstatic const unsigned char test_desc[]={'+','.join(map(str,d))+'};\n'
        raw=raw.replace('int main(void){return 0;}','')+fixtures+'''\nint main(void){uint32_t words[40]={WORDS};int checks=0;
#define CHECK(v) do{checks++;if(!(v))return checks;}while(0)
 CHECK(observe(test_rom,test_desc,words,0,0,1)==1);
 unsigned char again[352];CHECK(snapshot(again)==1 && model_maps==2);
 CHECK(ntwv_native_exit()==0 && closing && rom && descriptor);
 struct dioc blocked={0};CHECK(ntwv_native_dioc(&blocked)==21);closing=0;
 CHECK(observe(test_rom,test_desc,words,1,0,1)==0);
 CHECK(observe(test_rom,test_desc,words,0,1,1)==0);
 CHECK(observe(test_rom,test_desc,words,0,0,0)==0);
 for(unsigned i=0;i<10;i++){uint32_t old=words[i];words[i]^=0x80000000u;
  if(i!=4)CHECK(observe(test_rom,test_desc,words,0,0,1)==0);words[i]=old;}
 words[4]=0;CHECK(observe(test_rom,test_desc,words,0,0,1)==0);words[4]=1;
 words[10]^=0x1000;CHECK(observe(test_rom,test_desc,words,0,0,1)==0);words[10]^=0x1000;
 for(unsigned i=16;i<24;i++)words[i]=0;CHECK(observe(test_rom,test_desc,words,0,0,1)==0);
 printf("%d\\n",checks);return 0;}\n'''.replace('WORDS',','.join(map(str,words)))
        (lane/'harness.c').write_text(raw)
        cmd=['gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-misleading-indentation','-fno-pie','-no-pie',str(lane/'harness.c'),'-o',str(w/'controls')]
        subprocess.run(cmd,check=True);checks=int(subprocess.check_output([w/'controls'],text=True))
        print(json.dumps(dict(status='PASS_ACTUAL_GUARD_C_MODELED_EXTERNAL_SERVICES',checks=checks,VM_executed=False,default_changed=False)))
if __name__=='__main__':main()
