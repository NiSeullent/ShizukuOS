/* SPDX-License-Identifier: GPL-2.0-only
 * producer-b11: run the REAL native_input.c W98INPT.BIN parser over bytes the
 * host producer generated. argv: <W98INPT.BIN> <256-byte fw_cfg policy>.
 * Gate words 16..31 are derived from policy bytes 16..79 exactly as
 * native_device_gate.c w98_native_gate_gop_words() derives them (LE u32 of the
 * admitted nonce and VGA config SHA). Prints ADMIT flags=<n> or REFUSE. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../../src/devices.c"
#include "../native_input.c"
static long slurp(const char *path,uint8_t *buf,long max)
{FILE *f=fopen(path,"rb");if(!f)return -1;long n=(long)fread(buf,1,(size_t)max,f);fclose(f);return n;}
int main(int argc,char **argv)
{
    uint8_t blob[200],policy[300];uint32_t w[40];w98_input_policy_t out;
    if(argc!=3)return 3;
    long nb=slurp(argv[1],blob,sizeof blob),np=slurp(argv[2],policy,sizeof policy);
    if(nb<0 || np!=256)return 4;
    memset(w,0,sizeof w);
    for(unsigned i=0;i<16;i++)w[16+i]=policy[16+i*4]|(uint32_t)policy[17+i*4]<<8|(uint32_t)policy[18+i*4]<<16|(uint32_t)policy[19+i*4]<<24;
    memset(&out,0xcc,sizeof out);
    if(w98_input_policy_admit(blob,(uint64_t)nb,w,&out)){printf("REFUSE\n");return 0;}
    if(memcmp(&out,blob,sizeof out))return 5;
    printf("ADMIT flags=%u machine=%u\n",out.flags,out.machine);return 0;
}
