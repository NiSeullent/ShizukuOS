/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <string.h>
#include "../../loader/bootini.h"
#define CHECK(v) do {++checks;if(!(v)){fprintf(stderr,"FAIL line%u: %s\n",__LINE__,#v);return 2;}}while(0)
int main(void){unsigned checks=0;bootini_policy_t p;char error[128];
 const char *yes="mode=supervisor\nwin98_vga=yes\n";
 CHECK(bootini_parse(yes,strlen(yes),&p,error,sizeof error)==0);
#ifdef BOOTINI_WIN98_VGA
 CHECK(p.win98_vga==1&&p.win98_vga_set==1);
 const char *bad[]={"win98_vga=yes\n","mode=csm\nwin98_vga=yes\n","mode=supervisor\nwin98_vga=yes\nWIN98_VGA=no\n","mode=supervisor\nwin98_vga=maybe\n"};
 for(unsigned i=0;i<sizeof bad/sizeof bad[0];++i)CHECK(bootini_parse(bad[i],strlen(bad[i]),&p,error,sizeof error)>0);
 CHECK(bootini_parse("",0,&p,error,sizeof error)==0&&!p.win98_vga&&!p.win98_vga_set);
 const char *no="mode=auto\nwin98_vga=no\n";
 CHECK(bootini_parse(no,strlen(no),&p,error,sizeof error)==0&&!p.win98_vga&&p.win98_vga_set);
#endif
 printf("PASS %u explicit VGA loader policy checks, no firmware/VM\n",checks);return 0;}
