/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <string.h>
#include "../../loader/bootini.h"
#define CHECK(v) do {++checks;if(!(v)){fprintf(stderr,"FAIL line%u: %s\n",__LINE__,#v);return 2;}}while(0)
int main(void)
{
    unsigned checks=0;bootini_policy_t p;char error[160];
    const char *yes="mode=supervisor\nwin98_persistence=yes\n";
    CHECK(!bootini_parse(yes,strlen(yes),&p,error,sizeof error));
#ifdef BOOTINI_WIN98_PERSISTENCE
    CHECK(p.win98_persistence && p.win98_persistence_set);
    CHECK(!p.win98_vga && !p.win98_vga_set);
    CHECK(!bootini_parse("",0,&p,error,sizeof error));
    CHECK(!p.win98_persistence && !p.win98_persistence_set && !p.win98_vga);
    const char *no="mode=auto\nwin98_persistence=no\n";
    CHECK(!bootini_parse(no,strlen(no),&p,error,sizeof error));
    CHECK(!p.win98_persistence && p.win98_persistence_set);
    const char *bad[]={"win98_persistence=yes\n","mode=csm\nwin98_persistence=yes\n",
      "mode=supervisor\nwin98_persistence=yes\nWIN98_PERSISTENCE=no\n",
      "mode=supervisor\nwin98_persistence=maybe\n","mode=kernel64\nwin98_persistence=yes\n"};
    for(unsigned i=0;i<sizeof bad/sizeof bad[0];++i)CHECK(bootini_parse(bad[i],strlen(bad[i]),&p,error,sizeof error)>0);
    const char *both="mode=supervisor\nwin98_vga=yes\nwin98_persistence=yes\n";
    CHECK(!bootini_parse(both,strlen(both),&p,error,sizeof error));
    CHECK(p.win98_vga && p.win98_persistence);
#endif
    printf("PASS %u real persistence loader policy checks; no firmware/VM\n",checks);return 0;
}
