/* SPDX-License-Identifier: GPL-2.0-only -- static actual compiled input gate */
#include "fixture_contract.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do { checks++; if(!(x)) { fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while(0)
int main(int argc,char **argv)
{
    FILE *f; long bytes; uint8_t *data,*copy; np_image p; const uint8_t *raw; uint32_t count=0,i; const char *error=NULL;
    CHECK(argc==2); f=fopen(argv[1],"rb"); CHECK(f);
    CHECK(!fseek(f,0,SEEK_END)); bytes=ftell(f); CHECK(bytes>=64 && bytes<=1024*1024);
    CHECK(!fseek(f,0,SEEK_SET)); data=malloc((size_t)bytes); copy=malloc((size_t)bytes); CHECK(data && copy);
    CHECK(fread(data,1,(size_t)bytes,f)==(size_t)bytes); CHECK(!fclose(f)); memcpy(copy,data,(size_t)bytes);
    CHECK(np_parse(&p,data,(uint32_t)bytes,&error)); CHECK(np_runtime_profile(&p,&error));
    CHECK(np_imports(&p,0,NULL,NULL,&count,&error) && count==0);
    CHECK(ci_fixture_zero_imports(&p)); CHECK(!memcmp(data,copy,(size_t)bytes));
    if(p.directory[1][0]) {
        CHECK(p.directory[1][1]==20); raw=np_raw(&p,p.directory[1][0],20); CHECK(raw);
        for(i=0;i<20;i++) {
            uint8_t *byte=data+(raw-data)+i; CHECK(*byte==0); *byte=1;
            CHECK(!ci_fixture_zero_imports(&p)); *byte=0;
        }
        p.directory[1][1]=24; CHECK(!ci_fixture_zero_imports(&p)); p.directory[1][1]=20;
        { uint32_t rva=p.directory[1][0]; p.directory[1][0]=p.size-1; CHECK(!ci_fixture_zero_imports(&p)); p.directory[1][0]=rva; }
    }
    p.directory[1][0]=0; p.directory[1][1]=0; CHECK(ci_fixture_zero_imports(&p));
    p.directory[1][1]=20; CHECK(!ci_fixture_zero_imports(&p)); CHECK(!memcmp(data,copy,(size_t)bytes));
    free(copy); free(data);
    printf("PASS COMPILED_FIXTURE_ZERO_IMPORT_PROTOCOL_CHECKS=%u NATIVE_EXECUTED=0\n",checks); return 0;
}
