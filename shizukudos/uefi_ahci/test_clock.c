/* SPDX-License-Identifier: GPL-2.0-only */
#include "layout.h"
#include <assert.h>
#include <stdio.h>
int main(void)
{
    uint64_t random=UINT64_C(0xd02739a0406138ff);
    const uint64_t values[]={0,1,UINT32_MAX,UINT64_C(1)<<32,UINT64_MAX};
    const uint32_t divisors[]={1,2,3,10,1000,UINT32_MAX};
    unsigned i,j;
    assert(sdahci_divide(0,0)==UINT64_MAX);
    for(i=0;i<sizeof(values)/sizeof(values[0]);++i)
        for(j=0;j<sizeof(divisors)/sizeof(divisors[0]);++j)
            assert(sdahci_divide(values[i],divisors[j])==values[i]/divisors[j]);
    for(i=0;i<100000;++i) {
        uint32_t divisor;
        random=random*UINT64_C(6364136223846793005)+1;
        divisor=(uint32_t)(random>>16)|1;
        assert(sdahci_divide(random,divisor)==random/divisor);
    }
    puts("PASS: 100031 AHCI test-clock division cases against native division");
    return 0;
}
