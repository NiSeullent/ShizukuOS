/* SPDX-License-Identifier: GPL-2.0-only
 * A real C++ caller links the C implementation with the public browser header.
 */
#include "delay_runtime.h"
int main()
{
 const char *error=nullptr;uint32_t address=0;
 if(ntw_delay_init(nullptr,nullptr,nullptr,0,0,nullptr,&error))return 1;
 if(ntw_delay_resolve(nullptr,0,0,&address,&error))return 2;
 if(ntw_delay_dispose(nullptr,1,&error))return 3;
 return error&&address==0?0:4;
}
