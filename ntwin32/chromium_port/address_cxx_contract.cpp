/* SPDX-License-Identifier: GPL-2.0-only */
#include "address_wait.h"
#include "api_contract.h"
int main()
{
 aw_context context{};ac_target target{};ac_route route{};uint32_t error=0;
 if(aw_init(&context,nullptr)||aw_wait(&context,nullptr,nullptr,0,0,&error)||error!=AW_INVALID_PARAMETER)return 1;
 if(ac_init(&target,nullptr,0)||ac_lookup(&target,nullptr,nullptr,0,&route)||route.kind)return 2;
 return 0;
}
