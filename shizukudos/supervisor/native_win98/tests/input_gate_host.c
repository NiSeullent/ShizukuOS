/* SPDX-License-Identifier: GPL-2.0-only
 * producer-b11: actual native_device_gate.c input-option binding (policy bytes
 * 216..247 = SHA-256 of the exact W98INPT.BIN). Reuses the modeled fw_cfg/COM2/PCI
 * harness; no hardware, VM or guest input is executed. */
#define main gate_controls_main
#include "native_device_gate_host.c"
#undef main
static uint8_t input[96];
static void with_input(unsigned roles,int in_policy,int blob_slot)
{
    fixture(roles,0);memset(input,0,sizeof input);
    le32(input,0x4e493957u);le16(input+4,1);le16(input+6,96);le32(input+8,3);le32(input+12,1);
    memcpy(input+16,m.policy+16,32);memcpy(input+48,m.policy+48,32);
    if(in_policy)hash(input,96,m.policy+216);
    if(blob_slot>=0)blob((unsigned)blob_slot,"W98INPT.BIN",input,96);
}
int main(void)
{
    /* selected: field + blob, frozen copy retained, loader buffer mutation not observed */
    with_input(1,1,3);CHECK(!w98_native_device_gate_with_io(&gate,&info,&caps,&ports));CHECK(gate.admitted && !m.forbidden);
    CHECK(gate.snapshots[3].base==(uintptr_t)gate.input && gate.snapshots[3].size==96 && !memcmp(gate.input,input,96));
    input[20]^=1;CHECK(gate.input[20]!=input[20]);
    with_input(3,1,3);CHECK(!w98_native_device_gate_with_io(&gate,&info,&caps,&ports));CHECK(gate.admitted);
    /* absent option: unchanged default admission and no snapshot */
    with_input(1,0,-1);CHECK(!w98_native_device_gate_with_io(&gate,&info,&caps,&ports));CHECK(gate.admitted && !gate.snapshots[3].size);
    with_input(1,0,3);refuse(101);              /* blob without the sealed policy option */
    with_input(1,1,-1);refuse(102);             /* policy option without the blob */
    with_input(1,1,3);m.policy[216]^=1;refuse(103);  /* wrong SHA */
    with_input(1,1,3);input[80]=1;refuse(104);  /* blob altered after sealing */
    with_input(1,1,3);blob(4,"W98INPT.BIN",input,96);refuse(105);CHECK(!m.reads && !m.writes); /* duplicate file */
    with_input(1,1,3);info.blobs[3].size=95;refuse(106);CHECK(!m.reads && !m.writes);
    with_input(2,1,3);refuse(107);CHECK(!m.reads && !m.writes); /* input without the VGA pair */
    with_input(1,1,3);m.policy[248]=1;refuse(108);   /* 248..255 stay zero */
    printf("\nPASS %u actual gate input-option controls; modeled ports, no VM\n",checks);return 0;
}
