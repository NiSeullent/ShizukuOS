/* SPDX-License-Identifier: GPL-2.0-only
 * Reuse actual policy/serial grant controls; no physical authorization modeled. */
#define main gate_controls_main
#include "native_device_gate_host.c"
#undef main
int main(void)
{
    uint32_t words[40],before[40];
    CHECK(w98_native_device_gate_gop_words(words)==-1); /* production lifetime absent */
    fixture(0,0);CHECK(w98_native_gate_gop_words(&gate,words)==-1);
    fixture(2,0);CHECK(!w98_native_device_gate_with_io(&gate,&info,&caps,&ports));
    CHECK(w98_native_gate_gop_words(&gate,words)==-1); /* storage alone */
    fixture(3,0);CHECK(!w98_native_device_gate_with_io(&gate,&info,&caps,&ports));
    unsigned reads=m.reads,writes=m.writes;
    CHECK(!w98_native_gate_gop_words(&gate,words));
    CHECK(words[7]==16 && words[8]==0x11111234 && words[9]==0x030000);
    CHECK(words[10]==m.pci[0][4]);
    CHECK(!memcmp(words+16,m.policy+16,32));
    CHECK(!memcmp(words+24,m.policy+48,32));
    CHECK(!memcmp(words+32,m.policy+112,32));
    memcpy(before,words,sizeof words);
    CHECK(!w98_native_gate_gop_words(&gate,words) && !memcmp(before,words,sizeof words));
    CHECK(m.reads==reads && m.writes==writes); /* zero control/PCI/display writes */
    CHECK(w98_native_device_gate_gop_words(words)==-1); /* modeled object never promotes global */
    gate.admitted=0;CHECK(w98_native_gate_gop_words(&gate,words)==-1);gate.admitted=1;
    gate.protocol.protocol_admitted=0;CHECK(w98_native_gate_gop_words(&gate,words)==-1);gate.protocol.protocol_admitted=1;
    gate.protocol.nonce_consumed=0;CHECK(w98_native_gate_gop_words(&gate,words)==-1);gate.protocol.nonce_consumed=1;
    gate.protocol.state=W98_EPOCH_FAILED;CHECK(w98_native_gate_gop_words(&gate,words)==-1);gate.protocol.state=W98_EPOCH_ADMITTED;
    uint8_t nonce[32];memcpy(nonce,gate.protocol.expected.nonce,32);memset(gate.protocol.expected.nonce,0,32);
    CHECK(w98_native_gate_gop_words(&gate,words)==-1);memcpy(gate.protocol.expected.nonce,nonce,32);
    gate.config[0][0]^=1;CHECK(w98_native_gate_gop_words(&gate,words)==-1);gate.config[0][0]^=1;
    gate.rom[65535]^=1;CHECK(w98_native_gate_gop_words(&gate,words)==-1);gate.rom[65535]^=1;
    gate.protocol.expected.device[1]=gate.protocol.expected.device[0];CHECK(w98_native_gate_gop_words(&gate,words)==-1);
    CHECK(w98_native_gate_gop_words(NULL,words)==-1 && w98_native_gate_gop_words(&gate,NULL)==-1);
    printf("PASS %u actual C epoch controls; native current VMCS not executed\n",checks);
    return 0;
}
