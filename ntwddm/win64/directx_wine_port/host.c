/* SPDX-License-Identifier: GPL-2.0-only
 * Independent oracles for an actual pinned Wine VS 4.1 bytecode container.
 */
#include "container.h"
#include "vkd3d_shader.h"
#include "vkd3d_shader_private.h"
#include "fixture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"FAIL line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
int main(void)
{
    static const uint32_t tags[] = {0x4e475349,0x4e47534f,0x52444853};
    static const size_t sizes[] = {72,72,240};
    struct wp_dxbc *p = NULL;
    struct vkd3d_shader_signature sig;
    struct vkd3d_shader_code code = {fixture_vs_4_1,sizeof(fixture_vs_4_1)}, serialized = {0};
    struct vkd3d_shader_dxbc_desc d = {0}, reparsed = {0};
    _Alignas(uint32_t) unsigned char mutable[sizeof(fixture_vs_4_1)];
    uint32_t tag;
    const void *bytes;
    size_t size, i, j;
    char *messages = NULL;
    CHECK(sizeof(fixture_vs_4_1)==452);
    CHECK(wp_dxbc_open(fixture_vs_4_1,sizeof(fixture_vs_4_1),&p)==VKD3D_OK && p);
    CHECK(wp_dxbc_sections(p)==3);
    for(i=0;i<3;++i) {
        CHECK(wp_dxbc_section(p,i,&tag,&bytes,&size)==VKD3D_OK);
        CHECK(tag==tags[i] && size==sizes[i]);
        /* Fixture offsets are independently literal, not parser-derived. */
        CHECK(!memcmp(bytes,(const char *)fixture_vs_4_1+(i==0?52:i==1?132:212),size));
    }
    CHECK(wp_dxbc_section(p,3,&tag,&bytes,&size)==VKD3D_ERROR_INVALID_ARGUMENT);
    CHECK(!tag && !bytes && !size);
    wp_dxbc_close(p); p=NULL;
    CHECK(vkd3d_shader_parse_input_signature(&code,&sig,&messages)==VKD3D_OK);
    CHECK(sig.element_count==2);
    CHECK(!strcmp(sig.elements[0].semantic_name,"POSITION"));
    CHECK(!strcmp(sig.elements[1].semantic_name,"NORMAL"));
    CHECK(sig.elements[0].register_index==0 && sig.elements[0].mask==15);
    CHECK(sig.elements[1].register_index==1 && sig.elements[1].mask==7);
    vkd3d_shader_free_shader_signature(&sig); vkd3d_shader_free_messages(messages);
    messages=NULL;
    CHECK(vkd3d_shader_parse_dxbc(&code,0,&d,&messages)==VKD3D_OK);
    CHECK(vkd3d_shader_serialize_dxbc(d.section_count,d.sections,&serialized,NULL)==VKD3D_OK);
    CHECK(vkd3d_shader_parse_dxbc(&serialized,0,&reparsed,NULL)==VKD3D_OK);
    CHECK(reparsed.section_count==3 && reparsed.version==1);
    for(i=0;i<3;++i) {
        CHECK(reparsed.sections[i].tag==tags[i] && reparsed.sections[i].data.size==sizes[i]);
        CHECK(!memcmp(reparsed.sections[i].data.code,d.sections[i].data.code,sizes[i]));
    }
    vkd3d_shader_free_dxbc(&reparsed); vkd3d_shader_free_dxbc(&d);
    vkd3d_shader_free_shader_code(&serialized); vkd3d_shader_free_messages(messages);
    /* Every truncation and every one-byte checksum mutation is rejected. */
    for(i=0;i<sizeof(fixture_vs_4_1);++i) {
        p=(struct wp_dxbc *)1;
        CHECK(wp_dxbc_open(fixture_vs_4_1,i,&p)<0 && !p);
        memcpy(mutable,fixture_vs_4_1,sizeof(mutable)); mutable[i]^=1;
        p=(struct wp_dxbc *)1;
        CHECK(wp_dxbc_open(mutable,sizeof(mutable),&p)<0 && !p);
    }
    /* Recompute checksums after corrupting structural fields, so these
     * exercise the genuine parser bounds rather than its checksum gate. */
    for(i=0;i<3;++i) {
        uint32_t *words=(uint32_t *)mutable;
        memcpy(mutable,fixture_vs_4_1,sizeof(mutable));
        words[8+i]=0xfffffffcu;
        vkd3d_compute_md5(mutable+20,sizeof(mutable)-20,words+1,VKD3D_MD5_DXBC);
        CHECK(wp_dxbc_open(mutable,sizeof(mutable),&p)<0 && !p);
    }
    memcpy(mutable,fixture_vs_4_1,sizeof(mutable));
    CHECK(wp_dxbc_open(mutable,sizeof(mutable),&p)==0);
    memset(mutable,0,sizeof(mutable));
    CHECK(wp_dxbc_section(p,0,&tag,&bytes,&size)==0 && tag==tags[0] && size==72);
    CHECK(!memcmp(bytes,(const char *)fixture_vs_4_1+52,72));
    wp_dxbc_close(p);
    for(j=0;j<32;++j) { CHECK(wp_dxbc_open(fixture_vs_4_1,sizeof(fixture_vs_4_1),&p)==0); wp_dxbc_close(p); }
    CHECK(wp_dxbc_open(NULL,0,&p)<0 && !p);
    CHECK(wp_dxbc_open(fixture_vs_4_1,WP_DXBC_MAX_BYTES+1,&p)<0 && !p);
    CHECK(wp_dxbc_open(fixture_vs_4_1,sizeof(fixture_vs_4_1),NULL)<0);
    wp_dxbc_close(NULL);
    printf("GENUINE_DXBC checks=%u fixture_bytes=%zu sections=3 input_semantics=POSITION,NORMAL normal_cleanup=1 PASS\n",checks,sizeof(fixture_vs_4_1));
    return 0;
}
