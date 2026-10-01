/* SPDX-License-Identifier: GPL-2.0-only
 * Fresh-nonce actual guest ABI/pixel/lifetime acceptance for the private Mesa
 * resource backend. This is not a D3D11 application, DXGI or native Win98 pass.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "backend.h"
#include "trial_nonce.h"
static unsigned checks,failures,paints,visible_pixels;
static HANDLE output;
static int output_ok=1;
static uint8_t image[32*32*4];
static void *volatile relocation_anchor=&checks;
static char buffer[512];static unsigned used;
static void zero(void *p,SIZE_T n){uint8_t *b=p;while(n--)*b++=0;}
static void text(const char *s){while(*s){DWORD done;char c=*s++;if(used==sizeof(buffer)){output_ok=0;used=0;}buffer[used++]=c;if(c=='\n'){if(!WriteFile(output,buffer,used,&done,0)||done!=used)output_ok=0;used=0;}}}
static void number(unsigned n){char b[12];unsigned count=0,i;do{b[count++]=(char)('0'+n%10);n/=10;}while(n);for(i=0;i<count/2;i++){char c=b[i];b[i]=b[count-1-i];b[count-1-i]=c;}b[count]=0;text(b);}
static void check(int success,const char *name){checks++;if(!success)failures++;text(success?"NTG64 PASS ":"NTG64 FAIL ");text(name);text("\r\n");}
typedef struct {void *heap;SIZE_T live;} owner;
static void *allocate(void *u,size_t n){owner *o=u;void *p=HeapAlloc(o->heap,0,n);if(p)o->live++;return p;}
static void deallocate(void *u,void *p){owner *o=u;if(p){if(HeapFree(o->heap,0,p))o->live--;else{failures++;text("NTG64 FAIL heap_free\r\n");}}}
typedef double (*unary_math)(double);
typedef double (*binary_math)(double,double);
typedef double (*ldexp_math)(double,int);
static unary_math math_one[9];static binary_math math_pow;static ldexp_math math_ldexp;
static int math_provider(void *u,uint32_t op,double x,double y,double *out){(void)u;if(op<1||op>8)return 1;if(op==M98_SP_MATH_POW){*out=math_pow(x,y);return 0;}if(op==M98_SP_MATH_LDEXP){*out=math_ldexp(x,(int)y);return 0;}if(!math_one[op])return 1;*out=math_one[op](x);return 0;}
#define LOAD(m,var,name) do{union{FARPROC raw;__typeof__(var) typed;}fn;fn.raw=GetProcAddress(m,name);check(fn.raw!=0,name);if(!fn.raw)goto done;var=fn.typed;}while(0)
static int (*create)(const m98_sp_callbacks *,uint32_t *);
static int (*destroy)(uint32_t *);
static int (*texture_create)(uint32_t,const ntg_texture_desc *,ntg_resource *);
static int (*shader_create)(uint32_t,const m98_sp_program *,ntg_resource *);
static int (*release)(uint32_t,ntg_resource *);
static int (*map)(uint32_t,ntg_resource,ntg_mapping *);
static int (*unmap)(uint32_t,ntg_resource);
static int (*clear_color)(uint32_t,ntg_resource,const uint8_t [4]);
static int (*clear_depth)(uint32_t,ntg_resource,float);
static int (*copy)(uint32_t,ntg_resource,ntg_resource);
static int (*bind)(uint32_t,ntg_resource,ntg_resource,ntg_resource);
static int (*draw)(uint32_t,const ntg_draw_desc *,m98_r_stats *);
static uint32_t (*abi)(void);
static int mapping(uint32_t device,ntg_resource resource,ntg_mapping *out,uint32_t kind,uint32_t pitch,const char *name){int rc,valid;zero(out,sizeof(*out));rc=map(device,resource,out);valid=rc==0&&out->pixels&&out->width==32&&out->height==32&&out->format==kind&&out->pitch==pitch&&out->bytes==32*pitch&&(kind!=NTG_D32||(uintptr_t)out->pixels%4==0);check(valid,name);if(rc==0&&!valid)check(unmap(device,resource)==0,"reject_malformed_mapping_cleanup");return valid;}
static int memory_trial(owner *o){uint32_t device=0;ntg_resource color=0,depth=0,stage=0,shader=0,old;ntg_texture_desc d={1,32,32,NTG_RGBA8,140,1,1,1,0};ntg_mapping m;m98_r_stats stats;ntg_draw_desc draw_desc;m98_sp_instruction code[2];m98_sp_program p;m98_sp_callbacks cb;unsigned x,y,i,bad;const uint8_t bg[4]={3,7,11,255};int good=0;
 zero(&cb,sizeof(cb));cb.abi=1;cb.user=o;cb.allocate=allocate;cb.deallocate=deallocate;cb.math=math_provider;
 check(create(&cb,&device)==0&&device,"create_real_resource_device");if(!device)goto done;
 check(texture_create(device,&d,&color)==0&&color,"create_rgba8_target");if(!color)goto done;d.format=NTG_D32;d.pitch=144;check(texture_create(device,&d,&depth)==0&&depth,"create_d32_attachment");if(!depth)goto done;d.format=NTG_RGBA8;d.pitch=132;check(texture_create(device,&d,&stage)==0&&stage,"create_readback_resource");if(!stage)goto done;
 if(!mapping(device,color,&m,NTG_RGBA8,140,"map_rgba_target"))goto done;for(i=0;i<m.bytes;i++)((uint8_t*)m.pixels)[i]=0xa5;check(unmap(device,color)==0,"unmap_rgba_target");
 if(!mapping(device,stage,&m,NTG_RGBA8,132,"map_readback_resource"))goto done;for(i=0;i<m.bytes;i++)((uint8_t*)m.pixels)[i]=0xa5;check(unmap(device,stage)==0,"unmap_readback_resource");
 if(!mapping(device,depth,&m,NTG_D32,144,"map_depth_attachment"))goto done;for(i=0;i<m.bytes/4;i++)((float*)m.pixels)[i]=123456;check(unmap(device,depth)==0,"unmap_depth_attachment");
 check(clear_color(device,color,bg)==0&&clear_depth(device,depth,1)==0,"real_color_and_depth_clear");
 zero(code,sizeof(code));code[0].opcode=M98_SP_MOV;code[0].dst_file=M98_SP_OUTPUT;code[0].source_count=1;code[0].source[0].file=M98_SP_INPUT;for(i=0;i<4;i++)code[0].source[0].swizzle[i]=i;code[1].opcode=M98_SP_END;zero(&p,sizeof(p));p.abi=1;p.instruction_count=2;p.input_count=1;p.output_count=1;p.instructions=code;
 check(shader_create(device,&p,&shader)==0&&shader,"create_actual_mesa_tgsi_shader");if(!shader)goto done;
 check(bind(device,color,depth,shader)==0,"bind_actual_owned_targets");check(map(device,color,&m)==NTG_BUSY,"bound_target_map_rejected");
 zero(&draw_desc,sizeof(draw_desc));draw_desc.abi=1;draw_desc.varying_count=1;draw_desc.quad_budget=1024;draw_desc.depth_test=M98_R_DEPTH_LESS;draw_desc.depth_write=1;draw_desc.vertex[1].x16=512;draw_desc.vertex[2].y16=512;
 for(i=0;i<3;i++){draw_desc.vertex[i].z=.5f;draw_desc.vertex[i].varying[0][2]=.25f;draw_desc.vertex[i].varying[0][3]=1;}draw_desc.vertex[1].varying[0][0]=1;draw_desc.vertex[2].varying[0][1]=1;
 zero(&stats,sizeof(stats));check(draw(device,&draw_desc,&stats)==0,"actual_guest_mesa_triangle_dispatch");check(stats.covered_samples==496&&stats.written_samples==496&&stats.shader_quads>0,"independent_496_sample_coverage");check(copy(device,color,stage)==0,"actual_guest_resource_copy");
 if(!mapping(device,stage,&m,NTG_RGBA8,132,"map_actual_rendered_readback"))goto done;bad=0;
 for(y=0;y<32;y++){for(x=0;x<32;x++){uint8_t expected[4];uint8_t *sample=(uint8_t*)m.pixels+y*m.pitch+4*x;for(i=0;i<4;i++)expected[i]=bg[i];if(x+y<31){expected[0]=(uint8_t)((255*(2*x+1)+32)/64);expected[1]=(uint8_t)((255*(2*y+1)+32)/64);expected[2]=64;expected[3]=255;}for(i=0;i<4;i++){if(sample[i]!=expected[i])bad++;image[(y*32+x)*4+i]=sample[i];}}
  for(x=128;x<m.pitch;x++)if(((uint8_t*)m.pixels)[y*m.pitch+x]!=0xa5)bad++;
 }check(!bad,"all_4096_independent_rgba_bytes_and_padding");check(unmap(device,stage)==0,"unmap_rendered_readback");
 check(bind(device,0,0,0)==0,"unbind_retained_targets");if(!mapping(device,depth,&m,NTG_D32,144,"map_depth_readback"))goto done;bad=0;for(y=0;y<32;y++){for(x=0;x<32;x++)if(((float*)m.pixels)[y*36+x]!=(x+y<31?.5f:1))bad++;for(x=32;x<36;x++)if(((float*)m.pixels)[y*36+x]!=123456)bad++;}check(!bad,"independent_depth_and_padding");check(unmap(device,depth)==0,"unmap_depth_readback");
 old=shader;check(release(device,&shader)==0&&!shader,"release_shader");check(release(device,&old)==NTG_STALE,"stale_shader_cookie_rejected");good=!bad;
done:
 if(device)check(destroy(&device)==0&&!device,"destroy_device_and_owned_resources");check(!o->live,"all_allocator_blocks_released");return good;
}
static LRESULT CALLBACK window_proc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp){if(msg==WM_PAINT){PAINTSTRUCT ps;HDC dc=BeginPaint(hwnd,&ps);unsigned x,y,sx,sy,bad=0;if(!dc){check(0,"begin_window_paint");return 0;}
 for(y=0;y<32;y++)for(x=0;x<32;x++){uint8_t *p=image+(y*32+x)*4;COLORREF rgb=RGB(p[0],p[1],p[2]);for(sy=0;sy<4;sy++)for(sx=0;sx<4;sx++)if(SetPixel(dc,20+4*x+sx,40+4*y+sy,rgb)!=rgb)bad++;}check(!bad,"actual_visible_framebuffer_write");{BOOL flushed=GdiFlush();BOOL ended=EndPaint(hwnd,&ps);check(flushed&&ended,"complete_window_paint");}paints++;return 0;}return DefWindowProcW(hwnd,msg,wp,lp);}
static void visible_trial(void){WNDCLASSW wc;HINSTANCE instance=GetModuleHandleW(0);HWND window=0;HDC dc=0;unsigned x,y,bad=0;zero(&wc,sizeof(wc));wc.lpfnWndProc=window_proc;wc.hInstance=instance;wc.lpszClassName=L"NTGMesaResourceProbe";wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
 check(RegisterClassW(&wc)!=0,"register_actual_window");window=CreateWindowExW(0,wc.lpszClassName,L"Mesa resource backend - real triangle",WS_OVERLAPPEDWINDOW|WS_VISIBLE,90,70,250,240,0,0,instance,0);check(window!=0,"create_visible_window");if(!window)goto done;check(UpdateWindow(window)&&paints,"dispatch_real_window_paint");dc=GetDC(window);check(dc!=0,"capture_visible_window_dc");if(!dc)goto done;
 for(y=0;y<128;y++)for(x=0;x<128;x++){uint8_t *p=image+((y/4)*32+x/4)*4;if(GetPixel(dc,20+x,40+y)!=RGB(p[0],p[1],p[2]))bad++;}visible_pixels=16384;check(!bad,"all_16384_visible_framebuffer_pixels");Sleep(3000);
done:if(dc)check(ReleaseDC(window,dc)!=0,"release_visible_dc");if(window)check(DestroyWindow(window)!=0,"destroy_visible_window");check(UnregisterClassW(wc.lpszClassName,instance)!=0,"unregister_window_class");}
void ntg_probe_entry(void){HMODULE module=0,crt=0;owner o;const char *math_names[9]={0,"cos","sin","log","pow","sqrt","floor","ceil","ldexp"};unsigned i;output=GetStdHandle(STD_OUTPUT_HANDLE);o.heap=GetProcessHeap();o.live=0;zero(image,sizeof(image));text("NTG64 BEGIN nonce=" NTG_TRIAL_NONCE "\r\n");check(output&&output!=INVALID_HANDLE_VALUE&&o.heap,"actual_guest_handles");
 module=LoadLibraryA("C:\\SHZ\\SYS64\\NTGSW.DLL");check(module!=0,"load_exact_private_ntgsw");if(!module)goto done;crt=LoadLibraryA("C:\\SHZ\\SYS64\\UCRTBASE.DLL");check(crt!=0,"load_actual_math_owner");if(!crt)goto done;
 for(i=1;i<=8;i++){union{FARPROC raw;unary_math one;binary_math two;ldexp_math scale;}fn;fn.raw=GetProcAddress(crt,math_names[i]);check(fn.raw!=0,math_names[i]);if(!fn.raw)goto done;if(i==4)math_pow=fn.two;else if(i==8)math_ldexp=fn.scale;else math_one[i]=fn.one;}
 LOAD(module,abi,"ntg_abi");LOAD(module,create,"ntg_create");LOAD(module,destroy,"ntg_destroy");LOAD(module,texture_create,"ntg_texture_create");LOAD(module,shader_create,"ntg_shader_create");LOAD(module,release,"ntg_release");LOAD(module,map,"ntg_map");LOAD(module,unmap,"ntg_unmap");LOAD(module,clear_color,"ntg_clear_color");LOAD(module,clear_depth,"ntg_clear_depth");LOAD(module,copy,"ntg_copy");LOAD(module,bind,"ntg_bind");LOAD(module,draw,"ntg_draw");check(abi()==1,"resource_abi_1");if(memory_trial(&o)&&!failures)visible_trial();
done:if(crt)check(FreeLibrary(crt)!=0,"unload_math_owner");if(module)check(FreeLibrary(module)!=0,"unload_private_backend");check(relocation_anchor!=0,"actual_relocated_metadata");text("NTG64 COUNTS checks=");number(checks);text(" failures=");number(failures);text(" paints=");number(paints);text(" pixels=");number(visible_pixels);text("\r\n");text(failures||!output_ok?"NTG64 RESULT FAIL nonce=":"NTG64 RESULT PASS nonce=");text(NTG_TRIAL_NONCE "\r\n");ExitProcess(failures||!output_ok?1:0);}
