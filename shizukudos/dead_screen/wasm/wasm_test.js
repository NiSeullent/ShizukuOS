/* SPDX-License-Identifier: GPL-2.0-only */
'use strict';
const fs=require('fs'), crypto=require('crypto'), path=require('path');
let checks=0;
function check(condition,message){++checks;if(!condition)throw new Error(message);}
const bytes=fs.readFileSync(process.argv[2]);
const moduleObject=new WebAssembly.Module(bytes);
check(WebAssembly.Module.imports(moduleObject).length===0,'must have no imported services');
const expected=['memory','ds_preview_init','ds_preview_input','ds_preview_tick','ds_preview_render',
  'ds_preview_pixels','ds_preview_width','ds_preview_height','ds_preview_trace','ds_preview_trace_len',
  'ds_preview_mode','ds_preview_score','ds_preview_fallback','ds_preview_set_size'];
const actual=WebAssembly.Module.exports(moduleObject).map(x=>x.name).sort();
check(JSON.stringify(actual)===JSON.stringify(expected.sort()),'exact exported ABI');
const x=new WebAssembly.Instance(moduleObject,{}).exports;
check(x.memory.buffer.byteLength===4194304,'fixed 4MiB memory');
check(x.ds_preview_render()===-1,'no rendering before init');
check(x.ds_preview_init()===0,'init');
function trace(){return new TextDecoder().decode(new Uint8Array(x.memory.buffer,x.ds_preview_trace(),x.ds_preview_trace_len()));}
function raster(){return new Uint8Array(x.memory.buffer,x.ds_preview_pixels(),x.ds_preview_width()*x.ds_preview_height()*4);}
function digest(){return crypto.createHash('sha256').update(raster()).digest('hex');}
const font=fs.readFileSync(path.resolve(__dirname,'../../supervisor/src/font8x8_basic.h'),'utf8')
  .split('\n').filter(line=>line.includes('// U+')).map(line=>(line.split('}')[0].match(/0x[0-9a-fA-F]+/g)||[]).map(Number));
check(font.length===128 && font.every(row=>row.length===8),'actual public-domain font table');
function legend(text,left,top,right,color){
  const w=x.ds_preview_width(),ox=(w-640)/2,oy=(x.ds_preview_height()-480)/2,data=raster();
  for(let yy=0;yy<8;yy++)for(let xx=left;xx<right;xx++){
    const relative=xx-left,n=Math.floor(relative/8),bit=relative%8;
    const on=n<text.length && (font[text.charCodeAt(n)][yy]&(1<<bit));
    const want=on?color:0,offset=((oy+top+yy)*w+ox+xx)*4;
    check((data[offset]|data[offset+1]<<8|data[offset+2]<<16)===want,'visible preview legend pixel differs');
  }
}
function footer(){legend('Esc menu  R restart  L KO/EN  T trace/items | design/game preview',24,466,632,0xaaaaaa);}
const original=trace();
check(original.startsWith('You session got wasted\nEnglish traceback:'),'actual counted English fallback');
check(original.includes('SYNTHETIC EXAMPLE TRACE'),'explicit example scope');
check(original.includes('IP=0x0000000011111111'),'example metadata is known, not guest data');
check(x.ds_preview_mode()===0 && x.ds_preview_width()===640 && x.ds_preview_height()===480,'menu geometry');
let image=raster();for(let i=3;i<image.length;i+=4)check(image[i]===255,'opaque RGBA8');
const menu=digest();
legend('EXAMPLE TRACE - PREVIEW',304,76,632,0xffffff);footer();
x.ds_preview_input(1);check(x.ds_preview_mode()===1,'real Tetris selected');
for(let i=0;i<120;i++){x.ds_preview_input(7);for(let j=0;j<20;j++)x.ds_preview_tick();if(i%5===0)x.ds_preview_input(9);}
check(x.ds_preview_render()===0 && digest()!==menu,'actual Tetris moves/render');
footer();
check(trace()===original,'trace immutable through Tetris');
x.ds_preview_input(2);check(x.ds_preview_mode()===2,'real Suika selected');
for(let i=0;i<800;i++){if(i%31===0)x.ds_preview_input(7);x.ds_preview_tick();if(i%200===199)x.ds_preview_input(9);}
check(x.ds_preview_render()===0 && digest()!==menu,'actual Suika moves/render');
footer();
check(trace()===original,'trace immutable through Suika');
x.ds_preview_input(8);check(x.ds_preview_mode()===0,'real menu return');
x.ds_preview_input(11);check(x.ds_preview_render()===0,'actual item legend');
legend('T shows example traceback',304,396,632,0xaaaaaa);footer();
x.ds_preview_input(11);x.ds_preview_input(10);check(x.ds_preview_render()===0,'actual EN title toggle');
legend('EXAMPLE TRACE - PREVIEW',304,76,632,0xffffff);footer();
const prior=digest();x.ds_preview_input(999);x.ds_preview_input(-9);x.ds_preview_render();check(digest()===prior,'invalid input untouched');
check(x.ds_preview_set_size(320,200)===-1 && x.ds_preview_width()===640,'invalid resize untouched');
check(x.ds_preview_set_size(800,600)===0 && raster().length===1920000,'bounded 800x600');
footer();x.ds_preview_input(11);x.ds_preview_render();legend('T shows example traceback',304,396,632,0xaaaaaa);
x.ds_preview_input(11);x.ds_preview_render();legend('EXAMPLE TRACE - PREVIEW',304,76,632,0xffffff);
x.ds_preview_fallback(1);check(x.ds_preview_render()===0,'same C ASCII fallback');const textRaster=digest();
x.ds_preview_input(1);x.ds_preview_tick();x.ds_preview_render();check(digest()===textRaster,'fallback preview pauses games');
check(trace()===original,'first trace survives fallback');
x.ds_preview_fallback(0);check(x.ds_preview_render()===0 && digest()!==textRaster,'preview-only controlled return');
check(x.ds_preview_set_size(640,480)===0,'resize back');
check(x.ds_preview_init()===0 && x.ds_preview_mode()===0,'explicit preview reset');
check(trace()===original,'same explicit example after reset');
check(x.memory.buffer.byteLength===4194304,'no memory growth');
console.log(JSON.stringify({status:'PASS',checks,exports:actual,imports:[],memory_bytes:x.memory.buffer.byteLength,
  native_execution:false,scope:'design/game preview with explicitly synthetic example trace'}));
