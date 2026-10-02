/* SPDX-License-Identifier: GPL-2.0-only
 * Execute the actual generated offline script; DOM/timer are browser boundaries.
 * This is JavaScript behavioral evidence, not IE/ActiveDesktop execution.
 */
const fs=require('fs'),vm=require('vm');
const html=fs.readFileSync(process.argv[2],'utf8');
const script=html.match(/<script type="text\/javascript">([\s\S]+)<\/script>/)[1];
let checks=0,time=0,pending=new Map(),next=0;
function check(ok){checks++;if(!ok)throw new Error('assertion '+checks);}
let all={status:{innerText:''}};
for(let i=0;i<24;i++)all['dot'+i]={style:{}};
const context={document:{all,body:{clientWidth:320,clientHeight:180}},
  Date:function(){this.getTime=()=>time;},
  setTimeout:(fn,delay)=>{check(delay===100);pending.set(++next,fn);return next;},
  clearTimeout:id=>pending.delete(id)};
vm.createContext(context);vm.runInContext(script,context);
check(context.frame===1 && pending.size===1);
const initial=all.dot0.style.pixelLeft;
function dispatch(){const [id,fn]=pending.entries().next().value;pending.delete(id);time+=100;fn();}
dispatch();check(context.frame===2 && all.dot0.style.pixelLeft!==initial);
context.toggle();check(!context.running && pending.size===0);
time+=1000;context.toggle();check(context.running && pending.size===1);
for(let i=0;i<20;i++)dispatch();
for(let i=0;i<24;i++) {
  check(all['dot'+i].style.pixelLeft>=0 && all['dot'+i].style.pixelLeft<320);
  check(all['dot'+i].style.pixelTop>=0 && all['dot'+i].style.pixelTop<180);
}
time=300001;dispatch();check(!context.running && pending.size===0);
context.toggle();check(!context.running && pending.size===0);
check(!html.includes('http:') && !html.includes('https:') && !html.includes('ActiveX'));
console.log('PASS: '+checks+' offline HTML behavior checks; browser boundaries modeled');
