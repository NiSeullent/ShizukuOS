#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-only
// Independent headed Chrome acceptance. Does not replace strict urllib checks.
import {constants} from 'node:fs';
import * as fs from 'node:fs/promises';
import {createHash,randomUUID} from 'node:crypto';
import {spawn} from 'node:child_process';
import {lookup} from 'node:dns/promises';
import {isIP} from 'node:net';
import {tmpdir} from 'node:os';
import {join,resolve,dirname,basename} from 'node:path';
import {pathToFileURL} from 'node:url';

const ORIGIN='https://m98.nyase.kr', MAX_ISO=512*1024*1024, HTML_LIMIT=2*1024*1024;
const require=(ok,why)=>{if(!ok)throw new Error(why);};
const hash=b=>createHash('sha256').update(b).digest('hex');
const delay=ms=>new Promise(r=>setTimeout(r,ms));
let interruption=null;

export function publicURL(value) {
  require(typeof value==='string'&&!/[\x00-\x20\x7f\\]/.test(value),'unsafe public URL');
  require(!/%(?![a-fA-F0-9]{2})/.test(value),'invalid URL escape');
  const raw=value.startsWith('/')?value:value.replace(/^https:\/\/m98\.nyase\.kr/,'');
  const decoded=decodeURIComponent(raw);
  require(decoded.startsWith('/')&&!decoded.startsWith('//')&&!/[\x00-\x20\x7f\\?#]/.test(decoded)&&!decoded.split('/').some(x=>x==='.'||x==='..'),'unsafe public path');
  const u=new URL(value,ORIGIN);
  require(u.origin===ORIGIN&&!u.username&&!u.password&&!u.search&&!u.hash,'only canonical public HTTPS is permitted');
  return u.href;
}
export function chromeArguments(profile) {
  return ['--no-first-run','--disable-sync','--disable-extensions','--disable-background-networking',
    '--no-sandbox','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank'];
}
function addressNumber(address,family) {
  if(family===4)return address.split('.').reduce((value,part)=>(value<<8n)|BigInt(part),0n);
  const halves=address.split('::'),left=halves[0]?halves[0].split(':'):[],right=halves[1]?halves[1].split(':'):[];
  const parts=halves.length===1?left:[...left,...Array(8-left.length-right.length).fill('0'),...right];
  return parts.reduce((value,part)=>(value<<16n)|BigInt('0x'+part),0n);
}
function within(value,network,family) {
  const [base,prefix]=network.split('/'),shift=BigInt((family===4?32:128)-Number(prefix));
  return value>>shift===addressNumber(base,family)>>shift;
}
export function isPublicAddress(address) {
  if(typeof address!=='string'||address.includes('%'))return false;
  const family=isIP(address);if(!family)return false;
  if(family===4){
    const value=addressNumber(address,4);
    if(address==='192.0.0.9'||address==='192.0.0.10')return true;
    return !['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12',
      '192.0.0.0/24','192.0.2.0/24','192.88.99.0/24','192.168.0.0/16','198.18.0.0/15','198.51.100.0/24',
      '203.0.113.0/24','224.0.0.0/4','240.0.0.0/4'].some(n=>within(value,n,4));
  }
  // Public hostname admission is conservative global unicast. Mapped IPv4,
  // translation/reserved space and scoped addresses cannot stand in for DNS.
  if(address.includes('.'))return false;
  const value=addressNumber(address,6);
  if(!within(value,'2000::/3',6)||within(value,'2001:db8::/32',6)||within(value,'2002::/16',6)||within(value,'3fff::/20',6))return false;
  if(within(value,'2001::/23',6))return ['2001:1::1/128','2001:1::2/128','2001:3::/32','2001:4:112::/48','2001:20::/28','2001:30::/28'].some(n=>within(value,n,6));
  return true;
}
export function validateDocument(p) {
  publicURL(p.url);
  if(p.responseURL!==undefined)require(publicURL(p.responseURL)===p.url,'rendered URL differs from main document response');
  require(p.status===200&&p.tls===true&&!p.challenge,'trusted HTTPS 200 required');
  require(typeof p.userAgent==='string'&&!p.userAgent.includes('HeadlessChrome'),'ordinary headed Chrome UA required');
  require(typeof p.html==='string'&&Buffer.byteLength(p.html)>0&&Buffer.byteLength(p.html)<=HTML_LIMIT,'bounded DOM required');
  require(/\bshizukuos\b/i.test(p.title)&&/\bshizukuos\b/i.test(p.text),'visible ShizukuOS branding required');
  require(!p.vnc&&!/novnc/i.test(p.title),'active VNC interface rejected');
  require(!/just a moment|verify you are human|checking your browser|cf-chl-|chrome-error:|err_cert_|err_name_not_resolved|err_connection_/i.test(p.title+' '+p.text),'challenge or browser error rejected');
  require(!p.html.toLowerCase().replaceAll('/cdn-cgi/challenge-platform/scripts/jsd/main.js','').includes('challenge-platform'),'challenge interstitial rejected');
  return {status:'PASS',url:p.url,title:p.title,user_agent:p.userAgent,DOM_bytes:Buffer.byteLength(p.html),DOM_sha256:hash(p.html),http_status:200,trusted_TLS:true,VNC_absent:true};
}
export async function verifyDownloadedISO(path,bytes,sha256,timeoutMs) {
  require(Number.isSafeInteger(bytes)&&bytes>0&&bytes<=MAX_ISO&&/^[a-f0-9]{64}$/.test(sha256),'exact bounded ISO pins required');
  require(Number.isFinite(timeoutMs)&&timeoutMs>0,'ISO verification deadline exceeded');
  const deadline=Date.now()+timeoutMs, before=await fs.lstat(path);
  require(before.isFile()&&!before.isSymbolicLink()&&before.nlink===1&&before.size===bytes,'owned regular exact-size download required');
  const f=await fs.open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try {
    const initial=await f.stat();
    require(initial.dev===before.dev&&initial.ino===before.ino&&initial.size===bytes,'download identity changed');
    const sum=createHash('sha256'),buffer=Buffer.alloc(1024*1024),prefix=Buffer.alloc(32775);let total=0;
    while(true) {
      if(interruption)throw interruption;
      require(Date.now()<deadline,'ISO verification deadline exceeded');
      const {bytesRead}=await f.read(buffer,0,Math.min(buffer.length,bytes-total+1),null);
      if(!bytesRead)break;
      require(total+bytesRead<=bytes,'ISO contains extra bytes');
      if(total<prefix.length)buffer.copy(prefix,total,0,Math.min(bytesRead,prefix.length-total));
      sum.update(buffer.subarray(0,bytesRead));total+=bytesRead;
    }
    const final=await f.stat(),named=await fs.lstat(path),digest=sum.digest('hex');
    require(total===bytes&&digest===sha256,'downloaded full ISO size/SHA mismatch');
    require(final.dev===initial.dev&&final.ino===initial.ino&&final.size===initial.size&&final.mtimeMs===initial.mtimeMs&&final.ctimeMs===initial.ctimeMs&&named.dev===initial.dev&&named.ino===initial.ino&&!named.isSymbolicLink(),'download changed during verification');
    require(total>=32775&&prefix[32768]===1&&prefix.subarray(32769,32774).equals(Buffer.from('CD001'))&&prefix[32774]===1,'ISO9660 primary descriptor absent');
    return {status:'PASS',checked_bytes:total,sha256:digest,full_native_download_verified:true,ISO9660_PVD_verified:true,iso_boot_verified:false};
  } finally {await f.close();}
}
export class DownloadTracker {
  constructor(url,frame,bytes) {this.url=publicURL(url);this.frame=frame;this.bytes=bytes;this.received=0;this.guid=null;this.completed=false;}
  begin(p) {
    require(!this.guid&&p.frameId===this.frame&&publicURL(p.url)===this.url&&/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(p.guid),'foreign, duplicate or unsafe native download');
    this.guid=p.guid;
  }
  progress(p) {
    require(this.guid&&p.guid===this.guid&&!this.completed,'foreign or duplicate native progress');
    require(Number.isSafeInteger(p.receivedBytes)&&p.receivedBytes>=this.received&&p.receivedBytes<=this.bytes&&Number.isSafeInteger(p.totalBytes)&&(p.totalBytes===0||p.totalBytes===this.bytes),'native download byte budget/pins failed');
    require(p.state==='inProgress'||p.state==='completed','native download canceled');
    require(p.state!=='completed'||p.receivedBytes===this.bytes,'native download completed with wrong bytes');
    this.received=p.receivedBytes;this.completed=p.state==='completed';
  }
}
export async function evidenceFiles(out) {
  const names=await fs.readdir(out);
  for(const n of names) {const s=await fs.lstat(join(out,n));require(s.isFile()&&!s.isSymbolicLink()&&/^(result\.json|route-[0-9]+\.html|diagnostic\.log)$/.test(n),'private/download artifact rejected');}
  return names;
}
export async function writeAtomicJSON(path,record,io=fs) {
  const payload=Buffer.from(JSON.stringify(record,null,2)+'\n'),temporary=join(dirname(path),'.'+basename(path)+'.'+randomUUID()+'.tmp');
  let handle=null,published=false;
  try {
    handle=await io.open(temporary,'wx',0o600);
    let offset=0;
    while(offset<payload.length){const {bytesWritten}=await handle.write(payload,offset,payload.length-offset,null);
      require(Number.isSafeInteger(bytesWritten)&&bytesWritten>0&&bytesWritten<=payload.length-offset,'receipt write count invalid');offset+=bytesWritten;}
    await handle.sync();await handle.close();handle=null;
    require((await io.readFile(temporary)).equals(payload),'complete receipt readback mismatch');
    await io.rename(temporary,path);published=true;
  } finally {
    if(handle)await handle.close().catch(()=>{});
    if(!published)await io.rm(temporary,{force:true});
  }
}

export class CDP {
  constructor(socket,timeout=10000) {
    this.socket=socket;this.timeout=timeout;this.seq=0;this.pending=new Map();this.listeners=new Set();this.failure=null;
    socket.addEventListener('message',e=>{try{require(typeof e.data==='string'&&Buffer.byteLength(e.data)<=3*1024*1024,'CDP message budget');const m=JSON.parse(e.data);
      if(m.id){const p=this.pending.get(m.id);if(p){this.pending.delete(m.id);clearTimeout(p.timer);m.error?p.reject(new Error('CDP '+JSON.stringify(m.error))):p.resolve(m.result??{});}}
      else for(const fn of this.listeners)fn(m);
    }catch(e){this.fail(e);}});
    socket.addEventListener('close',()=>this.fail(new Error('owned CDP disconnected')));
    socket.addEventListener('error',()=>this.fail(new Error('owned CDP transport failed')));
  }
  fail(e){this.failure=e;for(const p of this.pending.values()){clearTimeout(p.timer);p.reject(e);}this.pending.clear();}
  call(method,params={},sessionId) {
    if(this.failure)return Promise.reject(this.failure);
    return new Promise((resolve,reject)=>{const id=++this.seq,timer=setTimeout(()=>{this.pending.delete(id);reject(new Error('CDP deadline: '+method));},this.timeout);
      this.pending.set(id,{resolve,reject,timer});try{this.socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));}catch(e){clearTimeout(timer);this.pending.delete(id);reject(e);}});
  }
  close(){this.socket.close();}
}
async function waitUntil(check,deadline,why,honorInterrupt=true) {
  while(Date.now()<deadline){if(honorInterrupt&&interruption)throw interruption;const result=await check();if(result)return result;await delay(50);}throw new Error(why);
}
function ownedProcess(command,args,env,logs) {
  const child=spawn(command,args,{env,detached:true,stdio:['ignore','pipe','pipe']});child.on('error',e=>{child.launchError=e;});
  for(const stream of [child.stdout,child.stderr])stream.on('data',b=>{logs.bytes+=b.length;if(logs.bytes>2*1024*1024){logs.error=new Error('owned process logs exceeded budget');try{process.kill(-child.pid,'SIGTERM');}catch{}}else logs.text+=b.toString('utf8');});
  return child;
}
export async function stopOwned(child) {
  if(!child?.pid)return;
  for(const signal of ['SIGTERM','SIGKILL']){try{process.kill(-child.pid,signal);}catch(e){if(e.code!=='ESRCH')throw e;}
    if(child.exitCode!==null||child.signalCode!==null)continue;
    await waitUntil(()=>child.exitCode!==null||child.signalCode!==null,Date.now()+3000,'owned child did not exit',false).catch(e=>{if(signal==='SIGKILL')throw e;});}
  for(const stream of [child.stdout,child.stderr])stream?.destroy();
}
export async function cleanupOwned({cdp,chrome,xvfb,work}) {
  const errors=[];
  if(cdp){try{await cdp.call('Browser.close').catch(()=>{});cdp.close();}catch(e){errors.push('CDP: '+e.message);}}
  for(const [label,child] of [['Chrome',chrome],['Xvfb',xvfb]]){try{await stopOwned(child);}catch(e){errors.push(label+': '+e.message);}}
  if(!errors.length&&work){try{await fs.rm(work,{recursive:true,force:true});}catch(e){errors.push('private directory: '+e.message);}}
  return {private_profile_and_ISO_removed:errors.length===0,...(errors.length?{cleanup_error:errors.join('; ')}:{})};
}
async function normalDNS() {
  const hosts=await fs.readFile('/etc/hosts','utf8');for(const row of hosts.split('\n'))require(!row.split('#')[0].trim().split(/\s+/).slice(1).some(x=>x.toLowerCase().replace(/\.$/,'')==='m98.nyase.kr'),'target hosts override forbidden');
  const addresses=(await lookup('m98.nyase.kr',{all:true})).map(x=>x.address);
  require(addresses.length>0&&addresses.every(isPublicAddress), 'public global-unicast DNS address required');
  return addresses;
}
export function pageExpression() {
  return String.raw`({url:location.href,title:document.title,text:document.body?.innerText||'',html:document.documentElement.outerHTML,userAgent:navigator.userAgent,vnc:[...document.querySelectorAll('[id]')].some(e=>e.id.toLowerCase().startsWith('novnc'))||[...document.scripts].some(e=>/novnc|\/core\/rfb\.js(?:$|\?)|\/app\/ui\.js(?:$|\?)/i.test(e.src))})`;
}
export function mainDocumentResponse(m,frame) {
  return m.method==='Network.responseReceived'&&m.params?.type==='Document'&&m.params?.frameId===frame?m.params.response:null;
}
async function page(cdp,session,url,index,out) {
  const frame=(await cdp.call('Page.getFrameTree',{},session)).frameTree.frame.id;
  let response=null,loaded=false;const responses=[];
  const listener=m=>{if(m.sessionId!==session)return;const document=mainDocumentResponse(m,frame);if(document){response=document;responses.push({url:response.url,status:response.status,trusted_TLS:!!response.securityDetails});}if(m.method==='Page.loadEventFired')loaded=true;};
  cdp.listeners.add(listener);
  try {
    const navigation=await cdp.call('Page.navigate',{url},session);require(!navigation.errorText,'page navigation failed: '+navigation.errorText);
    await waitUntil(()=>{if(cdp.failure)throw cdp.failure;return loaded&&response;},Date.now()+30000,'public page load deadline');
    await delay(1000);
    const r=await cdp.call('Runtime.evaluate',{returnByValue:true,expression:pageExpression()},session);
    require(!r.exceptionDetails&&r.result?.value,'actual page evaluation failed');const p=r.result.value;
    require(Buffer.byteLength(p.html??'')<=HTML_LIMIT,'DOM budget exceeded');await fs.writeFile(join(out,'route-'+index+'.html'),p.html,{flag:'wx'});
    const headers=Object.fromEntries(Object.entries(response.headers??{}).map(([k,v])=>[k.toLowerCase(),String(v).toLowerCase()]));
    const checked=validateDocument({...p,responseURL:response.url,status:response.status,tls:!!response.securityDetails,challenge:headers['cf-mitigated']==='challenge'});
    return {...checked,requested_url:url,responses};
  }finally{cdp.listeners.delete(listener);}
}
async function nativeDownload(cdp,session,url,bytes,sha256,downloads,deadline) {
  const frame=(await cdp.call('Page.getFrameTree',{},session)).frameTree.frame.id;
  const tracker=new DownloadTracker(url,frame,bytes);let failure=null;
  const listener=m=>{try{if(m.method==='Browser.downloadWillBegin')tracker.begin(m.params);if(m.method==='Browser.downloadProgress')tracker.progress(m.params);}catch(e){failure=e;}};
  cdp.listeners.add(listener);
  try {
    await cdp.call('Browser.setDownloadBehavior',{behavior:'allowAndName',downloadPath:downloads,eventsEnabled:true});
    const navigation=cdp.call('Page.navigate',{url},session).catch(e=>{failure=e;});
    await waitUntil(()=>{if(failure)throw failure;if(cdp.failure)throw cdp.failure;return tracker.completed;},deadline,'native ISO download deadline');
    await navigation;
    require(!failure&&tracker.completed,'native download did not complete');
    const f=join(downloads,tracker.guid);
    await waitUntil(async()=>{try{return(await fs.lstat(f)).isFile();}catch(e){if(e.code==='ENOENT')return false;throw e;}},Math.min(deadline,Date.now()+3000),'completed native download file absent');
    return {requested_url:url,native_browser_events_verified:true,...await verifyDownloadedISO(f,bytes,sha256,deadline-Date.now())};
  }finally{cdp.listeners.delete(listener);}
}

export async function main(argv=process.argv.slice(2)) {
  const args={};for(let i=0;i<argv.length;i+=2){require(argv[i].startsWith('--')&&i+1<argv.length,'paired CLI arguments required');require(!Object.hasOwn(args,argv[i]),'duplicate CLI argument');args[argv[i]]=argv[i+1];}
  require(args['--out']&&args['--chrome']&&args['--xvfb'],'out and installed Chrome/Xvfb required');
  require(Object.keys(args).every(k=>['--out','--chrome','--xvfb','--iso-path','--iso-sha256','--iso-bytes'].includes(k)),'unknown CLI argument');
  const isoFields=['--iso-path','--iso-sha256','--iso-bytes'];require(isoFields.every(k=>!args[k])||isoFields.every(k=>args[k]),'all ISO fields together');
  const isoURL=args['--iso-path']?publicURL(args['--iso-path']):null,isoBytes=Number(args['--iso-bytes']);
  if(isoURL)require(new URL(isoURL).pathname.toLowerCase().endsWith('.iso')&&/^[a-f0-9]{64}$/.test(args['--iso-sha256'])&&Number.isSafeInteger(isoBytes)&&isoBytes>0&&isoBytes<=MAX_ISO,'exact public ISO pins required');
  require(typeof WebSocket==='function','preinstalled Node with built-in WebSocket required');
  const out=resolve(args['--out']);await fs.mkdir(out,{mode:0o700});
  const sourceSHA=hash(await fs.readFile(new URL(import.meta.url)));
  const record={status:'FAIL',started_utc:new Date().toISOString(),source_sha256_before:sourceSHA,git_commit:process.env.GITHUB_SHA??null,Node_version:process.version,headed_Chrome:true,UA_headers_cookies_TLS_DNS_overrides:false,browser_or_npm_download:false,strict_urllib_result_unchanged:true,pages:[],ISO_requested:!!isoURL,...(isoURL?{ISO_expected:{url:isoURL,bytes:isoBytes,sha256:args['--iso-sha256']}}:{}),ISO_boot_verified:false,Windows98_MS_DOS_replacement_verified:false,modern_apps_verified:false};
  const logs={bytes:0,text:'',error:null};let work=null,xvfb=null,chrome=null,cdp=null;
  interruption=null;const interrupted=signal=>{interruption=new Error('owned browser interrupted: '+signal);if(cdp)cdp.fail(interruption);};
  const onINT=()=>interrupted('SIGINT'),onTERM=()=>interrupted('SIGTERM');process.on('SIGINT',onINT);process.on('SIGTERM',onTERM);
  try {
    record.normal_DNS_addresses=await normalDNS();work=await fs.mkdtemp(join(tmpdir(),'shizuku-public-chrome-'));await fs.chmod(work,0o700);
    const profile=join(work,'profile'),downloads=join(work,'downloads');await fs.mkdir(profile,{mode:0o700});await fs.mkdir(downloads,{mode:0o700});
    xvfb=ownedProcess(args['--xvfb'],['-displayfd','1','-screen','0','1280x1024x24','-nolisten','tcp'],process.env,logs);let display='';xvfb.stdout.on('data',b=>{display+=b.toString('ascii');});
    await waitUntil(()=>{if(xvfb.launchError)throw xvfb.launchError;return /^\d+\n/.test(display);},Date.now()+10000,'owned Xvfb startup deadline');
    chrome=ownedProcess(args['--chrome'],chromeArguments(profile),{...process.env,DISPLAY:':'+display.trim()},logs);
    const active=join(profile,'DevToolsActivePort');
    const address=await waitUntil(async()=>{if(chrome.launchError)throw chrome.launchError;if(chrome.exitCode!==null||chrome.signalCode!==null)throw new Error('owned Chrome exited before CDP');try{const v=(await fs.readFile(active,'utf8')).trim().split('\n');require(/^\d+$/.test(v[0])&&/^\/devtools\/browser\/[a-f0-9-]+$/i.test(v[1]),'owned Chrome CDP address malformed');return 'ws://127.0.0.1:'+v[0]+v[1];}catch(e){if(e.code==='ENOENT')return false;throw e;}},Date.now()+20000,'owned Chrome startup deadline');
    const socket=new WebSocket(address);await new Promise((res,rej)=>{const t=setTimeout(()=>rej(new Error('CDP connection deadline')),10000);socket.addEventListener('open',()=>{clearTimeout(t);res();},{once:true});socket.addEventListener('error',()=>{clearTimeout(t);rej(new Error('CDP connection failed'));},{once:true});});cdp=new CDP(socket);
    record.actual_browser_version=(await cdp.call('Browser.getVersion')).product;
    const target=await cdp.call('Target.createTarget',{url:'about:blank'});const session=(await cdp.call('Target.attachToTarget',{targetId:target.targetId,flatten:true})).sessionId;
    await cdp.call('Page.enable',{},session);await cdp.call('Network.enable',{},session);
    for(const [i,p] of ['/','/en/','/vnc.html','/vnc_lite.html'].entries()){try{record.pages.push(await page(cdp,session,publicURL(p),i,out));}catch(e){record.pages.push({status:'FAIL',requested_url:publicURL(p),error:String(e.message)});}}
    if(logs.error)throw logs.error;
    if(isoURL)record.ISO=await nativeDownload(cdp,session,isoURL,isoBytes,args['--iso-sha256'],downloads,Date.now()+600000);
    record.status=record.pages.every(p=>p.status==='PASS')&&(!isoURL||record.ISO?.status==='PASS')?'PASS':'FAIL';
  } catch(e){record.error=String(e.message);record.status='FAIL';}
  finally {
    Object.assign(record,await cleanupOwned({cdp,chrome,xvfb,work}));if(!record.private_profile_and_ISO_removed)record.status='FAIL';record.completed_utc=new Date().toISOString();
    try{record.source_sha256_after=hash(await fs.readFile(new URL(import.meta.url)));record.source_unchanged=record.source_sha256_after===sourceSHA;if(!record.source_unchanged)record.status='FAIL';}catch(e){record.source_unchanged=false;record.source_error=e.message;record.status='FAIL';}
    process.removeListener('SIGINT',onINT);process.removeListener('SIGTERM',onTERM);
    if(interruption){record.status='FAIL';record.error??=interruption.message;}
    await fs.writeFile(join(out,'diagnostic.log'),logs.text,{flag:'wx'});await evidenceFiles(out);await writeAtomicJSON(join(out,'result.json'),record);
    console.log(JSON.stringify(record,null,2));
  }
  return record.status==='PASS'?0:1;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)main().then(code=>{process.exitCode=code;}).catch(e=>{console.error(e.message);process.exitCode=2;});
