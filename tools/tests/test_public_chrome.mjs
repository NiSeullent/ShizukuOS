// SPDX-License-Identifier: GPL-2.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, writeFile, symlink, rm, stat,open,readFile,readdir,rename} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import vm from 'node:vm';

async function implementation() {
  try { return await import('../verify_public_chrome.mjs'); }
  catch (e) { if (e.code === 'ERR_MODULE_NOT_FOUND') assert.fail('headed Chrome verification implementation is missing'); throw e; }
}
const sha = b => createHash('sha256').update(b).digest('hex');
function iso() { const b=Buffer.alloc(65536); b[32768]=1; b.write('CD001',32769); b[32774]=1; return b; }
async function fixture(fn) {
  const p=await mkdtemp(join(tmpdir(),'shizuku-public-chrome-test-'));
  try {await fn(p);} finally {await rm(p,{recursive:true,force:true});}
}

test('only canonical public HTTPS ISO paths are admitted',async()=>{
  const m=await implementation();
  assert.equal(m.publicURL('/downloads/ShizukuOS.iso'),'https://m98.nyase.kr/downloads/ShizukuOS.iso');
  for(const u of ['http://m98.nyase.kr/a.iso','https://other.example/a.iso','//other.example/a.iso','/a.iso?token=1','/a.iso#part','/%2e%2e/a.iso','/../a.iso','https://user@m98.nyase.kr/a.iso','/a%00.iso','/a%5cb.iso']) assert.throws(()=>m.publicURL(u),undefined,u);
});
test('Chrome launch stays headed and adds no UA or TLS/DNS/cookie bypass',async()=>{
  const m=await implementation();const args=m.chromeArguments('/owned/profile');
  assert.ok(args.includes('--user-data-dir=/owned/profile'));
  assert.ok(args.includes('--remote-debugging-port=0'));
  assert.ok(!args.some(a=>/headless|user-agent|ignore-certificate|host-resolver|proxy-server|cookie|extra-headers/.test(a)));
});
test('real rendered homepage requires trusted TLS, 200, branding and no VNC or challenge',async()=>{
  const m=await implementation();const page={url:'https://m98.nyase.kr/',title:'ShizukuOS',text:'ShizukuOS 지금 바로 다운로드',html:'<title>ShizukuOS</title>',vnc:false,userAgent:'Mozilla/5.0 Chrome/146.0.0.0',status:200,tls:true,challenge:false};
  assert.equal(m.validateDocument(page).status,'PASS');
  for(const changed of [{status:403},{tls:false},{challenge:true},{vnc:true},{title:'noVNC'},{text:'Just a moment'},{userAgent:'HeadlessChrome/146'},{url:'https://other.example/'}]) assert.throws(()=>m.validateDocument({...page,...changed}));
});
test('complete downloaded ISO is hashed from an owned regular file and PVD checked',async()=>{
  const m=await implementation();await fixture(async p=>{const b=iso(),f=join(p,'download');await writeFile(f,b);const r=await m.verifyDownloadedISO(f,b.length,sha(b),1000);assert.equal(r.sha256,sha(b));assert.equal(r.checked_bytes,b.length);assert.equal(r.iso_boot_verified,false);});
});
test('truncated, oversized and corrupt native downloads fail their exact pins',async()=>{
  const m=await implementation();await fixture(async p=>{const b=iso(),f=join(p,'download');for(const wrong of [b.subarray(0,b.length-1),Buffer.concat([b,Buffer.from([1])]),Buffer.concat([Buffer.from([1]),b.subarray(1)])]){await writeFile(f,wrong);await assert.rejects(m.verifyDownloadedISO(f,b.length,sha(b),1000));}});
});
test('HTML and wrong descriptor types fail even when full hash and size match',async()=>{
  const m=await implementation();await fixture(async p=>{const f=join(p,'download');for(const b of [Buffer.from('<html>challenge</html>'),Object.assign(iso(),{32768:0})]){await writeFile(f,b);await assert.rejects(m.verifyDownloadedISO(f,b.length,sha(b),1000));}});
});
test('symlink downloads are rejected and deadline is enforced',async()=>{
  const m=await implementation();await fixture(async p=>{const b=iso();await writeFile(join(p,'real'),b);await symlink(join(p,'real'),join(p,'link'));await assert.rejects(m.verifyDownloadedISO(join(p,'link'),b.length,sha(b),1000));await assert.rejects(m.verifyDownloadedISO(join(p,'real'),b.length,sha(b),0));});
});
test('native browser completion requires one matching frame URL and exact bytes',async()=>{
  const m=await implementation();const t=new m.DownloadTracker('https://m98.nyase.kr/a.iso','frame-1',65536);t.begin({guid:'01234567-89ab-cdef-0123-456789abcdef',frameId:'frame-1',url:'https://m98.nyase.kr/a.iso'});t.progress({guid:t.guid,totalBytes:65536,receivedBytes:1024,state:'inProgress'});t.progress({guid:t.guid,totalBytes:65536,receivedBytes:65536,state:'completed'});assert.equal(t.completed,true);
});
test('canceled, foreign, duplicate and regressing downloads cannot pass',async()=>{
  const m=await implementation();const begin={guid:'01234567-89ab-cdef-0123-456789abcdef',frameId:'frame-1',url:'https://m98.nyase.kr/a.iso'};
  for(const wrong of [{frameId:'foreign'},{url:'https://other.example/a.iso'},{guid:'../escape'}]) assert.throws(()=>new m.DownloadTracker(begin.url,begin.frameId,65536).begin({...begin,...wrong}));
  const t=new m.DownloadTracker(begin.url,begin.frameId,65536);t.begin(begin);assert.throws(()=>t.begin(begin));t.progress({guid:t.guid,totalBytes:65536,receivedBytes:1024,state:'inProgress'});
  for(const wrong of [{guid:'foreign'},{receivedBytes:0},{receivedBytes:65537},{receivedBytes:1.5},{state:'canceled'},{state:'completed',receivedBytes:1024}]) assert.throws(()=>t.progress({guid:t.guid,totalBytes:65536,receivedBytes:2048,state:'inProgress',...wrong}));
});
test('artifact allowlist excludes private download files and Chrome profiles',async()=>{
  const m=await implementation();await fixture(async p=>{await writeFile(join(p,'result.json'),'{}');await writeFile(join(p,'route-0.html'),'<html/>');assert.deepEqual((await m.evidenceFiles(p)).sort(),['result.json','route-0.html']);await writeFile(join(p,'ShizukuOS.iso'),iso());await assert.rejects(m.evidenceFiles(p));});
});
test('CDP rejects protocol errors, disconnects, malformed messages and silent deadlines',async()=>{
  const m=await implementation();
  class Transport extends EventTarget {send(value){this.sent=JSON.parse(value);}close(){this.dispatchEvent(new Event('close'));}}
  for(const mode of ['error','close','malformed','deadline']) {
    const socket=new Transport(),cdp=new m.CDP(socket,20),request=cdp.call('Page.enable');
    if(mode==='error')socket.dispatchEvent(new MessageEvent('message',{data:JSON.stringify({id:socket.sent.id,error:{code:-1,message:'real protocol error'}})}));
    if(mode==='close')socket.close();
    if(mode==='malformed')socket.dispatchEvent(new MessageEvent('message',{data:'not json'}));
    await assert.rejects(request);
  }
});
test('rendered page expression is valid JavaScript and only the main frame supplies status',async()=>{
  const m=await implementation();
  const document={title:'ShizukuOS',body:{innerText:'ShizukuOS download'},documentElement:{outerHTML:'<html>ShizukuOS</html>'},querySelectorAll:()=>[],scripts:[]};
  assert.equal(vm.runInNewContext(m.pageExpression(),{document,location:{href:'https://m98.nyase.kr/'},navigator:{userAgent:'Chrome/146'}}).title,'ShizukuOS');
  const r={method:'Network.responseReceived',params:{type:'Document',frameId:'main',response:{url:'https://m98.nyase.kr/',status:403}}};
  assert.equal(m.mainDocumentResponse(r,'main').status,403);assert.equal(m.mainDocumentResponse(r,'other'),null);
});
test('cleanup terminates and reaps only an actual owned process group',async()=>{
  const m=await implementation();const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});
  try {await new Promise((resolve,reject)=>{child.once('spawn',resolve);child.once('error',reject);});await m.stopOwned(child);
    assert.ok(child.exitCode!==null||child.signalCode!==null);assert.throws(()=>process.kill(child.pid,0),/ESRCH/);
  } finally {if(child.pid&&child.exitCode===null&&child.signalCode===null){process.kill(-child.pid,'SIGKILL');await new Promise(r=>child.once('exit',r));}}
});
test('cleanup still reaps both actual owned children if CDP closure fails',async()=>{
  const m=await implementation();const children=[0,1].map(()=>spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'}));
  try {
    await Promise.all(children.map(c=>new Promise((resolve,reject)=>{c.once('spawn',resolve);c.once('error',reject);})));await fixture(async work=>{
      const result=await m.cleanupOwned({cdp:{call:async()=>({}),close:()=>{throw new Error('forced close failure');}},chrome:children[0],xvfb:children[1],work});
      assert.equal(result.private_profile_and_ISO_removed,false);assert.match(result.cleanup_error,/forced close failure/);
      for(const child of children){assert.ok(child.exitCode!==null||child.signalCode!==null);assert.throws(()=>process.kill(child.pid,0),/ESRCH/);}
    });
  } finally {for(const child of children)if(child.pid&&child.exitCode===null&&child.signalCode===null){process.kill(-child.pid,'SIGKILL');await new Promise(r=>child.once('exit',r));}}
});
test('successful owned cleanup removes private profile and download directory',async()=>{
  const m=await implementation();await fixture(async work=>{await writeFile(join(work,'private.iso'),iso());const result=await m.cleanupOwned({work});assert.equal(result.private_profile_and_ISO_removed,true);await assert.rejects(stat(work),{code:'ENOENT'});});
});
test('invalid CLI fields fail before creating output or launching children',async()=>{
  const m=await implementation();await fixture(async parent=>{
    for(const tail of [['--unknown','x'],['--iso-path','/public.iso'],['--iso-path','/public.iso','--iso-sha256','f'.repeat(64),'--iso-bytes','536870913'],['--out','duplicate']]){
      const out=join(parent,'never-created');await assert.rejects(m.main(['--out',out,'--chrome','/missing','--xvfb','/missing',...tail]));await assert.rejects(stat(out),{code:'ENOENT'});
    }
  });
});
test('public DNS classification rejects private, documentation, reserved and mapped addresses',async()=>{
  const m=await implementation();
  for(const a of ['8.8.8.8','172.64.80.1','104.21.44.73','192.0.0.9','192.0.0.10','2606:4700:3032::ac43:c4ef','2001:4860:4860::8888','2001:1::1','2001:20::1'])assert.equal(m.isPublicAddress(a),true,a);
  for(const a of ['0.0.0.0','10.0.0.1','100.64.0.1','127.0.0.1','169.254.1.1','172.16.0.1','172.31.255.255','192.0.0.8','192.0.2.1','192.88.99.1','192.168.1.1','198.18.0.1','198.19.255.255','198.51.100.1','203.0.113.1','224.0.0.1','239.255.255.255','240.0.0.1','255.255.255.255','::','::1','::ffff:192.168.1.1','::ffff:c0a8:101','::ffff:8.8.8.8','64:ff9b:1::1','100::1','2001::1','2001:2::1','2001:db8::1','2002:0808:0808::1','3fff::1','4000::1','fc00::1','fdff::1','fe80::1','fec0::1','ff02::1','2606:4700::1%eth0','not-ip','01.2.3.4','1.2.3.999'])assert.equal(m.isPublicAddress(a),false,a);
});
test('actual sparse 271 MiB download can pass full SHA and PVD inside the 512 MiB limit',async()=>{
  const m=await implementation();await fixture(async p=>{
    const bytes=284164096,f=join(p,'download'),header=Buffer.alloc(32775);header[32768]=1;header.write('CD001',32769);header[32774]=1;
    const fd=await open(f,'wx');try{await fd.truncate(bytes);await fd.write(header,0,header.length,0);}finally{await fd.close();}
    const h=createHash('sha256');h.update(header);const zeros=Buffer.alloc(1024*1024);let remaining=bytes-header.length;
    while(remaining){const n=Math.min(remaining,zeros.length);h.update(zeros.subarray(0,n));remaining-=n;}
    const r=await m.verifyDownloadedISO(f,bytes,h.digest('hex'),10000);assert.equal(r.checked_bytes,bytes);assert.equal(r.ISO9660_PVD_verified,true);
    await assert.rejects(m.verifyDownloadedISO(f,512*1024*1024+1,'f'.repeat(64),1000));
  });
});
test('atomic receipt completes real short writes and publishes exact bytes',async()=>{
  const m=await implementation();await fixture(async p=>{
    const path=join(p,'result.json'),record={status:'PASS',proof:'only after every byte closes successfully'},io={open:async(...args)=>{const h=await open(...args);return {write:(b,o,n,pos)=>h.write(b,o,Math.min(n,13),pos),sync:()=>h.sync(),close:()=>h.close()};},readFile,rename,rm};
    await m.writeAtomicJSON(path,record,io);assert.equal(await readFile(path,'utf8'),JSON.stringify(record,null,2)+'\n');assert.deepEqual(await readdir(p),['result.json']);
  });
});
test('partial valid PASS JSON followed by ENOSPC never becomes a canonical receipt',async()=>{
  const m=await implementation();await fixture(async p=>{
    const path=join(p,'result.json');let partialValid=false;
    const io={open:async(...args)=>{const h=await open(...args);let first=true;return {write:async(b,o,n,pos)=>{
      if(!first)throw Object.assign(new Error('forced ENOSPC'),{code:'ENOSPC'});first=false;const written=await h.write(b,o,n-1,pos);
      partialValid=JSON.parse(await readFile(args[0],'utf8')).status==='PASS';return written;
    },sync:()=>h.sync(),close:()=>h.close()};},readFile,rename,rm};
    await assert.rejects(m.writeAtomicJSON(path,{status:'PASS'},io),/ENOSPC/);assert.equal(partialValid,true);await assert.rejects(stat(path),{code:'ENOENT'});assert.deepEqual(await readdir(p),[]);
  });
});
test('close, fsync, misreported counts, no progress and rename failures leave no canonical PASS',async()=>{
  const m=await implementation();
  for(const mode of ['close','sync','lie','zero','oversized','rename'])await fixture(async p=>{
    const path=join(p,'result.json'),io={open:async(...args)=>{const h=await open(...args);return {
      write:async(b,o,n,pos)=>mode==='zero'?{bytesWritten:0}:mode==='oversized'?{bytesWritten:n+1}:mode==='lie'?{bytesWritten:n}:h.write(b,o,n,pos),
      sync:async()=>{if(mode==='sync')throw new Error('forced fsync failure');return h.sync();},
      close:async()=>{await h.close();if(mode==='close')throw new Error('forced close failure');}
    };},readFile,rename:async(...a)=>{if(mode==='rename')throw new Error('forced atomic rename failure');return rename(...a);},rm};
    await assert.rejects(m.writeAtomicJSON(path,{status:'PASS'},io));await assert.rejects(stat(path),{code:'ENOENT'});assert.deepEqual(await readdir(p),[]);
  });
});
