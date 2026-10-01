// SPDX-License-Identifier: GPL-2.0-only
// ShizukuDOS E1 Node-mode probe, run as `electron.exe nodeprobe.js` with ELECTRON_RUN_AS_NODE=1 (Electron's own Node, no
// Chromium): a ladder over the parts of libuv and Node that Electron and VS Code depend on. One line per step, so a
// run reports, for every step, "SHZ-E1-NODE step N ok: <name>" or "step N FAILED: <name>: <error>"; it goes on after a failed step.
// Output goes through process._rawDebug (C-level stderr) first, console.log second. Exit code 0 only when every step passed; the last line is "SHZ-E1-NODE-DONE <n> steps, <k> ok, <m> failed".
'use strict';

function raw(line) {
  try { process._rawDebug(line); } catch (e) { /* nothing left to report through */ }
}

let current = 'start';
let failures = 0;
function begin(name) { current = name; raw('SHZ-E1-NODE step begin: ' + name); }
function ok(n) { raw('SHZ-E1-NODE step ' + n + ' ok: ' + current); }
function stepFailed(n, err) {
  ++failures;
  raw('SHZ-E1-NODE step ' + n + ' FAILED: ' + current + ': ' + (err && err.stack ? err.stack : err));
}
// An error outside any step's promise chain (a callback that throws later) is charged to the step that was running.
process.on('uncaughtException', (err) => { stepFailed('?', err); });
process.on('unhandledRejection', (err) => { stepFailed('?', err); });

raw('SHZ-E1-NODE started: node ' + process.versions.node + ', v8 ' + process.versions.v8 + ', uv ' + process.versions.uv +
    ', ' + process.platform + '/' + process.arch + ', argv ' + JSON.stringify(process.argv.slice(1)));
const steps = [];
const add = (name, fn) => steps.push([name, fn]);

add('console.log', () => { console.log('SHZ-E1-NODE console.log works'); });

add('fs stat/read/write/readdir', () => {
  const fs = require('fs'), path = require('path');
  const st = fs.statSync(__filename);
  if (!st.isFile() || st.size <= 0) throw new Error('statSync(__filename) gave isFile=' + st.isFile() + ' size=' + st.size);
  const text = fs.readFileSync(__filename, 'utf8');
  if (!text.includes('SHZ-E1-NODE')) throw new Error('readFileSync content');
  const dir = path.join(path.dirname(__filename), 'e1probe.tmp');
  fs.mkdirSync(dir, { recursive: true });
  const f = path.join(dir, 'a.txt');
  fs.writeFileSync(f, 'hello');
  fs.appendFileSync(f, ' world');
  if (fs.readFileSync(f, 'utf8') !== 'hello world') throw new Error('write/append/read mismatch');
  if (!fs.readdirSync(dir).includes('a.txt')) throw new Error('readdir');
  fs.renameSync(f, path.join(dir, 'b.txt'));
  fs.unlinkSync(path.join(dir, 'b.txt'));
  fs.rmdirSync(dir);
});

add('os', () => {
  const os = require('os');
  raw('SHZ-E1-NODE os: ' + os.platform() + ' ' + os.arch() + ' cpus=' + os.cpus().length + ' totalmem=' + os.totalmem() +
      ' homedir=' + os.homedir() + ' tmpdir=' + os.tmpdir());
  try { raw('SHZ-E1-NODE os.hostname: ' + os.hostname()); } catch (e) { raw('SHZ-E1-NODE os.hostname threw ' + e.message); }
});

add('timers + immediates + microtasks', () => new Promise((resolve, reject) => {
  // The order of a timer and an immediate depends on how long the first loop iteration takes (an emulated machine is slow
  // enough for a 30 ms timer to be due first), so the immediate is compared with a timer that is far enough away.
  const order = [];
  setTimeout(() => { order.push('timeout'); }, 600);
  setImmediate(() => { order.push('immediate'); });
  process.nextTick(() => { order.push('tick'); });
  Promise.resolve().then(() => { order.push('micro'); });
  setTimeout(() => {
    const good = order.length === 4 && order.slice().sort().join() === 'immediate,micro,tick,timeout' &&
                 order.indexOf('immediate') === 2 && order[3] === 'timeout';
    if (good) resolve(); else reject(new Error('order ' + order.join() + ', want tick+micro, immediate, timeout'));
  }, 900);
}));

add('crypto random + hash', () => {
  const crypto = require('crypto');
  if (crypto.randomBytes(16).length !== 16) throw new Error('randomBytes');
  const h = crypto.createHash('sha256').update('abc').digest('hex');
  if (h !== 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') throw new Error('sha256 ' + h);
});

add('zlib', () => {
  const zlib = require('zlib');
  const src = Buffer.from('x'.repeat(5000) + 'shizuku');
  if (!zlib.gunzipSync(zlib.gzipSync(src)).equals(src)) throw new Error('gzip round trip');
});

add('net loopback echo', () => new Promise((resolve, reject) => {
  const net = require('net');
  const server = net.createServer((sock) => { sock.on('data', (d) => sock.end(d)); sock.on('error', reject); });
  server.on('error', reject);
  server.listen(0, '127.0.0.1', () => {
    const port = server.address().port;
    const c = net.connect(port, '127.0.0.1');
    let got = '';
    c.on('data', (d) => { got += d; });
    c.on('error', reject);
    c.on('close', () => { server.close(); if (got === 'ping-e1') resolve(); else reject(new Error('echo got "' + got + '"')); });
    c.write('ping-e1');
  });
}));

add('named pipe echo (\\\\.\\pipe\\)', () => new Promise((resolve, reject) => {
  const net = require('net');
  const name = '\\\\.\\pipe\\shz-e1-' + process.pid;
  const server = net.createServer((sock) => { sock.on('data', (d) => sock.end(d)); sock.on('error', reject); });
  server.on('error', reject);
  server.listen(name, () => {
    const c = net.connect(name);
    let got = '';
    c.on('data', (d) => { got += d; });
    c.on('error', reject);
    c.on('close', () => { server.close(); if (got === 'pipe-e1') resolve(); else reject(new Error('pipe echo got "' + got + '"')); });
    c.write('pipe-e1');
  });
}));

add('child_process.spawnSync (a process with a pipe)', () => {
  const cp = require('child_process');
  const r = cp.spawnSync(process.execPath, ['-e', 'process.stdout.write("child-e1")'], { env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' }, encoding: 'utf8' });
  if (r.error) throw r.error;
  if (r.status !== 0 || r.stdout !== 'child-e1') throw new Error('spawnSync status=' + r.status + ' stdout=' + JSON.stringify(r.stdout) + ' stderr=' + JSON.stringify(r.stderr));
});

add('dns.lookup("localhost") (uv_getaddrinfo on the thread pool)', () => new Promise((resolve, reject) => {
  require('dns').lookup('localhost', (err, address) => {
    if (err) return reject(err);
    raw('SHZ-E1-NODE dns localhost -> ' + address);
    resolve();
  });
}));

add('http loopback request', () => new Promise((resolve, reject) => {
  const http = require('http');
  const server = http.createServer((req, res) => { res.end('http-e1'); });
  server.on('error', reject);
  server.listen(0, '127.0.0.1', () => {
    http.get({ host: '127.0.0.1', port: server.address().port, path: '/' }, (res) => {
      let body = '';
      res.on('data', (d) => { body += d; });
      res.on('end', () => { server.close(); if (body === 'http-e1') resolve(); else reject(new Error('http body "' + body + '"')); });
    }).on('error', reject);
  });
}));

add('child_process.spawn (async, stdio pipes)', () => new Promise((resolve, reject) => {
  const cp = require('child_process');
  const c = cp.spawn(process.execPath, ['-e', 'process.stdin.on("data",d=>process.stdout.write("echo:"+d)); process.stdin.on("end",()=>process.exit(0))'],
                     { env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' }, stdio: ['pipe', 'pipe', 'inherit'] });
  let out = '';
  c.stdout.on('data', (d) => { out += d; });
  c.on('error', reject);
  c.on('exit', (code) => { if (code === 0 && out === 'echo:spawn-e1') resolve(); else reject(new Error('spawn exit=' + code + ' out=' + JSON.stringify(out))); });
  c.stdin.end('spawn-e1');
}));

add('worker_threads', () => new Promise((resolve, reject) => {
  const { Worker } = require('worker_threads');
  const w = new Worker('require("worker_threads").parentPort.postMessage(6*7)', { eval: true });
  w.on('message', (m) => { if (m === 42) resolve(); else reject(new Error('worker said ' + m)); });
  w.on('error', reject);
}));

add('fs.watch on a directory (ReadDirectoryChangesW)', () => new Promise((resolve, reject) => {
  const fs = require('fs'), path = require('path');
  const dir = path.dirname(__filename);
  const w = fs.watch(dir, () => {});
  setTimeout(() => { w.close(); resolve(); }, 100);
  w.on('error', reject);
}));

(async () => {
  for (let i = 0; i < steps.length; ++i) {
    begin(steps[i][0]);
    try {
      // a step that never settles would hang the run: give each one a bound
      await Promise.race([Promise.resolve().then(steps[i][1]),
                          new Promise((_, rej) => setTimeout(() => rej(new Error('timed out after 20 s')), 20000))]);
      ok(i + 1);
    } catch (err) {
      stepFailed(i + 1, err);
    }
  }
  raw('SHZ-E1-NODE-DONE ' + steps.length + ' steps, ' + (steps.length - failures) + ' ok, ' + failures + ' failed');
  process.exit(failures ? 1 : 0);
})();
