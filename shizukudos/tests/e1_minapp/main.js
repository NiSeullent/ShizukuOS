// SPDX-License-Identifier: GPL-2.0-only
// ShizukuDOS E1 minimal Electron probe: opens a hidden BrowserWindow on a local page whose script computes the marker,
// reads it back from the renderer and prints it on stdout/stderr, then quits with exit code 0. Any failure path exits
// non-zero, so run_k64_electron.py can PASS only when the page script actually ran.
//
// Every line goes out twice: through process._rawDebug (Node's C-level stderr write, no libuv stream needed) and through
// console.log (the stdout stream; a failure to create it is reported, not fatal). An uncaughtException handler is
// installed first: without one Electron shows its own "A JavaScript error occurred" dialog (TaskDialogIndirect), which a
// headless run cannot read; with it the stack of the error is the last line of the log.
let app = null;

function raw(line) {
  try { process._rawDebug(line); } catch (e) { /* nothing left to report through */ }
}

function say(line) {
  raw(line);
  try {
    console.log(line);
  } catch (e) {
    raw('SHZ-E1 main: console.log threw ' + (e && e.stack ? e.stack : e));
  }
}

function die(code, line) {
  raw(line);
  try { if (app) app.exit(code); } catch (e) { /* fall through */ }
  process.exit(code);
}

// A write error on stdout/stderr (EPIPE on a runtime whose stdio handle is not a working pipe) arrives as an 'error' event of the
// stream, which Node turns into an uncaughtException: it would end the probe before the marker. Every line also goes through
// process._rawDebug, so the error is reported and the run goes on.
for (const name of ['stdout', 'stderr']) {
  try {
    process[name].on('error', (err) => raw('SHZ-E1 main: ' + name + ' stream error ' + (err && err.code ? err.code : err) + ' (reported, not fatal)'));
  } catch (e) { raw('SHZ-E1 main: process.' + name + ' unavailable: ' + (e && e.message ? e.message : e)); }
}
process.on('uncaughtException', (err) => die(9, 'SHZ-E1 main: uncaughtException ' + (err && err.stack ? err.stack : err)));
process.on('unhandledRejection', (err) => die(10, 'SHZ-E1 main: unhandledRejection ' + (err && err.stack ? err.stack : err)));

raw('SHZ-E1 main: started, node ' + process.versions.node + ', electron ' + process.versions.electron +
    ', chrome ' + process.versions.chrome + ', ' + process.platform + '/' + process.arch);
const electron = require('electron');
raw('SHZ-E1 main: require(electron) ok');
app = electron.app;
const { BrowserWindow } = electron;
const path = require('path');

setTimeout(() => die(4, 'SHZ-E1 main: watchdog expired'), 900000);

app.on('window-all-closed', () => {});
app.whenReady().then(() => {
  say('SHZ-E1 main: app ready');
  const win = new BrowserWindow({ show: false, width: 320, height: 200, webPreferences: { sandbox: false } });
  win.webContents.on('console-message', (e) => say('SHZ-E1 renderer console: ' + (e.message ?? '')));
  win.webContents.on('render-process-gone', (e, d) => die(5, 'SHZ-E1 main: renderer gone ' + JSON.stringify(d)));
  win.webContents.on('did-fail-load', (e, code, desc) => die(3, 'SHZ-E1 main: load failed ' + code + ' ' + desc));
  win.webContents.on('did-finish-load', async () => {
    try {
      const title = await win.webContents.executeJavaScript('document.title');
      say('SHZ-E1-MARKER ' + title);
      app.exit(title === 'electron-min 42' ? 0 : 6);
    } catch (err) {
      die(7, 'SHZ-E1 main: executeJavaScript failed ' + (err && err.stack ? err.stack : err));
    }
  });
  win.loadFile(path.join(__dirname, 'index.html'));
}).catch((err) => die(8, 'SHZ-E1 main: whenReady failed ' + (err && err.stack ? err.stack : err)));
