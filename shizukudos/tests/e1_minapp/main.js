// SPDX-License-Identifier: GPL-2.0-only
// ShizukuDOS E1 minimal Electron probe: opens a hidden BrowserWindow on a local page whose script computes the marker,
// reads it back from the renderer and prints it on stdout/stderr, then quits with exit code 0. Any failure path exits
// non-zero, so run_k64_electron.py can PASS only when the page script actually ran.
const { app, BrowserWindow } = require('electron');
const path = require('path');

function say(line) {
  console.log(line);
  process.stderr.write(line + '\n');
}

say('SHZ-E1 main: started, electron ' + process.versions.electron + ', node ' + process.versions.node);
setTimeout(() => { say('SHZ-E1 main: watchdog expired'); app.exit(4); }, 900000);

app.on('window-all-closed', () => {});
app.whenReady().then(() => {
  say('SHZ-E1 main: app ready');
  const win = new BrowserWindow({ show: false, width: 320, height: 200, webPreferences: { sandbox: false } });
  win.webContents.on('console-message', (e) => say('SHZ-E1 renderer console: ' + (e.message ?? '')));
  win.webContents.on('render-process-gone', (e, d) => { say('SHZ-E1 main: renderer gone ' + JSON.stringify(d)); app.exit(5); });
  win.webContents.on('did-fail-load', (e, code, desc) => { say('SHZ-E1 main: load failed ' + code + ' ' + desc); app.exit(3); });
  win.webContents.on('did-finish-load', async () => {
    try {
      const title = await win.webContents.executeJavaScript('document.title');
      say('SHZ-E1-MARKER ' + title);
      app.exit(title === 'electron-min 42' ? 0 : 6);
    } catch (err) {
      say('SHZ-E1 main: executeJavaScript failed ' + err);
      app.exit(7);
    }
  });
  win.loadFile(path.join(__dirname, 'index.html'));
}).catch((err) => { say('SHZ-E1 main: whenReady failed ' + err); app.exit(8); });
