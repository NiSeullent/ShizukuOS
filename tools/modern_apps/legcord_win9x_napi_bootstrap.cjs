/* Inventory-checked loader for the real native lease adapter. GPL-2.0-only.
 * Importing this file does not launch Legcord or configure a runtime.
 * Initial addon/bootstrap staging must already be trusted. Existing-file
 * leases hold bytes; they do not prohibit new directory entries or prove
 * the complete future lazy-import dependency closure.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const HELPER_SHA = '921ab2a9872d5cf627ab4845089cf49c5411d9abcd805f037f97cab72f9937d8';
const MAX_FILES = 255; // one additional held file is the external manifest
const MAX_FILE = 8 * 1024 * 1024;
const MAX_TREE = 64 * 1024 * 1024;
const hex = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);

function dosPath(value) {
    if (typeof value !== 'string' || value.length < 4 || value.length >= 260 ||
        !/^[A-Za-z]:\\[\x20-\x7e]+$/.test(value) || /[/:*?"<>|]/.test(value.slice(3)))
        throw new Error('Require an exact representable absolute ASCII DOS path');
    if (value.slice(3).split('\\').some(part => !part || part === '.' || part === '..' || /[. ]$/.test(part) ||
        /^(CON|PRN|AUX|NUL|CLOCK\$|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(part)))
        throw new Error('Reject normalized aliases, empty components and parent traversal');
    return value;
}

function digestFile(file, limit) {
    const descriptor = fs.openSync(file, 'r');
    try {
        const before = fs.fstatSync(descriptor);
        if (!before.isFile() || before.size < 1 || before.size > limit)
            throw new Error('Frozen input is not a bounded regular file');
        const hash = crypto.createHash('sha256');
        const buffer = Buffer.alloc(64 * 1024);
        let bytes = 0;
        for (;;) {
            const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
            if (!count) break;
            bytes += count;
            if (bytes > limit) throw new Error('Frozen input grew beyond its bound');
            hash.update(buffer.subarray(0, count));
        }
        const after = fs.fstatSync(descriptor);
        if (bytes !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs)
            throw new Error('Frozen input changed during inspection');
        return { bytes, sha256: hash.digest('hex') };
    } finally { fs.closeSync(descriptor); }
}

function runtimeGate() {
    if (process.platform !== 'win32' || process.arch !== 'ia32' ||
        process.versions.node !== '24.18.0' || process.versions.electron !== '43.2.0' ||
        process.versions.chrome !== '150.0.7871.129')
        throw new Error('Require the frozen actual x86 Electron43.2.0 / Node24.18.0 process');
}

function treePaths(root) {
    const result = [];
    let directories = 0;
    function walk(directory) {
        if (++directories > 512) throw new Error('Frozen tree exceeds its directory bound');
        for (const name of fs.readdirSync(directory)) {
            const selected = dosPath(path.win32.join(directory, name));
            const info = fs.lstatSync(selected);
            if (info.isSymbolicLink()) throw new Error('Frozen tree must not contain source links');
            if (info.isDirectory()) walk(selected);
            else if (info.isFile()) {
                result.push(selected);
                if (result.length > MAX_FILES) throw new Error('Frozen tree exceeds native lease capacity');
            } else throw new Error('Frozen tree contains an unsupported source type');
        }
    }
    const rootInfo = fs.lstatSync(root);
    if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new Error('Require the actual frozen source root');
    walk(root);
    return result.sort((a, b) => a.toLowerCase() < b.toLowerCase() ? -1 : a.toLowerCase() > b.toLowerCase() ? 1 : 0);
}

function parseInventory(manifest, expectedSha) {
    dosPath(manifest);
    if (!hex(expectedSha)) throw new Error('Require the exact caller manifest SHA-256');
    const descriptor = fs.openSync(manifest, 'r');
    let raw;
    try {
        const info = fs.fstatSync(descriptor);
        if (!info.isFile() || info.size < 1 || info.size > 256 * 1024)
            throw new Error('Manifest must be a bounded regular file');
        const buffer = Buffer.alloc(info.size + 1);
        let bytes = 0;
        while (bytes < buffer.length) {
            const count = fs.readSync(descriptor, buffer, bytes, buffer.length - bytes, bytes);
            if (!count) break;
            bytes += count;
        }
        if (bytes !== info.size || fs.fstatSync(descriptor).size !== info.size)
            throw new Error('Manifest changed while being read');
        raw = buffer.subarray(0, bytes);
    } finally { fs.closeSync(descriptor); }
    if (!raw.length || raw.length > 256 * 1024 || crypto.createHash('sha256').update(raw).digest('hex') !== expectedSha)
        throw new Error('Frozen manifest bytes differ from the caller pin');
    const value = JSON.parse(raw.toString('utf8'));
    if (value.schema !== 'legcord-win9x-napi-frozen-tree-v1' || !Array.isArray(value.files) ||
        !value.files.length || value.files.length > MAX_FILES || !hex(value.runtimeSha256))
        throw new Error('Require the complete bounded frozen-tree manifest and runtime PE hash');
    const root = dosPath(value.root);
    const prefix = root.toLowerCase() + '\\';
    if (manifest.toLowerCase() === root.toLowerCase() || manifest.toLowerCase().startsWith(prefix))
        throw new Error('The checksum-bound manifest must be outside the frozen tree');
    const rows = new Map();
    let bytes = 0;
    for (const row of value.files) {
        if (!row || typeof row.path !== 'string' || path.win32.isAbsolute(row.path) ||
            !hex(row.sha256) || !Number.isSafeInteger(row.bytes) || row.bytes < 1 || row.bytes > MAX_FILE)
            throw new Error('Invalid frozen file inventory row');
        const absolute = dosPath(path.win32.join(root, row.path));
        if (!absolute.toLowerCase().startsWith(prefix) || path.win32.relative(root, absolute) !== row.path ||
            rows.has(absolute.toLowerCase())) throw new Error('Duplicate or aliased frozen source path');
        rows.set(absolute.toLowerCase(), { ...row, absolute });
        bytes += row.bytes;
        if (bytes > MAX_TREE) throw new Error('Frozen source tree exceeds its byte bound');
    }
    const select = key => {
        const relative = value[key];
        if (typeof relative !== 'string') throw new Error('Require the explicit frozen ' + key);
        const absolute = dosPath(path.win32.join(root, relative));
        const row = rows.get(absolute.toLowerCase());
        if (!row || row.path !== relative) throw new Error('Selected entry/adapter/helper is absent from the full inventory');
        return row;
    };
    const entry = select('entry');
    const adapter = select('adapter');
    const helper = select('entryBootstrap');
    if (path.win32.basename(entry.absolute) !== 'main.js' || !adapter.absolute.endsWith('.node') || helper.sha256 !== HELPER_SHA)
        throw new Error('Require the actual pinned entry bootstrap and native .node adapter');
    return { value, root, rows, entry, adapter, helper, manifest, expectedSha };
}

function verifyTree(inventory) {
    const actual = treePaths(inventory.root);
    if (actual.length !== inventory.rows.size || actual.some(file => !inventory.rows.has(file.toLowerCase())))
        throw new Error('Frozen source inventory has missing or extra files');
    for (const file of actual) {
        const row = inventory.rows.get(file.toLowerCase());
        const observed = digestFile(file, MAX_FILE);
        if (observed.bytes !== row.bytes || observed.sha256 !== row.sha256)
            throw new Error('Actual frozen source bytes differ: ' + file);
    }
    return actual;
}

async function loadAndStart(manifest, expectedSha) {
    runtimeGate();
    const inventory = parseInventory(manifest, expectedSha);
    const runtime = digestFile(dosPath(process.execPath), 512 * 1024 * 1024);
    if (runtime.sha256 !== inventory.value.runtimeSha256) throw new Error('The actual runtime PE differs from its caller pin');
    const addonBefore = digestFile(inventory.adapter.absolute, MAX_FILE);
    if (addonBefore.sha256 !== inventory.adapter.sha256 || addonBefore.bytes !== inventory.adapter.bytes)
        throw new Error('The real native adapter differs from its caller pin');
    const adapter = require(inventory.adapter.absolute);
    if (!adapter || typeof adapter.acquire !== 'function') throw new Error('Real native Node-API registration failed');
    const files = treePaths(inventory.root);
    if (files.length !== inventory.rows.size || files.some(file => !inventory.rows.has(file.toLowerCase())))
        throw new Error('Reject missing or extra source files before native acquisition');
    const lease = adapter.acquire([...files, manifest]);
    if (!lease || lease.held !== true || typeof lease.release !== 'function')
        throw new Error('The actual complete native source lease was not established');
    let retained = false;
    try {
        parseInventory(manifest, expectedSha); // exact manifest remains held
        verifyTree(inventory);                // all hashes are checked while held
        const electron = require('electron');
        if (Object.prototype.hasOwnProperty.call(electron, 'win98SourceLease'))
            throw new Error('Do not replace an existing native runtime binding');
        Object.defineProperty(electron, 'win98SourceLease', { value: adapter });
        const releaseAtExit = () => lease.release();
        process.once('exit', releaseAtExit);
        retained = true;
        const entry = require(inventory.helper.absolute);
        if (typeof entry.start !== 'function') throw new Error('Pinned actual entry bootstrap did not export start');
        // Keep the outer full-tree lease even if application import fails;
        // imported threads/lazy modules may already exist at that point.
        const observedEntry = files.find(file => file.toLowerCase() === inventory.entry.absolute.toLowerCase());
        if (!observedEntry) throw new Error('The actual observed entry is absent from the held inventory');
        await entry.start(observedEntry, inventory.entry.sha256, files);
    } finally {
        if (!retained) lease.release();
    }
}

module.exports = { dosPath, parseInventory, verifyTree, loadAndStart };
if (require.main === module) {
    loadAndStart(process.argv[2], process.argv[3]).catch(error => {
        process.stderr.write('legcord-native-bootstrap: ' + error.message + '\n');
        process.exitCode = 2;
    });
}
