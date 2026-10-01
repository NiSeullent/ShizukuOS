/* Source bootstrap tests only; no Electron or browser is launched. SPDX-License-Identifier: GPL-2.0-only */
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { configureRuntime, verifyEntryBytes, bindEntry, requireNativeTreeLease, retainLeaseToProcessExit } = require('./legcord_win9x_entry.cjs');
const versions = { electron: '43.2.0', chrome: '150.0.7871.129', node: '24.18.0' };
let disabled = 0;
const runtime = { app: { isReady: () => false, disableHardwareAcceleration: () => { disabled++; } } };
const report = configureRuntime(runtime, versions, 'win32', 'ia32');
assert.equal(disabled, 1);
assert.equal(report.discordPass, false);
assert.equal(report.runtimeCompatibility, 'unverified');
assert.throws(() => configureRuntime(runtime, versions, 'win32', 'x64'), /actual x86/);
assert.throws(() => configureRuntime(runtime, { ...versions, electron: '44.0.0' }, 'win32', 'ia32'), /differs/);
assert.throws(() => configureRuntime({ app: { isReady: () => true } }, versions, 'win32', 'ia32'), /precede/);
const raw = Buffer.from('selected source entry');
const hash = crypto.createHash('sha256').update(raw).digest('hex');
const binding = verifyEntryBytes('/owned/ts-out/main.js', hash, raw);
assert.equal(binding.sha256, hash);
assert.equal(binding.bytes, raw.length);
assert.equal(binding.sourceCommitVerified, false);
assert.throws(() => verifyEntryBytes('/owned/ts-out/main.js', '0'.repeat(64), raw), /differs/);
assert.throws(() => verifyEntryBytes('/owned/ts-out/main.js', undefined, raw), /exact entry SHA/);
assert.throws(() => bindEntry('/nonexistent/main.js', undefined), /build-receipt/);
assert.throws(() => verifyEntryBytes('main.js', hash, raw), /absolute path/);
assert.throws(() => requireNativeTreeLease(runtime, ['/owned/ts-out/main.js']), /native Win98/);
let released = 0;
assert.throws(() => requireNativeTreeLease({ win98SourceLease: {
    acquire: () => ({ held: false, release: () => { released++; } })
} }, ['/owned/ts-out/main.js']), /acquisition failed/);
assert.equal(released, 1);
/* Test the source-handle lifetime contract only; this host control does not
 * simulate successful Electron/Legcord execution. will-quit is cancellable. */
const lifecycle = new EventEmitter();
let closed = 0;
const releaseBeforeImport = retainLeaseToProcessExit(lifecycle, { release: () => { closed++; } });
let cancelled = false;
lifecycle.on('will-quit', event => event.preventDefault());
lifecycle.emit('will-quit', { preventDefault: () => { cancelled = true; } });
assert.equal(cancelled, true);
assert.equal(closed, 0);
lifecycle.emit('exit', 0);
lifecycle.emit('exit', 0);
releaseBeforeImport();
assert.equal(closed, 1);
const setupFailure = new EventEmitter();
const cleanupBeforeImport = retainLeaseToProcessExit(setupFailure, { release: () => { closed++; } });
cleanupBeforeImport();
setupFailure.emit('exit', 2);
assert.equal(closed, 2);
console.log('Legcord source bootstrap checks passed; native runtime and Discord remain unverified.');
