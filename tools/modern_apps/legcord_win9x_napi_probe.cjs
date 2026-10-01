/* Real adapter/lifecycle probe for the future exact native Electron port.
 * SPDX-License-Identifier: GPL-2.0-only. Never executes on import.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Worker, isMainThread, parentPort, workerData } = require('node:worker_threads');
const { dosPath } = require('./legcord_win9x_napi_bootstrap.cjs');

if (!isMainThread && workerData && workerData.scope === 'actual-win98-lease-env-cleanup') {
    const binding = require(workerData.addon);
    globalThis.retainedNativeSourceLease = binding.acquire(workerData.files);
    parentPort.postMessage({ held: globalThis.retainedNativeSourceLease.held });
    setInterval(() => {}, 1000); // parent terminates this real owned environment
}

function writerAllowed(file) {
    let descriptor;
    try { descriptor = fs.openSync(file, 'r+'); }
    catch { return false; }
    fs.closeSync(descriptor);
    return true;
}

function rejected(action) {
    try {
        const unexpected = action();
        if (unexpected && unexpected.held === true && typeof unexpected.release === 'function') unexpected.release();
        return false;
    } catch { return true; }
}

async function probe(addon, directory, nonce) {
    dosPath(addon); dosPath(directory);
    if (!/^[A-Za-z0-9_-]{1,80}$/.test(nonce || '')) throw new Error('Require a fresh bounded nonce');
    const binding = require(addon); // real native module rejects wrong OS/runtime
    if (typeof binding.acquire !== 'function') throw new Error('Actual Node-API initialization missing');
    fs.mkdirSync(directory); // fail closed on any preexisting fixture directory
    const first = path.win32.join(directory, 'LEASE0.TXT');
    const second = path.win32.join(directory, 'LEASE1.TXT');
    const missing = path.win32.join(directory, 'ABSENT.TXT');
    const log = path.win32.join(directory, 'NAPI.LOG');
    const checks = {};
    let lease, worker;
    const result = {
        scope: 'actual-node-api-source-lease-component', nonce,
        versions: process.versions, platform: process.platform, arch: process.arch,
        sourceSha256: crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex'),
        addonSha256: crypto.createHash('sha256').update(fs.readFileSync(addon)).digest('hex'),
        checks, nativeComponentPass: false, legcordStarted: false, wholeAppPass: false
    };
    try {
        fs.writeFileSync(first, 'actual-source-lease-0\r\n', { flag: 'wx' });
        fs.writeFileSync(second, 'actual-source-lease-1\r\n', { flag: 'wx' });
        checks.invalidArray = rejected(() => binding.acquire([]));
        checks.invalidType = rejected(() => binding.acquire([42]));
        checks.relativePath = rejected(() => binding.acquire(['relative.txt']));
        checks.unrepresentablePath = rejected(() => binding.acquire([directory + '\\\uD55C.txt']));
        checks.devicePath = rejected(() => binding.acquire([directory + '\\NUL']));
        checks.duplicates = rejected(() => binding.acquire([first, first.toLowerCase()]));
        checks.partialMissing = rejected(() => binding.acquire([first, missing])) && writerAllowed(first);
        lease = binding.acquire([first, second]);
        checks.held = lease.held === true;
        checks.writerBlocked = !writerAllowed(first);
        checks.deleteBlocked = rejected(() => fs.unlinkSync(first));
        checks.detachedReleaseRejected = rejected(() => lease.release.call({}));
        const getter = Object.getOwnPropertyDescriptor(lease, 'held').get;
        checks.foreignGetterRejected = rejected(() => getter.call({}));
        checks.stillHeldAfterInvalidReceiver = lease.held === true && !writerAllowed(first);
        lease.release(); lease.release();
        checks.releaseIdempotent = lease.held === false && writerAllowed(first);
        const reacquired = binding.acquire([first, second]);
        checks.reacquire = reacquired.held === true;
        reacquired.release();
        worker = new Worker(__filename, { workerData: {
            scope: 'actual-win98-lease-env-cleanup', addon, files: [first, second]
        } });
        const message = await new Promise((resolve, reject) => {
            const deadline = setTimeout(() => reject(new Error('Real worker lease timed out')), 10000);
            worker.once('message', value => { clearTimeout(deadline); resolve(value); });
            worker.once('error', error => { clearTimeout(deadline); reject(error); });
            worker.once('exit', () => { clearTimeout(deadline); reject(new Error('Worker exited before holding its lease')); });
        });
        checks.workerEnvironmentHeld = message.held === true && !writerAllowed(first);
        await worker.terminate(); worker = undefined;
        checks.environmentCleanupReleased = writerAllowed(first);
        if (typeof global.gc === 'function') {
            (() => { binding.acquire([first, second]); })();
            checks.gcInitiallyHeld = !writerAllowed(first);
            for (let count = 0; count < 20 && !writerAllowed(first); ++count) {
                global.gc();
                await new Promise(resolve => setImmediate(resolve));
            }
            checks.objectFinalizerReleased = writerAllowed(first);
        } else {
            checks.objectFinalizerReleased = false;
            result.gcCapability = 'unavailable; rerun real runtime with exposed GC before claiming lifecycle PASS';
        }
        result.nativeComponentPass = Object.values(checks).every(value => value === true);
    } catch (error) {
        result.failure = error.message;
    } finally {
        if (worker) await worker.terminate();
        if (lease) lease.release();
        // Delete only this probe's known created files after releasing handles.
        for (const file of [first, second]) {
            try { fs.unlinkSync(file); } catch (error) {
                if (error.code !== 'ENOENT') { result.nativeComponentPass = false; result.cleanupFailure = error.message; }
            }
        }
        fs.writeFileSync(log, JSON.stringify(result) + '\n', { flag: 'wx' });
    }
    return result;
}

module.exports = { probe };
if (isMainThread && require.main === module) {
    probe(process.argv[2], process.argv[3], process.argv[4]).then(result => {
        process.stdout.write(JSON.stringify(result) + '\n');
        process.exitCode = result.nativeComponentPass ? 0 : 2;
    }).catch(error => { process.stderr.write(error.message + '\n'); process.exitCode = 2; });
}
