/* Actual frozen Legcord entry bootstrap for a future native Electron port.
 * SPDX-License-Identifier: GPL-2.0-only
 * Never runs on import. No mocked Electron/Discord, no OS-version spoofing.
 */
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const fs = require('node:fs');
const crypto = require('node:crypto');
const MAX_ENTRY_BYTES = 4 * 1024 * 1024;

function verifyEntryBytes(entry, expectedSha256, raw) {
    if (!entry || !path.isAbsolute(entry) || path.basename(entry) !== 'main.js') {
        throw new Error('Pass the selected actual ts-out/main.js absolute path');
    }
    if (!/^[0-9a-f]{64}$/.test(expectedSha256 || '')) {
        throw new Error('Require an exact entry SHA-256 from the caller build receipt');
    }
    if (!Buffer.isBuffer(raw) || !raw.length || raw.length > MAX_ENTRY_BYTES) {
        throw new Error('Entry exceeds the bounded application-source size');
    }
    const observed = crypto.createHash('sha256').update(raw).digest('hex');
    if (observed !== expectedSha256) {
        throw new Error('Actual entry SHA-256 differs from the caller build receipt');
    }
    return { path: entry, sha256: observed, bytes: raw.length, sourceCommitVerified: false };
}

function bindEntry(entry, expectedSha256) {
    /* Validate arguments before opening anything or configuring Electron. */
    if (!entry || !path.isAbsolute(entry) || path.basename(entry) !== 'main.js' ||
        !/^[0-9a-f]{64}$/.test(expectedSha256 || '')) {
        throw new Error('Require the actual main.js absolute path and build-receipt entry SHA-256');
    }
    const selected = fs.realpathSync(entry);
    const descriptor = fs.openSync(selected, 'r');
    try {
        const info = fs.fstatSync(descriptor);
        if (!info.isFile() || info.size < 1 || info.size > MAX_ENTRY_BYTES) {
            throw new Error('Entry must be a bounded regular source file');
        }
        const raw = Buffer.alloc(info.size + 1);
        let count = 0;
        while (count < raw.length) {
            const read = fs.readSync(descriptor, raw, count, raw.length - count, count);
            if (!read) break;
            count += read;
        }
        if (count !== info.size) throw new Error('Entry changed while binding its build-receipt digest');
        return verifyEntryBytes(selected, expectedSha256, raw.subarray(0, count));
    } finally {
        fs.closeSync(descriptor);
    }
}

function requireNativeTreeLease(runtime, files) {
    if (!runtime.win98SourceLease || typeof runtime.win98SourceLease.acquire !== 'function') {
        throw new Error('Require the ported native Win98 source-read-lease binding before real import');
    }
    const lease = runtime.win98SourceLease.acquire(files);
    if (!lease || lease.held !== true || typeof lease.release !== 'function') {
        if (lease && typeof lease.release === 'function') lease.release();
        throw new Error('Native frozen-tree lease acquisition failed');
    }
    return lease;
}

function retainLeaseToProcessExit(lifetime, lease) {
    if (typeof lifetime.once !== 'function' || typeof lifetime.removeListener !== 'function') {
        throw new Error('Require the real synchronous process exit lifecycle');
    }
    let released = false;
    const releaseOnce = () => {
        if (!released) {
            released = true;
            lease.release();
        }
    };
    lifetime.once('exit', releaseOnce);
    /* Only failures before importing application code may release early.
     * A cancelled app will-quit event cannot release any source handles. */
    return () => {
        lifetime.removeListener('exit', releaseOnce);
        releaseOnce();
    };
}

function configureRuntime(runtime, versions, platform, arch) {
    if (platform !== 'win32' || arch !== 'ia32') {
        throw new Error('Require the actual x86 Win98 port process');
    }
    if (versions.electron !== '43.2.0' || versions.chrome !== '150.0.7871.129' || versions.node !== '24.18.0') {
        throw new Error('Electron/Chromium/Node runtime differs from the frozen Legcord release');
    }
    if (!runtime.app || runtime.app.isReady()) {
        throw new Error('Software-compositor configuration must precede app startup');
    }
    runtime.app.disableHardwareAcceleration();
    return {
        scope: 'actual-legcord-source-entry-prerequisite',
        versions: { electron: versions.electron, chromium: versions.chrome, node: versions.node },
        gpuHardwareAccelerationRequested: false,
        runtimeCompatibility: 'unverified',
        discordPass: false
    };
}

async function start(entry, expectedSha256, frozenPaths) {
    if (!Array.isArray(frozenPaths) || !frozenPaths.includes(entry) ||
        !frozenPaths.length || frozenPaths.length > 256 ||
        frozenPaths.some(file => typeof file !== 'string' || !path.isAbsolute(file))) {
        throw new Error('Require the caller complete frozen application-tree path inventory');
    }
    const runtime = require('electron');
    const lease = requireNativeTreeLease(runtime, frozenPaths);
    let releaseBeforeImport;
    let applicationImportStarted = false;
    try {
        /* The OS lease is acquired before hashing and stays held across the
         * path-based import and later lazy imports until actual app shutdown. */
        const binding = bindEntry(entry, expectedSha256);
        const record = configureRuntime(runtime, process.versions, process.platform, process.arch);
        record.entry = binding;
        record.nativeSourceReadLeaseHeld = true;
        record.completeTreeProvenanceVerified = false;
        releaseBeforeImport = retainLeaseToProcessExit(process, lease);
        process.stdout.write(JSON.stringify(record) + '\n');
        applicationImportStarted = true;
        await import(pathToFileURL(binding.path).href);
    } catch (error) {
        /* A failed import may already have started application threads/lazy
         * imports. Keep its lease until real process exit in that case. */
        if (!applicationImportStarted) {
            if (releaseBeforeImport) releaseBeforeImport();
            else lease.release();
        }
        throw error;
    }
}

module.exports = { verifyEntryBytes, bindEntry, requireNativeTreeLease, retainLeaseToProcessExit, configureRuntime, start };
if (require.main === module) {
    /* The plain CLI has no complete tree receipt/native binding; fail closed.
     * A frozen source build must invoke start with its validated full inventory. */
    start(process.argv[2], process.argv[3], undefined).catch(error => {
        process.stderr.write('legcord-win9x-entry: ' + error.message + '\n');
        process.exitCode = 2;
    });
}
