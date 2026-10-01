/* Real module graph, promises and authorized loopback fetch. MIT */
import { counter, increment, initializationToken } from './counter.mjs';
const fixture = window.ZetscapeFixture;
fixture.record('module.static_import', counter === 1 && typeof increment === 'function', 'Actual static ES module import');
increment();
fixture.record('module.live_binding', counter === 2, 'Imported binding reflects source module mutation');
try {
    const first = await import('./counter.mjs');
    const second = await import('./counter.mjs');
    fixture.record('module.dynamic_cache', first === second && first.initializationToken === initializationToken &&
        first.counter === 2, 'Actual dynamic import namespace/cache identity');
} catch (error) { fixture.record('module.dynamic_cache', false, error.message); }
try {
    const fulfilled = await Promise.resolve(21).then(value => value * 2);
    const recovered = await Promise.reject(new Error('intentional')).catch(error => error.message);
    fixture.record('async.promise_recovery', fulfilled === 42 && recovered === 'intentional', 'Actual fulfilled/rejected Promise continuations');
    const order = [];
    await new Promise(resolve => {
        Promise.resolve().then(() => order.push('microtask'));
        setTimeout(() => { order.push('timer'); resolve(); }, 0);
    });
    fixture.record('async.microtask_order', order.join(',') === 'microtask,timer', 'Actual Promise microtask executes before timer');
} catch (error) {
    for (const id of ['async.promise_recovery', 'async.microtask_order'])
        if (window.__zetscapeAcceptance.checks[id].status === 'NOT_RUN') fixture.record(id, false, error.message);
}
const parameters = new URLSearchParams(location.search);
const local = location.protocol === 'http:' && location.hostname === '127.0.0.1';
async function boundedPayload(response) {
    if (!response.body || typeof response.body.getReader !== 'function')
        throw new Error('Actual bounded Fetch body stream unavailable');
    const reader = response.body.getReader();
    const parts = [];
    let bytes = 0;
    try {
        for (;;) {
            const chunk = await reader.read();
            if (chunk.done) break;
            bytes += chunk.value.byteLength;
            if (bytes > 4096) { await reader.cancel(); throw new Error('Loopback fixture response exceeds4096 bytes'); }
            parts.push(chunk.value);
        }
    } finally { reader.releaseLock(); }
    const data = new Uint8Array(bytes);
    let offset = 0;
    for (const part of parts) { data.set(part, offset); offset += part.byteLength; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data));
}
if (!local || parameters.get('allow-loopback-fetch') !== window.__zetscapeAcceptance.nonce || !window.__zetscapeAcceptance.nonceValid) {
    fixture.record('fetch.local_fixture', false, 'NOT_RUN_ORIGIN_OR_AUTHORIZATION: requires same-origin http://127.0.0.1 plus explicit fresh-nonce authorization');
} else {
    let timeout;
    try {
        const controller = new AbortController();
        timeout = setTimeout(() => controller.abort(), 5000);
        const response = await fetch(new URL('./fetch_payload.json', location.href), {
            mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store', signal: controller.signal
        });
        const contentType = response.headers.get('content-type') || '';
        if (!/^application\/json(?:\s*;|$)/i.test(contentType)) throw new Error('Actual fixture JSON MIME type missing');
        const payload = await boundedPayload(response);
        fixture.record('fetch.local_fixture', response.status === 200 && payload.fixture === 'zetscape-loopback-v1' &&
            payload.message === '한글 Ω' && payload.number === 42, 'Actual bounded same-origin loopback fetch/JSON decoding');
    } catch (error) { fixture.record('fetch.local_fixture', false, error.message); }
    finally { clearTimeout(timeout); }
}
