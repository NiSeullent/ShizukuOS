/* Actual page assertion ledger. SPDX-License-Identifier: MIT */
'use strict';
(function () {
    const expected = [
        'dom.text_roundtrip', 'dom.capture_bubble', 'dom.mutation_observer',
        'input.trusted_click', 'input.trusted_keyboard', 'unicode.dom_roundtrip', 'unicode.normalization',
        'layout.grid', 'layout.flex', 'canvas.solid', 'canvas.transform', 'canvas.path',
        'canvas.png_roundtrip', 'svg.geometry', 'svg.raster_readback', 'webgl.shader_readback',
        'module.static_import', 'module.live_binding', 'module.dynamic_cache',
        'async.promise_recovery', 'async.microtask_order', 'fetch.local_fixture'
    ];
    const match = /(?:^|[?&])nonce=([^&]*)/.exec(location.search);
    let nonce = '';
    try { nonce = match ? decodeURIComponent(match[1]) : ''; } catch { /* invalid nonce */ }
    const nonceValid = typeof nonce === 'string' && nonce.length >= 1 && nonce.length <= 80 &&
        !/[^A-Za-z0-9_-]/.test(nonce);
    const result = {
        schema: 'zetscape-modern-web-page-result-v1', fixtureVersion: 1, nonce,
        scope: 'representative-actual-page-assertions', url: location.href,
        userAgentObservation: navigator.userAgent, nonceValid, checks: {}, errors: [], observations: {},
        fixtureSubsetPass: false, completed: false, nativeOsVerified: false,
        hardwareAccelerationVerified: false, fullModernWebPass: false, sourceCommitVerified: false
    };
    for (const id of expected) result.checks[id] = { status: 'NOT_RUN' };
    function update() {
        const rows = expected.map(id => result.checks[id]);
        result.completed = rows.every(row => row.status !== 'NOT_RUN');
        result.fixtureSubsetPass = nonceValid && result.completed && !result.errors.length &&
            rows.every(row => row.status === 'PASS');
        document.getElementById('status').textContent = !nonceValid ? 'FAIL: missing/invalid fresh nonce' :
            result.fixtureSubsetPass ? 'Representative fixture assertions passed; native/full-target evidence still required' :
            rows.some(row => row.status === 'FAIL') ? 'Fixture has failed assertions; see exact results' :
            'Running actual page checks; complete the native input controls';
        document.getElementById('results').textContent = JSON.stringify(result, null, 2);
    }
    function record(id, passed, detail) {
        if (!Object.prototype.hasOwnProperty.call(result.checks, id)) {
            result.errors.push('Unknown assertion ID: ' + id); update(); return;
        }
        if (result.checks[id].status !== 'NOT_RUN') {
            result.errors.push('Duplicate assertion ID: ' + id); update(); return;
        }
        result.checks[id] = { status: passed === true ? 'PASS' : 'FAIL', detail: String(detail || '') };
        update();
    }
    function test(id, action) {
        try { record(id, action() === true, 'Actual assertion evaluated'); }
        catch (error) { record(id, false, error.message); }
    }
    function observe(name, value) { result.observations[name] = value; update(); }
    Object.defineProperty(window, '__zetscapeAcceptance', { get: () => JSON.parse(JSON.stringify(result)) });
    Object.defineProperty(window, 'ZetscapeFixture', { value: Object.freeze({ record, test, observe }) });
    document.getElementById('module-fixture').addEventListener('error', () => {
        if (result.checks['module.static_import'].status === 'NOT_RUN')
            record('module.static_import', false, 'Actual module script load failed');
    });
    if (!('noModule' in document.createElement('script')))
        record('module.static_import', false, 'Modern module script capability absent');
    window.addEventListener('error', event => {
        result.errors.push(String(event.message || 'Actual page/script load error')); update();
    });
    window.addEventListener('unhandledrejection', event => {
        result.errors.push('Unhandled rejection: ' + String(event.reason)); update();
    });
    setTimeout(() => {
        for (const id of expected) if (result.checks[id].status === 'NOT_RUN')
            result.checks[id] = { status: 'FAIL', detail: 'Actual page check incomplete at 120 second deadline' };
        update();
    }, 120000);
    if (!nonceValid) result.errors.push('A fresh externally bound nonce is mandatory');
    update();
})();
