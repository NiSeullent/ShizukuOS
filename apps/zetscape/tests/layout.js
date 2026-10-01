/* Actual DOM, layout and native-input assertions. SPDX-License-Identifier: MIT */
'use strict';
(function () {
    const fixture = window.ZetscapeFixture;
    const unicode = '한글 Ω 🧪 e\u0301 é';
    fixture.test('dom.text_roundtrip', () => {
        const element = document.createElement('span');
        element.textContent = '<literal>& text';
        return element.childNodes.length === 1 && element.firstChild.nodeType === Node.TEXT_NODE &&
            element.textContent === '<literal>& text' && element.children.length === 0;
    });
    fixture.test('unicode.dom_roundtrip', () => {
        const element = document.getElementById('unicode-sample');
        return element.textContent === unicode && Array.from(element.textContent).length === 11;
    });
    fixture.test('unicode.normalization', () => 'e\u0301'.normalize('NFC') === '\u00e9' &&
        '\u00e9'.normalize('NFD') === 'e\u0301');
    fixture.test('dom.capture_bubble', () => {
        const parent = document.getElementById('event-parent');
        const target = document.getElementById('event-target');
        const order = [];
        parent.addEventListener('zetscape-order', () => order.push('capture'), { capture: true, once: true });
        target.addEventListener('zetscape-order', () => order.push('target'), { once: true });
        parent.addEventListener('zetscape-order', () => order.push('bubble'), { once: true });
        target.dispatchEvent(new Event('zetscape-order', { bubbles: true }));
        return order.join(',') === 'capture,target,bubble';
    });
    try {
        const target = document.getElementById('mutation-target');
        const observer = new MutationObserver(records => {
            observer.disconnect();
            fixture.record('dom.mutation_observer', records.length === 1 && records[0].type === 'childList' &&
                records[0].addedNodes.length === 1 && records[0].addedNodes[0].textContent === 'observed', 'Actual MutationObserver callback');
        });
        observer.observe(target, { childList: true });
        const child = document.createElement('span'); child.textContent = 'observed'; target.appendChild(child);
    } catch (error) { fixture.record('dom.mutation_observer', false, error.message); }
    function layout(id, widths, offsets) {
        const container = document.getElementById(id);
        const bounds = container.getBoundingClientRect();
        if (container.children.length !== widths.length || offsets.length !== widths.length) return false;
        return Array.from(container.children).every((child, index) => {
            const rect = child.getBoundingClientRect();
            return Math.abs(rect.width - widths[index]) < 0.1 && Math.abs(rect.left - bounds.left - offsets[index]) < 0.1;
        });
    }
    fixture.test('layout.grid', () => layout('grid', [80, 170], [0, 90]));
    fixture.test('layout.flex', () => layout('flex', [50, 130, 40], [0, 60, 200]));
    let clicks = 0, recorded = false;
    const button = document.getElementById('input-button');
    button.addEventListener('click', event => {
        if (event.isTrusted !== true) { fixture.observe('syntheticInputRejected', true); return; }
        ++clicks; button.textContent = 'Native input: ' + clicks + ' / 3';
        if (clicks === 3 && !recorded) {
            recorded = true; fixture.record('input.trusted_click', true, 'Three actual trusted engine click events; native IO ownership still required');
        }
    });
    const input = document.getElementById('input-text');
    let trustedCharacters = 0, keyboardRecorded = false;
    input.addEventListener('input', event => { if (event.isTrusted === true) ++trustedCharacters; });
    input.addEventListener('keydown', event => {
        if (event.key !== 'Enter' || keyboardRecorded) return;
        keyboardRecorded = true;
        fixture.record('input.trusted_keyboard', event.isTrusted === true && trustedCharacters > 0 &&
            input.value === 'Zetscape98', 'Actual trusted engine input/Enter events; native IO ownership still required');
    });
})();
