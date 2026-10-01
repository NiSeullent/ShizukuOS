/* Real Canvas/SVG/WebGL interior-pixel assertions. SPDX-License-Identifier: MIT */
'use strict';
(function () {
    const fixture = window.ZetscapeFixture;
    const canvas = document.getElementById('canvas');
    let context;
    function pixel(context_, x, y, expected) {
        const actual = context_.getImageData(x, y, 1, 1).data;
        return expected.every((value, index) => actual[index] === value);
    }
    function decodeImage(id, source, assertion) {
        let image, timeout, settled = false;
        function finish(passed, detail) {
            if (settled) return;
            settled = true; clearTimeout(timeout);
            if (image) { image.onload = null; image.onerror = null; }
            fixture.record(id, passed, detail);
        }
        try {
            image = new Image();
            image.onload = () => {
                try { finish(assertion(image) === true, 'Actual image decode and interior pixel readback'); }
                catch (error) { finish(false, error.message); }
            };
            image.onerror = () => finish(false, 'Actual image decode failed');
            timeout = setTimeout(() => finish(false, 'Actual image decode timed out'), 5000);
            image.src = source();
        } catch (error) { finish(false, error.message); }
    }
    try {
        context = canvas.getContext('2d');
        if (!context) throw new Error('Actual Canvas2D context unavailable');
        context.fillStyle = '#ff0000'; context.fillRect(0, 0, 16, 16);
        fixture.record('canvas.solid', pixel(context, 4, 4, [255, 0, 0, 255]), 'Opaque interior RGBA sample');
        context.save(); context.translate(16, 0); context.fillStyle = '#00ff00'; context.fillRect(0, 0, 16, 16); context.restore();
        fixture.record('canvas.transform', pixel(context, 20, 4, [0, 255, 0, 255]), 'Actual transformed fill interior');
        context.fillStyle = '#0000ff'; context.beginPath();
        context.moveTo(0, 20); context.lineTo(16, 20); context.lineTo(0, 36); context.closePath(); context.fill();
        fixture.record('canvas.path', pixel(context, 3, 23, [0, 0, 255, 255]), 'Actual path fill interior');
        decodeImage('canvas.png_roundtrip', () => canvas.toDataURL('image/png'), image => {
            const decoded = document.createElement('canvas'); decoded.width = 64; decoded.height = 64;
            const output = decoded.getContext('2d'); output.drawImage(image, 0, 0);
            return pixel(output, 4, 4, [255, 0, 0, 255]) && pixel(output, 20, 4, [0, 255, 0, 255]);
        });
    } catch (error) {
        for (const id of ['canvas.solid', 'canvas.transform', 'canvas.path', 'canvas.png_roundtrip'])
            if (window.__zetscapeAcceptance.checks[id].status === 'NOT_RUN') fixture.record(id, false, error.message);
    }
    fixture.test('svg.geometry', () => {
        const rect = document.getElementById('svg-rect').getBBox();
        return rect.x === 8 && rect.y === 12 && rect.width === 24 && rect.height === 20;
    });
    try {
        const text = new XMLSerializer().serializeToString(document.getElementById('svg'));
        decodeImage('svg.raster_readback', () => 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(text), image => {
            const outputCanvas = document.createElement('canvas'); outputCanvas.width = 64; outputCanvas.height = 64;
            const output = outputCanvas.getContext('2d'); output.drawImage(image, 0, 0);
            return pixel(output, 16, 20, [0, 255, 0, 255]);
        });
    } catch (error) { fixture.record('svg.raster_readback', false, error.message); }
    fixture.test('webgl.shader_readback', () => {
        const gl = document.getElementById('webgl').getContext('webgl', {
            antialias: false, alpha: false, preserveDrawingBuffer: true
        });
        if (!gl) throw new Error('Actual WebGL context unavailable; no software substitute is inserted');
        fixture.observe('webgl', { vendor: gl.getParameter(gl.VENDOR), renderer: gl.getParameter(gl.RENDERER),
            version: gl.getParameter(gl.VERSION), hardwareProof: false });
        const debug = gl.getExtension('WEBGL_debug_renderer_info');
        if (debug) fixture.observe('webglDebug', { vendor: gl.getParameter(debug.UNMASKED_VENDOR_WEBGL),
            renderer: gl.getParameter(debug.UNMASKED_RENDERER_WEBGL), hardwareProof: false });
        const objects = [];
        let buffer, program;
        function shader(type, source) {
            const object = gl.createShader(type); objects.push(object);
            gl.shaderSource(object, source); gl.compileShader(object);
            if (!gl.getShaderParameter(object, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(object));
            return object;
        }
        try {
            const vertex = shader(gl.VERTEX_SHADER, 'attribute vec2 position; void main(){ gl_Position=vec4(position,0.0,1.0); }');
            const fragment = shader(gl.FRAGMENT_SHADER, 'precision mediump float; void main(){ gl_FragColor=vec4(0.0,0.0,1.0,1.0); }');
            program = gl.createProgram(); gl.attachShader(program, vertex); gl.attachShader(program, fragment); gl.linkProgram(program);
            if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(program));
            gl.useProgram(program); buffer = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
            gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
            const position = gl.getAttribLocation(program, 'position');
            gl.enableVertexAttribArray(position); gl.vertexAttribPointer(position, 2, gl.FLOAT, false, 0, 0);
            gl.viewport(0, 0, 16, 16); gl.drawArrays(gl.TRIANGLES, 0, 3);
            const rgba = new Uint8Array(4); gl.readPixels(8, 8, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, rgba);
            return gl.getError() === gl.NO_ERROR && rgba[0] === 0 && rgba[1] === 0 && rgba[2] === 255 && rgba[3] === 255;
        } finally {
            if (buffer) gl.deleteBuffer(buffer);
            if (program) gl.deleteProgram(program);
            for (const object of objects) if (object) gl.deleteShader(object);
        }
    });
})();
