// Browser design/game preview using the same compiled C game core.
// Synthetic example metadata is never presented as a native OS capture.
(() => {
  'use strict';
  const binary = new URL('./dead-screen-preview.wasm', document.currentScript.src);
  const expectedHash = '7156b7bb536b2388df3cb6052c40d08789478c0c9d445281c39b9fc0a7ba54fb';
  const english = document.documentElement.lang.startsWith('en');
  const words = english ? {
    choose: 'Choose a game.', tetris: 'Tetris · arrows to move, Space to drop',
    suika: 'Suika · merge matching items', score: 'Score ',
    text: 'Text fallback preview', showText: 'Show text screen', showGame: 'Back to game screen',
    failed: 'Preview loading failed. English traceback follows.',
  } : {
    choose: '게임을 골라 주세요.', tetris: '테트리스 · 방향키로 이동, Space로 떨어뜨리기',
    suika: '수박게임 · 같은 아이템을 합쳐 보세요', score: '점수 ',
    text: '텍스트 오류 화면 미리보기', showText: '텍스트 화면 보기', showGame: '게임 화면으로',
    failed: '미리보기를 불러오지 못했습니다. 영문 오류 정보를 표시합니다.',
  };
  const canvas = document.getElementById('dead-canvas');
  const loading = document.getElementById('load-status');
  const loadTrace = document.getElementById('load-trace');
  const status = document.getElementById('game-status');
  const score = document.getElementById('game-score');
  const toggle = document.getElementById('text-toggle');
  const buttons = [...document.querySelectorAll('[data-key]')];
  let engine = null, context = null, frame = null, textMode = false, running = false;
  let last = 0, accumulator = 0, lastStatus = '', lastScore = '';
  function failed(error) {
    running = false;
    buttons.forEach(button => { button.disabled = true; });
    toggle.disabled = true;
    canvas.hidden = true;
    loading.hidden = true;
    status.textContent = words.failed;
    const traceback = error instanceof Error ? error.stack || error.message : String(error);
    loadTrace.textContent = 'You session got wasted\n\nEnglish traceback: browser preview loading\n' + traceback;
    loadTrace.hidden = false;
  }
  function paint() {
    if (engine.ds_preview_render() !== 0) throw new Error('Preview framebuffer rendering failed');
    const offset = Number(engine.ds_preview_pixels());
    const length = canvas.width * canvas.height * 4;
    if (!Number.isInteger(offset) || offset < 0 || offset + length > engine.memory.buffer.byteLength) {
      throw new Error('Preview framebuffer is outside retained WebAssembly memory');
    }
    const bytes = new Uint8ClampedArray(engine.memory.buffer, offset, length);
    frame.data.set(bytes);
    context.putImageData(frame, 0, 0);
    const mode = engine.ds_preview_mode();
    const message = textMode ? words.text : mode === 1 ? words.tetris : mode === 2 ? words.suika : words.choose;
    const points = words.score + engine.ds_preview_score();
    if (message !== lastStatus) { status.textContent = message; lastStatus = message; }
    if (points !== lastScore) { score.textContent = points; lastScore = points; }
    canvas.dataset.gameMode = String(mode);
    canvas.dataset.textFallback = String(textMode);
  }
  function input(key) {
    if (!engine || !running) return;
    try { engine.ds_preview_input(key); paint(); canvas.focus({preventScroll: true}); }
    catch (error) { failed(error); }
  }
  const keys = {
    '1': 1, '2': 2, ArrowLeft: 3, ArrowRight: 4, ArrowUp: 5, ArrowDown: 6,
    a: 3, A: 3, d: 4, D: 4, w: 5, W: 5, s: 6, S: 6, ' ': 7,
    Escape: 8, r: 9, R: 9, l: 10, L: 10, t: 11, T: 11,
  };
  buttons.forEach(button => button.addEventListener('click', () => input(Number(button.dataset.key))));
  canvas.addEventListener('keydown', event => {
    const key = keys[event.key];
    if (key) { event.preventDefault(); input(key); }
  });
  toggle.addEventListener('click', () => {
    if (!engine || !running) return;
    try {
      textMode = !textMode;
      engine.ds_preview_fallback(Number(textMode));
      toggle.textContent = textMode ? words.showGame : words.showText;
      paint();
    } catch (error) { failed(error); }
  });
  function animate(now) {
    if (!running) return;
    try {
      if (document.hidden) { last = now; accumulator = 0; }
      else {
        accumulator += Math.min(Math.max(now - last, 0), 100);
        last = now;
        let steps = 0;
        while (accumulator >= 1000 / 60 && steps < 6) {
          engine.ds_preview_tick(); accumulator -= 1000 / 60; steps++;
        }
        if (steps) paint();
      }
      requestAnimationFrame(animate);
    } catch (error) { failed(error); }
  }
  (async () => {
    const response = await fetch(binary, {cache: 'no-cache', credentials: 'same-origin'});
    if (!response.ok) throw new Error('Preview runtime HTTP ' + response.status);
    const bytes = await response.arrayBuffer();
    if (bytes.byteLength > 8 * 1024 * 1024) throw new Error('Preview runtime exceeds the reviewed size limit');
    const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(b => b.toString(16).padStart(2, '0')).join('');
    if (hash !== expectedHash) throw new Error('Preview runtime does not match the reviewed build');
    const instance = await WebAssembly.instantiate(bytes, {});
    engine = instance.instance.exports;
    for (const name of ['ds_preview_init', 'ds_preview_input', 'ds_preview_tick', 'ds_preview_render',
      'ds_preview_pixels', 'ds_preview_width', 'ds_preview_height', 'ds_preview_trace',
      'ds_preview_trace_len', 'ds_preview_mode', 'ds_preview_score', 'ds_preview_fallback']) {
      if (typeof engine[name] !== 'function') throw new Error('Preview runtime API unavailable: ' + name);
    }
    engine.ds_preview_init();
    if (english) engine.ds_preview_input(10);
    const width = engine.ds_preview_width(), height = engine.ds_preview_height();
    if (!Number.isInteger(width) || !Number.isInteger(height) || width < 640 || width > 1280 || height < 480 || height > 960) {
      throw new Error('Preview framebuffer dimensions are invalid');
    }
    canvas.width = width; canvas.height = height;
    context = canvas.getContext('2d', {alpha: false});
    if (!context) throw new Error('Browser canvas unavailable');
    frame = context.createImageData(width, height);
    running = true;
    paint();
    loading.hidden = true;
    buttons.forEach(button => { button.disabled = false; });
    toggle.disabled = false;
    last = performance.now();
    requestAnimationFrame(animate);
  })().catch(failed);
})();
