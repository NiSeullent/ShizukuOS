// Recorded guest screenshots. A playback control never simulates a live VM.
const text = (tag, value, className = '') => {
  const element = document.createElement(tag);
  element.textContent = value;
  if (className) element.className = className;
  return element;
};

export function validatePreviewManifest(data, baseUrl) {
  if (data?.schema !== 1 || !Array.isArray(data.collections) || !data.collections.length) {
    throw new Error('화면 기록을 읽을 수 없습니다.');
  }
  const base = new URL(baseUrl);
  const collections = data.collections.map(collection => {
    if (!collection.id || !collection.title || !collection.platform || !collection.display ||
        !collection.result || !collection.scope || !Array.isArray(collection.observations) ||
        !Array.isArray(collection.frames) || !collection.frames.length) {
      throw new Error('화면 기록이 비어 있습니다.');
    }
    return { ...collection, frames: collection.frames.map(frame => {
      const src = new URL(frame.src, base);
      if (src.origin !== base.origin || !['http:', 'https:'].includes(src.protocol) ||
          frame.kind !== 'guest-capture' || !/^[a-f0-9]{64}$/.test(frame.sha256) ||
          !frame.caption || !Number.isInteger(frame.width) || frame.width < 1 ||
          !Number.isInteger(frame.height) || frame.height < 1) {
        throw new Error('검증되지 않은 화면 기록입니다.');
      }
      return { ...frame, src: src.href };
    }) };
  });
  return { ...data, collections };
}

export async function mountPreview(container, { manifestUrl = './evidence/preview.json' } = {}) {
  if (!container || container.dataset.previewMounted) return;
  container.dataset.previewMounted = 'true';
  container.classList.add('preview-root');
  container.replaceChildren(text('p', '실제 게스트 화면 기록을 불러오고 있습니다.', 'preview-message'));
  let manifest;
  try {
    const url = new URL(manifestUrl, document.baseURI);
    const response = await fetch(url, { credentials: 'same-origin' });
    if (!response.ok) throw new Error('화면 기록을 불러오지 못했습니다.');
    manifest = validatePreviewManifest(await response.json(), url.href);
  } catch (error) {
    container.replaceChildren(text('p', error.message, 'preview-message'));
    return;
  }

  container.innerHTML = `
    <div class="preview-toolbar"><label class="preview-select-label">화면 선택 <select class="preview-select"></select></label><span class="preview-mode">실제 게스트의 기록 화면</span></div>
    <div class="preview-heading"><h2></h2><p class="preview-platform"></p></div>
    <figure class="preview-figure"><button type="button" class="preview-image-button" aria-label="현재 화면 크게 보기"><img class="preview-image" alt=""></button><figcaption class="preview-caption" aria-live="polite"></figcaption></figure>
    <div class="preview-controls"><button type="button" data-action="previous">이전</button><button type="button" data-action="play">기록 재생</button><button type="button" data-action="next">다음</button><label class="preview-slider-label">기록 위치 <input type="range" min="0" step="1" value="0"></label><output class="preview-position"></output><a class="preview-original" target="_blank" rel="noopener">원본 화면</a></div>
    <ol class="preview-timeline" aria-label="화면 기록 순서"></ol>
    <section class="preview-result" aria-label="확인한 동작"><h3></h3><ul></ul><p class="preview-scope"></p></section>
    <details class="preview-proof"><summary>화면 검증 정보</summary><dl></dl></details>
    <p class="preview-live-status"></p>
    <dialog class="preview-dialog"><button type="button" class="preview-close">닫기</button><img alt=""><p></p></dialog>`;

  const query = selector => container.querySelector(selector);
  const select = query('select');
  const image = query('.preview-image');
  const slider = query('input[type="range"]');
  const timeline = query('.preview-timeline');
  const play = query('[data-action="play"]');
  const dialog = query('dialog');
  let collection = manifest.collections[0], index = 0, timer = null;
  const stop = () => { clearInterval(timer); timer = null; play.textContent = '기록 재생'; play.setAttribute('aria-pressed', 'false'); };

  function render() {
    const frame = collection.frames[index];
    image.src = frame.src;
    image.alt = frame.alt || frame.caption;
    image.width = frame.width;
    image.height = frame.height;
    query('.preview-caption').textContent = frame.caption + (Number.isFinite(frame.captureSeconds)
      ? ` (해당 부팅 시작 후 ${frame.captureSeconds}초에 기록)` : '');
    query('.preview-position').textContent = `${index + 1} / ${collection.frames.length}`;
    query('.preview-original').href = frame.src;
    slider.value = index;
    slider.setAttribute('aria-valuetext', frame.caption);
    query('[data-action="previous"]').disabled = index === 0;
    query('[data-action="next"]').disabled = index === collection.frames.length - 1;
    timeline.querySelectorAll('button').forEach((button, n) => {
      button.setAttribute('aria-current', n === index ? 'step' : 'false');
    });
    const fields = [['종류', collection.platform], ['기록', frame.runLabel],
      ['화면 크기', `${frame.width} × ${frame.height}`], ['원본 SHA-256', frame.sha256],
      ['실행 기록 SHA-256', frame.receiptSha256]];
    if (frame.captureSource === 'physical-gop-framebuffer') {
      fields.push(['화면 기록 방식', '검증된 GOP 메모리 픽셀의 직접 PNG 변환'],
        ['화면 메모리 SHA-256', frame.rawSha256], ['변환기 SHA-256', frame.decoderSha256],
        ['모니터 출력', '후반 원본 모니터 캡처로 확인']);
    }
    if (frame.captureSource === 'qmp-monitor') fields.push(['화면 기록 방식', '원본 가상 모니터 캡처']);
    if (frame.correctionAuditSha256) fields.push(['추가 검증 SHA-256', frame.correctionAuditSha256]);
    if (frame.verificationReceiptSha256) fields.push(['동작 검증 SHA-256', frame.verificationReceiptSha256]);
    query('.preview-proof dl').replaceChildren(...fields.flatMap(([label, value]) => [text('dt', label), text('dd', value || '미기록')]));
  }

  function choose(id) {
    stop(); index = 0;
    collection = manifest.collections.find(item => item.id === id) || manifest.collections[0];
    query('.preview-heading h2').textContent = collection.title;
    query('.preview-platform').textContent = collection.platform + ' · ' + collection.display;
    query('.preview-result h3').textContent = collection.result;
    query('.preview-result ul').replaceChildren(...collection.observations.map(value => text('li', value)));
    query('.preview-scope').textContent = collection.scope;
    slider.max = collection.frames.length - 1;
    play.disabled = collection.frames.length < 2;
    timeline.replaceChildren(...collection.frames.map((frame, n) => {
      const item = document.createElement('li');
      const button = text('button', frame.chapter || frame.caption);
      button.type = 'button';
      button.addEventListener('click', () => { stop(); index = n; render(); });
      item.append(button); return item;
    }));
    render();
  }

  select.replaceChildren(...manifest.collections.map(item => {
    const option = text('option', item.title); option.value = item.id; return option;
  }));
  select.addEventListener('change', () => choose(select.value));
  slider.addEventListener('input', () => { stop(); index = Number(slider.value); render(); });
  query('[data-action="previous"]').addEventListener('click', () => { stop(); index = Math.max(0, index - 1); render(); });
  query('[data-action="next"]').addEventListener('click', () => { stop(); index = Math.min(collection.frames.length - 1, index + 1); render(); });
  play.addEventListener('click', () => {
    if (timer) return stop();
    if (index === collection.frames.length - 1) { index = 0; render(); }
    play.textContent = '재생 멈춤'; play.setAttribute('aria-pressed', 'true');
    timer = setInterval(() => {
      index++; render();
      if (index === collection.frames.length - 1) stop();
    }, 2500);
  });
  image.addEventListener('error', () => { stop(); query('.preview-caption').textContent = '원본 화면을 불러오지 못했습니다.'; });
  query('.preview-image-button').addEventListener('click', () => {
    const frame = collection.frames[index];
    dialog.querySelector('img').src = frame.src;
    dialog.querySelector('img').alt = frame.alt || frame.caption;
    dialog.querySelector('p').textContent = frame.caption;
    dialog.showModal();
  });
  query('.preview-close').addEventListener('click', () => dialog.close());
  const onVisibility = () => { if (document.hidden) stop(); };
  document.addEventListener('visibilitychange', onVisibility);
  query('.preview-live-status').textContent = manifest.live?.available
    ? '실시간 게스트는 소유자 전용 연결에서 볼 수 있습니다.' : '현재 연결된 실시간 게스트가 없습니다.';
  const requestedView = new URL(document.location.href).searchParams.get('view');
  if (requestedView && manifest.collections.some(item => item.id === requestedView)) select.value = requestedView;
  choose(select.value);
  return { stop, destroy: () => {
    stop(); document.removeEventListener('visibilitychange', onVisibility);
    container.replaceChildren(); delete container.dataset.previewMounted;
  } };
}

if (typeof document !== 'undefined') {
  const start = () => {
    const container = document.querySelector('#preview-viewer');
    if (container) mountPreview(container);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
}
