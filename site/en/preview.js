// Recorded guest screenshots. A playback control never simulates a live VM.
const text = (tag, value, className = '') => {
  const element = document.createElement(tag);
  element.textContent = value;
  if (className) element.className = className;
  return element;
};

export function validatePreviewManifest(data, baseUrl) {
  if (data?.schema !== 1 || !Array.isArray(data.collections) || !data.collections.length) {
    throw new Error('Unable to read the screenshot record.');
  }
  const base = new URL(baseUrl);
  const collections = data.collections.map(collection => {
    if (!collection.id || !collection.title || !collection.platform || !collection.display ||
        !collection.result || !collection.scope || !Array.isArray(collection.observations) ||
        !Array.isArray(collection.frames) || !collection.frames.length) {
      throw new Error('The screenshot record is empty.');
    }
    return { ...collection, frames: collection.frames.map(frame => {
      const src = new URL(frame.src, base);
      if (src.origin !== base.origin || !['http:', 'https:'].includes(src.protocol) ||
          frame.kind !== 'guest-capture' || !/^[a-f0-9]{64}$/.test(frame.sha256) ||
          !frame.caption || !Number.isInteger(frame.width) || frame.width < 1 ||
          !Number.isInteger(frame.height) || frame.height < 1) {
        throw new Error('This screenshot record failed validation.');
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
  container.replaceChildren(text('p', 'Loading recorded guest screenshots.', 'preview-message'));
  let manifest;
  try {
    const url = new URL(manifestUrl, document.baseURI);
    const response = await fetch(url, { credentials: 'same-origin' });
    if (!response.ok) throw new Error('Unable to load the screenshot record.');
    manifest = validatePreviewManifest(await response.json(), url.href);
  } catch (error) {
    container.replaceChildren(text('p', error.message, 'preview-message'));
    return;
  }

  container.innerHTML = `
    <div class="preview-toolbar"><label class="preview-select-label">Choose a collection <select class="preview-select"></select></label><span class="preview-mode">Recorded guest screenshots</span></div>
    <div class="preview-heading"><h2></h2><p class="preview-platform"></p></div>
    <figure class="preview-figure"><button type="button" class="preview-image-button" aria-label="Enlarge this screenshot"><img class="preview-image" alt=""></button><figcaption class="preview-caption" aria-live="polite"></figcaption></figure>
    <div class="preview-controls"><button type="button" data-action="previous">Previous</button><button type="button" data-action="play">Play recording</button><button type="button" data-action="next">Next</button><label class="preview-slider-label">Frame position <input type="range" min="0" step="1" value="0"></label><output class="preview-position"></output><a class="preview-original" target="_blank" rel="noopener">Original screenshot</a></div>
    <ol class="preview-timeline" aria-label="Screenshot sequence"></ol>
    <section class="preview-result" aria-label="Verified behavior"><h3></h3><ul></ul><p class="preview-scope"></p></section>
    <details class="preview-proof"><summary>Screenshot evidence</summary><dl></dl></details>
    <p class="preview-live-status"></p>
    <dialog class="preview-dialog"><button type="button" class="preview-close">Close</button><img alt=""><p></p></dialog>`;

  const query = selector => container.querySelector(selector);
  const select = query('select');
  const image = query('.preview-image');
  const slider = query('input[type="range"]');
  const timeline = query('.preview-timeline');
  const play = query('[data-action="play"]');
  const dialog = query('dialog');
  let collection = manifest.collections[0], index = 0, timer = null;
  const stop = () => { clearInterval(timer); timer = null; play.textContent = 'Play recording'; play.setAttribute('aria-pressed', 'false'); };

  function render() {
    const frame = collection.frames[index];
    image.src = frame.src;
    image.alt = frame.alt || frame.caption;
    image.width = frame.width;
    image.height = frame.height;
    query('.preview-caption').textContent = frame.caption + (Number.isFinite(frame.captureSeconds)
      ? ` (captured ${frame.captureSeconds}s after this boot began)` : '');
    query('.preview-position').textContent = `${index + 1} / ${collection.frames.length}`;
    query('.preview-original').href = frame.src;
    slider.value = index;
    slider.setAttribute('aria-valuetext', frame.caption);
    query('[data-action="previous"]').disabled = index === 0;
    query('[data-action="next"]').disabled = index === collection.frames.length - 1;
    timeline.querySelectorAll('button').forEach((button, n) => {
      button.setAttribute('aria-current', n === index ? 'step' : 'false');
    });
    const fields = [['Platform', collection.platform], ['Run', frame.runLabel],
      ['Dimensions', `${frame.width} × ${frame.height}`], ['Original SHA-256', frame.sha256],
      ['Run receipt SHA-256', frame.receiptSha256]];
    if (frame.captureSource === 'physical-gop-framebuffer') {
      fields.push(['Capture method', 'Direct PNG decoding of verified GOP framebuffer pixels'],
        ['Framebuffer SHA-256', frame.rawSha256], ['Decoder SHA-256', frame.decoderSha256],
        ['Monitor output', 'Verified with later original monitor captures']);
    }
    if (frame.captureSource === 'qmp-monitor') fields.push(['Capture method', 'Original virtual monitor capture']);
    if (frame.correctionAuditSha256) fields.push(['Correction audit SHA-256', frame.correctionAuditSha256]);
    if (frame.verificationReceiptSha256) fields.push(['Verification receipt SHA-256', frame.verificationReceiptSha256]);
    query('.preview-proof dl').replaceChildren(...fields.flatMap(([label, value]) => [text('dt', label), text('dd', value || 'Not recorded')]));
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
    play.textContent = 'Pause recording'; play.setAttribute('aria-pressed', 'true');
    timer = setInterval(() => {
      index++; render();
      if (index === collection.frames.length - 1) stop();
    }, 2500);
  });
  image.addEventListener('error', () => { stop(); query('.preview-caption').textContent = 'Unable to load the original screenshot.'; });
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
    ? 'A live guest is available only through a private owner connection.' : 'No live guest is currently connected.';
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
    mountHome();
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
}

// Progressive enhancement: original captures and links remain usable without JS.
export function mountHome() {
  const scenes = document.querySelector('[data-scenes]');
  if (scenes && !scenes.dataset.mounted) {
    const controls = scenes.querySelector('.scene-controls');
    const buttons = [...controls.querySelectorAll('[data-scene-target]')];
    const panels = [...scenes.querySelectorAll('[data-scene]')];
    if (buttons.length && buttons.length === panels.length && buttons.every(button => panels.some(panel => panel.dataset.scene === button.dataset.sceneTarget))) {
      scenes.dataset.mounted = 'true';
      scenes.querySelector('.scene-inner').dataset.enhanced = 'true';
      controls.setAttribute('role', 'tablist');
      buttons.forEach(button => {
        button.id = `scene-tab-${button.dataset.sceneTarget}`;
        button.setAttribute('role', 'tab');
        button.setAttribute('aria-controls', `scene-${button.dataset.sceneTarget}`);
      });
      panels.forEach(panel => {
        panel.setAttribute('role', 'tabpanel');
        panel.setAttribute('aria-labelledby', `scene-tab-${panel.dataset.scene}`);
        panel.tabIndex = 0;
      });
      const choose = (index, focus = false) => {
        buttons.forEach((button, n) => {
          button.setAttribute('aria-selected', String(n === index));
          button.tabIndex = n === index ? 0 : -1;
        });
        panels.forEach(panel => { panel.hidden = panel.dataset.scene !== buttons[index].dataset.sceneTarget; });
        if (focus) buttons[index].focus();
      };
      buttons.forEach((button, index) => {
        button.addEventListener('click', () => choose(index));
        button.addEventListener('keydown', event => {
          let next = index;
          if (event.key === 'ArrowRight') next = (index + 1) % buttons.length;
          else if (event.key === 'ArrowLeft') next = (index + buttons.length - 1) % buttons.length;
          else if (event.key === 'Home') next = 0;
          else if (event.key === 'End') next = buttons.length - 1;
          else return;
          event.preventDefault(); choose(next, true);
        });
      });
      choose(0); controls.hidden = false;
    }
  }
  if ('IntersectionObserver' in window && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (!entry.isIntersecting) return;
        entry.target.classList.remove('reveal-pending');
        entry.target.classList.add('reveal-visible');
        observer.unobserve(entry.target);
      });
    }, { threshold: 0.06 });
    document.querySelectorAll('[data-reveal]').forEach(element => {
      if (element.getBoundingClientRect().top > window.innerHeight) {
        element.classList.add('reveal-pending'); observer.observe(element);
      }
    });
  }
}
