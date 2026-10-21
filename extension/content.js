// ── Floating selection bubble (content script) ──────────────────────────────
// Shows a small floating button next to any text selection on the page, as
// a faster alternative to the right-click "Send via Blink" menu item.
// Runs on every http(s) page (see manifest.json), so it's built defensively:
// a closed Shadow DOM keeps the host page's CSS from leaking in (or ours
// from leaking out), and nothing here touches the page's own DOM/state
// beyond reading the current selection.
(() => {
  let host = null;
  let shadow = null;
  let btn = null;
  let lastText = '';
  let cooldownInterval = null;
  // True from the moment a create request starts until the post-create
  // cooldown finishes. Guards against spamming the server's create-rate
  // limiter (10/min/IP) by rapid-fire clicking the bubble.
  let locked = false;
  let bubbleEnabled = true;

  blinkGetSettings().then((s) => { bubbleEnabled = s.bubbleEnabled; });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'sync' || !changes.bubbleEnabled) return;
    bubbleEnabled = changes.bubbleEnabled.newValue;
    if (!bubbleEnabled) hideButton();
  });

  // Returns true if the host/button exist and are ready to use. Can fail
  // (and return false) if the extension was reloaded/updated while this
  // content script is still running in an old tab: chrome.runtime.getURL
  // then throws "Extension context invalidated", which used to abort this
  // function midway, leaving `host` set (blocking retries) but `btn` never
  // created, crashing every later showButton() call on a null `btn`.
  function ensureHost() {
    if (btn) return true;
    if (host) return false;

    try {
      host = document.createElement('div');
      host.style.all = 'initial';
      host.style.position = 'fixed';
      host.style.top = '0';
      host.style.left = '0';
      host.style.zIndex = '2147483647';
      document.documentElement.appendChild(host);
      shadow = host.attachShadow({ mode: 'closed' });

      // Bundled locally (extension/icons/logo.png) and served from the
      // extension's own chrome-extension:// origin, declared in manifest.json's
      // web_accessible_resources, so this always loads regardless of the host
      // page's own CSP (a remote cross-origin asset would be silently blocked
      // by any page with a strict img-src/style-src policy).
      const iconUrl = chrome.runtime.getURL('icons/logo.png');

      const style = document.createElement('style');
      style.textContent = `
      .btn {
        position: fixed;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 7px;
        width: 30px;
        height: 30px;
        border-radius: 999px;
        background: #161616;
        border: 1px solid rgba(255,255,255,.15);
        box-shadow: 0 4px 16px rgba(0,0,0,.35);
        cursor: pointer;
        padding: 0;
        transition: transform .12s ease, box-shadow .12s ease, background .12s ease;
        font: 600 12px/1 -apple-system, "Segoe UI", Roboto, sans-serif;
        color: #fff;
        white-space: nowrap;
      }
      .btn:hover { transform: scale(1.08); box-shadow: 0 6px 20px rgba(0,0,0,.45); }
      .btn.busy, .btn.done, .btn.failed {
        width: auto;
        justify-content: flex-start;
        padding: 0 14px 0 8px;
        transform: none;
      }
      .btn.busy { cursor: wait; }
      .btn.done { background: #2f9e2a; }
      .btn.failed { background: #d92d2d; }
      .icon {
        flex-shrink: 0;
        width: 17px;
        height: 17px;
        background-color: #61cf5a;
        -webkit-mask: url('${iconUrl}') center / contain no-repeat;
        mask: url('${iconUrl}') center / contain no-repeat;
      }
      .btn.done .icon, .btn.failed .icon { background-color: #fff; }
      .spinner {
        display: none;
        flex-shrink: 0;
        width: 13px;
        height: 13px;
        border-radius: 50%;
        border: 2px solid rgba(255,255,255,.3);
        border-top-color: #fff;
        animation: blink-spin .6s linear infinite;
      }
      .btn.busy .icon { display: none; }
      .btn.busy .spinner { display: block; }
      .label { display: none; }
      .btn.busy .label, .btn.done .label, .btn.failed .label { display: inline; }
      @keyframes blink-spin { to { transform: rotate(360deg); } }
    `;
      shadow.appendChild(style);

      btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn';
      btn.title = 'Send via Blink';
      btn.style.display = 'none';
      btn.innerHTML = '<span class="icon"></span><span class="spinner"></span><span class="label"></span>';
      shadow.appendChild(btn);

      // Prevent the mousedown from collapsing the live selection before click fires.
      btn.addEventListener('mousedown', (e) => e.preventDefault());
      btn.addEventListener('click', onButtonClick);
      return true;
    } catch (err) {
      console.error('[Blink extension] could not set up the selection bubble (the page may need a refresh after the extension updated):', err);
      host = null;
      shadow = null;
      btn = null;
      return false;
    }
  }

  function setLabel(text) {
    btn.querySelector('.label').textContent = text;
  }

  function showButton(rect) {
    if (!ensureHost()) return;
    btn.classList.remove('busy', 'done', 'failed');
    btn.title = 'Send via Blink';
    btn.style.display = 'flex';
    const top  = Math.max(8, rect.top - 38);
    const left = Math.max(8, rect.right - 30);
    btn.style.top  = `${top}px`;
    btn.style.left = `${left}px`;
  }

  function hideButton() {
    if (btn) btn.style.display = 'none';
  }

  // Keeps the bubble visible with a ticking "wait Ns" label for
  // COOLDOWN_SECONDS, blocking further clicks (via `locked`) the whole
  // time, then hides it and unlocks for the next selection.
  const COOLDOWN_SECONDS = 5;
  function startCooldown(baseLabel) {
    clearInterval(cooldownInterval);
    let seconds = COOLDOWN_SECONDS;
    setLabel(`${baseLabel} (${seconds})`);
    cooldownInterval = setInterval(() => {
      seconds -= 1;
      if (seconds <= 0) {
        clearInterval(cooldownInterval);
        locked = false;
        hideButton();
        return;
      }
      setLabel(`${baseLabel} (${seconds})`);
    }, 1000);
  }

  function onSelectionChange() {
    if (!bubbleEnabled) return;
    const sel = window.getSelection();
    const text = sel ? sel.toString().trim() : '';
    if (!text || text.length > 10_000 || sel.rangeCount === 0) {
      hideButton();
      return;
    }
    const rect = sel.getRangeAt(0).getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) {
      hideButton();
      return;
    }
    lastText = text;
    showButton(rect);
  }

  document.addEventListener('mouseup', (e) => {
    if (host?.contains(e.target)) return;
    setTimeout(onSelectionChange, 0);
  });

  document.addEventListener('mousedown', (e) => {
    if (host?.contains(e.target)) return;
    hideButton();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') hideButton();
  });

  async function onButtonClick() {
    if (!lastText || locked) return;
    locked = true;
    btn.classList.add('busy');
    setLabel('Encrypting…');
    try {
      const resp = await chrome.runtime.sendMessage({ type: 'blink-create-from-selection', text: lastText });
      if (!resp?.ok) throw new Error(resp?.error || 'Failed to create link.');
      // Copied here, not in background.js: this click is a live user gesture
      // in the page itself, which the Clipboard API accepts. background.js's
      // chrome.scripting.executeScript route needs activeTab, which this
      // trigger (a click on content the page didn't grant us) doesn't have.
      await navigator.clipboard.writeText(resp.link);
      btn.classList.remove('busy');
      btn.classList.add('done');
      btn.title = 'Copied to clipboard';
      startCooldown('Link copied, next in');
    } catch (err) {
      // Visible failure state instead of silently vanishing, plus a logged
      // reason so it's debuggable from the page's own devtools console.
      console.error('[Blink extension] failed to create link:', err);
      btn.classList.remove('busy');
      btn.classList.add('failed');
      btn.title = err.message || 'Could not create the link. Check the console for details.';
      startCooldown(err.message || 'Failed, retry in');
    }
  }
})();
