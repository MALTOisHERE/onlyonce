// Shared across background.js, content.js, popup.js, and options.js.
const BLINK_API_BASE        = 'https://blink.malto.icu';
const BLINK_MAX_SECRET_BYTES = 10 * 1024; // mirrors server.js / app.js
const BLINK_DEFAULT_TTL_HOURS = 48;

// ── User settings (chrome.storage.sync) ─────────────────────────────────────
// Read by content.js (bubble on/off), background.js (context menu on/off,
// default expiry for both quick-create triggers), and written by options.js.
const BLINK_SETTINGS_DEFAULTS = {
  bubbleEnabled:      true,
  contextMenuEnabled: true,
  defaultExpiryHours: BLINK_DEFAULT_TTL_HOURS,
};

function blinkGetSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(BLINK_SETTINGS_DEFAULTS, (stored) => resolve(stored));
  });
}
