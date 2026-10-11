// Chrome loads this as a true service worker (no access to other manifest
// scripts unless imported here). Firefox's MV3 background runs as an event
// page that already loaded config.js/crypto.js first via the "scripts"
// array in manifest.json, where `importScripts` doesn't exist (guard it).
if (typeof importScripts === 'function') {
  importScripts('config.js', 'crypto.js');
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'blink-send-selection',
    title: 'Send via Blink',
    contexts: ['selection'],
  });
});

function notify(title, message) {
  chrome.notifications.create({
    type:    'basic',
    iconUrl: 'icons/icon-192.png',
    title,
    message,
  });
}

// chrome.scripting.executeScript only works on a tab the extension currently
// has host access to. A context-menu click is one of the gestures Chrome
// grants activeTab for, so this is safe there. It is NOT safe for the
// floating bubble content.js shows (see below) because a click on an element
// the content script drew itself isn't a qualifying activeTab gesture, and
// this throws "Cannot access contents of the page" in that case.
async function copyToTab(tabId, text) {
  await chrome.scripting.executeScript({
    target: { tabId },
    func:   (value) => navigator.clipboard.writeText(value),
    args:   [text],
  });
}

// Shared by both triggers: the context menu item and the floating selection
// bubble (content.js). Just encrypts and creates the link; copying to the
// clipboard is each caller's own responsibility since the two triggers need
// different mechanisms (see copyToTab's comment above).
async function createLinkFromText(text) {
  const trimmed = (text || '').trim();
  if (!trimmed) throw new Error('No text selected.');
  return blinkCreateLink(trimmed);
}

// Declared async so the listener itself returns the pending promise to the
// browser, needed so the service worker isn't torn down mid-fetch (a
// detached, un-returned async IIFE here would let Chrome consider the
// event "handled" immediately and recycle the worker before it finishes).
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'blink-send-selection') return;
  try {
    const link = await createLinkFromText(info.selectionText);
    if (tab?.id) await copyToTab(tab.id, link);
    notify('Blink link ready', 'Copied to clipboard, view once, then gone.');
  } catch (err) {
    notify('Blink failed', err.message || 'Could not create the link.');
  }
});

// From the floating bubble content.js shows next to a text selection. The
// content script copies the link to the clipboard itself (it already has a
// live user gesture from the click, no activeTab needed) once this resolves.
// Returning true keeps the message channel open until sendResponse() fires
// (required for an async response per the chrome.runtime.onMessage contract).
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== 'blink-create-from-selection') return;
  (async () => {
    try {
      const link = await createLinkFromText(message.text);
      sendResponse({ ok: true, link });
    } catch (err) {
      sendResponse({ ok: false, error: err.message || 'Could not create the link.' });
    }
  })();
  return true;
});
