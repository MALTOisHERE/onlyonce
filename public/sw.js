// ── Service worker ───────────────────────────────────────────────────────────
// Offline/PWA support: caches a handful of static assets at install time
// and serves them when the network fetch fails. Deliberately stays out of
// the way of anything dynamic - see the fetch handler below for exactly
// what it will and won't intercept.
const CACHE = 'blink-v5';
const STATIC = ['/style.css', '/app.js', '/about.html', '/fonts/space-grotesk.woff2'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(STATIC)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
  ));
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // Only ever handle same-origin requests. A cross-origin resource (e.g. the
  // CDN-hosted logo) is left to the browser's normal, uncached fetch instead
  // of being re-issued here, which can fail CORS and leave nothing cached to
  // fall back to.
  if (url.origin !== self.location.origin) return;
  // Never intercept API calls or secret view pages
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/view/')) return;
  e.respondWith(
    fetch(e.request).catch(() => caches.match(e.request).then(cached => cached || Response.error()))
  );
});
