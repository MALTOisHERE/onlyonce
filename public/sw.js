const CACHE = 'blink-v1';
const STATIC = ['/style.css', '/app.js', '/logo.png', '/logo-192.png', '/logo-512.png', '/about.html'];

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
  // Never intercept API calls or secret view pages
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/view/')) return;
  e.respondWith(
    fetch(e.request).catch(() => caches.match(e.request))
  );
});
