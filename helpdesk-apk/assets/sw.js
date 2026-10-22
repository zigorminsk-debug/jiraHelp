// PWA only: Android loads bundled assets and does not register a service worker.
const CACHE_PREFIX = 'csl-helpdesk-' + self.registration.scope;
const CACHE_NAME = CACHE_PREFIX + '-v2';
const ASSETS = ['index.html', 'manifest.json', 'safety.js'];
self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS))
    .then(() => self.skipWaiting()));
});
self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(names => Promise.all(names
    .filter(name => name.startsWith(CACHE_PREFIX) && name !== CACHE_NAME)
    .map(name => caches.delete(name)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || !ASSETS.some(asset =>
    url.href === new URL(asset, self.registration.scope).href)) return;
  // Network first to avoid indefinitely serving the old interface after updates.
  event.respondWith(fetch(event.request).then(response => {
    if (response.ok) {
      const copy = response.clone();
      event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.put(event.request, copy)));
    }
    return response;
  }).catch(() => caches.match(event.request)));
});
