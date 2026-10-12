const DEFAULT_URL = '/';

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

self.addEventListener('push', event => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch {
    payload = { body: event.data ? event.data.text() : 'Neue Whale-Aktivität erkannt.' };
  }

  const notification = payload.notification || payload;
  const title = notification.title || 'ReviewSpot · Whale Alert';
  const options = {
    body: notification.body || 'Neue Whale-Aktivität erkannt.',
    tag: notification.tag || 'reviewspot-whale-alert',
    renotify: true,
    data: {
      url: notification.navigate || notification.url || DEFAULT_URL
    }
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || DEFAULT_URL;

  event.waitUntil((async () => {
    const windows = await clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const client of windows) {
      if ('focus' in client) {
        await client.focus();
        if ('navigate' in client) {
          try { await client.navigate(url); } catch {}
        }
        return;
      }
    }
    if (clients.openWindow) await clients.openWindow(url);
  })());
});
