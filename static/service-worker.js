// CyberTech Security Platform - Service Worker
// Copyright Simbarashe Chimbera

const CACHE_NAME = 'cybertech-cache-v1';
const OFFLINE_URL = '/offline';

// Assets to pre-cache for offline availability
const ASSETS_TO_CACHE = [
  // Core pages
  '/',
  '/offline',
  '/login',
  '/register',
  '/dashboard',
  '/dashboard/home',
  '/dashboard/datasets',
  '/analysis/anomaly_detection',
  '/analysis/user_behavior',
  '/vulnerabilities/management',
  '/incident_response/manage',
  '/settings',
  
  // Static assets - CSS
  '/static/css/main.css',
  '/static/css/dashboard.css',
  '/static/css/auth.css',
  
  // Static assets - JavaScript
  '/static/js/main.js',
  '/static/js/charts.js',
  '/static/js/anomaly_detection.js',
  '/static/js/user_behavior.js',
  '/static/js/vulnerability_scan.js',
  '/static/js/offline.js',
  '/static/js/app-cache.js',
  
  // Static assets - Images
  '/static/images/cyber_bg.svg',
  '/static/images/logo.svg',
  '/static/manifest.json',
  
  // Third-party assets
  'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css',
  'https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js',
  'https://code.jquery.com/jquery-3.6.0.min.js'
];

// Install event - pre-cache assets
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Pre-caching offline assets');
        return cache.addAll(ASSETS_TO_CACHE);
      })
      .then(() => self.skipWaiting())
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.filter(cacheName => {
          return cacheName !== CACHE_NAME;
        }).map(cacheName => {
          console.log('Deleting old cache:', cacheName);
          return caches.delete(cacheName);
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch event - serve from cache if possible, otherwise fetch from network
self.addEventListener('fetch', event => {
  // Handle all requests, including cross-origin for resources we've cached
  event.respondWith(
    caches.match(event.request)
      .then(cachedResponse => {
        // Return cached response if available
        if (cachedResponse) {
          return cachedResponse;
        }

        // Otherwise fetch from network
        return fetch(event.request)
          .then(response => {
            // Don't cache cross-origin responses that aren't explicitly in our cache list
            if (!response || response.status !== 200 || 
                (!event.request.url.startsWith(self.location.origin) && 
                 !ASSETS_TO_CACHE.includes(event.request.url))) {
              return response;
            }

            // Clone response to cache and return
            const responseToCache = response.clone();
            caches.open(CACHE_NAME)
              .then(cache => {
                cache.put(event.request, responseToCache);
              });

            return response;
          })
          .catch(error => {
            // For navigation requests, show offline page if network request fails
            if (event.request.mode === 'navigate') {
              return caches.match(OFFLINE_URL);
            }
            
            // For other requests like API calls, return a JSON with offline indicator
            if (event.request.headers.get('Accept')?.includes('application/json')) {
              return new Response(JSON.stringify({
                status: 'offline',
                message: 'You are currently offline. Data shown may not be up to date.'
              }), {
                headers: {'Content-Type': 'application/json'}
              });
            }
            
            console.error('Fetch failed:', error);
            return new Response('Network error occurred', { status: 503, statusText: 'Service Unavailable' });
          });
      })
  );
});

// Handle messages from clients
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// Function to sync data when online again
self.addEventListener('sync', event => {
  if (event.tag === 'sync-pending-data') {
    event.waitUntil(syncPendingData());
  }
});

// Sync pending data to server when online
async function syncPendingData() {
  try {
    const pendingDataCache = await caches.open('pending-data-cache');
    const pendingRequests = await pendingDataCache.keys();
    
    for (const request of pendingRequests) {
      const pendingData = await pendingDataCache.match(request);
      const data = await pendingData.json();
      
      // Attempt to send the data to the server
      const response = await fetch(request.url, {
        method: request.method,
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      });
      
      if (response.ok) {
        // If successful, remove from pending cache
        await pendingDataCache.delete(request);
      }
    }
    
    // Notify clients of sync completion
    const clients = await self.clients.matchAll();
    clients.forEach(client => {
      client.postMessage({
        type: 'SYNC_COMPLETED'
      });
    });
    
  } catch (error) {
    console.error('Error syncing pending data:', error);
  }
}