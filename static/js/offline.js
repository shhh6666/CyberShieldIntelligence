/**
 * CyberTech - Cybersecurity Breach Detection System
 * Offline Functionality JavaScript file
 * Copyright Simbarashe Chimbera
 */

// Initialize offline functionality
document.addEventListener('DOMContentLoaded', function() {
    initOfflineMode();
    registerSyncEvents();
    setupLocalStorage();
});

// Check if user is online and update UI accordingly
function initOfflineMode() {
    updateOnlineStatus();
    
    // Listen for online/offline events
    window.addEventListener('online', updateOnlineStatus);
    window.addEventListener('offline', updateOnlineStatus);
}

// Update UI based on online status
function updateOnlineStatus() {
    const offlineIndicator = document.getElementById('offline-indicator');
    
    if (!offlineIndicator) {
        // Create offline indicator if it doesn't exist
        createOfflineIndicator();
        return;
    }
    
    if (navigator.onLine) {
        offlineIndicator.classList.add('online');
        offlineIndicator.classList.remove('offline');
        offlineIndicator.querySelector('.status-text').textContent = 'Online';
        
        // Attempt to sync data if we just came back online
        syncData();
    } else {
        offlineIndicator.classList.add('offline');
        offlineIndicator.classList.remove('online');
        offlineIndicator.querySelector('.status-text').textContent = 'Offline';
        
        // Show offline notification
        showOfflineNotification();
    }
}

// Create offline status indicator in the topbar
function createOfflineIndicator() {
    const topbarNav = document.querySelector('.topbar-nav');
    
    if (!topbarNav) return;
    
    const offlineIndicator = document.createElement('div');
    offlineIndicator.id = 'offline-indicator';
    offlineIndicator.className = navigator.onLine ? 'online' : 'offline';
    
    offlineIndicator.innerHTML = `
        <i class="fas ${navigator.onLine ? 'fa-wifi' : 'fa-wifi-slash'}"></i>
        <span class="status-text">${navigator.onLine ? 'Online' : 'Offline'}</span>
    `;
    
    // Insert before the user element
    const userElement = document.querySelector('.topbar-user');
    if (userElement) {
        topbarNav.insertBefore(offlineIndicator, userElement);
    } else {
        topbarNav.appendChild(offlineIndicator);
    }
    
    // Add styles
    const style = document.createElement('style');
    style.textContent = `
        #offline-indicator {
            display: flex;
            align-items: center;
            padding: 0.5rem 1rem;
            border-radius: 50px;
            margin-right: 1rem;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }
        
        #offline-indicator i {
            margin-right: 0.5rem;
        }
        
        #offline-indicator.online {
            background-color: rgba(63, 185, 80, 0.15);
            color: #3fb950;
        }
        
        #offline-indicator.offline {
            background-color: rgba(248, 81, 73, 0.15);
            color: #f85149;
        }
        
        .offline-notification {
            position: fixed;
            bottom: 1rem;
            right: 1rem;
            background-color: var(--secondary-dark);
            color: var(--text-primary);
            padding: 1rem;
            border-radius: 6px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            z-index: 9999;
            display: flex;
            align-items: center;
            max-width: 350px;
            animation: slideIn 0.3s ease;
        }
        
        .offline-notification i {
            margin-right: 1rem;
            font-size: 1.5rem;
            color: #f85149;
        }
        
        .offline-notification-content {
            flex: 1;
        }
        
        .offline-notification-title {
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        
        .offline-notification-message {
            font-size: 0.9rem;
            color: var(--text-secondary);
        }
        
        .offline-notification-close {
            padding: 0.25rem;
            cursor: pointer;
            opacity: 0.7;
            transition: opacity 0.2s ease;
        }
        
        .offline-notification-close:hover {
            opacity: 1;
        }
        
        @keyframes slideIn {
            from {
                transform: translateY(100%);
                opacity: 0;
            }
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }
    `;
    
    document.head.appendChild(style);
}

// Show offline notification
function showOfflineNotification() {
    // Check if notification already exists
    if (document.querySelector('.offline-notification')) {
        return;
    }
    
    const notification = document.createElement('div');
    notification.className = 'offline-notification';
    
    notification.innerHTML = `
        <i class="fas fa-wifi-slash"></i>
        <div class="offline-notification-content">
            <div class="offline-notification-title">You're Offline</div>
            <div class="offline-notification-message">Working in offline mode. Changes will be synced when you're back online.</div>
        </div>
        <div class="offline-notification-close">
            <i class="fas fa-times"></i>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Remove notification when close button is clicked
    notification.querySelector('.offline-notification-close').addEventListener('click', function() {
        document.body.removeChild(notification);
    });
    
    // Auto-remove after 10 seconds
    setTimeout(function() {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    }, 10000);
}

// Register for sync events
function registerSyncEvents() {
    // Check if service worker and background sync are supported
    if ('serviceWorker' in navigator && 'SyncManager' in window) {
        // Listen for messages from service worker
        navigator.serviceWorker.addEventListener('message', event => {
            if (event.data && event.data.type === 'SYNC_COMPLETED') {
                console.log('Data synced successfully');
                
                // Show sync notification
                showSyncNotification();
                
                // Update cached data timestamps
                updateTimestamps();
            }
        });
    }
}

// Show sync notification
function showSyncNotification() {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = 'offline-notification';
    
    notification.innerHTML = `
        <i class="fas fa-sync-alt" style="color: #3fb950;"></i>
        <div class="offline-notification-content">
            <div class="offline-notification-title">Data Synchronized</div>
            <div class="offline-notification-message">Your offline changes have been successfully synced with the server.</div>
        </div>
        <div class="offline-notification-close">
            <i class="fas fa-times"></i>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Remove notification when close button is clicked
    notification.querySelector('.offline-notification-close').addEventListener('click', function() {
        document.body.removeChild(notification);
    });
    
    // Auto-remove after 5 seconds
    setTimeout(function() {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    }, 5000);
}

// Setup local storage for offline data
function setupLocalStorage() {
    // Set up initial timestamps if they don't exist
    if (!localStorage.getItem('dashboard-last-updated')) {
        localStorage.setItem('dashboard-last-updated', new Date().toLocaleString());
    }
    
    if (!localStorage.getItem('datasets-last-updated')) {
        localStorage.setItem('datasets-last-updated', new Date().toLocaleString());
    }
    
    if (!localStorage.getItem('detection-last-updated')) {
        localStorage.setItem('detection-last-updated', new Date().toLocaleString());
    }
    
    if (!localStorage.getItem('incidents-last-updated')) {
        localStorage.setItem('incidents-last-updated', new Date().toLocaleString());
    }
}

// Update timestamps when data is refreshed
function updateTimestamps() {
    const now = new Date().toLocaleString();
    const page = window.location.pathname;
    
    if (page.includes('dashboard')) {
        localStorage.setItem('dashboard-last-updated', now);
    } else if (page.includes('dataset')) {
        localStorage.setItem('datasets-last-updated', now);
    } else if (page.includes('anomaly') || page.includes('detection')) {
        localStorage.setItem('detection-last-updated', now);
    } else if (page.includes('incident')) {
        localStorage.setItem('incidents-last-updated', now);
    }
}

// Save form data to IndexedDB for offline use
function saveFormData(formId, formData) {
    // Return if online (let the normal form submission handle it)
    if (navigator.onLine) return;
    
    console.log('Saving form data for offline use');
    
    // Check if IndexedDB is supported
    if (!window.indexedDB) {
        console.log('IndexedDB not supported');
        alert('Your browser doesn\'t support offline data storage. Changes may be lost when offline.');
        return;
    }
    
    // Open/create the database
    const request = indexedDB.open('CyberTechOfflineDB', 1);
    
    request.onerror = function(event) {
        console.log('Error opening offline database:', event.target.error);
    };
    
    request.onupgradeneeded = function(event) {
        const db = event.target.result;
        
        // Create object stores if they don't exist
        if (!db.objectStoreNames.contains('pendingForms')) {
            db.createObjectStore('pendingForms', { keyPath: 'id', autoIncrement: true });
        }
    };
    
    request.onsuccess = function(event) {
        const db = event.target.result;
        const transaction = db.transaction(['pendingForms'], 'readwrite');
        const store = transaction.objectStore('pendingForms');
        
        // Add the form data to the store
        const addRequest = store.add({
            formId: formId,
            data: formData,
            url: window.location.href,
            timestamp: new Date().toISOString()
        });
        
        addRequest.onsuccess = function() {
            console.log('Form data saved for offline use');
            
            // Show confirmation to user
            alert('You are offline. Your changes have been saved locally and will be synchronized when you\'re back online.');
        };
        
        addRequest.onerror = function(event) {
            console.log('Error saving form data:', event.target.error);
        };
    };
}

// Sync data when back online
function syncData() {
    console.log('Attempting to sync offline data');
    
    // Check if service worker and background sync are supported
    if ('serviceWorker' in navigator && 'SyncManager' in window) {
        navigator.serviceWorker.ready
            .then(registration => {
                return registration.sync.register('sync-pending-data');
            })
            .catch(error => {
                console.log('Error registering sync:', error);
                // Fall back to manual sync
                manualSync();
            });
    } else {
        // Fall back to manual sync for browsers that don't support background sync
        manualSync();
    }
}

// Manual sync when background sync isn't supported
function manualSync() {
    console.log('Performing manual sync');
    
    // Check if IndexedDB is supported
    if (!window.indexedDB) {
        console.log('IndexedDB not supported');
        return;
    }
    
    // Open the database
    const request = indexedDB.open('CyberTechOfflineDB', 1);
    
    request.onerror = function(event) {
        console.log('Error opening offline database:', event.target.error);
    };
    
    request.onsuccess = function(event) {
        const db = event.target.result;
        const transaction = db.transaction(['pendingForms'], 'readwrite');
        const store = transaction.objectStore('pendingForms');
        
        // Get all pending forms
        const getAllRequest = store.getAll();
        
        getAllRequest.onsuccess = function() {
            const pendingForms = getAllRequest.result;
            
            if (pendingForms.length === 0) {
                console.log('No pending forms to sync');
                return;
            }
            
            console.log(`Found ${pendingForms.length} pending forms to sync`);
            
            // Process each pending form
            let syncedCount = 0;
            
            pendingForms.forEach((formData, index) => {
                // Submit the form data
                fetch(formData.url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: new URLSearchParams(formData.data).toString()
                })
                .then(response => {
                    if (response.ok) {
                        console.log(`Successfully synced form ${index + 1}`);
                        
                        // Remove the synced form from the store
                        const deleteRequest = store.delete(formData.id);
                        
                        deleteRequest.onsuccess = function() {
                            syncedCount++;
                            
                            // Show notification when all forms are synced
                            if (syncedCount === pendingForms.length) {
                                showSyncNotification();
                                updateTimestamps();
                            }
                        };
                    } else {
                        console.log(`Failed to sync form ${index + 1}:`, response.statusText);
                    }
                })
                .catch(error => {
                    console.log(`Error syncing form ${index + 1}:`, error);
                });
            });
        };
        
        getAllRequest.onerror = function(event) {
            console.log('Error getting pending forms:', event.target.error);
        };
    };
}