/**
 * CyberTech - Cybersecurity Breach Detection System
 * App Cache for Offline Data Storage
 * Copyright Simbarashe Chimbera
 */

// Initialize IndexedDB
const dbName = 'CyberTechOfflineDB';
const dbVersion = 1;
let db;

// Open IndexedDB connection
function openDatabase() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(dbName, dbVersion);
        
        request.onerror = event => {
            console.error('Error opening database:', event.target.error);
            reject(event.target.error);
        };
        
        request.onsuccess = event => {
            db = event.target.result;
            console.log('Database opened successfully');
            resolve(db);
        };
        
        request.onupgradeneeded = event => {
            const db = event.target.result;
            
            // Create object stores if they don't exist
            if (!db.objectStoreNames.contains('pendingForms')) {
                db.createObjectStore('pendingForms', { keyPath: 'id', autoIncrement: true });
            }
            
            if (!db.objectStoreNames.contains('cachedData')) {
                db.createObjectStore('cachedData', { keyPath: 'key' });
            }
            
            if (!db.objectStoreNames.contains('dashboardData')) {
                db.createObjectStore('dashboardData', { keyPath: 'id' });
            }
            
            if (!db.objectStoreNames.contains('datasets')) {
                db.createObjectStore('datasets', { keyPath: 'id' });
            }
            
            if (!db.objectStoreNames.contains('anomalies')) {
                db.createObjectStore('anomalies', { keyPath: 'id' });
            }
            
            if (!db.objectStoreNames.contains('vulnerabilities')) {
                db.createObjectStore('vulnerabilities', { keyPath: 'id' });
            }
            
            if (!db.objectStoreNames.contains('incidents')) {
                db.createObjectStore('incidents', { keyPath: 'id' });
            }
        };
    });
}

// Initialize database connection
openDatabase().catch(error => {
    console.error('Failed to open database:', error);
});

// Cache API response data
function cacheApiData(key, data) {
    return new Promise((resolve, reject) => {
        if (!db) {
            reject(new Error('Database not initialized'));
            return;
        }
        
        const transaction = db.transaction(['cachedData'], 'readwrite');
        const store = transaction.objectStore('cachedData');
        
        // Add timestamp to data
        const dataWithTimestamp = {
            ...data,
            cachedAt: new Date().toISOString()
        };
        
        const request = store.put({
            key: key,
            data: dataWithTimestamp
        });
        
        request.onsuccess = () => {
            console.log(`Data cached with key: ${key}`);
            // Update localStorage with timestamp for UI display
            localStorage.setItem(`${key}-last-updated`, new Date().toLocaleString());
            resolve();
        };
        
        request.onerror = event => {
            console.error(`Error caching data for key ${key}:`, event.target.error);
            reject(event.target.error);
        };
    });
}

// Get cached API response data
function getCachedData(key) {
    return new Promise((resolve, reject) => {
        if (!db) {
            reject(new Error('Database not initialized'));
            return;
        }
        
        const transaction = db.transaction(['cachedData'], 'readonly');
        const store = transaction.objectStore('cachedData');
        const request = store.get(key);
        
        request.onsuccess = event => {
            const result = event.target.result;
            if (result) {
                console.log(`Retrieved cached data for key: ${key}`);
                resolve(result.data);
            } else {
                console.log(`No cached data found for key: ${key}`);
                resolve(null);
            }
        };
        
        request.onerror = event => {
            console.error(`Error retrieving cached data for key ${key}:`, event.target.error);
            reject(event.target.error);
        };
    });
}

// API wrapper function with offline support
async function fetchWithOfflineSupport(url, options = {}) {
    // Generate cache key based on URL and method
    const cacheKey = `${options.method || 'GET'}_${url}`;
    
    try {
        // First try to fetch from network
        if (navigator.onLine) {
            const response = await fetch(url, options);
            
            if (response.ok) {
                const data = await response.json();
                
                // Cache the successful response
                await cacheApiData(cacheKey, data);
                
                return {
                    data: data,
                    offline: false
                };
            } else {
                throw new Error(`API request failed with status: ${response.status}`);
            }
        } else {
            throw new Error('Offline mode');
        }
    } catch (error) {
        console.log('Using cached data due to:', error.message);
        
        // Try to get cached data
        const cachedData = await getCachedData(cacheKey);
        
        if (cachedData) {
            return {
                data: cachedData,
                offline: true,
                cachedAt: cachedData.cachedAt
            };
        } else {
            throw new Error('No cached data available and unable to fetch from network');
        }
    }
}

// Save form data for offline submission
function saveFormForOfflineSubmission(formId, formData, url) {
    return new Promise((resolve, reject) => {
        if (!db) {
            reject(new Error('Database not initialized'));
            return;
        }
        
        const transaction = db.transaction(['pendingForms'], 'readwrite');
        const store = transaction.objectStore('pendingForms');
        
        const request = store.add({
            formId: formId,
            data: formData,
            url: url,
            timestamp: new Date().toISOString()
        });
        
        request.onsuccess = () => {
            console.log('Form saved for offline submission');
            resolve();
        };
        
        request.onerror = event => {
            console.error('Error saving form for offline submission:', event.target.error);
            reject(event.target.error);
        };
    });
}

// Check if there are pending forms to be submitted
async function hasPendingForms() {
    if (!db) return false;
    
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(['pendingForms'], 'readonly');
        const store = transaction.objectStore('pendingForms');
        const countRequest = store.count();
        
        countRequest.onsuccess = () => {
            resolve(countRequest.result > 0);
        };
        
        countRequest.onerror = event => {
            console.error('Error checking pending forms:', event.target.error);
            reject(event.target.error);
        };
    });
}

// Export functionality
window.AppCache = {
    cacheApiData,
    getCachedData,
    fetchWithOfflineSupport,
    saveFormForOfflineSubmission,
    hasPendingForms
};