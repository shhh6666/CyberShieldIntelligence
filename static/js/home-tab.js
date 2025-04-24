/**
 * CyberTech - Cybersecurity Breach Detection System
 * Home Tab JavaScript file
 * Copyright Simbarashe Chimbera
 */

document.addEventListener('DOMContentLoaded', function() {
    // Check if service worker is supported
    if ('serviceWorker' in navigator) {
        // Register service worker for offline functionality
        navigator.serviceWorker.register('/static/js/service-worker.js')
            .then(registration => {
                console.log('Service Worker registered with scope:', registration.scope);
            })
            .catch(error => {
                console.error('Service Worker registration failed:', error);
            });
    }
    
    // Add smooth scrolling for anchor links on home page
    const anchors = document.querySelectorAll('a[href^="#"]');
    anchors.forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                window.scrollTo({
                    top: targetElement.offsetTop - 100,
                    behavior: 'smooth'
                });
            }
        });
    });
    
    // Set up feature cards hover animation
    const featureCards = document.querySelectorAll('.feature-card');
    featureCards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-10px)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = '';
        });
    });
    
    // Check offline status
    updateOfflineStatus();
    
    // Listen for online/offline events
    window.addEventListener('online', updateOfflineStatus);
    window.addEventListener('offline', updateOfflineStatus);
    
    function updateOfflineStatus() {
        const offlineBadge = document.querySelector('.offline-badge');
        if (!offlineBadge) return;
        
        const offlineIcon = offlineBadge.querySelector('.offline-icon');
        
        if (navigator.onLine) {
            offlineBadge.style.backgroundColor = '#3fb950'; // Green
            if (offlineIcon) {
                offlineIcon.className = 'fas fa-wifi offline-icon';
            }
            offlineBadge.textContent = offlineBadge.textContent.replace('Offline', 'Online');
        } else {
            offlineBadge.style.backgroundColor = '#f85149'; // Red
            if (offlineIcon) {
                offlineIcon.className = 'fas fa-wifi-slash offline-icon';
            }
            offlineBadge.textContent = offlineBadge.textContent.replace('Online', 'Offline');
            
            // Show offline notification
            showOfflineNotification();
        }
    }
    
    function showOfflineNotification() {
        // Don't show notification if already present
        if (document.querySelector('.offline-notification')) return;
        
        const notification = document.createElement('div');
        notification.className = 'offline-notification';
        notification.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            background-color: #212630;
            color: #fff;
            padding: 15px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            z-index: 9999;
            display: flex;
            align-items: center;
            max-width: 350px;
        `;
        
        notification.innerHTML = `
            <i class="fas fa-wifi-slash" style="color: #f85149; margin-right: 15px; font-size: 24px;"></i>
            <div>
                <div style="font-weight: 600; margin-bottom: 5px;">You're Offline</div>
                <div style="font-size: 14px; color: #a0a8b7;">Working in offline mode. Some features may be limited.</div>
            </div>
            <div style="margin-left: 15px; cursor: pointer; opacity: 0.7;" id="close-notification">
                <i class="fas fa-times"></i>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        // Add event listener to close button
        document.getElementById('close-notification').addEventListener('click', function() {
            document.body.removeChild(notification);
        });
        
        // Auto-remove after 8 seconds
        setTimeout(function() {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 8000);
    }
});