/**
 * CyberTech - Cybersecurity Breach Detection System
 * Futuristic Dashboard JavaScript
 * Copyright Simbarashe Chimbera
 */

// DOM Content Loaded Event
document.addEventListener('DOMContentLoaded', function() {
    initFuturisticDashboard();
});

// Initialize Futuristic Dashboard
function initFuturisticDashboard() {
    // Initialize the animated background grid
    initHexGrid();
    
    // Initialize tooltips
    initTooltips();
    
    // Initialize data flow animations
    initDataFlowAnimations();
    
    // Add cyberpunk glow effects to elements
    initGlowEffects();
    
    // Initialize 3D transforms for cards
    init3DCardEffects();
    
    // Initialize simulated connection line animations
    initConnectionLines();
}

// Initialize Animated Hex Grid
function initHexGrid() {
    const hexGrid = document.querySelector('.hex-grid');
    if (!hexGrid) return;
    
    // Add subtle animation
    hexGrid.style.animation = 'pulse 10s infinite';
}

// Initialize Tooltips
function initTooltips() {
    // This could be expanded with a real tooltip library if needed
    const tooltipElements = document.querySelectorAll('[data-tooltip]');
    
    tooltipElements.forEach(element => {
        element.style.position = 'relative';
        
        element.addEventListener('mouseenter', function() {
            const tooltipText = this.getAttribute('data-tooltip');
            const tooltip = document.createElement('div');
            tooltip.classList.add('futuristic-tooltip');
            tooltip.textContent = tooltipText;
            
            tooltip.style.position = 'absolute';
            tooltip.style.bottom = '100%';
            tooltip.style.left = '50%';
            tooltip.style.transform = 'translateX(-50%)';
            tooltip.style.marginBottom = '10px';
            tooltip.style.padding = '8px 12px';
            tooltip.style.backgroundColor = 'rgba(10, 25, 41, 0.9)';
            tooltip.style.color = 'white';
            tooltip.style.borderRadius = '4px';
            tooltip.style.fontSize = '0.8rem';
            tooltip.style.zIndex = '100';
            tooltip.style.whiteSpace = 'nowrap';
            tooltip.style.boxShadow = '0 0 15px rgba(0, 243, 255, 0.2)';
            tooltip.style.border = '1px solid rgba(0, 243, 255, 0.3)';
            
            this.appendChild(tooltip);
        });
        
        element.addEventListener('mouseleave', function() {
            const tooltip = this.querySelector('.futuristic-tooltip');
            if (tooltip) {
                tooltip.remove();
            }
        });
    });
}

// Initialize Glow Effects
function initGlowEffects() {
    // Add pulse glow effect to important elements
    const glowElements = document.querySelectorAll('.glow-text, .futuristic-stat-value, .threat-badge');
    
    glowElements.forEach(element => {
        // Create a subtle pulse animation
        const randomDelay = Math.random() * 4;
        element.style.animation = `pulse-glow 3s infinite ${randomDelay}s`;
    });
}

// Initialize 3D Card Effects
function init3DCardEffects() {
    const cards = document.querySelectorAll('.futuristic-card');
    
    cards.forEach(card => {
        card.addEventListener('mousemove', function(e) {
            const rect = this.getBoundingClientRect();
            const x = e.clientX - rect.left; // x position within the card
            const y = e.clientY - rect.top; // y position within the card
            
            // Calculate the rotation angle based on mouse position
            // The division by a larger number (20) makes the effect more subtle
            const rotateX = (y - rect.height / 2) / 20;
            const rotateY = (rect.width / 2 - x) / 20;
            
            // Apply the transform
            this.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale3d(1.02, 1.02, 1.02)`;
            this.style.zIndex = '10';
            
            // Add a subtle shadow and glow effect
            this.style.boxShadow = `0 10px 30px rgba(0,0,0,0.3), 0 0 20px rgba(0, 243, 255, 0.3)`;
        });
        
        card.addEventListener('mouseleave', function() {
            // Reset the transform and shadow when mouse leaves the card
            this.style.transform = 'perspective(1000px) rotateX(0) rotateY(0) scale3d(1, 1, 1)';
            this.style.zIndex = '1';
            this.style.boxShadow = '0 0 20px rgba(0, 243, 255, 0.2)';
        });
    });
}

// Initialize Data Flow Animations
function initDataFlowAnimations() {
    const dataFlows = document.querySelectorAll('.data-flow');
    
    dataFlows.forEach(dataFlow => {
        // This is a placeholder for a more complex data flow visualization
        // In a real implementation, this would use Canvas or WebGL to create
        // an animated visualization of data packets flowing through the system
    });
}

// Initialize Connection Lines
function initConnectionLines() {
    // This is a placeholder for a more complex network visualization
    // In a real implementation, this would draw animated connection lines
    // between different network nodes using Canvas or SVG
}

// Real-time Data Functions
function updateSecurityScore(score) {
    const scoreElements = document.querySelectorAll('.score-number');
    scoreElements.forEach(element => {
        element.textContent = score;
        
        // Update the color based on the score
        if (score >= 80) {
            element.style.color = '#00ff8b'; // Green for good scores
        } else if (score >= 60) {
            element.style.color = '#ffce3b'; // Yellow for medium scores
        } else {
            element.style.color = '#ff3b3b'; // Red for bad scores
        }
    });
}

function updateThreatMap(threats) {
    // This would update the threat map visualization with new threat data
    // 'threats' would be an array of objects with location and severity information
}

function updateNetworkTraffic(inbound, outbound, blocked) {
    // This would update the network traffic visualization with new data
    // Parameters would include inbound traffic, outbound traffic, and blocked connections
}

// Utility Functions
function formatDataSize(bytes) {
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    if (bytes === 0) return '0 Byte';
    const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
    return Math.round(bytes / Math.pow(1024, i), 2) + ' ' + sizes[i];
}

function formatNumber(num) {
    return num.toString().replace(/(\d)(?=(\d{3})+(?!\d))/g, '$1,');
}

// Add some CSS animations programmatically
const style = document.createElement('style');
style.textContent = `
@keyframes pulse-glow {
    0% {
        filter: brightness(1);
        text-shadow: 0 0 5px currentColor;
    }
    50% {
        filter: brightness(1.3);
        text-shadow: 0 0 15px currentColor;
    }
    100% {
        filter: brightness(1);
        text-shadow: 0 0 5px currentColor;
    }
}

@keyframes flow {
    0% {
        transform: translateX(0) translateY(0);
        opacity: 0;
    }
    10% {
        opacity: 1;
    }
    90% {
        opacity: 1;
    }
    100% {
        transform: translateX(100px) translateY(-50px);
        opacity: 0;
    }
}

@keyframes pulse {
    0% {
        transform: scale(1);
        opacity: 0.8;
    }
    50% {
        transform: scale(1.05);
        opacity: 0.4;
    }
    100% {
        transform: scale(1);
        opacity: 0.8;
    }
}

.data-particle {
    position: absolute;
    width: 3px;
    height: 3px;
    background-color: var(--neon-blue);
    border-radius: 50%;
    animation: flow 5s linear infinite;
}
`;

document.head.appendChild(style);