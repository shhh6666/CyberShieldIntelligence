/**
 * CyberTech - Cybersecurity Breach Detection System
 * Anomaly Detection JavaScript file
 * Copyright Simbarashe Chimbera
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize anomaly detection form
    initAnomalyDetectionForm();
    
    // Initialize result filtering
    initAnomalyResultFiltering();
    
    // Initialize anomaly details expansion
    initAnomalyDetailsExpansion();
    
    // Initialize anomaly action buttons
    initAnomalyActionButtons();
});

// Initialize anomaly detection form with validation
function initAnomalyDetectionForm() {
    const form = document.getElementById('anomaly-detection-form');
    if (!form) return;
    
    // Dataset selection change handler
    const datasetSelect = form.querySelector('#dataset');
    if (datasetSelect) {
        datasetSelect.addEventListener('change', function() {
            // You could potentially fetch dataset details here
            const datasetId = this.value;
            if (datasetId) {
                fetchDatasetDetails(datasetId);
            }
        });
    }
    
    // Sensitivity selection change handler
    const sensitivitySelect = form.querySelector('#sensitivity');
    if (sensitivitySelect) {
        const sensitivityInfo = document.getElementById('sensitivity-info');
        
        sensitivitySelect.addEventListener('change', function() {
            if (!sensitivityInfo) return;
            
            // Update information based on selected sensitivity
            const selectedSensitivity = this.value;
            let infoText = '';
            
            switch(selectedSensitivity) {
                case 'low':
                    infoText = 'Low sensitivity will detect only the most obvious anomalies, resulting in fewer alerts but potentially missing some suspicious activities.';
                    break;
                case 'medium':
                    infoText = 'Medium sensitivity provides a balanced approach to anomaly detection, suitable for most environments.';
                    break;
                case 'high':
                    infoText = 'High sensitivity will detect more subtle anomalies but may generate more false positives that require review.';
                    break;
            }
            
            sensitivityInfo.textContent = infoText;
        });
    }
    
    // Form submission handler with validation
    form.addEventListener('submit', function(e) {
        if (!validateAnomalyDetectionForm(form)) {
            e.preventDefault();
        } else {
            // Show loading state
            const submitButton = form.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.innerHTML = '<span class="loader"></span> Processing...';
            }
            
            // Show processing message
            const processingMsg = document.getElementById('processing-message');
            if (processingMsg) {
                processingMsg.style.display = 'block';
            }
        }
    });
}

// Validate anomaly detection form
function validateAnomalyDetectionForm(form) {
    let isValid = true;
    
    // Check dataset selection
    const datasetSelect = form.querySelector('#dataset');
    if (datasetSelect && (!datasetSelect.value || datasetSelect.value === '')) {
        displayFormError(datasetSelect, 'Please select a dataset');
        isValid = false;
    } else {
        clearFormError(datasetSelect);
    }
    
    // Check analysis name
    const analysisName = form.querySelector('#analysis_name');
    if (analysisName && (!analysisName.value || analysisName.value.trim() === '')) {
        displayFormError(analysisName, 'Please enter an analysis name');
        isValid = false;
    } else {
        clearFormError(analysisName);
    }
    
    return isValid;
}

// Display form validation error
function displayFormError(element, message) {
    // Clear any existing error
    clearFormError(element);
    
    // Add error class to input
    element.classList.add('error');
    
    // Create and add error message
    const errorElement = document.createElement('div');
    errorElement.className = 'invalid-feedback';
    errorElement.textContent = message;
    
    // Insert error after the element
    element.parentNode.insertBefore(errorElement, element.nextSibling);
}

// Clear form validation error
function clearFormError(element) {
    element.classList.remove('error');
    
    // Remove any existing error message
    const errorElement = element.nextElementSibling;
    if (errorElement && errorElement.className === 'invalid-feedback') {
        errorElement.remove();
    }
}

// Fetch dataset details (for information display)
function fetchDatasetDetails(datasetId) {
    const datasetInfo = document.getElementById('dataset-info');
    if (!datasetInfo) return;
    
    // Show loading state
    datasetInfo.innerHTML = '<span class="loader"></span> Loading dataset details...';
    datasetInfo.style.display = 'block';
    
    // In a real implementation, you would fetch details from server
    // Here we're just simulating the display
    setTimeout(() => {
        const datasets = document.querySelectorAll('#dataset option');
        let datasetName = '';
        
        // Find selected dataset name
        datasets.forEach(option => {
            if (option.value === datasetId) {
                datasetName = option.textContent;
            }
        });
        
        if (datasetName) {
            datasetInfo.innerHTML = `
                <div class="mt-2">
                    <strong>Selected Dataset:</strong> ${datasetName}<br>
                    <small class="text-secondary">This dataset will be analyzed for anomalous patterns and behaviors.</small>
                </div>
            `;
        } else {
            datasetInfo.style.display = 'none';
        }
    }, 500);
}

// Initialize filtering for anomaly results
function initAnomalyResultFiltering() {
    const filterControls = document.querySelectorAll('.anomaly-filter');
    if (filterControls.length === 0) return;
    
    filterControls.forEach(control => {
        control.addEventListener('change', filterAnomalies);
    });
    
    // Initialize search box
    const searchBox = document.getElementById('anomaly-search');
    if (searchBox) {
        searchBox.addEventListener('keyup', filterAnomalies);
    }
}

// Filter anomalies based on selected criteria
function filterAnomalies() {
    const severityFilter = document.getElementById('severity-filter');
    const statusFilter = document.getElementById('status-filter');
    const searchBox = document.getElementById('anomaly-search');
    
    const selectedSeverity = severityFilter ? severityFilter.value : 'all';
    const selectedStatus = statusFilter ? statusFilter.value : 'all';
    const searchTerm = searchBox ? searchBox.value.toLowerCase() : '';
    
    const anomalyItems = document.querySelectorAll('.anomaly-item');
    let visibleCount = 0;
    
    anomalyItems.forEach(item => {
        // Check severity filter
        const severityMatch = selectedSeverity === 'all' || 
                            item.getAttribute('data-severity') === selectedSeverity;
        
        // Check status filter
        const isFalsePositive = item.classList.contains('false-positive');
        const statusMatch = selectedStatus === 'all' || 
                          (selectedStatus === 'false-positive' && isFalsePositive) ||
                          (selectedStatus === 'active' && !isFalsePositive);
        
        // Check search term
        const itemText = item.textContent.toLowerCase();
        const searchMatch = searchTerm === '' || itemText.includes(searchTerm);
        
        // Apply visibility
        if (severityMatch && statusMatch && searchMatch) {
            item.style.display = '';
            visibleCount++;
        } else {
            item.style.display = 'none';
        }
    });
    
    // Update results count
    const resultsCounter = document.getElementById('results-count');
    if (resultsCounter) {
        resultsCounter.textContent = visibleCount;
    }
    
    // Display "no results" message if needed
    const noResultsMessage = document.getElementById('no-results-message');
    if (noResultsMessage) {
        noResultsMessage.style.display = visibleCount === 0 ? 'block' : 'none';
    }
}

// Initialize anomaly details expansion functionality
function initAnomalyDetailsExpansion() {
    const expandButtons = document.querySelectorAll('.expand-anomaly-details');
    if (expandButtons.length === 0) return;
    
    expandButtons.forEach(button => {
        button.addEventListener('click', function() {
            const anomalyId = this.getAttribute('data-anomaly-id');
            const detailsPanel = document.querySelector(`.anomaly-details[data-anomaly-id="${anomalyId}"]`);
            
            if (detailsPanel) {
                // Toggle the details panel
                const isExpanded = detailsPanel.classList.toggle('expanded');
                
                // Update button text/icon
                this.innerHTML = isExpanded ? 
                    '<i class="fas fa-chevron-up"></i> Hide Details' : 
                    '<i class="fas fa-chevron-down"></i> Show Details';
            }
        });
    });
}

// Initialize anomaly action buttons
function initAnomalyActionButtons() {
    // False positive marking
    const falsePositiveButtons = document.querySelectorAll('.mark-false-positive-btn');
    falsePositiveButtons.forEach(button => {
        button.addEventListener('click', function() {
            const anomalyId = this.getAttribute('data-anomaly-id');
            
            if (confirm('Are you sure you want to mark this anomaly as a false positive?')) {
                markAnomalyAsFalsePositive(anomalyId);
            }
        });
    });
    
    // Create incident buttons
    const createIncidentButtons = document.querySelectorAll('.create-incident-btn');
    createIncidentButtons.forEach(button => {
        button.addEventListener('click', function() {
            const anomalyId = this.getAttribute('data-anomaly-id');
            const anomalyText = document.querySelector(`.anomaly-item[data-anomaly-id="${anomalyId}"] .anomaly-title`).textContent;
            
            if (confirm(`Are you sure you want to create an incident from anomaly: "${anomalyText}"?`)) {
                createIncidentFromAnomaly(anomalyId);
            }
        });
    });
}

// Real-time anomaly detection simulation
class AnomalyDetectionSimulator {
    constructor(containerId, options = {}) {
        this.container = document.getElementById(containerId);
        if (!this.container) return;
        
        this.options = Object.assign({
            interval: 3000, // ms between anomaly checks
            detectionChance: 0.3, // probability of detecting anomaly per check
            criticalChance: 0.2, // probability of critical among detected
            highChance: 0.3, // probability of high among detected
            autoStart: false,
            maxAnomalies: 10
        }, options);
        
        this.isRunning = false;
        this.anomalyCount = 0;
        this.timer = null;
        
        this.init();
    }
    
    init() {
        // Create UI
        this.createControlUI();
        
        // Auto-start if configured
        if (this.options.autoStart) {
            this.start();
        }
    }
    
    createControlUI() {
        const controlsDiv = document.createElement('div');
        controlsDiv.className = 'anomaly-detection-controls mb-3';
        
        const buttonStart = document.createElement('button');
        buttonStart.className = 'btn btn-primary mr-2';
        buttonStart.textContent = 'Start Monitoring';
        buttonStart.addEventListener('click', () => this.start());
        
        const buttonStop = document.createElement('button');
        buttonStop.className = 'btn btn-danger mr-2';
        buttonStop.textContent = 'Stop Monitoring';
        buttonStop.addEventListener('click', () => this.stop());
        
        const buttonClear = document.createElement('button');
        buttonClear.className = 'btn btn-secondary';
        buttonClear.textContent = 'Clear Results';
        buttonClear.addEventListener('click', () => this.clear());
        
        controlsDiv.appendChild(buttonStart);
        controlsDiv.appendChild(buttonStop);
        controlsDiv.appendChild(buttonClear);
        
        this.container.appendChild(controlsDiv);
        
        // Create results area
        const resultsDiv = document.createElement('div');
        resultsDiv.className = 'anomaly-detection-results';
        resultsDiv.innerHTML = `
            <div class="status-indicator mb-3">
                <span class="status-dot"></span>
                <span class="status-text">Monitoring inactive</span>
            </div>
            <div class="results-container"></div>
        `;
        
        this.container.appendChild(resultsDiv);
        
        this.resultsContainer = resultsDiv.querySelector('.results-container');
        this.statusDot = resultsDiv.querySelector('.status-dot');
        this.statusText = resultsDiv.querySelector('.status-text');
    }
    
    start() {
        if (this.isRunning) return;
        
        this.isRunning = true;
        this.statusDot.classList.add('active');
        this.statusText.textContent = 'Monitoring active - scanning network traffic...';
        
        this.timer = setInterval(() => this.checkForAnomalies(), this.options.interval);
    }
    
    stop() {
        if (!this.isRunning) return;
        
        this.isRunning = false;
        clearInterval(this.timer);
        this.statusDot.classList.remove('active');
        this.statusText.textContent = 'Monitoring paused';
    }
    
    clear() {
        this.resultsContainer.innerHTML = '';
        this.anomalyCount = 0;
    }
    
    checkForAnomalies() {
        // Simulated detection logic
        if (Math.random() < this.options.detectionChance) {
            this.detectAnomaly();
        }
    }
    
    detectAnomaly() {
        // Generate a random anomaly
        const anomalyTypes = [
            { type: 'Unusual login activity', details: 'Multiple failed login attempts detected from unusual IP address' },
            { type: 'Suspicious file access', details: 'Sensitive files accessed outside normal working hours' },
            { type: 'Network traffic spike', details: 'Abnormal data transfer volume detected' },
            { type: 'Unusual database query', details: 'Query pattern indicates potential data exfiltration attempt' },
            { type: 'Configuration change', details: 'Security settings modified without change request' }
        ];
        
        const randomType = anomalyTypes[Math.floor(Math.random() * anomalyTypes.length)];
        
        // Determine severity
        let severity;
        const rand = Math.random();
        if (rand < this.options.criticalChance) {
            severity = 'critical';
        } else if (rand < this.options.criticalChance + this.options.highChance) {
            severity = 'high';
        } else if (rand < 0.8) {
            severity = 'medium';
        } else {
            severity = 'low';
        }
        
        // Create timestamp
        const timestamp = new Date().toLocaleTimeString();
        
        // Generate random IP
        const sourceIP = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
        
        // Add to results
        this.addAnomalyToResults({
            type: randomType.type,
            details: randomType.details,
            severity: severity,
            timestamp: timestamp,
            sourceIP: sourceIP
        });
    }
    
    addAnomalyToResults(anomaly) {
        // Create result element
        const resultElement = document.createElement('div');
        resultElement.className = `anomaly-alert alert-${anomaly.severity}`;
        resultElement.innerHTML = `
            <div class="anomaly-alert-header">
                <span class="anomaly-timestamp">${anomaly.timestamp}</span>
                <span class="badge badge-${anomaly.severity}">${anomaly.severity.toUpperCase()}</span>
            </div>
            <div class="anomaly-alert-title">${anomaly.type}</div>
            <div class="anomaly-alert-details">${anomaly.details}</div>
            <div class="anomaly-alert-meta">Source IP: ${anomaly.sourceIP}</div>
        `;
        
        // Add to container (at the top)
        if (this.resultsContainer.firstChild) {
            this.resultsContainer.insertBefore(resultElement, this.resultsContainer.firstChild);
        } else {
            this.resultsContainer.appendChild(resultElement);
        }
        
        // Limit the number of displayed anomalies
        this.anomalyCount++;
        if (this.anomalyCount > this.options.maxAnomalies) {
            if (this.resultsContainer.lastChild) {
                this.resultsContainer.removeChild(this.resultsContainer.lastChild);
            }
            this.anomalyCount = this.options.maxAnomalies;
        }
        
        // Add animation class
        resultElement.classList.add('new-anomaly');
        setTimeout(() => {
            resultElement.classList.remove('new-anomaly');
        }, 2000);
        
        // Play alert sound for critical and high anomalies
        if (anomaly.severity === 'critical' || anomaly.severity === 'high') {
            this.playAlertSound(anomaly.severity);
        }
    }
    
    playAlertSound(severity) {
        // This would typically play a sound, but we'll just console log for now
        console.log(`Playing ${severity} alert sound`);
    }
}
