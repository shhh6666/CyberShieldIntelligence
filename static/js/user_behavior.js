/**
 * CyberTech - Cybersecurity Breach Detection System
 * User Behavior Analysis JavaScript file
 * Copyright Simbarashe Chimbera
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize user behavior visualization
    initUserBehaviorVisualization();
    
    // Initialize user activity timeline
    initUserActivityTimeline();
    
    // Initialize behavior pattern analysis
    initBehaviorPatternAnalysis();
    
    // Initialize risk score visualization
    initRiskScoreVisualization();
    
    // Initialize activity filters
    initActivityFilters();
});

// Initialize user behavior visualization with activity types chart
function initUserBehaviorVisualization() {
    const activityChartElement = document.getElementById('activityTypeChart');
    if (!activityChartElement) return;
    
    // Extract data from the chart element's data attributes
    let activityTypes = {};
    
    try {
        activityTypes = JSON.parse(activityChartElement.dataset.activities || '{}');
    } catch(e) {
        console.error('Error parsing activity data:', e);
        return;
    }
    
    const labels = Object.keys(activityTypes);
    const data = Object.values(activityTypes);
    
    // Set up the chart
    const style = getComputedStyle(document.documentElement);
    
    const chartColors = [
        style.getPropertyValue('--primary-accent').trim(),
        style.getPropertyValue('--info-color').trim(),
        style.getPropertyValue('--success-color').trim(),
        style.getPropertyValue('--warning-color').trim(),
        style.getPropertyValue('--danger-color').trim(),
        'rgba(137, 87, 229, 0.7)',
        'rgba(63, 185, 80, 0.7)',
        'rgba(240, 136, 62, 0.7)'
    ];
    
    const chart = new Chart(activityChartElement, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: chartColors.slice(0, labels.length),
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: style.getPropertyValue('--text-primary').trim(),
                        padding: 15,
                        font: {
                            size: 12
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
    
    // Store chart instance for potential updates
    window.behaviorCharts = window.behaviorCharts || {};
    window.behaviorCharts.activityType = chart;
}

// Initialize user activity timeline with time-of-day heatmap
function initUserActivityTimeline() {
    const timelineChartElement = document.getElementById('activityTimelineChart');
    if (!timelineChartElement) return;
    
    // Get activity by hour data from data attribute
    let hourlyData = [];
    
    try {
        const activityByHour = JSON.parse(timelineChartElement.dataset.hourlyActivity || '{}');
        // Convert to array for Chart.js
        for (let i = 0; i < 24; i++) {
            hourlyData.push(activityByHour[i] || 0);
        }
    } catch(e) {
        console.error('Error parsing hourly activity data:', e);
        // Fallback to empty data
        hourlyData = Array(24).fill(0);
    }
    
    // Generate labels for each hour
    const hourLabels = Array.from({ length: 24 }, (_, i) => {
        const hour = i % 12 || 12;
        const ampm = i < 12 ? 'AM' : 'PM';
        return `${hour}${ampm}`;
    });
    
    const style = getComputedStyle(document.documentElement);
    
    // Create gradient color for the bars
    const ctx = timelineChartElement.getContext('2d');
    const gradient = ctx.createLinearGradient(0, 0, 0, 400);
    gradient.addColorStop(0, style.getPropertyValue('--primary-accent').trim());
    gradient.addColorStop(1, 'rgba(88, 166, 255, 0.2)');
    
    const chart = new Chart(timelineChartElement, {
        type: 'bar',
        data: {
            labels: hourLabels,
            datasets: [{
                label: 'Activity Count',
                data: hourlyData,
                backgroundColor: gradient,
                borderWidth: 0,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        title: function(tooltipItems) {
                            return `${tooltipItems[0].label}`;
                        },
                        label: function(context) {
                            const value = context.raw;
                            return `Activities: ${value}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: style.getPropertyValue('--text-secondary').trim(),
                        maxRotation: 0,
                        autoSkip: false,
                        callback: function(value, index) {
                            // Only show every 3 hours for readability
                            return index % 3 === 0 ? hourLabels[index] : '';
                        }
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(48, 54, 61, 0.5)'
                    },
                    ticks: {
                        color: style.getPropertyValue('--text-secondary').trim()
                    }
                }
            }
        }
    });
    
    // Store chart instance for potential updates
    window.behaviorCharts = window.behaviorCharts || {};
    window.behaviorCharts.activityTimeline = chart;
}

// Initialize behavior pattern analysis with unusual patterns display
function initBehaviorPatternAnalysis() {
    const patternContainer = document.getElementById('behavior-patterns');
    if (!patternContainer) return;
    
    // Get unusual patterns data from container data attributes
    let unusualPatterns = [];
    
    try {
        unusualPatterns = JSON.parse(patternContainer.dataset.patterns || '[]');
    } catch(e) {
        console.error('Error parsing unusual patterns data:', e);
        return;
    }
    
    // Generate pattern elements
    if (unusualPatterns.length === 0) {
        patternContainer.innerHTML = `
            <div class="alert alert-info">
                No unusual behavior patterns detected in the current timeframe.
            </div>
        `;
        return;
    }
    
    // Clear container
    patternContainer.innerHTML = '';
    
    // Add each pattern
    unusualPatterns.forEach(pattern => {
        // Determine pattern class based on severity
        let patternClass = 'behavior-pattern-normal';
        let iconClass = 'fas fa-check-circle text-success';
        
        if (pattern.severity === 'high') {
            patternClass = 'behavior-pattern-anomalous';
            iconClass = 'fas fa-exclamation-triangle text-danger';
        } else if (pattern.severity === 'medium') {
            patternClass = 'behavior-pattern-suspicious';
            iconClass = 'fas fa-exclamation-circle text-warning';
        }
        
        const patternElement = document.createElement('div');
        patternElement.className = `behavior-pattern ${patternClass} mb-3`;
        patternElement.innerHTML = `
            <div class="behavior-icon">
                <i class="${iconClass}"></i>
            </div>
            <div class="behavior-content">
                <div class="behavior-title">${pattern.type}</div>
                <div class="behavior-desc">${pattern.description}</div>
            </div>
            <div class="behavior-actions">
                <button class="btn btn-sm btn-outline-primary investigate-pattern" data-pattern-id="${pattern.type}">
                    Investigate
                </button>
            </div>
        `;
        
        patternContainer.appendChild(patternElement);
    });
    
    // Add event listeners to investigate buttons
    const investigateButtons = patternContainer.querySelectorAll('.investigate-pattern');
    investigateButtons.forEach(button => {
        button.addEventListener('click', function() {
            const patternId = this.getAttribute('data-pattern-id');
            investigatePattern(patternId);
        });
    });
}

// Function to handle pattern investigation
function investigatePattern(patternId) {
    // In a real implementation, this would show detailed analysis
    // For now, we'll just show an alert
    alert(`Investigating pattern: ${patternId}\n\nThis would typically open a detailed analysis panel.`);
}

// Initialize risk score visualization with gauge chart
function initRiskScoreVisualization() {
    const riskScoreElement = document.getElementById('riskScoreGauge');
    if (!riskScoreElement) return;
    
    // Get risk score from data attribute
    const riskScore = parseInt(riskScoreElement.dataset.score || '0');
    
    const style = getComputedStyle(document.documentElement);
    
    // Determine color based on risk score
    let scoreColor;
    if (riskScore >= 70) {
        scoreColor = style.getPropertyValue('--danger-color').trim();
    } else if (riskScore >= 40) {
        scoreColor = style.getPropertyValue('--warning-color').trim();
    } else {
        scoreColor = style.getPropertyValue('--success-color').trim();
    }
    
    const chart = new Chart(riskScoreElement, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [riskScore, 100 - riskScore],
                backgroundColor: [
                    scoreColor,
                    'rgba(48, 54, 61, 0.2)'
                ],
                borderWidth: 0,
                cutout: '80%'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            circumference: 180,
            rotation: 270,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    enabled: false
                }
            }
        }
    });
    
    // Add center text with risk score
    const scoreValueElement = document.getElementById('risk-score-value');
    if (scoreValueElement) {
        scoreValueElement.textContent = riskScore;
        scoreValueElement.style.color = scoreColor;
    }
    
    // Add risk level text
    const riskLevelElement = document.getElementById('risk-level');
    if (riskLevelElement) {
        let riskLevel;
        if (riskScore >= 70) {
            riskLevel = 'High Risk';
            riskLevelElement.style.color = scoreColor;
        } else if (riskScore >= 40) {
            riskLevel = 'Medium Risk';
            riskLevelElement.style.color = scoreColor;
        } else {
            riskLevel = 'Low Risk';
            riskLevelElement.style.color = scoreColor;
        }
        riskLevelElement.textContent = riskLevel;
    }
    
    // Store chart instance for potential updates
    window.behaviorCharts = window.behaviorCharts || {};
    window.behaviorCharts.riskScore = chart;
}

// Initialize activity filters
function initActivityFilters() {
    const filterForm = document.getElementById('activity-filter-form');
    if (!filterForm) return;
    
    // Date range filter
    const dateRangeSelect = document.getElementById('date-range');
    if (dateRangeSelect) {
        dateRangeSelect.addEventListener('change', updateActivityFilters);
    }
    
    // Activity type filter
    const activityTypeSelect = document.getElementById('activity-type');
    if (activityTypeSelect) {
        activityTypeSelect.addEventListener('change', updateActivityFilters);
    }
    
    // Search filter
    const searchInput = document.getElementById('activity-search');
    if (searchInput) {
        searchInput.addEventListener('keyup', updateActivityFilters);
    }
    
    // Initial update
    updateActivityFilters();
}

// Update activity list based on filters
function updateActivityFilters() {
    const dateRangeSelect = document.getElementById('date-range');
    const activityTypeSelect = document.getElementById('activity-type');
    const searchInput = document.getElementById('activity-search');
    
    if (!dateRangeSelect && !activityTypeSelect && !searchInput) return;
    
    const dateRange = dateRangeSelect ? dateRangeSelect.value : 'all';
    const activityType = activityTypeSelect ? activityTypeSelect.value : 'all';
    const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
    
    // Calculate date threshold based on selected range
    let dateThreshold = null;
    if (dateRange !== 'all') {
        dateThreshold = new Date();
        const days = parseInt(dateRange);
        dateThreshold.setDate(dateThreshold.getDate() - days);
    }
    
    // Filter activities
    const activityItems = document.querySelectorAll('.activity-item');
    let visibleCount = 0;
    
    activityItems.forEach(item => {
        // Check date filter
        let dateMatch = true;
        if (dateThreshold) {
            const activityDate = new Date(item.getAttribute('data-timestamp'));
            dateMatch = activityDate >= dateThreshold;
        }
        
        // Check activity type filter
        const typeMatch = activityType === 'all' || 
                         item.getAttribute('data-activity-type') === activityType;
        
        // Check search term
        const itemText = item.textContent.toLowerCase();
        const searchMatch = searchTerm === '' || itemText.includes(searchTerm);
        
        // Apply visibility
        if (dateMatch && typeMatch && searchMatch) {
            item.style.display = '';
            visibleCount++;
        } else {
            item.style.display = 'none';
        }
    });
    
    // Update results count
    const resultsCounter = document.getElementById('activity-count');
    if (resultsCounter) {
        resultsCounter.textContent = visibleCount;
    }
    
    // Show no results message if needed
    const noResultsMessage = document.getElementById('no-activities-message');
    if (noResultsMessage) {
        noResultsMessage.style.display = visibleCount === 0 ? 'block' : 'none';
    }
}

// Generate user behavior report
function generateBehaviorReport() {
    const reportBtn = document.getElementById('generate-report-btn');
    if (!reportBtn) return;
    
    // Show loading state
    reportBtn.disabled = true;
    reportBtn.innerHTML = '<span class="loader"></span> Generating...';
    
    // Simulate report generation (would connect to backend in real implementation)
    setTimeout(() => {
        // Reset button
        reportBtn.disabled = false;
        reportBtn.innerHTML = '<i class="fas fa-file-pdf"></i> Generate PDF Report';
        
        // Show success message
        const messageContainer = document.getElementById('message-container');
        if (messageContainer) {
            messageContainer.innerHTML = `
                <div class="alert alert-success mt-3">
                    <i class="fas fa-check-circle"></i> User behavior report generated successfully. 
                    <a href="#" class="alert-link">Download Report</a>
                </div>
            `;
            
            // Auto-dismiss after 5 seconds
            setTimeout(() => {
                messageContainer.innerHTML = '';
            }, 5000);
        }
    }, 2000);
}

// Update behavior analysis for a different time period
function updateBehaviorAnalysis(period) {
    // This would typically fetch new data from the server
    // For now, we'll just update the UI to show it's working
    
    const periodButtons = document.querySelectorAll('.period-btn');
    periodButtons.forEach(btn => {
        btn.classList.remove('active');
        if (btn.getAttribute('data-period') === period) {
            btn.classList.add('active');
        }
    });
    
    // Show loading state
    const chartsContainer = document.getElementById('behavior-charts');
    if (chartsContainer) {
        chartsContainer.innerHTML = `
            <div class="text-center p-5">
                <div class="loader mx-auto"></div>
                <p class="mt-3">Loading behavior analysis for ${period}...</p>
            </div>
        `;
    }
    
    // In a real implementation, this would fetch data and update charts
    // For now, we'll just simulate loading
    setTimeout(() => {
        location.reload();
    }, 1500);
}
