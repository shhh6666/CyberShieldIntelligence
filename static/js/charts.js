/**
 * CyberTech - Cybersecurity Breach Detection System
 * Charts JavaScript file
 * Copyright Simbarashe Chimbera
 */

// DOM Content Loaded Event
document.addEventListener('DOMContentLoaded', function() {
    // Initialize all charts
    initCharts();
});

// Initialize chart configurations
function initCharts() {
    // Set default chart colors based on CSS variables
    const style = getComputedStyle(document.documentElement);
    const chartColors = {
        primary: style.getPropertyValue('--primary-accent').trim(),
        success: style.getPropertyValue('--success-color').trim(),
        danger: style.getPropertyValue('--danger-color').trim(),
        warning: style.getPropertyValue('--warning-color').trim(),
        info: style.getPropertyValue('--info-color').trim(),
        critical: style.getPropertyValue('--critical').trim(),
        high: style.getPropertyValue('--high').trim(),
        medium: style.getPropertyValue('--medium').trim(),
        low: style.getPropertyValue('--low').trim(),
        textColor: style.getPropertyValue('--text-primary').trim(),
        gridColor: style.getPropertyValue('--border-color').trim()
    };
    
    // Set default chart options
    Chart.defaults.color = chartColors.textColor;
    Chart.defaults.borderColor = chartColors.gridColor;
    Chart.defaults.elements.line.borderWidth = 2;
    Chart.defaults.elements.line.tension = 0.4;
    Chart.defaults.plugins.legend.position = 'top';
    Chart.defaults.plugins.legend.labels.boxWidth = 15;
    Chart.defaults.plugins.legend.labels.padding = 15;
    Chart.defaults.plugins.legend.labels.color = chartColors.textColor;
    Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(21, 25, 32, 0.9)';
    Chart.defaults.plugins.tooltip.padding = 10;
    Chart.defaults.plugins.tooltip.titleColor = chartColors.textColor;
    Chart.defaults.plugins.tooltip.bodyColor = chartColors.textColor;
    Chart.defaults.plugins.tooltip.borderColor = chartColors.gridColor;
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.font.family = "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";
    
    // Initialize specific charts
    initSecurityOverviewChart();
    initAnomalyDistributionChart();
    initVulnerabilityTrendsChart();
    initUserActivityChart();
    initSecurityScoreChart();
    initThreatSourcesChart();
    initIncidentResponseTimeChart();
    initAnomalySeverityChart();
    initVulnerabilityStatusChart();
}

// Security Overview Chart
function initSecurityOverviewChart() {
    const chartElement = document.getElementById('securityOverviewChart');
    if (!chartElement) return;
    
    // Get chart data from data attributes if available
    const chartData = chartElement.dataset.chartData ? JSON.parse(chartElement.dataset.chartData) : null;
    
    // Use provided data or fallback to demo data
    const labels = chartData?.labels || ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'];
    const anomalies = chartData?.anomalies || [65, 59, 80, 81, 56, 55, 40];
    const vulnerabilities = chartData?.vulnerabilities || [28, 48, 40, 19, 86, 27, 90];
    const incidents = chartData?.incidents || [10, 30, 15, 12, 20, 18, 14];
    
    const style = getComputedStyle(document.documentElement);
    
    const chart = new Chart(chartElement, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Anomalies',
                    data: anomalies,
                    borderColor: style.getPropertyValue('--danger-color').trim(),
                    backgroundColor: 'rgba(248, 81, 73, 0.1)',
                    fill: true
                },
                {
                    label: 'Vulnerabilities',
                    data: vulnerabilities,
                    borderColor: style.getPropertyValue('--warning-color').trim(),
                    backgroundColor: 'rgba(240, 136, 62, 0.1)',
                    fill: true
                },
                {
                    label: 'Incidents',
                    data: incidents,
                    borderColor: style.getPropertyValue('--info-color').trim(),
                    backgroundColor: 'rgba(137, 87, 229, 0.1)',
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: {
                    mode: 'index',
                    intersect: false
                },
                title: {
                    display: false
                }
            },
            scales: {
                x: {
                    grid: {
                        drawOnChartArea: false
                    }
                },
                y: {
                    grid: {
                        drawBorder: false,
                        color: function(context) {
                            return context.tick.value === 0 ? 
                                  style.getPropertyValue('--border-color').trim() : 
                                  'rgba(48, 54, 61, 0.5)';
                        }
                    },
                    ticks: {
                        beginAtZero: true,
                        stepSize: 20
                    }
                }
            },
            interaction: {
                intersect: false,
                mode: 'index'
            }
        }
    });
    
    // Store chart instance for potential updates
    window.dashboardCharts = window.dashboardCharts || {};
    window.dashboardCharts.securityOverview = chart;
}

// Anomaly Distribution Chart
function initAnomalyDistributionChart() {
    const chartElement = document.getElementById('anomalyDistributionChart');
    if (!chartElement) return;
    
    // Get chart data from data attributes if available
    const chartData = chartElement.dataset.chartData ? JSON.parse(chartElement.dataset.chartData) : null;
    
    // Use provided data or fallback to demo data
    const critical = chartData?.critical || 12;
    const high = chartData?.high || 23;
    const medium = chartData?.medium || 45;
    const low = chartData?.low || 20;
    
    const style = getComputedStyle(document.documentElement);
    
    const chart = new Chart(chartElement, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [
                {
                    data: [critical, high, medium, low],
                    backgroundColor: [
                        style.getPropertyValue('--critical').trim(),
                        style.getPropertyValue('--high').trim(),
                        style.getPropertyValue('--medium').trim(),
                        style.getPropertyValue('--low').trim()
                    ],
                    borderWidth: 0,
                    hoverOffset: 4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        padding: 15
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
    window.dashboardCharts = window.dashboardCharts || {};
    window.dashboardCharts.anomalyDistribution = chart;
}

// Vulnerability Trends Chart
function initVulnerabilityTrendsChart() {
    const chartElement = document.getElementById('vulnerabilityTrendsChart');
    if (!chartElement) return;
    
    // Get chart data from data attributes if available
    const chartData = chartElement.dataset.chartData ? JSON.parse(chartElement.dataset.chartData) : null;
    
    // Use provided data or fallback to demo data
    const labels = chartData?.labels || ['Week 1', 'Week 2', 'Week 3', 'Week 4', 'Week 5', 'Week 6'];
    const discovered = chartData?.discovered || [15, 30, 25, 40, 35, 50];
    const remediated = chartData?.remediated || [10, 15, 20, 25, 30, 35];
    
    const style = getComputedStyle(document.documentElement);
    
    const chart = new Chart(chartElement, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Discovered',
                    data: discovered,
                    backgroundColor: style.getPropertyValue('--warning-color').trim(),
                    borderWidth: 0,
                    borderRadius: 4
                },
                {
                    label: 'Remediated',
                    data: remediated,
                    backgroundColor: style.getPropertyValue('--success-color').trim(),
                    borderWidth: 0,
                    borderRadius: 4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top'
                },
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(48, 54, 61, 0.5)'
                    },
                    ticks: {
                        beginAtZero: true,
                        stepSize: 10
                    }
                }
            }
        }
    });
    
    // Store chart instance for potential updates
    window.dashboardCharts = window.dashboardCharts || {};
    window.dashboardCharts.vulnerabilityTrends = chart;
}

// User Activity Chart
function initUserActivityChart() {
    const chartElement = document.getElementById('userActivityChart');
    if (!chartElement) return;
    
    // Get chart data from data attributes if available
    const chartData = chartElement.dataset.chartData ? JSON.parse(chartElement.dataset.chartData) : null;
    
    // Use provided data or fallback to demo data
    const activityLabels = chartData?.labels || ['Login', 'File Upload', 'Analysis', 'Dataset Access', 'Vulnerability Scan', 'Other'];
    const activityData = chartData?.data || [65, 28, 45, 35, 20, 15];
    
    const style = getComputedStyle(document.documentElement);
    
    const chart = new Chart(chartElement, {
        type: 'polarArea',
        data: {
            labels: activityLabels,
            datasets: [
                {
                    data: activityData,
                    backgroundColor: [
                        style.getPropertyValue('--primary-accent').trim(),
                        style.getPropertyValue('--info-color').trim(),
                        style.getPropertyValue('--warning-color').trim(),
                        style.getPropertyValue('--success-color').trim(),
                        style.getPropertyValue('--danger-color').trim(),
                        style.getPropertyValue('--tertiary-dark').trim()
                    ],
                    borderWidth: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        padding: 15
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.label}: ${context.raw}`;
                        }
                    }
                }
            },
            scales: {
                r: {
                    ticks: {
                        display: false
                    },
                    grid: {
                        color: 'rgba(48, 54, 61, 0.5)'
                    },
                    angleLines: {
                        color: 'rgba(48, 54, 61, 0.5)'
                    }
                }
            }
        }
    });
    
    // Store chart instance for potential updates
    window.dashboardCharts = window.dashboardCharts || {};
    window.dashboardCharts.userActivity = chart;
}

// Security Score Chart
function initSecurityScoreChart() {
    const chartElement = document.getElementById('securityScoreChart');
    if (!chartElement) return;
    
    // Get score from data attribute if available
    const score = parseInt(chartElement.dataset.score) || 78;
    
    const style = getComputedStyle(document.documentElement);
    
    // Determine color based on score
    let scoreColor;
    if (score >= 80) {
        scoreColor = style.getPropertyValue('--success-color').trim();
    } else if (score >= 60) {
        scoreColor = style.getPropertyValue('--warning-color').trim();
    } else {
        scoreColor = style.getPropertyValue('--danger-color').trim();
    }
    
    const chart = new Chart(chartElement, {
        type: 'doughnut',
        data: {
            datasets: [
                {
                    data: [score, 100 - score],
                    backgroundColor: [
                        scoreColor,
                        'rgba(48, 54, 61, 0.5)'
                    ],
                    borderWidth: 0,
                    cutout: '80%'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
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
    
    // Add center text
    const chartContainer = chartElement.parentElement;
    const scoreValue = chartContainer.querySelector('.score-value');
    if (scoreValue) {
        scoreValue.textContent = score;
        scoreValue.style.color = scoreColor;
    }
    
    // Store chart instance for potential updates
    window.dashboardCharts = window.dashboardCharts || {};
    window.dashboardCharts.securityScore = chart;
}

// Threat Sources Chart
function initThreatSourcesChart() {
    const chartElement = document.getElementById('threatSourcesChart');
    if (!chartElement) return;
    
    // Get chart data from data attributes if available
    const chartData = chartElement.dataset.chartData ? JSON.parse(chartElement.dataset.chartData) : null;
    
    // Use provided data or fallback to demo data
    const labels = chartData?.labels || ['Malware', 'Phishing', 'Insider Threats', 'Unpatched Systems', 'Weak Credentials', 'Other'];
    const data = chartData?.data || [35, 25, 15, 10, 8, 7];
    
    const style = getComputedStyle(document.documentElement);
    
    const chart = new Chart(chartElement, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [
                {
                    data: data,
                    backgroundColor: [
                        style.getPropertyValue('--danger-color').trim(),
                        style.getPropertyValue('--warning-color').trim(),
                        style.getPropertyValue('--info-color').trim(),
                        style.getPropertyValue('--primary-accent').trim(),
                        style.getPropertyValue('--success-color').trim(),
                        style.getPropertyValue('--tertiary-dark').trim()
                    ],
                    borderWidth: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        padding: 15
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${percentage}%`;
                        }
                    }
                }
            }
        }
    });
    
    // Store chart instance for potential updates
    window.dashboardCharts = window.dashboardCharts || {};
    window.dashboardCharts.threatSources = chart;
}

// Incident Response Time Chart
function initIncidentResponseTimeChart() {
    const chartElement = document.getElementById('incidentResponseTimeChart');
    if (!chartElement) return;
    
    // Get chart data from data attributes if available
    const chartData = chartElement.dataset.chartData ? JSON.parse(chartElement.dataset.chartData) : null;
    
    // Use provided data or fallback to demo data
    const labels = chartData?.labels || ['Critical', 'High', 'Medium', 'Low'];
    const data = chartData?.data || [0.5, 2, 8, 24]; // Hours to response
    
    const style = getComputedStyle(document.documentElement);
    
    const chart = new Chart(chartElement, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Average Response Time (Hours)',
                    data: data,
                    backgroundColor: [
                        style.getPropertyValue('--critical').trim(),
                        style.getPropertyValue('--high').trim(),
                        style.getPropertyValue('--medium').trim(),
                        style.getPropertyValue('--low').trim()
                    ],
                    borderWidth: 0,
                    borderRadius: 4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y', // Horizontal bar chart
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(48, 54, 61, 0.5)'
                    },
                    ticks: {
                        beginAtZero: true
                    }
                },
                y: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
    
    // Store chart instance for potential updates
    window.dashboardCharts = window.dashboardCharts || {};
    window.dashboardCharts.incidentResponseTime = chart;
}

// Anomaly Severity Chart (for a specific analysis)
function initAnomalySeverityChart() {
    const chartElement = document.getElementById('anomalySeverityChart');
    if (!chartElement) return;
    
    // Get severity counts from data attributes
    const critical = parseInt(chartElement.dataset.critical) || 0;
    const high = parseInt(chartElement.dataset.high) || 0;
    const medium = parseInt(chartElement.dataset.medium) || 0;
    const low = parseInt(chartElement.dataset.low) || 0;
    
    const style = getComputedStyle(document.documentElement);
    
    const chart = new Chart(chartElement, {
        type: 'bar',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [
                {
                    data: [critical, high, medium, low],
                    backgroundColor: [
                        style.getPropertyValue('--critical').trim(),
                        style.getPropertyValue('--high').trim(),
                        style.getPropertyValue('--medium').trim(),
                        style.getPropertyValue('--low').trim()
                    ],
                    borderWidth: 0,
                    borderRadius: 4
                }
            ]
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
                        label: function(context) {
                            return `${context.label}: ${context.raw} anomalies`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(48, 54, 61, 0.5)'
                    },
                    ticks: {
                        beginAtZero: true,
                        stepSize: 1
                    }
                }
            }
        }
    });
    
    // Store chart instance for potential updates
    window.dashboardCharts = window.dashboardCharts || {};
    window.dashboardCharts.anomalySeverity = chart;
}

// Vulnerability Status Chart
function initVulnerabilityStatusChart() {
    const chartElement = document.getElementById('vulnerabilityStatusChart');
    if (!chartElement) return;
    
    // Get vulnerability status counts from data attributes
    const open = parseInt(chartElement.dataset.open) || 0;
    const inProgress = parseInt(chartElement.dataset.inProgress) || 0;
    const resolved = parseInt(chartElement.dataset.resolved) || 0;
    const falsePositive = parseInt(chartElement.dataset.falsePositive) || 0;
    
    const style = getComputedStyle(document.documentElement);
    
    const chart = new Chart(chartElement, {
        type: 'doughnut',
        data: {
            labels: ['Open', 'In Progress', 'Resolved', 'False Positive'],
            datasets: [
                {
                    data: [open, inProgress, resolved, falsePositive],
                    backgroundColor: [
                        style.getPropertyValue('--danger-color').trim(),
                        style.getPropertyValue('--info-color').trim(),
                        style.getPropertyValue('--success-color').trim(),
                        style.getPropertyValue('--text-secondary').trim()
                    ],
                    borderWidth: 0,
                    hoverOffset: 4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '60%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        padding: 15
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
    window.dashboardCharts = window.dashboardCharts || {};
    window.dashboardCharts.vulnerabilityStatus = chart;
}

// Update charts with new data
function updateChart(chartId, newData) {
    if (!window.dashboardCharts || !window.dashboardCharts[chartId]) {
        console.error(`Chart with ID ${chartId} not found`);
        return;
    }
    
    const chart = window.dashboardCharts[chartId];
    
    // Update chart data
    chart.data.datasets.forEach((dataset, i) => {
        dataset.data = newData.datasets[i].data;
    });
    
    // Update labels if provided
    if (newData.labels) {
        chart.data.labels = newData.labels;
    }
    
    // Update the chart
    chart.update();
}
