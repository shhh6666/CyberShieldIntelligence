/**
 * CyberTech - Cybersecurity Breach Detection System
 * Main JavaScript file
 * Copyright Simbarashe Chimbera
 */

// DOM Content Loaded Event
document.addEventListener('DOMContentLoaded', function() {
    // Initialize sidebar toggle
    initSidebar();
    
    // Initialize alerts dismissal
    initAlerts();
    
    // Initialize data tables if they exist
    initDataTables();
    
    // Initialize tooltips
    initTooltips();
    
    // Initialize tabs
    initTabs();
    
    // Initialize dropdown menus
    initDropdowns();
    
    // Setup flash messages auto-dismiss
    setupFlashMessages();
    
    // Mark alert as read functionality
    setupAlertReadMarking();
    
    // Initialize form validation
    initFormValidation();
});

// Initialize sidebar functionality
function initSidebar() {
    const sidebarToggler = document.querySelector('.topbar-toggler');
    const sidebar = document.querySelector('.sidebar');
    const contentWrapper = document.querySelector('.content-wrapper');
    
    if (sidebarToggler && sidebar && contentWrapper) {
        sidebarToggler.addEventListener('click', function() {
            sidebar.classList.toggle('sidebar-collapsed');
            contentWrapper.classList.toggle('content-wrapper-expanded');
            
            // Store sidebar state in local storage
            const isCollapsed = sidebar.classList.contains('sidebar-collapsed');
            localStorage.setItem('sidebar-collapsed', isCollapsed);
        });
        
        // Check if sidebar was collapsed previously
        const wasCollapsed = localStorage.getItem('sidebar-collapsed') === 'true';
        if (wasCollapsed) {
            sidebar.classList.add('sidebar-collapsed');
            contentWrapper.classList.add('content-wrapper-expanded');
        }
        
        // For mobile: Show/hide sidebar
        const mobileToggler = document.querySelector('.mobile-toggler');
        if (mobileToggler) {
            mobileToggler.addEventListener('click', function() {
                sidebar.classList.toggle('sidebar-visible');
            });
            
            // Close sidebar when clicking outside
            document.addEventListener('click', function(e) {
                if (!sidebar.contains(e.target) && e.target !== mobileToggler) {
                    sidebar.classList.remove('sidebar-visible');
                }
            });
        }
    }
}

// Initialize alert dismissal
function initAlerts() {
    const alerts = document.querySelectorAll('.alert');
    
    alerts.forEach(alert => {
        const closeBtn = alert.querySelector('.alert-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', function() {
                alert.classList.add('fade-out');
                setTimeout(() => {
                    alert.remove();
                }, 300);
            });
        }
        
        // Auto-dismiss success and info alerts after 5 seconds
        if (alert.classList.contains('alert-success') || alert.classList.contains('alert-info')) {
            setTimeout(() => {
                alert.classList.add('fade-out');
                setTimeout(() => {
                    alert.remove();
                }, 300);
            }, 5000);
        }
    });
}

// Initialize data tables
function initDataTables() {
    const tables = document.querySelectorAll('.data-table');
    
    if (tables.length > 0) {
        tables.forEach(table => {
            const searchInput = document.querySelector(`#${table.id}-search`);
            if (searchInput) {
                searchInput.addEventListener('keyup', function() {
                    const searchTerm = this.value.toLowerCase();
                    const rows = table.querySelectorAll('tbody tr');
                    
                    rows.forEach(row => {
                        const text = row.textContent.toLowerCase();
                        row.style.display = text.includes(searchTerm) ? '' : 'none';
                    });
                });
            }
            
            // Sorting
            const sortableHeaders = table.querySelectorAll('th[data-sort]');
            sortableHeaders.forEach(header => {
                header.addEventListener('click', function() {
                    const sortCol = this.dataset.sort;
                    const sortDir = this.dataset.direction === 'asc' ? 'desc' : 'asc';
                    
                    // Update header state
                    sortableHeaders.forEach(h => {
                        h.dataset.direction = h === this ? sortDir : '';
                        h.classList.remove('sort-asc', 'sort-desc');
                    });
                    
                    this.dataset.direction = sortDir;
                    this.classList.add(sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
                    
                    // Sort table
                    const rows = Array.from(table.querySelectorAll('tbody tr'));
                    const sortedRows = rows.sort((a, b) => {
                        const aVal = a.querySelector(`td:nth-child(${parseInt(sortCol) + 1})`).textContent;
                        const bVal = b.querySelector(`td:nth-child(${parseInt(sortCol) + 1})`).textContent;
                        
                        if (sortDir === 'asc') {
                            return aVal.localeCompare(bVal);
                        } else {
                            return bVal.localeCompare(aVal);
                        }
                    });
                    
                    // Update table
                    const tbody = table.querySelector('tbody');
                    while (tbody.firstChild) {
                        tbody.removeChild(tbody.firstChild);
                    }
                    
                    sortedRows.forEach(row => {
                        tbody.appendChild(row);
                    });
                });
            });
        });
    }
}

// Initialize tooltips
function initTooltips() {
    const tooltips = document.querySelectorAll('[data-tooltip]');
    
    tooltips.forEach(tooltip => {
        tooltip.addEventListener('mouseenter', function() {
            const text = this.dataset.tooltip;
            const tooltipEl = document.createElement('div');
            tooltipEl.className = 'tooltip';
            tooltipEl.textContent = text;
            document.body.appendChild(tooltipEl);
            
            const rect = this.getBoundingClientRect();
            tooltipEl.style.top = `${rect.top - tooltipEl.offsetHeight - 5}px`;
            tooltipEl.style.left = `${rect.left + (rect.width / 2) - (tooltipEl.offsetWidth / 2)}px`;
            tooltipEl.classList.add('tooltip-visible');
            
            this.addEventListener('mouseleave', function onMouseLeave() {
                tooltipEl.remove();
                this.removeEventListener('mouseleave', onMouseLeave);
            });
        });
    });
}

// Initialize tabs
function initTabs() {
    const tabContainers = document.querySelectorAll('.tabs-container');
    
    tabContainers.forEach(container => {
        const tabs = container.querySelectorAll('.dashboard-tab');
        const contents = container.querySelectorAll('.tab-content');
        
        tabs.forEach((tab, index) => {
            tab.addEventListener('click', function() {
                // Remove active class from all tabs and contents
                tabs.forEach(t => t.classList.remove('active'));
                contents.forEach(c => c.classList.remove('active'));
                
                // Add active class to clicked tab and corresponding content
                this.classList.add('active');
                contents[index].classList.add('active');
                
                // Save active tab in local storage
                const tabId = this.dataset.tab;
                if (tabId) {
                    localStorage.setItem(`active-tab-${container.id}`, tabId);
                }
            });
        });
        
        // Restore active tab from local storage
        const activeTabId = localStorage.getItem(`active-tab-${container.id}`);
        if (activeTabId) {
            const savedTab = container.querySelector(`.dashboard-tab[data-tab="${activeTabId}"]`);
            if (savedTab) {
                savedTab.click();
            }
        } else if (tabs.length > 0) {
            // Set first tab as active by default
            tabs[0].click();
        }
    });
}

// Initialize dropdown menus
function initDropdowns() {
    const dropdowns = document.querySelectorAll('.dropdown');
    
    dropdowns.forEach(dropdown => {
        const toggle = dropdown.querySelector('.dropdown-toggle');
        const menu = dropdown.querySelector('.dropdown-menu');
        
        if (toggle && menu) {
            toggle.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                menu.classList.toggle('show');
            });
            
            // Close when clicking outside
            document.addEventListener('click', function(e) {
                if (!menu.contains(e.target) && e.target !== toggle) {
                    menu.classList.remove('show');
                }
            });
        }
    });
}

// Set up flash messages auto-dismiss
function setupFlashMessages() {
    const flashMessages = document.querySelectorAll('.flash-message');
    
    flashMessages.forEach(message => {
        setTimeout(() => {
            message.classList.add('fade-out');
            setTimeout(() => {
                message.remove();
            }, 300);
        }, 5000);
    });
}

// Set up functionality to mark alerts as read
function setupAlertReadMarking() {
    const markReadButtons = document.querySelectorAll('.mark-alert-read');
    
    markReadButtons.forEach(button => {
        button.addEventListener('click', function() {
            const alertId = this.dataset.alertId;
            const alertElement = document.querySelector(`.alert-item[data-alert-id="${alertId}"]`);
            
            // Send AJAX request to mark alert as read
            fetch(`/mark_alert_read/${alertId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    if (alertElement) {
                        alertElement.classList.add('alert-read');
                        
                        // Update unread alert counter if it exists
                        const counter = document.querySelector('.alert-counter');
                        if (counter) {
                            let count = parseInt(counter.textContent);
                            if (count > 0) {
                                count--;
                                counter.textContent = count;
                                if (count === 0) {
                                    counter.style.display = 'none';
                                }
                            }
                        }
                    }
                }
            })
            .catch(error => {
                console.error('Error marking alert as read:', error);
            });
        });
    });
}

// Initialize form validation
function initFormValidation() {
    const forms = document.querySelectorAll('form.needs-validation');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(event) {
            if (!this.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            
            this.classList.add('was-validated');
        }, false);
    });
}

// Update vulnerability status
function updateVulnerabilityStatus(vulnId, status) {
    fetch(`/update_vulnerability_status/${vulnId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify({ status: status })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Update UI
            const statusBadge = document.querySelector(`.vuln-status[data-vuln-id="${vulnId}"]`);
            if (statusBadge) {
                // Remove all status classes
                statusBadge.classList.remove('status-open', 'status-in-progress', 'status-resolved', 'status-false-positive');
                // Add new status class
                statusBadge.classList.add(`status-${status.replace('_', '-')}`);
                // Update text
                statusBadge.textContent = status.replace('_', ' ').toUpperCase();
            }
            
            // Show success message
            const messageContainer = document.getElementById('message-container');
            if (messageContainer) {
                messageContainer.innerHTML = `
                    <div class="alert alert-success">
                        Vulnerability status updated successfully.
                    </div>
                `;
                
                setTimeout(() => {
                    messageContainer.innerHTML = '';
                }, 3000);
            }
        }
    })
    .catch(error => {
        console.error('Error updating vulnerability status:', error);
    });
}

// Update incident status
function updateIncidentStatus(incidentId, status) {
    fetch(`/update_incident_status/${incidentId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify({ status: status })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Update UI
            const statusBadge = document.querySelector(`.incident-status[data-incident-id="${incidentId}"]`);
            if (statusBadge) {
                // Remove all status classes
                statusBadge.classList.remove('status-open', 'status-in-progress', 'status-resolved');
                // Add new status class
                statusBadge.classList.add(`status-${status.replace('_', '-')}`);
                // Update text
                statusBadge.textContent = status.replace('_', ' ').toUpperCase();
            }
            
            // Show success message
            const messageContainer = document.getElementById('message-container');
            if (messageContainer) {
                messageContainer.innerHTML = `
                    <div class="alert alert-success">
                        Incident status updated successfully.
                    </div>
                `;
                
                setTimeout(() => {
                    messageContainer.innerHTML = '';
                }, 3000);
            }
        }
    })
    .catch(error => {
        console.error('Error updating incident status:', error);
    });
}

// Mark anomaly as false positive
function markAnomalyAsFalsePositive(anomalyId) {
    fetch(`/mark_false_positive/${anomalyId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Update UI
            const anomalyEl = document.querySelector(`.anomaly-item[data-anomaly-id="${anomalyId}"]`);
            if (anomalyEl) {
                anomalyEl.classList.add('false-positive');
                
                const badge = anomalyEl.querySelector('.false-positive-badge');
                if (badge) {
                    badge.style.display = 'inline-block';
                }
                
                const btn = anomalyEl.querySelector('.mark-false-positive-btn');
                if (btn) {
                    btn.disabled = true;
                    btn.textContent = 'Marked as False Positive';
                }
            }
            
            // Show success message
            const messageContainer = document.getElementById('message-container');
            if (messageContainer) {
                messageContainer.innerHTML = `
                    <div class="alert alert-success">
                        Anomaly marked as false positive.
                    </div>
                `;
                
                setTimeout(() => {
                    messageContainer.innerHTML = '';
                }, 3000);
            }
        }
    })
    .catch(error => {
        console.error('Error marking anomaly as false positive:', error);
    });
}

// Delete dataset confirmation
function confirmDeleteDataset(datasetId, datasetName) {
    if (confirm(`Are you sure you want to delete the dataset "${datasetName}"? This action cannot be undone.`)) {
        document.getElementById(`delete-dataset-form-${datasetId}`).submit();
    }
}

// Create incident from anomaly
function createIncidentFromAnomaly(anomalyId) {
    document.getElementById(`create-incident-form-${anomalyId}`).submit();
}

// Format a timestamp for display
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

// Format file size for display
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
