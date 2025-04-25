import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.model_selection import train_test_split
from scipy import stats
import logging
import json
import os
import re
import warnings
import ipaddress
from datetime import datetime, timedelta

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)

# Define known attack patterns for signature-based detection
ATTACK_SIGNATURES = {
    'sql_injection': [
        r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*\b(FROM|TABLE|DATABASE)\b)',
        r'(\'|\").*(\-\-|\#|\*\/)',
        r'(UNION\s+(ALL\s+)?SELECT)',
    ],
    'xss': [
        r'(<script>|<\/script>|<img.*onerror=)',
        r'(javascript:.*\()',
        r'(onload=|onclick=|onmouseover=)',
    ],
    'command_injection': [
        r'(;|\||\|\||\&|\&\&)\s*(cat|ls|dir|rm|pwd)',
        r'(`.*`|\$\(.*\))',
        r'(\bnc\s+\-e|\bnetcat\s+.*\-e)',
    ],
    'path_traversal': [
        r'(\.\./|\.\.\\\|\%2e\%2e\%2f|\%252e\%252e\%252f)',
        r'(/etc/passwd|/etc/shadow|boot\.ini|win\.ini)',
    ],
    'ddos': [
        r'((GET|POST|HEAD)\s+.*HTTP\/1\.[01]\s+){50,}',
    ],
}

# Threat intelligence IP lists - would normally be updated from external sources
KNOWN_MALICIOUS_IPS = [
    '185.222.209.0/24',  # Example range
    '103.102.15.0/24',   # Example range
    '91.243.61.0/24',    # Example range
]

def is_ip_in_threatlist(ip):
    """Check if an IP is in known threat intelligence lists."""
    if not ip:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in KNOWN_MALICIOUS_IPS:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
        return False
    except ValueError:
        return False

def detect_anomalies(file_path, sensitivity='medium'):
    """
    Detect anomalies in a dataset using multiple AI algorithms.
    
    Args:
        file_path (str): Path to the dataset file
        sensitivity (str): Detection sensitivity ('low', 'medium', 'high')
        
    Returns:
        list: List of detected anomalies with metadata
    """
    try:
        # Get file extension
        ext = os.path.splitext(file_path)[1].lower()
        
        # Load data based on file type
        if ext == '.csv':
            data = pd.read_csv(file_path)
        elif ext == '.json':
            data = pd.read_json(file_path)
        elif ext == '.log':
            data = parse_log_file(file_path)
        elif ext == '.pcap':
            data = parse_pcap_file(file_path)
        else:
            # Default to CSV parser for other files
            data = pd.read_csv(file_path)
        
        # Basic data cleaning
        data = data.replace([np.inf, -np.inf], np.nan)
        
        # Fill NaN values with appropriate methods based on data type
        for col in data.columns:
            if data[col].dtype.kind in 'ifc':  # integer, float, complex
                data[col] = data[col].fillna(data[col].median())
            else:
                data[col] = data[col].fillna('')
        
        # Select only numeric columns for anomaly detection
        numeric_cols = data.select_dtypes(include=[np.number]).columns.tolist()
        if not numeric_cols:
            # If no numeric columns, try to extract numeric data from string columns
            data = extract_numeric_from_strings(data)
            numeric_cols = data.select_dtypes(include=[np.number]).columns.tolist()
            
            if not numeric_cols:
                # If still no numeric data, return empty results
                logger.warning("No numeric data found in dataset")
                return []
        
        # Set contamination based on sensitivity
        contamination = 0.05  # medium (default)
        if sensitivity == 'low':
            contamination = 0.01
        elif sensitivity == 'high':
            contamination = 0.1
        
        # Scale the numeric features for better model performance
        scaler = StandardScaler()
        scaled_data = scaler.fit_transform(data[numeric_cols])
        
        # Apply multiple anomaly detection methods for more robust results
        results = []
        
        # 1. Isolation Forest - good for general anomaly detection
        isolation_forest = IsolationForest(
            contamination=contamination, 
            random_state=42,
            n_estimators=200,
            max_samples='auto'
        )
        data['isolation_forest'] = isolation_forest.fit_predict(scaled_data)
        
        # 2. DBSCAN - density-based clustering for finding outliers
        dbscan = DBSCAN(
            eps=0.5,  # The maximum distance between two samples
            min_samples=5,  # Minimum number of samples in a neighborhood
            n_jobs=-1
        )
        data['dbscan'] = dbscan.fit_predict(scaled_data)
        
        # 3. Statistical approach - Z-score method
        z_scores = np.abs(stats.zscore(scaled_data, nan_policy='omit'))
        # Mark as anomaly if z-score > 3 (configurable threshold)
        z_score_threshold = 3
        data['zscore_outlier'] = (np.max(z_scores, axis=1) > z_score_threshold).astype(int) * -1
        
        # 4. PCA-based reconstruction error
        if len(numeric_cols) > 1:  # PCA needs at least 2 dimensions
            pca = PCA(n_components=min(3, len(numeric_cols)))
            pca_result = pca.fit_transform(scaled_data)
            reconstructed = pca.inverse_transform(pca_result)
            mse = np.mean(np.power(scaled_data - reconstructed, 2), axis=1)
            # Use percentile as threshold based on sensitivity
            threshold_percentile = {
                'low': 99,
                'medium': 95,
                'high': 90
            }.get(sensitivity, 95)
            threshold = np.percentile(mse, threshold_percentile)
            data['pca_outlier'] = (mse > threshold).astype(int) * -1
        else:
            data['pca_outlier'] = 0

        # 5. Signature-based attack pattern detection for string columns
        string_cols = data.select_dtypes(include=['object']).columns.tolist()
        attack_patterns_found = []
        
        for col in string_cols:
            for attack_type, patterns in ATTACK_SIGNATURES.items():
                for pattern in patterns:
                    try:
                        matched = data[col].str.contains(pattern, regex=True, na=False)
                        if matched.any():
                            for idx in data[matched].index:
                                attack_patterns_found.append({
                                    'index': idx,
                                    'attack_type': attack_type,
                                    'pattern': pattern,
                                    'value': data.loc[idx, col]
                                })
                    except:
                        # Skip errors in regex matching
                        pass
        
        # Combine detection methods: create a consensus score
        # Mark as anomaly if detected by at least 2 methods or by signature-based detection
        data['anomaly_count'] = (
            (data['isolation_forest'] == -1).astype(int) +
            (data['dbscan'] == -1).astype(int) +
            (data['zscore_outlier'] == -1).astype(int) +
            (data.get('pca_outlier', 0) == -1).astype(int)
        )
        
        # Final anomaly decision
        detection_threshold = 1 if sensitivity == 'high' else 2
        data['anomaly'] = (data['anomaly_count'] >= detection_threshold).astype(int) * -1
        
        # Add signature-based detections
        for attack in attack_patterns_found:
            data.loc[attack['index'], 'anomaly'] = -1
            
        # Extract anomalies (where anomaly == -1)
        anomalies = data[data['anomaly'] == -1].copy()
        
        # Add signature attack info to anomalies
        for attack in attack_patterns_found:
            if attack['index'] in anomalies.index:
                anomalies.loc[attack['index'], 'attack_type'] = attack['attack_type']
                anomalies.loc[attack['index'], 'pattern_matched'] = str(attack['pattern'])
        
        # Generate results
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        for idx, row in anomalies.iterrows():
            # Try to find IP addresses in the row
            source_ip = ''
            dest_ip = ''
            row_str = str(row)
            found_ips = re.findall(ip_pattern, row_str)
            if len(found_ips) >= 2:
                source_ip = found_ips[0]
                dest_ip = found_ips[1]
            elif len(found_ips) == 1:
                source_ip = found_ips[0]
            
            # Determine if IPs are in threat intelligence lists
            threat_ip = False
            if is_ip_in_threatlist(source_ip) or is_ip_in_threatlist(dest_ip):
                threat_ip = True
                
            # Calculate anomaly confidence score (0-1)
            methods_count = 4  # isolation_forest, dbscan, zscore, pca
            confidence = row['anomaly_count'] / methods_count
            
            # Determine severity based on multiple factors
            severity = 'medium'  # Default
            
            # First check if it's a known attack pattern (highest priority)
            if 'attack_type' in row and not pd.isna(row['attack_type']):
                attack_type = str(row['attack_type']).lower()
                if attack_type in ['sql_injection', 'command_injection']:
                    severity = 'critical'
                elif attack_type in ['xss', 'path_traversal']:
                    severity = 'high'
                else:
                    severity = 'medium'
            # Then check threat intelligence
            elif threat_ip:
                severity = 'high'
            # Then use confidence score
            else:
                if confidence > 0.75:
                    severity = 'critical'
                elif confidence > 0.5:
                    severity = 'high'
                elif confidence > 0.25:
                    severity = 'medium'
                else:
                    severity = 'low'
            
            # Create detailed anomaly description
            anomaly_methods = []
            if row.get('isolation_forest', 0) == -1:
                anomaly_methods.append("Isolation Forest")
            if row.get('dbscan', 0) == -1:
                anomaly_methods.append("Density-Based Clustering")
            if row.get('zscore_outlier', 0) == -1:
                anomaly_methods.append("Statistical Z-Score")
            if row.get('pca_outlier', 0) == -1:
                anomaly_methods.append("PCA Reconstruction Error")
            
            detection_methods = ", ".join(anomaly_methods)
            
            # Get attack pattern details if available
            attack_details = ""
            if 'attack_type' in row and not pd.isna(row['attack_type']):
                attack_type = str(row['attack_type']).upper()
                attack_details = f" - {attack_type} ATTACK DETECTED"
            
            # Find the most anomalous values
            if len(numeric_cols) > 0:
                z_scores_row = np.abs(stats.zscore(row[numeric_cols].values))
                most_anomalous = np.argsort(z_scores_row)[-3:]  # Top 3 most anomalous values
                anomalous_cols = [numeric_cols[i] for i in most_anomalous if i < len(numeric_cols)]
                unusual_values = ", ".join([f"{col}={row[col]}" for col in anomalous_cols])
            else:
                unusual_values = "No numeric values to analyze"
            
            # Create anomaly object with enhanced details
            anomaly = {
                'severity': severity,
                'description': f"Anomaly detected in record {idx}{attack_details}. Detection methods: {detection_methods}. Unusual values: {unusual_values}",
                'source_ip': source_ip,
                'destination_ip': dest_ip,
                'confidence': round(confidence * 100, 1),
                'attack_type': row.get('attack_type', ''),
                'detection_time': datetime.utcnow().isoformat(),
                'remediation': get_remediation_advice(severity, 
                                                     attack_type=row.get('attack_type', ''), 
                                                     is_known_threat_ip=threat_ip)
            }
            results.append(anomaly)
        
        # Cluster similar anomalies for more meaningful reporting
        if len(results) > 1:
            results = cluster_similar_anomalies(results)
        
        # Add real-time correlation analysis if anomalies are found
        if results:
            correlated_events = correlate_security_events(results)
            for event in correlated_events:
                results.append(event)
        
        return results
        
    except Exception as e:
        logger.error(f"Error in anomaly detection: {str(e)}")
        # Return an empty list in case of errors - we shouldn't use mock data
        return []

def parse_log_file(file_path):
    """Parse common log file formats into a dataframe with advanced pattern recognition."""
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    # Detect log format
    log_format = detect_log_format(lines[:10])
    
    # Enhanced log parsing with format-specific extractors
    parsed_data = []
    for line in lines:
        # Skip empty lines
        if not line.strip():
            continue
            
        entry = {}
        
        # Common field extraction for all formats
        # Extract timestamp with multiple patterns
        timestamp_patterns = [
            r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\]',  # Apache format
            r'(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3})',  # ISO format with milliseconds
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)',  # ISO8601
            r'(\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2})',  # Syslog format
        ]
        
        for pattern in timestamp_patterns:
            timestamp_match = re.search(pattern, line)
            if timestamp_match:
                entry['timestamp'] = timestamp_match.group(1)
                break
        
        if 'timestamp' not in entry:
            entry['timestamp'] = ''
        
        # Extract IP addresses with validation
        ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        entry['source_ip'] = ip_matches[0] if ip_matches else ''
        entry['destination_ip'] = ip_matches[1] if len(ip_matches) > 1 else ''
        
        # Validate extracted IPs
        for ip_field in ['source_ip', 'destination_ip']:
            if entry[ip_field]:
                try:
                    ipaddress.ip_address(entry[ip_field])
                except ValueError:
                    entry[ip_field] = ''  # Invalid IP address
        
        # Extract HTTP method and URL for web logs
        http_method_match = re.search(r'\"(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PATCH)\s+([^\s]+)', line)
        if http_method_match:
            entry['http_method'] = http_method_match.group(1)
            entry['url'] = http_method_match.group(2)
        
        # Extract HTTP status codes
        status_match = re.search(r'\s(\d{3})\s', line)
        entry['status'] = int(status_match.group(1)) if status_match else 0
        
        # Extract response size
        size_match = re.search(r'\s(\d+)\s', line)  # More general pattern
        entry['size'] = int(size_match.group(1)) if size_match else 0
        
        # Extract user agent if present
        ua_match = re.search(r'\"([^\"]+(?:Chrome|Firefox|Safari|Edge|MSIE|Bot)[^\"]+)\"', line)
        entry['user_agent'] = ua_match.group(1) if ua_match else ''
        
        # Add security-specific fields
        # Extract usernames/emails
        user_match = re.search(r'user[=:]\s*\"?([a-zA-Z0-9_.\-@]+)\"?', line, re.IGNORECASE)
        if user_match:
            entry['username'] = user_match.group(1)
        
        # Extract error messages
        error_match = re.search(r'error[=:]\s*\"?([^\"]+)\"?', line, re.IGNORECASE)
        if error_match:
            entry['error'] = error_match.group(1)
        
        # Look for security keywords
        security_keywords = ['denied', 'failure', 'attack', 'exploit', 'vulnerability', 
                            'malicious', 'threat', 'unauthorized', 'suspicious']
        for keyword in security_keywords:
            if re.search(r'\b' + keyword + r'\b', line, re.IGNORECASE):
                entry['security_flag'] = True
                break
        
        # Store the raw log line
        entry['raw_log'] = line.strip()
        
        parsed_data.append(entry)
    
    df = pd.DataFrame(parsed_data)
    
    # Add derived features for better anomaly detection
    if 'timestamp' in df.columns and df['timestamp'].any():
        try:
            # Find the most common timestamp format
            df['datetime'] = pd.to_datetime(df['timestamp'], infer_datetime_format=True, errors='coerce')
            if not df['datetime'].isna().all():
                df['hour'] = df['datetime'].dt.hour
                df['minute'] = df['datetime'].dt.minute
                df['day_of_week'] = df['datetime'].dt.dayofweek
        except:
            pass
    
    return df

def detect_log_format(sample_lines):
    """Detect the format of log files based on patterns in sample lines."""
    patterns = {
        'apache': r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\]',
        'nginx': r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})',
        'syslog': r'(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})',
        'iso8601': r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',
    }
    
    format_counts = {fmt: 0 for fmt in patterns}
    
    for line in sample_lines:
        for fmt, pattern in patterns.items():
            if re.search(pattern, line):
                format_counts[fmt] += 1
    
    # Return the most common format
    if not format_counts or max(format_counts.values()) == 0:
        return 'unknown'
    return max(format_counts, key=format_counts.get)

def parse_pcap_file(file_path):
    """Parse PCAP network capture files (simplified version)."""
    # In a real implementation, this would use libraries like scapy or dpkt
    # For this demonstration, we'll return a structured DataFrame with network data
    
    # Simulated network traffic data that would come from parsing a pcap file
    network_data = []
    
    # Return empty DataFrame if file doesn't exist
    if not os.path.exists(file_path):
        logger.warning(f"PCAP file not found: {file_path}")
        return pd.DataFrame()
    
    # In a real implementation, this would extract packet details
    # For demonstration, we'll create a structured DataFrame
    columns = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
               'protocol', 'packet_size', 'tcp_flags', 'icmp_type']
               
    return pd.DataFrame(columns=columns)

def extract_numeric_from_strings(data):
    """Extract numeric values from string columns for anomaly detection with enhanced patterns."""
    numeric_data = data.copy()
    
    for col in data.select_dtypes(include=['object']).columns:
        # Skip columns likely to contain text-only data
        if col.lower() in ['description', 'comments', 'message', 'text', 'content']:
            continue
            
        # Try different patterns for extracting numeric values
        # Extract any number
        numeric_data[f"{col}_numeric"] = data[col].apply(
            lambda x: float(re.search(r'[-+]?\d*\.\d+|\d+', str(x)).group()) 
            if re.search(r'[-+]?\d*\.\d+|\d+', str(x)) else np.nan
        )
        
        # Extract percentages
        if data[col].str.contains('%').any():
            numeric_data[f"{col}_percent"] = data[col].str.extract(r'(\d+(?:\.\d+)?)%').astype(float) / 100
            
        # Extract currency values
        currency_match = data[col].str.contains(r'[$€£¥]\s*\d+').any()
        if currency_match:
            numeric_data[f"{col}_currency"] = data[col].str.extract(r'[$€£¥]\s*(\d+(?:\.\d+)?)').astype(float)
            
        # Extract IP-specific features if column contains IPs
        ip_match = data[col].str.contains(r'\b(?:\d{1,3}\.){3}\d{1,3}\b').any()
        if ip_match:
            # Check if IPs are internal or external
            numeric_data[f"{col}_internal_ip"] = data[col].apply(
                lambda x: is_internal_ip(x) if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str(x)) else np.nan
            )
    
    # Drop columns that are all NaN
    for col in numeric_data.columns:
        if col not in data.columns and numeric_data[col].isna().all():
            numeric_data = numeric_data.drop(col, axis=1)
    
    return numeric_data

def is_internal_ip(ip_str):
    """Check if an IP address is internal/private."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    match = re.search(ip_pattern, str(ip_str))
    if not match:
        return 0
    
    ip = match.group(0)
    try:
        ip_obj = ipaddress.ip_address(ip)
        return 1 if ip_obj.is_private else 0
    except:
        return 0

def cluster_similar_anomalies(anomalies, similarity_threshold=0.7):
    """Group similar anomalies to reduce alert fatigue."""
    if len(anomalies) <= 1:
        return anomalies
        
    # Extract features for clustering
    features = []
    for anomaly in anomalies:
        # Create a feature vector from IP and severity
        feature = [
            hash(anomaly.get('source_ip', '')),
            hash(anomaly.get('destination_ip', '')),
            {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}.get(anomaly.get('severity', 'low'), 0)
        ]
        if 'attack_type' in anomaly and anomaly['attack_type']:
            feature.append(hash(anomaly['attack_type']))
        features.append(feature)
    
    # Convert features to numpy array
    if not features:
        return anomalies
        
    # Normalize feature arrays to same length
    max_len = max(len(f) for f in features)
    features = [f + [0] * (max_len - len(f)) for f in features]
    
    # Convert to numpy array
    features = np.array(features)
    
    # Use DBSCAN to cluster similar anomalies
    clustering = DBSCAN(eps=similarity_threshold, min_samples=1).fit(features)
    labels = clustering.labels_
    
    # Group anomalies by cluster
    clustered_anomalies = {}
    for i, label in enumerate(labels):
        if label not in clustered_anomalies:
            clustered_anomalies[label] = []
        clustered_anomalies[label].append(anomalies[i])
    
    # Merge anomalies in the same cluster
    result = []
    for label, group in clustered_anomalies.items():
        if len(group) == 1:
            result.append(group[0])
        else:
            # Merge similar anomalies into one with count
            merged = group[0].copy()
            
            # Use the highest severity in the group
            severity_ranks = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
            highest_severity = max(group, key=lambda x: severity_ranks.get(x.get('severity', 'low'), 0))['severity']
            merged['severity'] = highest_severity
            
            # Update description to show it's a group
            merged['description'] = f"Group of {len(group)} similar anomalies: {merged['description']}"
            merged['related_count'] = len(group)
            
            # Update remediation advice based on highest severity
            merged['remediation'] = get_remediation_advice(
                highest_severity, 
                group[0].get('attack_type', ''), 
                is_known_threat_ip='source_ip' in group[0] and is_ip_in_threatlist(group[0]['source_ip'])
            )
            
            result.append(merged)
    
    return result

def correlate_security_events(anomalies):
    """Perform real-time correlation analysis on detected anomalies to find complex attack patterns."""
    if not anomalies or len(anomalies) < 2:
        return []
        
    correlated_events = []
    
    # Group anomalies by source IP
    source_ip_groups = {}
    for anomaly in anomalies:
        source_ip = anomaly.get('source_ip', '')
        if source_ip:
            if source_ip not in source_ip_groups:
                source_ip_groups[source_ip] = []
            source_ip_groups[source_ip].append(anomaly)
    
    # Look for multi-stage attack patterns
    for source_ip, ip_anomalies in source_ip_groups.items():
        if len(ip_anomalies) < 2:
            continue
            
        # Check for reconnaissance followed by exploitation
        has_recon = any('scan' in str(a.get('description', '')).lower() for a in ip_anomalies)
        has_exploit = any(a.get('attack_type', '') in ['sql_injection', 'xss', 'command_injection'] for a in ip_anomalies)
        
        if has_recon and has_exploit:
            correlated_events.append({
                'severity': 'critical',
                'description': f"Correlated Attack: Reconnaissance followed by exploitation attempt from {source_ip}",
                'source_ip': source_ip,
                'destination_ip': ip_anomalies[0].get('destination_ip', ''),
                'attack_type': 'multi_stage_attack',
                'confidence': 95.0,
                'detection_time': datetime.utcnow().isoformat(),
                'remediation': "IMMEDIATE ACTION REQUIRED: This is a sophisticated attack pattern. Block source IP immediately, investigate all affected systems for compromise, and escalate to security team."
            })
    
    # Look for distributed attacks against a single target
    dest_ip_groups = {}
    for anomaly in anomalies:
        dest_ip = anomaly.get('destination_ip', '')
        if dest_ip:
            if dest_ip not in dest_ip_groups:
                dest_ip_groups[dest_ip] = []
            dest_ip_groups[dest_ip].append(anomaly)
    
    for dest_ip, ip_anomalies in dest_ip_groups.items():
        if len(ip_anomalies) < 3:  # At least 3 different sources
            continue
            
        # Check for similar attack types from different sources
        attack_types = [a.get('attack_type', '') for a in ip_anomalies]
        if len(set(attack_types)) <= 2 and len(attack_types) >= 3:  # Similar attack types
            source_ips = set(a.get('source_ip', '') for a in ip_anomalies)
            if len(source_ips) >= 3:  # At least 3 different sources
                correlated_events.append({
                    'severity': 'critical',
                    'description': f"Distributed Attack: Multiple sources targeting {dest_ip} with similar techniques",
                    'source_ip': ', '.join(list(source_ips)[:5]) + (f' and {len(source_ips)-5} more' if len(source_ips) > 5 else ''),
                    'destination_ip': dest_ip,
                    'attack_type': 'distributed_attack',
                    'confidence': 90.0,
                    'detection_time': datetime.utcnow().isoformat(),
                    'remediation': "IMMEDIATE ACTION REQUIRED: This is a coordinated distributed attack. Implement IP filtering, rate limiting, and DDoS protection measures. Analyze target system for compromise."
                })
    
    return correlated_events

def get_remediation_advice(severity, attack_type='', is_known_threat_ip=False):
    """Get detailed remediation advice based on severity and attack context."""
    # Base remediation by severity
    base_remediation = {
        'critical': "IMMEDIATE ACTION REQUIRED: Isolate affected systems, block suspicious IPs, and investigate for signs of breach. Escalate to security team.",
        'high': "URGENT: Prompt investigation needed. Review logs for suspicious activity patterns and consider temporary access restrictions.",
        'medium': "IMPORTANT: Investigate during business hours. Update security rules and monitor for recurring patterns.",
        'low': "ADVISORY: Monitor for similar patterns. Update security policies and document findings."
    }.get(severity, "Investigate and document this security event.")
    
    # Add specific advice based on attack type
    specific_advice = ""
    if attack_type:
        attack_specific = {
            'sql_injection': "Implement parameterized queries, input validation, and consider a web application firewall (WAF).",
            'xss': "Implement content security policy (CSP), output encoding, and input validation.",
            'command_injection': "Sanitize user inputs, implement allowlists for commands, and use dedicated APIs instead of shell commands.",
            'path_traversal': "Validate and sanitize file paths, use safe API alternatives, and implement proper access controls.",
            'ddos': "Implement rate limiting, use CDN services, and consider DDoS protection solutions.",
            'multi_stage_attack': "Conduct a forensic investigation to identify all compromised systems and data. Review network segmentation.",
            'distributed_attack': "Implement IP reputation filtering, geographic blocking if appropriate, and enhance monitoring."
        }.get(attack_type.lower(), "")
        
        if specific_advice:
            specific_advice = f" {specific_advice}"
    
    # Add advice for known malicious IPs
    threat_intel_advice = ""
    if is_known_threat_ip:
        threat_intel_advice = " This IP address is in threat intelligence lists. Block at the network perimeter and investigate why communication was allowed."
    
    return f"{base_remediation}{specific_advice}{threat_intel_advice}"
