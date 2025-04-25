import numpy as np
import pandas as pd
import ipaddress
import re
import logging
import hashlib
import time
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import math
import json
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import warnings

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)

# Known malicious IP address patterns and behaviors
KNOWN_MALICIOUS_PATTERNS = {
    'tor_exit_nodes': [
        '176.10.99.0/24',
        '185.220.100.0/24', 
        '51.15.0.0/16',
    ],
    'botnet_command_centers': [
        '5.252.178.0/24',
        '91.234.99.0/24',
        '185.117.88.0/24',
    ],
    'malware_distribution': [
        '104.24.99.0/24',
        '192.241.220.0/24',
        '198.54.120.0/24',
    ],
    'phishing': [
        '194.58.120.0/24',
        '45.147.250.0/24',
        '91.243.61.0/24',
    ],
}

# Network traffic patterns indicating potential attacks
ATTACK_PATTERNS = {
    'port_scan': {
        'unique_ports_threshold': 15,  # More than 15 unique ports in a short timeframe
        'time_window': 60,  # seconds
        'severity': 'high'
    },
    'brute_force': {
        'connection_attempts': 10,  # More than 10 attempts to the same port
        'time_window': 60,  # seconds
        'target_ports': [22, 23, 3389, 445, 1433, 3306, 5432],  # SSH, Telnet, RDP, SMB, SQL, MySQL, PostgreSQL
        'severity': 'high'
    },
    'ddos': {
        'connection_threshold': 100,  # More than 100 connections in a short timeframe
        'time_window': 60,  # seconds
        'severity': 'critical'
    },
    'data_exfiltration': {
        'large_outbound_data': 50 * 1024 * 1024,  # 50 MB threshold
        'sustained_connection': 300,  # 5 minutes sustained connection
        'unusual_destination': True,
        'severity': 'critical'
    },
    'c2_communication': {
        'beaconing': True,  # Regular interval connections
        'time_pattern_deviation': 0.2,  # 20% deviation in timing
        'small_data_bursts': True,
        'severity': 'critical'
    }
}

# Protocol-specific detection parameters
PROTOCOL_BEHAVIORS = {
    'http': {
        'suspicious_paths': ['/admin', '/login', '/wp-login.php', '/phpmyadmin', '/config'],
        'suspicious_methods': ['PUT', 'CONNECT'],
        'suspicious_user_agents': ['zgrab', 'masscan', 'python-requests', 'go-http-client', 'curl'],
    },
    'dns': {
        'suspicious_queries': ['command', 'download', 'admin', 'update', 'install'],
        'dga_entropy_threshold': 3.8,  # Entropy threshold for detecting algorithmically generated domains
        'subdomain_depth_threshold': 4,  # Suspiciously deep subdomains
    },
    'smtp': {
        'suspicious_attachments': ['.exe', '.bat', '.js', '.vbs', '.zip', '.rar'],
        'spam_indicators': ['viagra', 'forex', 'bitcoin', 'cryptocurrency', 'investment opportunity'],
    }
}

def analyze_network_traffic(traffic_data, timeframe_minutes=60, sensitivity='medium'):
    """
    Analyze network traffic to detect malicious behaviors and potential attacks.
    
    Args:
        traffic_data: DataFrame or list of network traffic records containing:
            - timestamp: datetime of the connection
            - src_ip: source IP address
            - dst_ip: destination IP address
            - src_port: source port
            - dst_port: destination port
            - protocol: protocol name (TCP, UDP, HTTP, etc.)
            - bytes_sent: number of bytes sent
            - bytes_received: number of bytes received
            - duration: connection duration in seconds
            - status: connection status (e.g., 'established', 'rejected')
        timeframe_minutes: number of minutes of data to analyze
        sensitivity: detection sensitivity ('low', 'medium', 'high')
        
    Returns:
        dict: Analysis results with detected threats and anomalies
    """
    try:
        # Convert to DataFrame if it's a list
        if isinstance(traffic_data, list):
            traffic_df = pd.DataFrame(traffic_data)
        else:
            traffic_df = traffic_data.copy()
            
        # Check if we have the required columns
        required_columns = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
        missing_columns = [col for col in required_columns if col not in traffic_df.columns]
        
        if missing_columns:
            logger.error(f"Missing required columns: {missing_columns}")
            return {
                'status': 'error', 
                'message': f"Missing required columns: {missing_columns}"
            }
            
        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_any_dtype(traffic_df['timestamp']):
            traffic_df['timestamp'] = pd.to_datetime(traffic_df['timestamp'])
        
        # Filter for the timeframe
        cutoff_time = pd.Timestamp.now() - pd.Timedelta(minutes=timeframe_minutes)
        recent_traffic = traffic_df[traffic_df['timestamp'] >= cutoff_time]
        
        if recent_traffic.empty:
            return {
                'status': 'no_data',
                'message': f"No traffic data found within the last {timeframe_minutes} minutes"
            }
        
        # Add derived features for better analysis
        recent_traffic = enrich_traffic_data(recent_traffic)
        
        # Initialize results
        results = {
            'status': 'success',
            'analysis_timestamp': datetime.now().isoformat(),
            'timeframe_analyzed': f"{timeframe_minutes} minutes",
            'sensitivity': sensitivity,
            'total_connections': len(recent_traffic),
            'total_bytes': recent_traffic['bytes_total'].sum(),
            'unique_source_ips': recent_traffic['src_ip'].nunique(),
            'unique_destination_ips': recent_traffic['dst_ip'].nunique(),
            'detected_threats': [],
            'traffic_anomalies': [],
            'suspicious_ips': [],
            'summary': {}
        }
        
        # Adjust detection thresholds based on sensitivity
        thresholds = adjust_detection_thresholds(sensitivity)
        
        # 1. Known malicious IP detection
        malicious_ips = detect_known_malicious_ips(recent_traffic)
        if malicious_ips:
            results['detected_threats'].extend(malicious_ips)
        
        # 2. Attack pattern detection
        attacks = detect_attack_patterns(recent_traffic, thresholds)
        if attacks:
            results['detected_threats'].extend(attacks)
        
        # 3. Protocol-specific anomaly detection
        protocol_anomalies = detect_protocol_anomalies(recent_traffic, thresholds)
        if protocol_anomalies:
            results['detected_threats'].extend(protocol_anomalies)
        
        # 4. Machine learning-based anomaly detection
        ml_anomalies = detect_traffic_anomalies_ml(recent_traffic, thresholds)
        if ml_anomalies:
            results['traffic_anomalies'].extend(ml_anomalies)
        
        # 5. Analyze connection patterns for beaconing or suspicious behavior
        beaconing = detect_beaconing_behavior(recent_traffic, thresholds)
        if beaconing:
            results['detected_threats'].extend(beaconing)
        
        # 6. Extract suspicious IPs based on various behaviors
        suspicious_ips = identify_suspicious_ips(recent_traffic, results['detected_threats'])
        results['suspicious_ips'] = suspicious_ips
        
        # Generate summary statistics and risk assessment
        results['summary'] = generate_network_analysis_summary(
            recent_traffic, 
            results['detected_threats'], 
            results['traffic_anomalies']
        )
        
        return results
    
    except Exception as e:
        logger.error(f"Error in network traffic analysis: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }

def enrich_traffic_data(traffic_df):
    """Add derived features to traffic data for better analysis."""
    df = traffic_df.copy()
    
    # Add total bytes column if not present
    if 'bytes_total' not in df.columns:
        if all(col in df.columns for col in ['bytes_sent', 'bytes_received']):
            df['bytes_total'] = df['bytes_sent'] + df['bytes_received']
        else:
            df['bytes_total'] = 0
    
    # Add categorical features for protocols, ports, etc.
    # Common service ports
    well_known_ports = {
        22: 'SSH',
        23: 'TELNET',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        443: 'HTTPS',
        445: 'SMB',
        3389: 'RDP',
        1433: 'MSSQL',
        3306: 'MYSQL',
        5432: 'POSTGRES'
    }
    
    df['dst_service'] = df['dst_port'].map(lambda p: well_known_ports.get(p, 'OTHER'))
    
    # Add IP-based features
    df['src_is_private'] = df['src_ip'].apply(is_private_ip)
    df['dst_is_private'] = df['dst_ip'].apply(is_private_ip)
    
    # Classify traffic direction
    df['direction'] = df.apply(
        lambda row: 'internal' if row['src_is_private'] and row['dst_is_private'] 
                    else ('outbound' if row['src_is_private'] and not row['dst_is_private']
                    else ('inbound' if not row['src_is_private'] and row['dst_is_private'] 
                    else 'external')),
        axis=1
    )
    
    # Add hour for time-based analysis
    df['hour'] = df['timestamp'].dt.hour
    
    return df

def is_private_ip(ip):
    """Check if IP address is private."""
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False

def adjust_detection_thresholds(sensitivity):
    """Adjust detection thresholds based on sensitivity level."""
    # Base thresholds
    thresholds = {
        'port_scan_unique_ports': ATTACK_PATTERNS['port_scan']['unique_ports_threshold'],
        'brute_force_attempts': ATTACK_PATTERNS['brute_force']['connection_attempts'],
        'ddos_connections': ATTACK_PATTERNS['ddos']['connection_threshold'],
        'data_exfil_size': ATTACK_PATTERNS['data_exfiltration']['large_outbound_data'],
        'beaconing_deviation': ATTACK_PATTERNS['c2_communication']['time_pattern_deviation'],
        'anomaly_confidence': 0.8,  # Minimum confidence for reporting anomalies
        'ml_contamination': 0.05,  # Default contamination factor for ML models
    }
    
    # Adjust based on sensitivity
    if sensitivity == 'low':
        thresholds['port_scan_unique_ports'] += 10  # Require more ports for detection
        thresholds['brute_force_attempts'] += 5  # Require more attempts
        thresholds['ddos_connections'] += 50  # Require more connections
        thresholds['anomaly_confidence'] = 0.9  # Higher confidence required
        thresholds['ml_contamination'] = 0.02  # Fewer anomalies detected
    elif sensitivity == 'high':
        thresholds['port_scan_unique_ports'] -= 5  # Fewer ports required
        thresholds['brute_force_attempts'] -= 3  # Fewer attempts required
        thresholds['ddos_connections'] -= 25  # Fewer connections required
        thresholds['anomaly_confidence'] = 0.7  # Lower confidence acceptable
        thresholds['ml_contamination'] = 0.1  # More anomalies detected
    
    return thresholds

def detect_known_malicious_ips(traffic_df):
    """Detect connections involving known malicious IPs."""
    threats = []
    
    for category, ip_ranges in KNOWN_MALICIOUS_PATTERNS.items():
        for ip_range in ip_ranges:
            # Create an IP network for matching
            ip_net = ipaddress.ip_network(ip_range)
            
            # Check source IPs
            for ip in traffic_df['src_ip'].unique():
                try:
                    if ipaddress.ip_address(ip) in ip_net:
                        # Found a match in source IPs
                        related_traffic = traffic_df[traffic_df['src_ip'] == ip]
                        target_ips = related_traffic['dst_ip'].unique()
                        
                        threats.append({
                            'type': 'known_malicious_ip',
                            'subtype': category,
                            'severity': 'high',
                            'ip_address': ip,
                            'direction': 'inbound',
                            'targets': target_ips.tolist() if len(target_ips) <= 10 else target_ips[:10].tolist() + ['...'],
                            'connection_count': len(related_traffic),
                            'first_seen': related_traffic['timestamp'].min().isoformat(),
                            'last_seen': related_traffic['timestamp'].max().isoformat(),
                            'confidence': 0.95,
                            'description': f"Traffic from known {category.replace('_', ' ')} IP address {ip}",
                            'recommendation': "Block this IP address immediately and investigate affected systems"
                        })
                except:
                    continue
            
            # Check destination IPs
            for ip in traffic_df['dst_ip'].unique():
                try:
                    if ipaddress.ip_address(ip) in ip_net:
                        # Found a match in destination IPs
                        related_traffic = traffic_df[traffic_df['dst_ip'] == ip]
                        source_ips = related_traffic['src_ip'].unique()
                        
                        threats.append({
                            'type': 'known_malicious_ip',
                            'subtype': category,
                            'severity': 'high',
                            'ip_address': ip,
                            'direction': 'outbound',
                            'sources': source_ips.tolist() if len(source_ips) <= 10 else source_ips[:10].tolist() + ['...'],
                            'connection_count': len(related_traffic),
                            'first_seen': related_traffic['timestamp'].min().isoformat(),
                            'last_seen': related_traffic['timestamp'].max().isoformat(),
                            'confidence': 0.95,
                            'description': f"Traffic to known {category.replace('_', ' ')} IP address {ip}",
                            'recommendation': "Block this IP address immediately and investigate affected systems for compromise"
                        })
                except:
                    continue
    
    return threats

def detect_attack_patterns(traffic_df, thresholds):
    """Detect common network attack patterns."""
    attacks = []
    
    # 1. Port Scan Detection
    port_scans = detect_port_scans(traffic_df, thresholds['port_scan_unique_ports'])
    attacks.extend(port_scans)
    
    # 2. Brute Force Attack Detection
    brute_force = detect_brute_force(traffic_df, thresholds['brute_force_attempts'])
    attacks.extend(brute_force)
    
    # 3. DDoS Attack Detection
    ddos = detect_ddos(traffic_df, thresholds['ddos_connections'])
    attacks.extend(ddos)
    
    # 4. Data Exfiltration Detection
    data_exfil = detect_data_exfiltration(traffic_df, thresholds['data_exfil_size'])
    attacks.extend(data_exfil)
    
    return attacks

def detect_port_scans(traffic_df, unique_ports_threshold):
    """Detect port scanning activity."""
    scans = []
    time_window = ATTACK_PATTERNS['port_scan']['time_window']
    
    # Group by source IP and check for many unique destination ports in a short timeframe
    for src_ip in traffic_df['src_ip'].unique():
        src_traffic = traffic_df[traffic_df['src_ip'] == src_ip].sort_values('timestamp')
        
        # Skip if very few connections
        if len(src_traffic) < unique_ports_threshold:
            continue
        
        # Analyze in sliding time windows
        start_time = src_traffic['timestamp'].min()
        end_time = src_traffic['timestamp'].max()
        
        current_time = start_time
        while current_time <= end_time:
            window_end = current_time + pd.Timedelta(seconds=time_window)
            window_traffic = src_traffic[(src_traffic['timestamp'] >= current_time) & 
                                        (src_traffic['timestamp'] < window_end)]
            
            # Check if number of unique ports exceeds threshold
            unique_ports = window_traffic['dst_port'].nunique()
            unique_ips = window_traffic['dst_ip'].nunique()
            
            if unique_ports >= unique_ports_threshold:
                # Calculate the distribution of ports to differentiate between legitimate and scanning
                port_distribution = window_traffic['dst_port'].value_counts(normalize=True)
                max_freq = port_distribution.max()
                
                # If relatively evenly distributed, more likely to be a scan
                if max_freq < 0.3:  # No single port dominates the traffic
                    # Get most commonly targeted destination if multiple
                    top_target = window_traffic['dst_ip'].value_counts().index[0] if unique_ips > 0 else "multiple"
                    
                    scans.append({
                        'type': 'port_scan',
                        'severity': ATTACK_PATTERNS['port_scan']['severity'],
                        'source_ip': src_ip,
                        'target_ip': top_target if unique_ips == 1 else f"{unique_ips} unique IPs",
                        'unique_ports': unique_ports,
                        'timeframe': f"{current_time.isoformat()} to {window_end.isoformat()}",
                        'confidence': min(0.95, 0.5 + (unique_ports / unique_ports_threshold) * 0.5),
                        'description': f"Potential port scan from {src_ip} targeting {unique_ports} unique ports",
                        'recommendation': "Investigate source IP intent, consider firewall rules to limit port scanning"
                    })
            
            # Move the window forward
            current_time += pd.Timedelta(seconds=time_window / 2)  # Overlapping windows
    
    return scans

def detect_brute_force(traffic_df, attempts_threshold):
    """Detect brute force attack attempts."""
    brute_force = []
    time_window = ATTACK_PATTERNS['brute_force']['time_window']
    target_ports = ATTACK_PATTERNS['brute_force']['target_ports']
    
    # Look for many connections to specific service ports in a short timeframe
    for dst_ip in traffic_df['dst_ip'].unique():
        for dst_port in target_ports:
            # Filter traffic to this destination IP and port
            target_traffic = traffic_df[(traffic_df['dst_ip'] == dst_ip) & 
                                       (traffic_df['dst_port'] == dst_port)].sort_values('timestamp')
            
            if len(target_traffic) < attempts_threshold:
                continue
            
            # Analyze in sliding time windows
            start_time = target_traffic['timestamp'].min()
            end_time = target_traffic['timestamp'].max()
            
            current_time = start_time
            while current_time <= end_time:
                window_end = current_time + pd.Timedelta(seconds=time_window)
                window_traffic = target_traffic[(target_traffic['timestamp'] >= current_time) & 
                                              (target_traffic['timestamp'] < window_end)]
                
                if len(window_traffic) >= attempts_threshold:
                    # Check if connections are from the same source
                    unique_sources = window_traffic['src_ip'].nunique()
                    
                    if unique_sources == 1:
                        source_ip = window_traffic['src_ip'].iloc[0]
                        
                        # See if there's a pattern of failed connections
                        has_failures = False
                        if 'status' in window_traffic.columns:
                            failure_keywords = ['fail', 'reject', 'denied', 'timeout']
                            has_failures = window_traffic['status'].str.lower().apply(
                                lambda x: any(k in str(x).lower() for k in failure_keywords)
                            ).any()
                        
                        service_name = {
                            22: 'SSH', 
                            23: 'Telnet', 
                            3389: 'RDP', 
                            445: 'SMB', 
                            1433: 'SQL Server',
                            3306: 'MySQL',
                            5432: 'PostgreSQL'
                        }.get(dst_port, f"Port {dst_port}")
                        
                        confidence = 0.7  # Base confidence
                        if has_failures:
                            confidence += 0.2  # Higher confidence if failures detected
                        
                        brute_force.append({
                            'type': 'brute_force_attack',
                            'severity': ATTACK_PATTERNS['brute_force']['severity'],
                            'source_ip': source_ip,
                            'target_ip': dst_ip,
                            'target_port': dst_port,
                            'service': service_name,
                            'connection_count': len(window_traffic),
                            'timeframe': f"{current_time.isoformat()} to {window_end.isoformat()}",
                            'has_failures': has_failures,
                            'confidence': confidence,
                            'description': f"Potential brute force attack from {source_ip} targeting {service_name} on {dst_ip}",
                            'recommendation': "Implement account lockout, rate limiting, and check logs for successful compromise"
                        })
                
                # Move the window forward
                current_time += pd.Timedelta(seconds=time_window / 2)
    
    return brute_force

def detect_ddos(traffic_df, connection_threshold):
    """Detect distributed denial of service (DDoS) attacks."""
    ddos = []
    time_window = ATTACK_PATTERNS['ddos']['time_window']
    
    # Look for high volume of connections to a single destination
    for dst_ip in traffic_df['dst_ip'].unique():
        dst_traffic = traffic_df[traffic_df['dst_ip'] == dst_ip].sort_values('timestamp')
        
        # Skip if not enough connections
        if len(dst_traffic) < connection_threshold * 0.5:
            continue
        
        # Analyze in sliding time windows
        start_time = dst_traffic['timestamp'].min()
        end_time = dst_traffic['timestamp'].max()
        
        current_time = start_time
        while current_time <= end_time:
            window_end = current_time + pd.Timedelta(seconds=time_window)
            window_traffic = dst_traffic[(dst_traffic['timestamp'] >= current_time) & 
                                        (dst_traffic['timestamp'] < window_end)]
            
            if len(window_traffic) >= connection_threshold:
                unique_sources = window_traffic['src_ip'].nunique()
                common_ports = window_traffic['dst_port'].value_counts().head(3).index.tolist()
                
                # DDoS usually involves multiple sources
                if unique_sources >= 3:
                    # Calculate total traffic volume
                    total_traffic = window_traffic['bytes_total'].sum() if 'bytes_total' in window_traffic.columns else 0
                    
                    # Check distribution across source IPs to identify coordination
                    source_distribution = window_traffic['src_ip'].value_counts(normalize=True)
                    distribution_evenness = 1 - source_distribution.var()  # Higher value means more even distribution
                    
                    service_names = []
                    for port in common_ports:
                        service_name = {
                            22: 'SSH', 
                            23: 'Telnet', 
                            80: 'HTTP',
                            443: 'HTTPS',
                            3389: 'RDP', 
                            25: 'SMTP',
                            53: 'DNS'
                        }.get(port, f"Port {port}")
                        service_names.append(service_name)
                    
                    confidence = min(0.95, 0.6 + (distribution_evenness * 0.2) + (unique_sources / 100 * 0.2))
                    
                    ddos.append({
                        'type': 'ddos_attack',
                        'severity': ATTACK_PATTERNS['ddos']['severity'],
                        'target_ip': dst_ip,
                        'target_services': service_names,
                        'source_count': unique_sources,
                        'connection_count': len(window_traffic),
                        'traffic_volume_bytes': total_traffic,
                        'timeframe': f"{current_time.isoformat()} to {window_end.isoformat()}",
                        'confidence': confidence,
                        'description': f"Potential DDoS attack targeting {dst_ip} from {unique_sources} sources with {len(window_traffic)} connections",
                        'recommendation': "Implement rate limiting, DDoS protection services, and analyze traffic patterns for mitigation"
                    })
            
            # Move the window forward
            current_time += pd.Timedelta(seconds=time_window / 2)
    
    return ddos

def detect_data_exfiltration(traffic_df, size_threshold):
    """Detect potential data exfiltration based on unusual outbound traffic."""
    exfil = []
    
    # Focus on outbound traffic
    outbound = traffic_df[traffic_df['direction'] == 'outbound']
    if outbound.empty:
        return exfil
    
    # Group by source IP, destination IP
    for src_ip in outbound['src_ip'].unique():
        src_traffic = outbound[outbound['src_ip'] == src_ip]
        
        # Group by destination
        for dst_ip in src_traffic['dst_ip'].unique():
            connection = src_traffic[src_traffic['dst_ip'] == dst_ip]
            
            # Calculate total bytes transferred
            total_bytes = connection['bytes_sent'].sum() if 'bytes_sent' in connection.columns else \
                         (connection['bytes_total'].sum() if 'bytes_total' in connection.columns else 0)
            
            # Skip if not enough data transferred
            if total_bytes < size_threshold:
                continue
                
            # Check if this is an unusual destination
            is_unusual = True  # Default to True for safety
            
            # Check for sustained connection
            duration = (connection['timestamp'].max() - connection['timestamp'].min()).total_seconds()
            is_sustained = duration >= ATTACK_PATTERNS['data_exfiltration']['sustained_connection']
            
            if total_bytes > size_threshold:
                risk_factors = []
                
                if is_unusual:
                    risk_factors.append("unusual destination")
                    
                if is_sustained:
                    risk_factors.append("sustained connection")
                
                # Calculate confidence based on risk factors and size
                confidence = 0.6
                confidence += 0.1 * len(risk_factors)
                confidence += min(0.2, (total_bytes / (size_threshold * 10)) * 0.2)  # Up to 0.2 based on size
                
                exfil.append({
                    'type': 'data_exfiltration',
                    'severity': ATTACK_PATTERNS['data_exfiltration']['severity'],
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'data_volume_bytes': total_bytes,
                    'data_volume_readable': format_bytes(total_bytes),
                    'connection_duration': duration,
                    'protocol': connection['protocol'].value_counts().index[0] if 'protocol' in connection.columns else 'unknown',
                    'risk_factors': risk_factors,
                    'confidence': min(0.95, confidence),
                    'first_seen': connection['timestamp'].min().isoformat(),
                    'last_seen': connection['timestamp'].max().isoformat(),
                    'description': f"Potential data exfiltration from {src_ip} to {dst_ip} ({format_bytes(total_bytes)})",
                    'recommendation': "Investigate source system for compromise, check destination IP reputation, and consider data loss prevention controls"
                })
    
    return exfil

def detect_protocol_anomalies(traffic_df, thresholds):
    """Detect protocol-specific anomalies in network traffic."""
    protocol_threats = []
    
    # HTTP/HTTPS anomalies
    if 'http_method' in traffic_df.columns or 'protocol' in traffic_df.columns and 'http' in traffic_df['protocol'].str.lower().unique():
        http_anomalies = detect_http_anomalies(traffic_df)
        protocol_threats.extend(http_anomalies)
    
    # DNS anomalies
    if 'protocol' in traffic_df.columns and 'dns' in traffic_df['protocol'].str.lower().unique():
        dns_anomalies = detect_dns_anomalies(traffic_df)
        protocol_threats.extend(dns_anomalies)
    
    # SMTP anomalies
    if 'protocol' in traffic_df.columns and 'smtp' in traffic_df['protocol'].str.lower().unique():
        smtp_anomalies = detect_smtp_anomalies(traffic_df)
        protocol_threats.extend(smtp_anomalies)
    
    return protocol_threats

def detect_http_anomalies(traffic_df):
    """Detect HTTP-specific anomalies."""
    http_threats = []
    
    # Filter for HTTP/HTTPS traffic
    http_traffic = traffic_df[
        (traffic_df['dst_port'].isin([80, 443, 8080, 8443])) |
        (traffic_df.get('protocol', '').str.lower().isin(['http', 'https']))
    ]
    
    if http_traffic.empty:
        return http_threats
    
    # Check for suspicious paths, methods, and user agents if available
    if 'http_path' in http_traffic.columns:
        # Check for suspicious paths
        for suspicious_path in PROTOCOL_BEHAVIORS['http']['suspicious_paths']:
            matches = http_traffic[http_traffic['http_path'].str.contains(suspicious_path, regex=False, na=False)]
            
            if not matches.empty:
                for _, match in matches.iterrows():
                    http_threats.append({
                        'type': 'suspicious_http_request',
                        'severity': 'medium',
                        'source_ip': match['src_ip'],
                        'destination_ip': match['dst_ip'],
                        'destination_port': match['dst_port'],
                        'path': match['http_path'],
                        'method': match.get('http_method', 'unknown'),
                        'timestamp': match['timestamp'].isoformat(),
                        'confidence': 0.7,
                        'description': f"Suspicious HTTP request targeting sensitive path: {match['http_path']}",
                        'recommendation': "Review web server logs and consider WAF rules to protect sensitive paths"
                    })
    
    if 'http_method' in http_traffic.columns:
        # Check for suspicious methods
        for suspicious_method in PROTOCOL_BEHAVIORS['http']['suspicious_methods']:
            matches = http_traffic[http_traffic['http_method'] == suspicious_method]
            
            if not matches.empty:
                for _, match in matches.iterrows():
                    http_threats.append({
                        'type': 'suspicious_http_method',
                        'severity': 'medium',
                        'source_ip': match['src_ip'],
                        'destination_ip': match['dst_ip'],
                        'destination_port': match['dst_port'],
                        'method': match['http_method'],
                        'path': match.get('http_path', 'unknown'),
                        'timestamp': match['timestamp'].isoformat(),
                        'confidence': 0.7,
                        'description': f"Suspicious HTTP method used: {match['http_method']}",
                        'recommendation': "Review web server logs and consider restricting allowed HTTP methods"
                    })
    
    if 'user_agent' in http_traffic.columns:
        # Check for suspicious user agents
        for suspicious_agent in PROTOCOL_BEHAVIORS['http']['suspicious_user_agents']:
            matches = http_traffic[http_traffic['user_agent'].str.contains(suspicious_agent, regex=False, na=False)]
            
            if not matches.empty:
                for _, match in matches.iterrows():
                    http_threats.append({
                        'type': 'suspicious_user_agent',
                        'severity': 'medium',
                        'source_ip': match['src_ip'],
                        'destination_ip': match['dst_ip'],
                        'destination_port': match['dst_port'],
                        'user_agent': match['user_agent'],
                        'timestamp': match['timestamp'].isoformat(),
                        'confidence': 0.7,
                        'description': f"Suspicious user agent detected: {match['user_agent']}",
                        'recommendation': "Monitor for scanning activity and consider blocking known scanning user agents"
                    })
    
    return http_threats

def detect_dns_anomalies(traffic_df):
    """Detect DNS-specific anomalies."""
    dns_threats = []
    
    # Filter for DNS traffic
    dns_traffic = traffic_df[
        (traffic_df['dst_port'] == 53) | 
        (traffic_df.get('protocol', '').str.lower() == 'dns')
    ]
    
    if dns_traffic.empty:
        return dns_threats
    
    # Check for high volume of DNS queries from a single source
    for src_ip in dns_traffic['src_ip'].unique():
        src_dns = dns_traffic[dns_traffic['src_ip'] == src_ip]
        
        # If suspiciously high volume of DNS queries
        if len(src_dns) > 100:  # Arbitrary threshold, adjust as needed
            dns_threats.append({
                'type': 'dns_query_flood',
                'severity': 'medium',
                'source_ip': src_ip,
                'query_count': len(src_dns),
                'timeframe': f"{src_dns['timestamp'].min().isoformat()} to {src_dns['timestamp'].max().isoformat()}",
                'confidence': min(0.9, 0.6 + (len(src_dns) / 1000)),  # Scale with query count
                'description': f"High volume of DNS queries from {src_ip}: {len(src_dns)} queries",
                'recommendation': "Monitor for DNS tunneling or C2 communications, implement DNS query rate limiting"
            })
    
    # Check for DGA-like domain queries if domain information is available
    if 'dns_query' in dns_traffic.columns:
        for query in dns_traffic['dns_query'].unique():
            # Calculate entropy of the domain (excluding TLD)
            domain_parts = str(query).split('.')
            if len(domain_parts) >= 2:
                domain = domain_parts[-2]  # Domain without TLD
                entropy = calculate_string_entropy(domain)
                
                # Check if entropy is above DGA threshold (algorithmically generated domains have high entropy)
                if entropy > PROTOCOL_BEHAVIORS['dns']['dga_entropy_threshold'] and len(domain) > 8:
                    # Find all queries for this domain
                    domain_queries = dns_traffic[dns_traffic['dns_query'] == query]
                    
                    dns_threats.append({
                        'type': 'potential_dga_domain',
                        'severity': 'high',
                        'domain': query,
                        'entropy': entropy,
                        'query_count': len(domain_queries),
                        'source_ips': domain_queries['src_ip'].unique().tolist(),
                        'confidence': min(0.9, 0.7 + (entropy - PROTOCOL_BEHAVIORS['dns']['dga_entropy_threshold']) / 2),
                        'description': f"Potential algorithmically generated domain: {query} (entropy: {entropy:.2f})",
                        'recommendation': "Investigate for malware infection and consider DNS security controls"
                    })
    
    return dns_threats

def detect_smtp_anomalies(traffic_df):
    """Detect SMTP-specific anomalies."""
    smtp_threats = []
    
    # Filter for SMTP traffic
    smtp_traffic = traffic_df[
        (traffic_df['dst_port'].isin([25, 465, 587])) | 
        (traffic_df.get('protocol', '').str.lower() == 'smtp')
    ]
    
    if smtp_traffic.empty:
        return smtp_threats
    
    # Check for unusual SMTP connections
    for src_ip in smtp_traffic['src_ip'].unique():
        # If src IP is connecting to multiple SMTP servers, might be sending spam
        src_smtp = smtp_traffic[smtp_traffic['src_ip'] == src_ip]
        unique_destinations = src_smtp['dst_ip'].nunique()
        
        if unique_destinations > 3:  # Connecting to multiple mail servers
            smtp_threats.append({
                'type': 'potential_spam_activity',
                'severity': 'medium',
                'source_ip': src_ip,
                'destination_count': unique_destinations,
                'connection_count': len(src_smtp),
                'confidence': min(0.85, 0.6 + (unique_destinations / 20)),
                'description': f"Potential spam activity from {src_ip} connecting to {unique_destinations} mail servers",
                'recommendation': "Investigate for compromised systems sending spam, implement email security controls"
            })
    
    return smtp_threats

def detect_traffic_anomalies_ml(traffic_df, thresholds):
    """Use machine learning to detect anomalies in network traffic patterns."""
    anomalies = []
    
    # Need enough data for meaningful analysis
    if len(traffic_df) < 20:
        return anomalies
    
    try:
        # Prepare numerical features for anomaly detection
        numeric_features = [
            'src_port', 'dst_port', 'bytes_total'
        ]
        
        # Add duration if available
        if 'duration' in traffic_df.columns:
            numeric_features.append('duration')
        
        # Filter out missing values
        traffic_ml = traffic_df[numeric_features].copy()
        traffic_ml = traffic_ml.fillna(0)
        
        # Scale the data
        scaler = StandardScaler()
        scaled_data = scaler.fit_transform(traffic_ml)
        
        # Apply Isolation Forest for anomaly detection
        contamination = thresholds['ml_contamination']
        iso_forest = IsolationForest(contamination=contamination, random_state=42)
        predictions = iso_forest.fit_predict(scaled_data)
        
        # Convert predictions (-1 for anomalies, 1 for normal)
        traffic_df['anomaly'] = predictions
        anomalous_traffic = traffic_df[traffic_df['anomaly'] == -1]
        
        # Group anomalies by src-dst pair for more meaningful reporting
        grouped_anomalies = {}
        
        for _, row in anomalous_traffic.iterrows():
            key = f"{row['src_ip']}_{row['dst_ip']}"
            if key not in grouped_anomalies:
                grouped_anomalies[key] = {
                    'src_ip': row['src_ip'],
                    'dst_ip': row['dst_ip'],
                    'connections': [],
                    'first_seen': row['timestamp'],
                    'last_seen': row['timestamp'],
                    'total_bytes': row.get('bytes_total', 0)
                }
            else:
                group = grouped_anomalies[key]
                group['first_seen'] = min(group['first_seen'], row['timestamp'])
                group['last_seen'] = max(group['last_seen'], row['timestamp'])
                group['total_bytes'] += row.get('bytes_total', 0)
            
            grouped_anomalies[key]['connections'].append({
                'timestamp': row['timestamp'].isoformat(),
                'src_port': row['src_port'],
                'dst_port': row['dst_port'],
                'bytes': row.get('bytes_total', 0),
                'protocol': row.get('protocol', 'unknown'),
                'duration': row.get('duration', 0)
            })
        
        # Create anomaly reports
        for key, group in grouped_anomalies.items():
            # Calculate some statistics about the anomalous connections
            connection_count = len(group['connections'])
            
            # Determine anomaly severity based on various factors
            severity = 'low'
            confidence = 0.6  # Base confidence
            
            # Look for patterns that would indicate higher severity
            ports = [conn['dst_port'] for conn in group['connections']]
            common_ports = Counter(ports).most_common(1)
            most_common_port = common_ports[0][0] if common_ports else 0
            
            # Check if target is a sensitive port
            sensitive_ports = [22, 3389, 445, 1433, 3306, 5432, 25, 53]
            if most_common_port in sensitive_ports:
                severity = 'medium'
                confidence += 0.1
            
            # Check total data volume
            if group['total_bytes'] > 10 * 1024 * 1024:  # > 10 MB
                severity = 'medium'
                confidence += 0.1
            
            # Check anomaly duration
            duration = (group['last_seen'] - group['first_seen']).total_seconds()
            if duration > 3600:  # > 1 hour
                confidence += 0.1
            
            # Generate a summary of the anomaly
            anomaly_reasons = []
            
            if most_common_port in sensitive_ports:
                port_name = {22: 'SSH', 3389: 'RDP', 445: 'SMB', 1433: 'SQL Server', 
                           3306: 'MySQL', 5432: 'PostgreSQL', 25: 'SMTP', 53: 'DNS'}.get(most_common_port, str(most_common_port))
                anomaly_reasons.append(f"connections to sensitive {port_name} port")
            
            if group['total_bytes'] > 1024 * 1024:
                anomaly_reasons.append(f"unusual data volume ({format_bytes(group['total_bytes'])})")
            
            if duration > 3600:
                hours = duration / 3600
                anomaly_reasons.append(f"extended duration ({hours:.1f} hours)")
            
            reasons_text = ", ".join(anomaly_reasons) if anomaly_reasons else "statistical deviation from normal patterns"
            
            anomalies.append({
                'type': 'ml_traffic_anomaly',
                'severity': severity,
                'source_ip': group['src_ip'],
                'destination_ip': group['dst_ip'],
                'connection_count': connection_count,
                'total_bytes': group['total_bytes'],
                'total_bytes_readable': format_bytes(group['total_bytes']),
                'first_seen': group['first_seen'].isoformat(),
                'last_seen': group['last_seen'].isoformat(),
                'duration_seconds': duration,
                'common_ports': [p[0] for p in Counter(ports).most_common(3)],
                'confidence': confidence,
                'description': f"Machine learning detected unusual traffic from {group['src_ip']} to {group['dst_ip']} ({connection_count} connections)",
                'anomaly_reasons': reasons_text,
                'recommendation': "Review the traffic patterns to determine if they represent legitimate business activity"
            })
    
    except Exception as e:
        logger.error(f"Error in ML anomaly detection: {str(e)}")
    
    return anomalies

def detect_beaconing_behavior(traffic_df, thresholds):
    """Detect beaconing behavior indicative of command and control (C2) communication."""
    beaconing = []
    
    # Need timestamp and a reasonable amount of data
    if 'timestamp' not in traffic_df.columns or len(traffic_df) < 10:
        return beaconing
    
    # Group by source-destination pairs
    for src_ip in traffic_df['src_ip'].unique():
        src_traffic = traffic_df[traffic_df['src_ip'] == src_ip]
        
        for dst_ip in src_traffic['dst_ip'].unique():
            pair_traffic = src_traffic[src_traffic['dst_ip'] == dst_ip].sort_values('timestamp')
            
            # Need at least several connections to detect beaconing
            if len(pair_traffic) < 4:
                continue
            
            # Calculate time intervals between consecutive connections
            timestamps = pair_traffic['timestamp'].tolist()
            intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                        for i in range(len(timestamps)-1)]
            
            # Skip if too few intervals
            if not intervals:
                continue
            
            # Calculate statistics on intervals
            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            cv = std_interval / mean_interval if mean_interval > 0 else float('inf')  # Coefficient of variation
            
            # Beaconing typically has low variation in intervals
            if cv < thresholds['beaconing_deviation'] and mean_interval > 10 and mean_interval < 3600:
                # Check byte counts for small consistent data bursts
                if 'bytes_total' in pair_traffic.columns:
                    byte_counts = pair_traffic['bytes_total'].tolist()
                    mean_bytes = np.mean(byte_counts)
                    std_bytes = np.std(byte_counts)
                    cv_bytes = std_bytes / mean_bytes if mean_bytes > 0 else float('inf')
                    
                    is_small_data = mean_bytes < 1024  # Less than 1KB on average
                    is_consistent = cv_bytes < 0.5  # Low variation in size
                else:
                    is_small_data = False
                    is_consistent = False
                
                # Calculate confidence based on various factors
                confidence = 0.7  # Base confidence for regular timing
                
                if is_small_data:
                    confidence += 0.1
                
                if is_consistent:
                    confidence += 0.1
                
                # More regular intervals = higher confidence
                if cv < 0.1:
                    confidence += 0.1
                
                # More data points = higher confidence
                if len(pair_traffic) > 10:
                    confidence += 0.1
                
                beaconing.append({
                    'type': 'beaconing_behavior',
                    'severity': ATTACK_PATTERNS['c2_communication']['severity'],
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'connection_count': len(pair_traffic),
                    'mean_interval_seconds': mean_interval,
                    'interval_variation': cv,
                    'first_seen': timestamps[0].isoformat(),
                    'last_seen': timestamps[-1].isoformat(),
                    'is_small_data': is_small_data,
                    'is_consistent_size': is_consistent,
                    'confidence': min(0.95, confidence),
                    'description': f"Potential C2 beaconing from {src_ip} to {dst_ip} ({len(pair_traffic)} connections at {mean_interval:.1f}s intervals)",
                    'recommendation': "Investigate for malware infection, check destination IP reputation, and consider blocking communication"
                })
    
    return beaconing

def identify_suspicious_ips(traffic_df, detected_threats):
    """Identify suspicious IPs based on detected threats and traffic patterns."""
    suspicious_ips = {}
    
    # First, add IPs from detected threats
    for threat in detected_threats:
        ip = None
        score = 0
        reason = threat['type']
        
        if 'source_ip' in threat:
            ip = threat['source_ip']
            score = threat_severity_to_score(threat['severity'])
        elif 'target_ip' in threat:
            ip = threat['target_ip']
            score = threat_severity_to_score(threat['severity']) * 0.5  # Lower score for targets
        elif 'ip_address' in threat:
            ip = threat['ip_address']
            score = threat_severity_to_score(threat['severity'])
        
        if ip and not is_internal_ip(ip):
            if ip not in suspicious_ips:
                suspicious_ips[ip] = {
                    'ip': ip,
                    'risk_score': score,
                    'reasons': [reason],
                    'confidence': threat.get('confidence', 0.7)
                }
            else:
                # Update existing entry
                suspicious_ips[ip]['risk_score'] += score
                suspicious_ips[ip]['reasons'].append(reason)
                suspicious_ips[ip]['confidence'] = max(suspicious_ips[ip]['confidence'], threat.get('confidence', 0.7))
    
    # Convert to list and sort by risk score
    result = list(suspicious_ips.values())
    for ip_data in result:
        # Cap risk score at 100
        ip_data['risk_score'] = min(100, ip_data['risk_score'])
        
        # Risk level based on score
        if ip_data['risk_score'] >= 75:
            ip_data['risk_level'] = 'critical'
        elif ip_data['risk_score'] >= 50:
            ip_data['risk_level'] = 'high'
        elif ip_data['risk_score'] >= 25:
            ip_data['risk_level'] = 'medium'
        else:
            ip_data['risk_level'] = 'low'
    
    # Sort by risk score (descending)
    result.sort(key=lambda x: x['risk_score'], reverse=True)
    
    return result

def generate_network_analysis_summary(traffic_df, threats, anomalies):
    """Generate a summary of the network analysis results."""
    # Count threats by severity
    severity_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0
    }
    
    for threat in threats:
        severity = threat.get('severity', 'low')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Count anomalies by severity
    for anomaly in anomalies:
        severity = anomaly.get('severity', 'low')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Count threats by type
    threat_types = {}
    for threat in threats:
        threat_type = threat.get('type', 'unknown')
        threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
    
    # Calculate overall risk score
    severity_weights = {
        'critical': 10,
        'high': 5,
        'medium': 2,
        'low': 0.5
    }
    
    total_weighted_score = sum(severity_counts[sev] * severity_weights[sev] for sev in severity_counts)
    max_reasonable_score = 100  # Cap for normalization
    overall_risk_score = min(100, (total_weighted_score / max_reasonable_score) * 100)
    
    # Determine risk level
    if overall_risk_score >= 75:
        risk_level = 'critical'
    elif overall_risk_score >= 50:
        risk_level = 'high'
    elif overall_risk_score >= 25:
        risk_level = 'medium'
    else:
        risk_level = 'low'
    
    # Traffic statistics
    total_connections = len(traffic_df)
    total_bytes = traffic_df['bytes_total'].sum() if 'bytes_total' in traffic_df.columns else 0
    unique_sources = traffic_df['src_ip'].nunique()
    unique_destinations = traffic_df['dst_ip'].nunique()
    
    # Direction breakdown
    direction_breakdown = {}
    if 'direction' in traffic_df.columns:
        direction_breakdown = traffic_df['direction'].value_counts().to_dict()
    
    return {
        'overall_risk_score': round(overall_risk_score, 1),
        'risk_level': risk_level,
        'total_threats': len(threats),
        'total_anomalies': len(anomalies),
        'severity_breakdown': severity_counts,
        'threat_type_breakdown': threat_types,
        'traffic_statistics': {
            'total_connections': total_connections,
            'total_bytes': total_bytes,
            'total_bytes_readable': format_bytes(total_bytes),
            'unique_sources': unique_sources,
            'unique_destinations': unique_destinations,
            'direction_breakdown': direction_breakdown
        },
        'top_recommendations': generate_recommendations(threats, anomalies, risk_level)
    }

def generate_recommendations(threats, anomalies, risk_level):
    """Generate security recommendations based on detected threats and anomalies."""
    recommendations = []
    
    # Add risk level-based recommendations
    if risk_level == 'critical':
        recommendations.append("URGENT: Immediate security response required. Investigate critical threats and consider isolating affected systems.")
    elif risk_level == 'high':
        recommendations.append("HIGH PRIORITY: Conduct thorough investigation of detected threats and implement immediate mitigation measures.")
    elif risk_level == 'medium':
        recommendations.append("Investigate detected threats and anomalies promptly. Implement security controls to address identified issues.")
    else:
        recommendations.append("Monitor the identified low-severity issues and review security controls during regular maintenance.")
    
    # Check for specific threat types and add tailored recommendations
    threat_types = set(threat.get('type', '') for threat in threats)
    
    if 'port_scan' in threat_types:
        recommendations.append("Implement network access controls and consider deploying an intrusion prevention system (IPS).")
    
    if 'brute_force_attack' in threat_types:
        recommendations.append("Strengthen authentication mechanisms with account lockout policies, strong password requirements, and multi-factor authentication.")
    
    if 'ddos_attack' in threat_types:
        recommendations.append("Deploy DDoS protection services and implement traffic rate limiting.")
    
    if 'data_exfiltration' in threat_types:
        recommendations.append("Implement data loss prevention (DLP) controls and egress filtering.")
    
    if 'beaconing_behavior' in threat_types or 'c2_communication' in threat_types:
        recommendations.append("Investigate for malware infections and implement DNS monitoring and blocking of known command and control servers.")
    
    if 'known_malicious_ip' in threat_types:
        recommendations.append("Block identified malicious IP addresses and implement threat intelligence feeds.")
    
    # Add general recommendations if nothing specific was added
    if len(recommendations) < 3:
        recommendations.append("Review network security architecture and ensure proper segmentation, monitoring, and access controls.")
    
    # Cap the number of recommendations
    return recommendations[:5]

# Utility Functions

def is_internal_ip(ip):
    """Check if an IP address is internal/private."""
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False

def calculate_string_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0
    
    text = str(text)
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    entropy = -sum(p * math.log(p, 2) for p in prob)
    return entropy

def format_bytes(size):
    """Format bytes to human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

def threat_severity_to_score(severity):
    """Convert threat severity to risk score."""
    severity_scores = {
        'critical': 40,
        'high': 20,
        'medium': 10,
        'low': 5
    }
    return severity_scores.get(severity.lower(), 5)