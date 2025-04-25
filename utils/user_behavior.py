import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import logging
from collections import Counter, defaultdict
import re
import ipaddress
import warnings
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from scipy.spatial.distance import pdist, squareform
from sklearn.ensemble import IsolationForest
import json
import math

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)

# Define known attacker behavior patterns
SUSPICIOUS_BEHAVIORS = {
    'brute_force': {
        'description': 'Multiple failed login attempts in short timeframe',
        'severity': 'high',
        'threshold': 5,  # n failed attempts
        'timeframe': 10  # minutes
    },
    'credential_stuffing': {
        'description': 'Multiple account access attempts with different credentials',
        'severity': 'critical',
        'threshold': 3,  # n different accounts
        'timeframe': 30  # minutes
    },
    'privilege_escalation': {
        'description': 'Multiple permission/role changes or admin function attempts',
        'severity': 'critical',
        'keywords': ['admin', 'permission', 'role', 'privilege', 'sudo', 'su']
    },
    'data_exfiltration': {
        'description': 'Unusual volume of data access or export operations',
        'severity': 'high',
        'keywords': ['download', 'export', 'extract', 'backup', 'dump'],
        'threshold': 10  # n operations
    },
    'account_hopping': {
        'description': 'User accessing multiple accounts from same IP/device',
        'severity': 'high',
        'threshold': 3  # n different accounts
    },
    'unusual_hours': {
        'description': 'Activities during non-business hours',
        'severity': 'medium',
        'hours': [0, 1, 2, 3, 4, 5, 22, 23]  # Outside 6am-10pm
    },
    'rapid_movement': {
        'description': 'User accessing system from different geographic locations in short timeframe',
        'severity': 'high',
        'threshold': 2,  # n locations
        'timeframe': 8   # hours
    }
}

def analyze_user_behavior(activities, timeframe_days=30):
    """
    Advanced analysis of user behavior patterns using AI and heuristic methods.
    
    Args:
        activities (list): List of UserActivity objects
        timeframe_days (int): Number of days to analyze
        
    Returns:
        dict: User behavior analysis results with behavioral anomalies and security risks
    """
    try:
        # Convert activities to DataFrame for easier analysis
        activity_data = []
        for activity in activities:
            activity_data.append({
                'user_id': activity.user_id,
                'activity_type': activity.activity_type,
                'timestamp': activity.timestamp,
                'ip_address': activity.ip_address,
                'user_agent': activity.user_agent,
                'details': activity.details or '',
                'location': extract_location_from_ip(activity.ip_address)
            })
        
        df = pd.DataFrame(activity_data)
        
        # Filter for the specified timeframe
        cutoff_date = datetime.utcnow() - timedelta(days=timeframe_days)
        df = df[df['timestamp'] >= cutoff_date]
        
        if df.empty:
            return {
                'status': 'no_data',
                'message': f'No activity data found in the last {timeframe_days} days'
            }
        
        # Ensure timestamp is datetime for temporal analysis
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Add derived features for better behavior modeling
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['weekend'] = df['day_of_week'].apply(lambda x: 1 if x >= 5 else 0)
        df['is_business_hour'] = df['hour'].apply(lambda x: 1 if 9 <= x <= 17 else 0)
        
        # Add user agent details
        df['agent_details'] = df['user_agent'].apply(get_user_agent_info)
        df['browser'] = df['agent_details'].apply(lambda x: x.get('browser', 'Unknown'))
        df['os'] = df['agent_details'].apply(lambda x: x.get('operating_system', 'Unknown'))
        
        # Extract activity data by user for user-specific behavioral profiling
        user_profiles = {}
        unusual_patterns = []
        all_users = df['user_id'].unique()
        
        for user_id in all_users:
            user_data = df[df['user_id'] == user_id]
            
            # Create baseline behavior profile for this user
            baseline = create_user_baseline(user_data)
            
            # Detect anomalies specific to this user
            user_anomalies = detect_user_anomalies(user_data, baseline)
            unusual_patterns.extend(user_anomalies)
            
            # Store profile for this user
            user_profiles[user_id] = baseline
        
        # Cross-user behavior analysis for detecting organizational anomalies
        org_anomalies = detect_organizational_anomalies(df, user_profiles)
        unusual_patterns.extend(org_anomalies)
        
        # Detect known attack patterns using temporal and behavioral signatures
        attack_patterns = detect_attack_patterns(df)
        unusual_patterns.extend(attack_patterns)
        
        # Use machine learning for unsupervised anomaly detection
        ml_anomalies = detect_ml_anomalies(df)
        unusual_patterns.extend(ml_anomalies)
        
        # Calculate risk score with weighted factors
        risk_score = calculate_advanced_risk_score(unusual_patterns, df)
        
        # Generate comprehensive summary
        result = {
            'status': 'success',
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'timeframe_analyzed': f'{timeframe_days} days',
            'total_activities': len(df),
            'total_users': len(all_users),
            'activity_distribution': df['activity_type'].value_counts().to_dict(),
            'hourly_activity_distribution': df['hour'].value_counts().sort_index().to_dict(),
            'user_activity_summary': {user_id: {'total_activities': len(df[df['user_id'] == user_id])} 
                                     for user_id in all_users},
            'unusual_patterns': unusual_patterns,
            'risk_score': risk_score,
            'risk_category': get_risk_category(risk_score),
            'recommendations': generate_security_recommendations(unusual_patterns, risk_score)
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Error in user behavior analysis: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }

def create_user_baseline(user_data):
    """Create a behavioral baseline for a specific user."""
    # Skip if insufficient data
    if len(user_data) < 5:
        return {'status': 'insufficient_data'}
    
    # Temporal patterns
    hour_distribution = user_data['hour'].value_counts(normalize=True).to_dict()
    day_distribution = user_data['day_of_week'].value_counts(normalize=True).to_dict()
    most_active_hours = sorted(hour_distribution, key=hour_distribution.get, reverse=True)[:3]
    
    # Activity patterns
    activity_distribution = user_data['activity_type'].value_counts(normalize=True).to_dict()
    most_common_activities = sorted(activity_distribution, key=activity_distribution.get, reverse=True)[:3]
    
    # Location and device patterns
    common_ips = user_data['ip_address'].value_counts().to_dict()
    common_browsers = user_data['browser'].value_counts().to_dict()
    common_os = user_data['os'].value_counts().to_dict()
    
    # Calculate typical session duration and activity frequency
    sessions = extract_user_sessions(user_data)
    avg_session_duration = np.mean([s['duration_minutes'] for s in sessions]) if sessions else 0
    avg_activities_per_day = len(user_data) / (user_data['timestamp'].max() - user_data['timestamp'].min()).days \
                            if (user_data['timestamp'].max() - user_data['timestamp'].min()).days > 0 else len(user_data)
    
    return {
        'user_id': user_data['user_id'].iloc[0],
        'data_points': len(user_data),
        'first_activity': user_data['timestamp'].min().isoformat(),
        'last_activity': user_data['timestamp'].max().isoformat(),
        'hour_distribution': hour_distribution,
        'day_distribution': day_distribution,
        'most_active_hours': most_active_hours,
        'activity_distribution': activity_distribution,
        'most_common_activities': most_common_activities,
        'common_ips': common_ips,
        'common_browsers': common_browsers,
        'common_os': common_os,
        'avg_session_duration_minutes': avg_session_duration,
        'avg_activities_per_day': avg_activities_per_day
    }

def extract_user_sessions(user_data, session_gap_minutes=30):
    """Extract user sessions based on activity timestamps."""
    if user_data.empty:
        return []
    
    # Sort by timestamp
    sorted_activities = user_data.sort_values('timestamp')
    
    sessions = []
    current_session = {
        'start': sorted_activities['timestamp'].iloc[0],
        'activities': [sorted_activities.iloc[0].to_dict()],
        'ip_addresses': {sorted_activities['ip_address'].iloc[0]},
        'user_agents': {sorted_activities['user_agent'].iloc[0]}
    }
    
    for i in range(1, len(sorted_activities)):
        current = sorted_activities.iloc[i]
        previous = sorted_activities.iloc[i-1]
        time_diff = (current['timestamp'] - previous['timestamp']).total_seconds() / 60
        
        if time_diff > session_gap_minutes:
            # Close current session and start a new one
            current_session['end'] = previous['timestamp']
            current_session['duration_minutes'] = (current_session['end'] - current_session['start']).total_seconds() / 60
            sessions.append(current_session)
            
            # Start new session
            current_session = {
                'start': current['timestamp'],
                'activities': [current.to_dict()],
                'ip_addresses': {current['ip_address']},
                'user_agents': {current['user_agent']}
            }
        else:
            # Add to current session
            current_session['activities'].append(current.to_dict())
            current_session['ip_addresses'].add(current['ip_address'])
            current_session['user_agents'].add(current['user_agent'])
    
    # Add the last session
    if current_session:
        current_session['end'] = sorted_activities['timestamp'].iloc[-1]
        current_session['duration_minutes'] = (current_session['end'] - current_session['start']).total_seconds() / 60
        sessions.append(current_session)
    
    return sessions

def detect_user_anomalies(user_data, baseline):
    """Detect anomalies in user behavior compared to their baseline."""
    anomalies = []
    
    # Skip if baseline has insufficient data
    if baseline.get('status') == 'insufficient_data':
        return anomalies
    
    user_id = baseline['user_id']
    
    # Check for unusual access times
    business_hours_pct = user_data['is_business_hour'].mean() * 100
    if business_hours_pct < 30:  # Less than 30% during business hours
        anomalies.append({
            'type': 'unusual_hours',
            'severity': 'medium',
            'description': f'User {user_id} has {business_hours_pct:.1f}% of activity outside business hours',
            'user_id': user_id,
            'detection_method': 'temporal_analysis'
        })
    
    # Check for unusual locations/IPs
    ip_counts = user_data['ip_address'].value_counts()
    new_ips = [ip for ip in ip_counts.index if ip not in baseline['common_ips']]
    if new_ips and len(ip_counts) > 1:
        anomalies.append({
            'type': 'new_location',
            'severity': 'medium',
            'description': f'User {user_id} accessed from {len(new_ips)} new IP addresses',
            'user_id': user_id,
            'ip_addresses': new_ips,
            'detection_method': 'location_analysis'
        })
    
    # Check for unusual activity types
    activity_counts = user_data['activity_type'].value_counts()
    unusual_activities = [act for act in activity_counts.index 
                         if act not in baseline['most_common_activities'] and activity_counts[act] > 3]
    if unusual_activities:
        anomalies.append({
            'type': 'unusual_activity_type',
            'severity': 'low',
            'description': f'User {user_id} performed unusual activities: {", ".join(unusual_activities)}',
            'user_id': user_id,
            'detection_method': 'activity_analysis'
        })
    
    # Check for unusual session behavior
    sessions = extract_user_sessions(user_data)
    if sessions:
        session_durations = [s['duration_minutes'] for s in sessions]
        avg_duration = np.mean(session_durations)
        baseline_duration = baseline['avg_session_duration_minutes']
        
        # Flag sessions significantly longer than usual
        if avg_duration > baseline_duration * 2 and avg_duration > 30:
            anomalies.append({
                'type': 'extended_session',
                'severity': 'low',
                'description': f'User {user_id} has unusually long sessions (avg: {avg_duration:.1f} min vs baseline: {baseline_duration:.1f} min)',
                'user_id': user_id,
                'detection_method': 'session_analysis'
            })
        
        # Check for sessions with multiple devices/IPs
        for session in sessions:
            if len(session['ip_addresses']) > 1:
                anomalies.append({
                    'type': 'session_ip_change',
                    'severity': 'high',
                    'description': f'User {user_id} changed IP addresses {len(session["ip_addresses"])} times within a single session',
                    'user_id': user_id,
                    'session_start': session['start'].isoformat(),
                    'session_end': session['end'].isoformat(),
                    'ip_addresses': list(session['ip_addresses']),
                    'detection_method': 'session_analysis'
                })
    
    # Check for failed login attempts
    failed_logins = len([a for a in user_data['details'] if isinstance(a, str) and 'failed' in a.lower() and 'login' in a.lower()])
    if failed_logins > 3:
        anomalies.append({
            'type': 'failed_logins',
            'severity': 'high',
            'description': f'User {user_id} had {failed_logins} failed login attempts',
            'user_id': user_id,
            'detection_method': 'security_analysis'
        })
    
    return anomalies

def detect_organizational_anomalies(df, user_profiles):
    """Detect anomalies across users at an organizational level."""
    anomalies = []
    
    # Skip if not enough data
    if len(df) < 10 or len(user_profiles) < 2:
        return anomalies
    
    # 1. Detect users with similar activity patterns (potential shared accounts)
    # Get feature vectors for each user's behavior
    user_vectors = {}
    for user_id, profile in user_profiles.items():
        if profile.get('status') == 'insufficient_data':
            continue
        
        # Create feature vector from common attributes
        vector = []
        # Temporal features - hour distribution (0-23)
        for hour in range(24):
            vector.append(profile['hour_distribution'].get(hour, 0))
            
        # Browser/OS features
        browser_os = f"{list(profile['common_browsers'].keys())[0] if profile['common_browsers'] else 'Unknown'} / {list(profile['common_os'].keys())[0] if profile['common_os'] else 'Unknown'}"
        user_vectors[user_id] = {'vector': vector, 'browser_os': browser_os}
    
    # Compare user similarity
    similar_users = []
    users = list(user_vectors.keys())
    for i in range(len(users)):
        for j in range(i+1, len(users)):
            user1, user2 = users[i], users[j]
            # Compare temporal patterns
            similarity = cosine_similarity(user_vectors[user1]['vector'], user_vectors[user2]['vector'])
            
            # Check for very similar patterns
            if similarity > 0.9:
                # Check if they also use similar browsers/OS
                if user_vectors[user1]['browser_os'] == user_vectors[user2]['browser_os']:
                    similar_users.append((user1, user2, similarity))
    
    if similar_users:
        for user1, user2, similarity in similar_users:
            anomalies.append({
                'type': 'similar_user_patterns',
                'severity': 'medium',
                'description': f'Users {user1} and {user2} show suspiciously similar behavior patterns (similarity: {similarity:.2f})',
                'users': [user1, user2],
                'similarity_score': similarity,
                'detection_method': 'cross_user_analysis'
            })
    
    # 2. Detect unusual account access patterns
    account_access = defaultdict(set)
    ip_accounts = defaultdict(set)
    
    for _, row in df.iterrows():
        account_access[row['user_id']].add(row['ip_address'])
        ip_accounts[row['ip_address']].add(row['user_id'])
    
    # Check for IPs accessing multiple accounts
    for ip, accounts in ip_accounts.items():
        if len(accounts) >= 3:  # IP accessing 3+ different accounts
            anomalies.append({
                'type': 'ip_multiple_accounts',
                'severity': 'high',
                'description': f'IP address {ip} accessed {len(accounts)} different user accounts',
                'ip_address': ip,
                'affected_users': list(accounts),
                'detection_method': 'access_pattern_analysis'
            })
    
    # 3. Check for simultaneous activity from different locations
    user_sessions = {}
    for user_id in df['user_id'].unique():
        user_data = df[df['user_id'] == user_id].sort_values('timestamp')
        if len(user_data) < 2:
            continue
            
        # Look for impossible travel (activity from different locations too close in time)
        prev_row = None
        for _, row in user_data.iterrows():
            if prev_row is not None:
                time_diff = (row['timestamp'] - prev_row['timestamp']).total_seconds() / 3600  # hours
                
                # Different IPs with short time difference
                if (row['ip_address'] != prev_row['ip_address'] and 
                    time_diff < 1 and  # Less than 1 hour difference
                    row['location'] != prev_row['location'] and
                    row['location'] != 'Unknown' and 
                    prev_row['location'] != 'Unknown'):
                    
                    anomalies.append({
                        'type': 'impossible_travel',
                        'severity': 'critical',
                        'description': f'User {user_id} had activity from {prev_row["location"]} and {row["location"]} within {time_diff:.1f} hours',
                        'user_id': user_id,
                        'locations': [prev_row['location'], row['location']],
                        'timestamps': [prev_row['timestamp'].isoformat(), row['timestamp'].isoformat()],
                        'detection_method': 'impossible_travel_analysis'
                    })
            
            prev_row = row
    
    return anomalies

def detect_attack_patterns(df):
    """Detect known attack patterns based on behavioral signatures."""
    attack_anomalies = []
    
    # Skip if not enough data
    if len(df) < 5:
        return attack_anomalies
    
    # 1. Detect brute force attempts
    for user_id in df['user_id'].unique():
        user_data = df[df['user_id'] == user_id]
        
        # Check for failed logins in short timeframe
        login_attempts = user_data[user_data['activity_type'] == 'login'].copy()
        if len(login_attempts) >= SUSPICIOUS_BEHAVIORS['brute_force']['threshold']:
            login_attempts['failed'] = login_attempts['details'].apply(
                lambda x: 1 if isinstance(x, str) and 'failed' in x.lower() else 0
            )
            
            # Group by short time windows and count failed attempts
            login_attempts['timegroup'] = login_attempts['timestamp'].dt.floor('10min')
            grouped = login_attempts.groupby('timegroup')['failed'].sum()
            
            for timegroup, failed_count in grouped.items():
                if failed_count >= SUSPICIOUS_BEHAVIORS['brute_force']['threshold']:
                    attack_anomalies.append({
                        'type': 'brute_force_attack',
                        'severity': 'high',
                        'description': f'Potential brute force attack detected: {failed_count} failed logins for user {user_id} within 10 minutes',
                        'user_id': user_id,
                        'timestamp': timegroup.isoformat(),
                        'failed_count': int(failed_count),
                        'detection_method': 'attack_pattern_recognition'
                    })
    
    # 2. Check for privilege escalation attempts
    for user_id in df['user_id'].unique():
        user_data = df[df['user_id'] == user_id]
        
        # Look for suspicious keywords in details
        suspicious_activities = []
        for _, row in user_data.iterrows():
            details = str(row['details']).lower()
            if any(keyword in details for keyword in SUSPICIOUS_BEHAVIORS['privilege_escalation']['keywords']):
                suspicious_activities.append({
                    'timestamp': row['timestamp'],
                    'details': row['details'],
                    'ip_address': row['ip_address']
                })
        
        if len(suspicious_activities) >= 3:  # Threshold for suspicious privilege activities
            attack_anomalies.append({
                'type': 'privilege_escalation',
                'severity': 'critical',
                'description': f'Potential privilege escalation attempt by user {user_id}: {len(suspicious_activities)} suspicious admin/privilege activities',
                'user_id': user_id,
                'detection_method': 'attack_pattern_recognition'
            })
    
    # 3. Check for unusual data access/export (potential data exfiltration)
    for user_id in df['user_id'].unique():
        user_data = df[df['user_id'] == user_id]
        
        # Look for data export keywords
        export_activities = []
        for _, row in user_data.iterrows():
            details = str(row['details']).lower()
            activity = str(row['activity_type']).lower()
            
            if (any(keyword in details for keyword in SUSPICIOUS_BEHAVIORS['data_exfiltration']['keywords']) or
                any(keyword in activity for keyword in SUSPICIOUS_BEHAVIORS['data_exfiltration']['keywords'])):
                export_activities.append({
                    'timestamp': row['timestamp'],
                    'details': row['details'],
                    'ip_address': row['ip_address']
                })
        
        if len(export_activities) >= SUSPICIOUS_BEHAVIORS['data_exfiltration']['threshold']:
            attack_anomalies.append({
                'type': 'data_exfiltration',
                'severity': 'high',
                'description': f'Potential data exfiltration by user {user_id}: {len(export_activities)} data export/download activities',
                'user_id': user_id,
                'detection_method': 'attack_pattern_recognition'
            })
    
    return attack_anomalies

def detect_ml_anomalies(df):
    """Use machine learning to detect behavioral anomalies."""
    ml_anomalies = []
    
    # Skip if not enough data
    if len(df) < 10:
        return ml_anomalies
    
    try:
        # Prepare numerical features
        numeric_features = ['hour', 'day_of_week', 'is_business_hour', 'weekend']
        
        # Prepare categorical features
        categorical_features = ['activity_type', 'browser', 'os']
        categorical_data = df[categorical_features].fillna('unknown')
        
        # One-hot encode categorical features
        encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
        encoded_cats = encoder.fit_transform(categorical_data)
        
        # Combine features
        numeric_data = df[numeric_features].fillna(0)
        X = np.hstack([numeric_data.values, encoded_cats])
        
        # Apply isolation forest for anomaly detection
        contamination = min(0.05, 10/len(df))  # Adaptive contamination
        clf = IsolationForest(contamination=contamination, n_estimators=100, random_state=42)
        df['anomaly_score'] = clf.fit_predict(X)
        
        # Extract anomalies
        anomalies = df[df['anomaly_score'] == -1]
        
        # Group anomalies by user
        for user_id in anomalies['user_id'].unique():
            user_anomalies = anomalies[anomalies['user_id'] == user_id]
            
            if len(user_anomalies) > 0:
                # Determine severity based on number of anomalies
                severity = 'low'
                if len(user_anomalies) >= 5:
                    severity = 'medium'
                if len(user_anomalies) >= 10:
                    severity = 'high'
                
                ml_anomalies.append({
                    'type': 'ml_behavioral_anomaly',
                    'severity': severity,
                    'description': f'Machine learning detected unusual behavioral patterns for user {user_id}: {len(user_anomalies)} anomalous activities',
                    'user_id': user_id,
                    'anomaly_count': len(user_anomalies),
                    'detection_method': 'machine_learning'
                })
                
                # Include specific anomalous activities if there are few of them
                if len(user_anomalies) <= 5:
                    activity_details = []
                    for _, row in user_anomalies.iterrows():
                        activity_details.append({
                            'timestamp': row['timestamp'].isoformat(),
                            'activity_type': row['activity_type'],
                            'ip_address': row['ip_address']
                        })
                    ml_anomalies[-1]['activity_details'] = activity_details
        
    except Exception as e:
        logger.error(f"Error in ML anomaly detection: {str(e)}")
        
    return ml_anomalies

def calculate_advanced_risk_score(unusual_patterns, df):
    """Calculate an advanced risk score based on detected anomalies and other factors."""
    if not unusual_patterns:
        return 0
    
    # Base severity weights
    severity_weights = {
        'low': 5,
        'medium': 15,
        'high': 40,
        'critical': 70
    }
    
    # Type weights - some anomaly types are more concerning than others
    type_weights = {
        'brute_force_attack': 1.5,
        'privilege_escalation': 2.0,
        'data_exfiltration': 1.8,
        'impossible_travel': 1.7,
        'ip_multiple_accounts': 1.4,
        'failed_logins': 1.3,
        'session_ip_change': 1.2,
        'ml_behavioral_anomaly': 1.1,
        'similar_user_patterns': 0.9,
        'new_location': 0.8,
        'unusual_hours': 0.7,
        'extended_session': 0.6,
        'unusual_activity_type': 0.5
    }
    
    # Calculate base score from anomalies
    total_score = 0
    for pattern in unusual_patterns:
        severity = pattern.get('severity', 'low')
        pattern_type = pattern.get('type', '')
        
        # Base score from severity
        severity_score = severity_weights.get(severity, 1)
        
        # Apply type-specific weight
        type_weight = type_weights.get(pattern_type, 1.0)
        
        pattern_score = severity_score * type_weight
        total_score += pattern_score
    
    # Adjust score based on dataset size
    # More data = more confidence in the score
    confidence_factor = min(1.0, len(df) / 1000)
    adjusted_score = total_score * confidence_factor
    
    # Normalize to a 0-100 scale with diminishing returns for very high scores
    normalized_score = 100 * (1 - math.exp(-adjusted_score/100))
    
    return min(100, round(normalized_score))

def get_risk_category(risk_score):
    """Get a risk category label based on the risk score."""
    if risk_score < 10:
        return 'minimal'
    elif risk_score < 30:
        return 'low'
    elif risk_score < 60:
        return 'medium'
    elif risk_score < 85:
        return 'high'
    else:
        return 'critical'

def generate_security_recommendations(unusual_patterns, risk_score):
    """Generate security recommendations based on detected patterns."""
    recommendations = []
    
    # Add general recommendations based on risk level
    if risk_score >= 85:
        recommendations.append({
            'priority': 'critical',
            'action': 'Immediate security review required',
            'description': 'Critical security risks detected. Initiate incident response procedures and conduct a full security review.'
        })
    elif risk_score >= 60:
        recommendations.append({
            'priority': 'high',
            'action': 'Urgent security assessment needed',
            'description': 'Significant security risks detected. Review and strengthen access controls, and investigate suspicious activities.'
        })
    elif risk_score >= 30:
        recommendations.append({
            'priority': 'medium',
            'action': 'Security review recommended',
            'description': 'Moderate security concerns identified. Review security policies and increase monitoring of user activities.'
        })
    
    # Add specific recommendations based on anomaly types
    anomaly_types = [p.get('type') for p in unusual_patterns]
    
    if 'brute_force_attack' in anomaly_types or 'failed_logins' in anomaly_types:
        recommendations.append({
            'priority': 'high',
            'action': 'Strengthen authentication',
            'description': 'Implement multi-factor authentication, account lockout policies, and IP-based access restrictions.'
        })
    
    if 'privilege_escalation' in anomaly_types:
        recommendations.append({
            'priority': 'critical',
            'action': 'Review permission systems',
            'description': 'Audit administrative privileges, implement least privilege principles, and add approval workflows for privilege changes.'
        })
    
    if 'data_exfiltration' in anomaly_types:
        recommendations.append({
            'priority': 'high',
            'action': 'Strengthen data controls',
            'description': 'Implement data loss prevention (DLP) solutions, file activity monitoring, and restrictions on bulk data exports.'
        })
    
    if 'impossible_travel' in anomaly_types or 'session_ip_change' in anomaly_types:
        recommendations.append({
            'priority': 'high',
            'action': 'Location-based controls',
            'description': 'Implement location-based authentication rules and continuous authentication throughout user sessions.'
        })
    
    if 'ip_multiple_accounts' in anomaly_types or 'similar_user_patterns' in anomaly_types:
        recommendations.append({
            'priority': 'medium',
            'action': 'Audit shared accounts',
            'description': 'Review account usage policies, restrict account sharing, and conduct user awareness training.'
        })
    
    if 'unusual_hours' in anomaly_types:
        recommendations.append({
            'priority': 'low',
            'action': 'Time-based access controls',
            'description': 'Consider implementing time-based access restrictions for sensitive systems outside of business hours.'
        })
    
    return recommendations

def extract_location_from_ip(ip_address):
    """Extract general location from IP address (simplified version)."""
    if not ip_address:
        return "Unknown"
    
    # In a real system this would use a GeoIP database or API
    # For this simplified implementation:
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private:
            return "Internal Network"
        
        # First octet-based mock geolocation (simplified)
        first_octet = int(ip_address.split('.')[0])
        if first_octet < 50:
            return "North America"
        elif first_octet < 100:
            return "Europe"
        elif first_octet < 150:
            return "Asia"
        elif first_octet < 200:
            return "South America"
        else:
            return "Other"
    except:
        return "Unknown"

def cosine_similarity(v1, v2):
    """Calculate cosine similarity between two vectors."""
    v1, v2 = np.array(v1), np.array(v2)
    dot_product = np.dot(v1, v2)
    norm_v1 = np.linalg.norm(v1)
    norm_v2 = np.linalg.norm(v2)
    
    if norm_v1 == 0 or norm_v2 == 0:
        return 0
    
    return dot_product / (norm_v1 * norm_v2)

def get_user_agent_info(user_agent_string):
    """Extract detailed browser and OS information from user agent string."""
    if not user_agent_string:
        return {'browser': 'Unknown', 'browser_version': '', 'operating_system': 'Unknown', 'os_version': '', 'device_type': 'Unknown'}
    
    user_agent = str(user_agent_string)
    result = {
        'browser': 'Unknown',
        'browser_version': '',
        'operating_system': 'Unknown',
        'os_version': '',
        'device_type': 'Desktop'  # Default
    }
    
    # Device type detection
    if any(mobile_indicator in user_agent.lower() for mobile_indicator in 
           ['mobile', 'android', 'iphone', 'ipod', 'ipad', 'windows phone', 'blackberry']):
        result['device_type'] = 'Mobile'
    elif any(tablet_indicator in user_agent.lower() for tablet_indicator in 
             ['ipad', 'tablet', 'kindle']):
        result['device_type'] = 'Tablet'
    
    # Browser detection with versions
    browsers_with_patterns = {
        'Chrome': (r'Chrome/(\d+\.\d+)', r'Chromium/(\d+\.\d+)'),
        'Firefox': (r'Firefox/(\d+\.\d+)',),
        'Safari': (r'Version/(\d+\.\d+).*Safari',),
        'Edge': (r'Edge/(\d+\.\d+)', r'Edg/(\d+\.\d+)'),
        'Opera': (r'Opera/.*Version/(\d+\.\d+)', r'OPR/(\d+\.\d+)'),
        'Internet Explorer': (r'MSIE (\d+\.\d+)', r'Trident/.*rv:(\d+\.\d+)'),
        'Samsung Browser': (r'SamsungBrowser/(\d+\.\d+)',),
        'UC Browser': (r'UCBrowser/(\d+\.\d+)',)
    }
    
    for browser_name, patterns in browsers_with_patterns.items():
        for pattern in patterns:
            match = re.search(pattern, user_agent)
            if match:
                result['browser'] = browser_name
                result['browser_version'] = match.group(1)
                break
        if result['browser'] != 'Unknown':
            break
    
    # OS detection with versions
    os_patterns = {
        'Windows': [
            (r'Windows NT 10\.0', 'Windows 10/11'),
            (r'Windows NT 6\.3', 'Windows 8.1'),
            (r'Windows NT 6\.2', 'Windows 8'),
            (r'Windows NT 6\.1', 'Windows 7'),
            (r'Windows NT 6\.0', 'Windows Vista'),
            (r'Windows NT 5\.1', 'Windows XP'),
            (r'Windows NT 5\.0', 'Windows 2000')
        ],
        'Mac OS': [
            (r'Mac OS X (\d+[._]\d+[._]?\d*)', 'Mac OS')
        ],
        'iOS': [
            (r'iPhone OS (\d+[._]\d+[._]?\d*)', 'iOS'),
            (r'iPad.*OS (\d+[._]\d+[._]?\d*)', 'iOS')
        ],
        'Android': [
            (r'Android (\d+[._]\d+[._]?\d*)', 'Android')
        ],
        'Linux': [
            (r'Linux', 'Linux')
        ]
    }
    
    for os_name, patterns in os_patterns.items():
        for pattern, os_label in patterns:
            match = re.search(pattern, user_agent)
            if match:
                result['operating_system'] = os_label
                if len(match.groups()) > 0:
                    version = match.group(1).replace('_', '.')
                    result['os_version'] = version
                break
        if result['operating_system'] != 'Unknown':
            break
    
    return result
