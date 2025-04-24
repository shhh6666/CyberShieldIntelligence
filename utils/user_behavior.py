import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import logging
from collections import Counter
import re

logger = logging.getLogger(__name__)

def analyze_user_behavior(activities, timeframe_days=30):
    """
    Analyze user behavior patterns from activity logs.
    
    Args:
        activities (list): List of UserActivity objects
        timeframe_days (int): Number of days to analyze
        
    Returns:
        dict: User behavior analysis results
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
                'details': activity.details
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
        
        # Analyze login patterns
        login_data = df[df['activity_type'] == 'login']
        login_times = pd.to_datetime(login_data['timestamp']).dt.hour
        unusual_hours = [h for h in login_times if h < 6 or h > 22]  # Logins outside 6am-10pm
        
        # Analyze login locations (based on IP)
        unique_ips = login_data['ip_address'].nunique()
        
        # Analyze activity types
        activity_counts = df['activity_type'].value_counts().to_dict()
        
        # Detect unusual patterns
        unusual_patterns = []
        
        # 1. Multiple logins from different IPs in short time
        if unique_ips > 3:
            unusual_patterns.append({
                'type': 'multiple_ips',
                'severity': 'medium',
                'description': f'Logins from {unique_ips} different IP addresses detected'
            })
        
        # 2. Logins at unusual hours
        if len(unusual_hours) > 0:
            unusual_patterns.append({
                'type': 'unusual_hours',
                'severity': 'low',
                'description': f'{len(unusual_hours)} logins detected outside normal hours (6am-10pm)'
            })
        
        # 3. Unusual activity spikes
        common_activities = ['login', 'logout', 'view_page', 'dataset_upload']
        for activity in activity_counts:
            if activity not in common_activities and activity_counts[activity] > 10:
                unusual_patterns.append({
                    'type': 'activity_spike',
                    'severity': 'medium',
                    'description': f'Unusual spike in {activity} activity: {activity_counts[activity]} occurrences'
                })
        
        # 4. Failed login attempts (if available in data)
        failed_logins = len([a for a in df['details'] if isinstance(a, str) and 'failed' in a.lower() and 'login' in a.lower()])
        if failed_logins > 3:
            unusual_patterns.append({
                'type': 'failed_logins',
                'severity': 'high',
                'description': f'{failed_logins} failed login attempts detected'
            })
        
        # Generate summary
        result = {
            'status': 'success',
            'total_activities': len(df),
            'activity_distribution': activity_counts,
            'unique_ip_addresses': unique_ips,
            'most_active_hours': login_times.value_counts().to_dict(),
            'unusual_patterns': unusual_patterns,
            'risk_score': calculate_risk_score(unusual_patterns)
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Error in user behavior analysis: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }

def calculate_risk_score(unusual_patterns):
    """Calculate a risk score based on unusual patterns detected."""
    if not unusual_patterns:
        return 0
    
    severity_weights = {
        'low': 1,
        'medium': 3,
        'high': 5,
        'critical': 10
    }
    
    total_score = sum(severity_weights[p['severity']] for p in unusual_patterns)
    
    # Normalize to a 0-100 scale
    normalized_score = min(100, total_score * 5)  # Cap at 100
    return normalized_score

def get_user_agent_info(user_agent_string):
    """Extract browser and OS information from user agent string."""
    browser = "Unknown"
    os = "Unknown"
    
    # Extract browser info
    browsers = {
        'Chrome': r'Chrome/(\d+)',
        'Firefox': r'Firefox/(\d+)',
        'Safari': r'Safari/(\d+)',
        'Edge': r'Edge/(\d+)',
        'Opera': r'Opera|OPR/(\d+)'
    }
    
    for browser_name, pattern in browsers.items():
        match = re.search(pattern, user_agent_string)
        if match:
            browser = f"{browser_name} {match.group(1) if '(' in pattern else ''}"
            break
    
    # Extract OS info
    os_patterns = {
        'Windows': r'Windows NT (\d+\.\d+)',
        'Mac': r'Mac OS X (\d+[._]\d+)',
        'Linux': r'Linux',
        'iOS': r'iPhone OS (\d+)',
        'Android': r'Android (\d+)'
    }
    
    for os_name, pattern in os_patterns.items():
        match = re.search(pattern, user_agent_string)
        if match:
            if '(' in pattern and match.group(1):
                os = f"{os_name} {match.group(1).replace('_', '.')}"
            else:
                os = os_name
            break
    
    return {'browser': browser, 'operating_system': os}
