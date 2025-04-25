import requests
import logging
import json
import os
import hashlib
import re
import ipaddress
import time
from datetime import datetime, timedelta
import uuid
from urllib.parse import urlparse
from requests.exceptions import RequestException, Timeout
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

# Default configuration values - should be overridden by environment variables or settings
DEFAULT_CONFIG = {
    'cache_duration_hours': 24,
    'concurrent_requests': 5,
    'request_timeout': 10,
    'max_retries': 3,
    'retry_delay': 2,
    'user_agent': 'CyberTech-ThreatIntel/1.0',
}

class ThreatIntelligence:
    """
    Provides threat intelligence capabilities by querying external sources.
    """
    
    def __init__(self, api_keys=None, config=None):
        """
        Initialize the threat intelligence module.
        
        Args:
            api_keys (dict): API keys for external services
            config (dict): Configuration options
        """
        self.api_keys = api_keys or {}
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.cache = {}
        self.cache_timestamps = {}
        self.cache_stats = {'hits': 0, 'misses': 0}
        self.available_sources = self._get_available_sources()
    
    def _get_available_sources(self):
        """
        Determine which threat intelligence sources are available based on API keys.
        
        Returns:
            dict: Available sources with status
        """
        sources = {
            'virustotal': {
                'enabled': 'virustotal' in self.api_keys,
                'name': 'VirusTotal',
                'api_key_name': 'virustotal',
                'capabilities': ['ip_reputation', 'domain_reputation', 'file_analysis', 'url_analysis']
            },
            'abuseipdb': {
                'enabled': 'abuseipdb' in self.api_keys,
                'name': 'AbuseIPDB',
                'api_key_name': 'abuseipdb',
                'capabilities': ['ip_reputation']
            },
            'otx': {
                'enabled': 'otx' in self.api_keys,
                'name': 'AlienVault OTX',
                'api_key_name': 'otx',
                'capabilities': ['ip_reputation', 'domain_reputation', 'url_analysis']
            },
            'ibm_xforce': {
                'enabled': 'ibm_xforce_key' in self.api_keys and 'ibm_xforce_password' in self.api_keys,
                'name': 'IBM X-Force Exchange',
                'api_key_name': 'ibm_xforce_key',
                'capabilities': ['ip_reputation', 'domain_reputation', 'url_analysis']
            },
            'threatfox': {
                'enabled': 'threatfox' in self.api_keys,
                'name': 'ThreatFox',
                'api_key_name': 'threatfox',
                'capabilities': ['ip_reputation', 'domain_reputation', 'indicator_lookup']
            },
            'local': {
                'enabled': True,
                'name': 'Local Intelligence DB',
                'api_key_name': None,
                'capabilities': ['ip_reputation', 'domain_reputation', 'indicator_lookup']
            }
        }
        
        return sources
    
    def check_ip_reputation(self, ip_address, sources=None, force_refresh=False):
        """
        Check the reputation of an IP address using threat intelligence sources.
        
        Args:
            ip_address (str): IP address to check
            sources (list): List of source names to query (default: all available)
            force_refresh (bool): Force refresh of cached data
            
        Returns:
            dict: IP reputation data from multiple sources
        """
        try:
            # Validate IP address
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                return {
                    'status': 'error',
                    'message': f"Invalid IP address: {ip_address}",
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            # Check cache first
            cache_key = f"ip_{ip_address}"
            cached_result = self._check_cache(cache_key)
            
            if cached_result and not force_refresh:
                return cached_result
            
            # Determine sources to query
            available_sources = self._get_ip_reputation_sources(sources)
            
            if not available_sources:
                return {
                    'status': 'error',
                    'message': "No available sources for IP reputation",
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            # Query each source
            results = {}
            
            with ThreadPoolExecutor(max_workers=self.config['concurrent_requests']) as executor:
                # Create future tasks
                futures = {}
                
                for source_id, source_info in available_sources.items():
                    if source_id == 'virustotal' and source_info['enabled']:
                        futures[executor.submit(self._query_virustotal_ip, ip_address)] = 'virustotal'
                    elif source_id == 'abuseipdb' and source_info['enabled']:
                        futures[executor.submit(self._query_abuseipdb, ip_address)] = 'abuseipdb'
                    elif source_id == 'otx' and source_info['enabled']:
                        futures[executor.submit(self._query_otx_ip, ip_address)] = 'otx'
                    elif source_id == 'ibm_xforce' and source_info['enabled']:
                        futures[executor.submit(self._query_xforce_ip, ip_address)] = 'ibm_xforce'
                    elif source_id == 'threatfox' and source_info['enabled']:
                        futures[executor.submit(self._query_threatfox_ip, ip_address)] = 'threatfox'
                    elif source_id == 'local' and source_info['enabled']:
                        futures[executor.submit(self._query_local_intelligence, 'ip', ip_address)] = 'local'
                
                # Collect results as they complete
                for future in futures:
                    source_id = futures[future]
                    try:
                        result = future.result()
                        results[source_id] = result
                    except Exception as e:
                        logger.error(f"Error querying {source_id} for IP {ip_address}: {str(e)}")
                        results[source_id] = {
                            'status': 'error',
                            'message': str(e),
                            'timestamp': datetime.utcnow().isoformat()
                        }
            
            # Aggregate and analyze results
            aggregated_result = self._aggregate_ip_reputation_results(ip_address, results)
            
            # Cache the result
            self._update_cache(cache_key, aggregated_result)
            
            return aggregated_result
            
        except Exception as e:
            logger.error(f"Error checking IP reputation for {ip_address}: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def check_domain_reputation(self, domain, sources=None, force_refresh=False):
        """
        Check the reputation of a domain using threat intelligence sources.
        
        Args:
            domain (str): Domain to check
            sources (list): List of source names to query (default: all available)
            force_refresh (bool): Force refresh of cached data
            
        Returns:
            dict: Domain reputation data from multiple sources
        """
        try:
            # Validate domain
            if not self._is_valid_domain(domain):
                return {
                    'status': 'error',
                    'message': f"Invalid domain: {domain}",
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            # Check cache first
            cache_key = f"domain_{domain}"
            cached_result = self._check_cache(cache_key)
            
            if cached_result and not force_refresh:
                return cached_result
            
            # Determine sources to query
            available_sources = self._get_domain_reputation_sources(sources)
            
            if not available_sources:
                return {
                    'status': 'error',
                    'message': "No available sources for domain reputation",
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            # Query each source
            results = {}
            
            with ThreadPoolExecutor(max_workers=self.config['concurrent_requests']) as executor:
                # Create future tasks
                futures = {}
                
                for source_id, source_info in available_sources.items():
                    if source_id == 'virustotal' and source_info['enabled']:
                        futures[executor.submit(self._query_virustotal_domain, domain)] = 'virustotal'
                    elif source_id == 'otx' and source_info['enabled']:
                        futures[executor.submit(self._query_otx_domain, domain)] = 'otx'
                    elif source_id == 'ibm_xforce' and source_info['enabled']:
                        futures[executor.submit(self._query_xforce_domain, domain)] = 'ibm_xforce'
                    elif source_id == 'threatfox' and source_info['enabled']:
                        futures[executor.submit(self._query_threatfox_domain, domain)] = 'threatfox'
                    elif source_id == 'local' and source_info['enabled']:
                        futures[executor.submit(self._query_local_intelligence, 'domain', domain)] = 'local'
                
                # Collect results as they complete
                for future in futures:
                    source_id = futures[future]
                    try:
                        result = future.result()
                        results[source_id] = result
                    except Exception as e:
                        logger.error(f"Error querying {source_id} for domain {domain}: {str(e)}")
                        results[source_id] = {
                            'status': 'error',
                            'message': str(e),
                            'timestamp': datetime.utcnow().isoformat()
                        }
            
            # Aggregate and analyze results
            aggregated_result = self._aggregate_domain_reputation_results(domain, results)
            
            # Cache the result
            self._update_cache(cache_key, aggregated_result)
            
            return aggregated_result
            
        except Exception as e:
            logger.error(f"Error checking domain reputation for {domain}: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def check_url_reputation(self, url, sources=None, force_refresh=False):
        """
        Check the reputation of a URL using threat intelligence sources.
        
        Args:
            url (str): URL to check
            sources (list): List of source names to query (default: all available)
            force_refresh (bool): Force refresh of cached data
            
        Returns:
            dict: URL reputation data from multiple sources
        """
        try:
            # Validate URL
            try:
                parsed_url = urlparse(url)
                if not parsed_url.scheme or not parsed_url.netloc:
                    raise ValueError("Invalid URL format")
            except Exception:
                return {
                    'status': 'error',
                    'message': f"Invalid URL: {url}",
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            # Check cache first
            cache_key = f"url_{hashlib.md5(url.encode()).hexdigest()}"
            cached_result = self._check_cache(cache_key)
            
            if cached_result and not force_refresh:
                return cached_result
            
            # Determine sources to query
            available_sources = self._get_url_reputation_sources(sources)
            
            if not available_sources:
                return {
                    'status': 'error',
                    'message': "No available sources for URL reputation",
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            # Query each source
            results = {}
            
            with ThreadPoolExecutor(max_workers=self.config['concurrent_requests']) as executor:
                # Create future tasks
                futures = {}
                
                for source_id, source_info in available_sources.items():
                    if source_id == 'virustotal' and source_info['enabled']:
                        futures[executor.submit(self._query_virustotal_url, url)] = 'virustotal'
                    elif source_id == 'otx' and source_info['enabled']:
                        futures[executor.submit(self._query_otx_url, url)] = 'otx'
                    elif source_id == 'ibm_xforce' and source_info['enabled']:
                        futures[executor.submit(self._query_xforce_url, url)] = 'ibm_xforce'
                
                # Collect results as they complete
                for future in futures:
                    source_id = futures[future]
                    try:
                        result = future.result()
                        results[source_id] = result
                    except Exception as e:
                        logger.error(f"Error querying {source_id} for URL {url}: {str(e)}")
                        results[source_id] = {
                            'status': 'error',
                            'message': str(e),
                            'timestamp': datetime.utcnow().isoformat()
                        }
            
            # Aggregate and analyze results
            aggregated_result = self._aggregate_url_reputation_results(url, results)
            
            # Cache the result
            self._update_cache(cache_key, aggregated_result)
            
            return aggregated_result
            
        except Exception as e:
            logger.error(f"Error checking URL reputation for {url}: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def check_file_reputation(self, file_hash, sources=None, force_refresh=False):
        """
        Check the reputation of a file using its hash.
        
        Args:
            file_hash (str): File hash (MD5, SHA1, or SHA256)
            sources (list): List of source names to query (default: all available)
            force_refresh (bool): Force refresh of cached data
            
        Returns:
            dict: File reputation data from multiple sources
        """
        try:
            # Validate hash format
            if not self._is_valid_hash(file_hash):
                return {
                    'status': 'error',
                    'message': f"Invalid file hash format: {file_hash}",
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            # Check cache first
            cache_key = f"file_{file_hash}"
            cached_result = self._check_cache(cache_key)
            
            if cached_result and not force_refresh:
                return cached_result
            
            # Determine sources to query
            available_sources = self._get_file_reputation_sources(sources)
            
            if not available_sources:
                return {
                    'status': 'error',
                    'message': "No available sources for file reputation",
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            # Query each source
            results = {}
            
            with ThreadPoolExecutor(max_workers=self.config['concurrent_requests']) as executor:
                # Create future tasks
                futures = {}
                
                for source_id, source_info in available_sources.items():
                    if source_id == 'virustotal' and source_info['enabled']:
                        futures[executor.submit(self._query_virustotal_file, file_hash)] = 'virustotal'
                
                # Collect results as they complete
                for future in futures:
                    source_id = futures[future]
                    try:
                        result = future.result()
                        results[source_id] = result
                    except Exception as e:
                        logger.error(f"Error querying {source_id} for file hash {file_hash}: {str(e)}")
                        results[source_id] = {
                            'status': 'error',
                            'message': str(e),
                            'timestamp': datetime.utcnow().isoformat()
                        }
            
            # Aggregate and analyze results
            aggregated_result = self._aggregate_file_reputation_results(file_hash, results)
            
            # Cache the result
            self._update_cache(cache_key, aggregated_result)
            
            return aggregated_result
            
        except Exception as e:
            logger.error(f"Error checking file reputation for {file_hash}: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def batch_check_indicators(self, indicators):
        """
        Check a batch of indicators (IPs, domains, URLs, file hashes).
        
        Args:
            indicators (list): List of dictionaries with 'type' and 'value' keys
            
        Returns:
            dict: Results for each indicator
        """
        results = {}
        
        for indicator in indicators:
            indicator_type = indicator.get('type', '').lower()
            value = indicator.get('value', '')
            
            if not value:
                continue
                
            if indicator_type == 'ip':
                results[value] = self.check_ip_reputation(value)
            elif indicator_type == 'domain':
                results[value] = self.check_domain_reputation(value)
            elif indicator_type == 'url':
                results[value] = self.check_url_reputation(value)
            elif indicator_type in ('file', 'hash'):
                results[value] = self.check_file_reputation(value)
            else:
                results[value] = {
                    'status': 'error',
                    'message': f"Unsupported indicator type: {indicator_type}",
                    'timestamp': datetime.utcnow().isoformat()
                }
        
        return results
    
    def get_available_sources(self):
        """
        Get a list of available threat intelligence sources.
        
        Returns:
            dict: Available sources with capabilities
        """
        return self.available_sources
    
    def add_to_local_intelligence(self, indicator_type, value, reputation_data):
        """
        Add an indicator to the local threat intelligence database.
        
        Args:
            indicator_type (str): Type of indicator ('ip', 'domain', 'url', 'file')
            value (str): Indicator value
            reputation_data (dict): Reputation data for the indicator
            
        Returns:
            bool: True if successful
        """
        try:
            # Validate indicator type
            if indicator_type not in ('ip', 'domain', 'url', 'file'):
                return False
            
            # Validate value based on type
            if indicator_type == 'ip':
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    return False
            elif indicator_type == 'domain':
                if not self._is_valid_domain(value):
                    return False
            elif indicator_type == 'url':
                try:
                    parsed_url = urlparse(value)
                    if not parsed_url.scheme or not parsed_url.netloc:
                        return False
                except Exception:
                    return False
            elif indicator_type == 'file':
                if not self._is_valid_hash(value):
                    return False
            
            # Format the intelligence data
            intel_data = {
                'type': indicator_type,
                'value': value,
                'reputation': reputation_data,
                'timestamp': datetime.utcnow().isoformat(),
                'id': str(uuid.uuid4())
            }
            
            # In a real implementation, this would store to a database
            # For this demonstration, we'll use a simple file-based approach
            local_intel_file = os.path.join(os.path.dirname(__file__), 'local_intelligence.json')
            
            # Load existing intelligence
            existing_intel = []
            if os.path.exists(local_intel_file):
                try:
                    with open(local_intel_file, 'r') as f:
                        existing_intel = json.load(f)
                except Exception as e:
                    logger.error(f"Error loading local intelligence: {str(e)}")
            
            # Check if indicator already exists
            for i, item in enumerate(existing_intel):
                if item.get('type') == indicator_type and item.get('value') == value:
                    # Update existing entry
                    existing_intel[i] = intel_data
                    break
            else:
                # Add new entry
                existing_intel.append(intel_data)
            
            # Save updated intelligence
            with open(local_intel_file, 'w') as f:
                json.dump(existing_intel, f, indent=2)
            
            return True
            
        except Exception as e:
            logger.error(f"Error adding to local intelligence: {str(e)}")
            return False
    
    def get_cache_statistics(self):
        """
        Get statistics about the cache.
        
        Returns:
            dict: Cache statistics
        """
        return {
            'hits': self.cache_stats['hits'],
            'misses': self.cache_stats['misses'],
            'cache_size': len(self.cache),
            'hit_ratio': self.cache_stats['hits'] / (self.cache_stats['hits'] + self.cache_stats['misses']) if (self.cache_stats['hits'] + self.cache_stats['misses']) > 0 else 0
        }
    
    def clear_cache(self):
        """
        Clear the cache.
        
        Returns:
            int: Number of items cleared
        """
        count = len(self.cache)
        self.cache.clear()
        self.cache_timestamps.clear()
        return count
    
    # Internal methods
    
    def _check_cache(self, key):
        """
        Check if a key exists in the cache and is not expired.
        
        Args:
            key (str): Cache key
            
        Returns:
            dict or None: Cached data if found and not expired, None otherwise
        """
        if key in self.cache and key in self.cache_timestamps:
            timestamp = self.cache_timestamps[key]
            expiration = timestamp + timedelta(hours=self.config['cache_duration_hours'])
            
            if datetime.utcnow() < expiration:
                self.cache_stats['hits'] += 1
                return self.cache[key]
        
        self.cache_stats['misses'] += 1
        return None
    
    def _update_cache(self, key, data):
        """
        Update the cache with new data.
        
        Args:
            key (str): Cache key
            data (dict): Data to cache
        """
        self.cache[key] = data
        self.cache_timestamps[key] = datetime.utcnow()
    
    def _get_ip_reputation_sources(self, sources=None):
        """
        Get sources that support IP reputation lookups.
        
        Args:
            sources (list): List of source names to filter by
            
        Returns:
            dict: Sources that support IP reputation
        """
        return self._filter_sources_by_capability('ip_reputation', sources)
    
    def _get_domain_reputation_sources(self, sources=None):
        """
        Get sources that support domain reputation lookups.
        
        Args:
            sources (list): List of source names to filter by
            
        Returns:
            dict: Sources that support domain reputation
        """
        return self._filter_sources_by_capability('domain_reputation', sources)
    
    def _get_url_reputation_sources(self, sources=None):
        """
        Get sources that support URL reputation lookups.
        
        Args:
            sources (list): List of source names to filter by
            
        Returns:
            dict: Sources that support URL reputation
        """
        return self._filter_sources_by_capability('url_analysis', sources)
    
    def _get_file_reputation_sources(self, sources=None):
        """
        Get sources that support file reputation lookups.
        
        Args:
            sources (list): List of source names to filter by
            
        Returns:
            dict: Sources that support file reputation
        """
        return self._filter_sources_by_capability('file_analysis', sources)
    
    def _filter_sources_by_capability(self, capability, sources=None):
        """
        Filter sources by capability.
        
        Args:
            capability (str): Capability to filter by
            sources (list): List of source names to filter by
            
        Returns:
            dict: Sources that have the capability
        """
        result = {}
        
        for source_id, source_info in self.available_sources.items():
            if capability in source_info['capabilities'] and source_info['enabled']:
                if sources is None or source_id in sources:
                    result[source_id] = source_info
        
        return result
    
    def _is_valid_domain(self, domain):
        """
        Check if a domain name is valid.
        
        Args:
            domain (str): Domain name to check
            
        Returns:
            bool: True if valid
        """
        if not domain:
            return False
            
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, domain))
    
    def _is_valid_hash(self, file_hash):
        """
        Check if a file hash is valid.
        
        Args:
            file_hash (str): File hash to check
            
        Returns:
            bool: True if valid
        """
        if not file_hash:
            return False
            
        # Check for MD5, SHA-1, or SHA-256 format
        md5_pattern = r'^[a-fA-F0-9]{32}$'
        sha1_pattern = r'^[a-fA-F0-9]{40}$'
        sha256_pattern = r'^[a-fA-F0-9]{64}$'
        
        return bool(re.match(md5_pattern, file_hash) or 
                   re.match(sha1_pattern, file_hash) or 
                   re.match(sha256_pattern, file_hash))
    
    def _make_api_request(self, url, method='GET', headers=None, params=None, data=None, auth=None):
        """
        Make an API request with error handling and retries.
        
        Args:
            url (str): URL to request
            method (str): HTTP method
            headers (dict): HTTP headers
            params (dict): Query parameters
            data (dict): Request body data
            auth (tuple): Authentication credentials
            
        Returns:
            dict: Response data
        """
        headers = headers or {}
        headers['User-Agent'] = self.config['user_agent']
        
        for attempt in range(self.config['max_retries']):
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=data if data and method != 'GET' else None,
                    auth=auth,
                    timeout=self.config['request_timeout']
                )
                
                # Check for rate limiting
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', self.config['retry_delay']))
                    logger.warning(f"Rate limited by {url}, retrying after {retry_after} seconds")
                    time.sleep(retry_after)
                    continue
                
                # Check for successful response
                response.raise_for_status()
                
                # Parse response
                if response.content:
                    return response.json()
                else:
                    return {'status': 'success'}
                    
            except Timeout:
                logger.warning(f"Timeout connecting to {url}, attempt {attempt + 1}/{self.config['max_retries']}")
                if attempt < self.config['max_retries'] - 1:
                    time.sleep(self.config['retry_delay'])
            except RequestException as e:
                logger.error(f"Error connecting to {url}: {str(e)}")
                if attempt < self.config['max_retries'] - 1:
                    time.sleep(self.config['retry_delay'])
                else:
                    raise
        
        raise RequestException(f"Failed to connect to {url} after {self.config['max_retries']} attempts")
    
    # VirusTotal API methods
    
    def _query_virustotal_ip(self, ip_address):
        """Query VirusTotal for IP reputation."""
        if 'virustotal' not in self.api_keys:
            return {'status': 'error', 'message': 'VirusTotal API key not configured'}
        
        api_key = self.api_keys['virustotal']
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {'x-apikey': api_key}
        
        try:
            response = self._make_api_request(url, headers=headers)
            
            # Process and normalize the response
            if 'data' in response:
                data = response['data']
                attributes = data.get('attributes', {})
                
                # Extract key information
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                detection_count = last_analysis_stats.get('malicious', 0)
                total_engines = sum(last_analysis_stats.values())
                
                # Determine a severity score based on detections
                if detection_count >= 5:
                    severity = 'high'
                elif detection_count >= 2:
                    severity = 'medium'
                elif detection_count >= 1:
                    severity = 'low'
                else:
                    severity = 'clean'
                
                return {
                    'status': 'success',
                    'source': 'VirusTotal',
                    'ip': ip_address,
                    'detection_count': detection_count,
                    'detection_ratio': f"{detection_count}/{total_engines}",
                    'categories': attributes.get('categories', {}),
                    'country': attributes.get('country', 'Unknown'),
                    'as_owner': attributes.get('as_owner', 'Unknown'),
                    'reputation': attributes.get('reputation', 0),
                    'severity': severity,
                    'last_analysis_date': attributes.get('last_analysis_date', 0),
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            return {
                'status': 'error',
                'message': 'Unexpected response format from VirusTotal',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error querying VirusTotal for IP {ip_address}: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _query_virustotal_domain(self, domain):
        """Query VirusTotal for domain reputation."""
        if 'virustotal' not in self.api_keys:
            return {'status': 'error', 'message': 'VirusTotal API key not configured'}
        
        api_key = self.api_keys['virustotal']
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {'x-apikey': api_key}
        
        try:
            response = self._make_api_request(url, headers=headers)
            
            # Process and normalize the response
            if 'data' in response:
                data = response['data']
                attributes = data.get('attributes', {})
                
                # Extract key information
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                detection_count = last_analysis_stats.get('malicious', 0)
                total_engines = sum(last_analysis_stats.values())
                
                # Determine a severity score based on detections
                if detection_count >= 5:
                    severity = 'high'
                elif detection_count >= 2:
                    severity = 'medium'
                elif detection_count >= 1:
                    severity = 'low'
                else:
                    severity = 'clean'
                
                return {
                    'status': 'success',
                    'source': 'VirusTotal',
                    'domain': domain,
                    'detection_count': detection_count,
                    'detection_ratio': f"{detection_count}/{total_engines}",
                    'categories': attributes.get('categories', {}),
                    'creation_date': attributes.get('creation_date', 0),
                    'registrar': attributes.get('registrar', 'Unknown'),
                    'reputation': attributes.get('reputation', 0),
                    'severity': severity,
                    'last_analysis_date': attributes.get('last_analysis_date', 0),
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            return {
                'status': 'error',
                'message': 'Unexpected response format from VirusTotal',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error querying VirusTotal for domain {domain}: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _query_virustotal_url(self, url):
        """Query VirusTotal for URL reputation."""
        if 'virustotal' not in self.api_keys:
            return {'status': 'error', 'message': 'VirusTotal API key not configured'}
        
        api_key = self.api_keys['virustotal']
        # URL ID is the base64 of the URL
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
        request_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {'x-apikey': api_key}
        
        try:
            response = self._make_api_request(request_url, headers=headers)
            
            # Process and normalize the response
            if 'data' in response:
                data = response['data']
                attributes = data.get('attributes', {})
                
                # Extract key information
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                detection_count = last_analysis_stats.get('malicious', 0)
                total_engines = sum(last_analysis_stats.values())
                
                # Determine a severity score based on detections
                if detection_count >= 5:
                    severity = 'high'
                elif detection_count >= 2:
                    severity = 'medium'
                elif detection_count >= 1:
                    severity = 'low'
                else:
                    severity = 'clean'
                
                return {
                    'status': 'success',
                    'source': 'VirusTotal',
                    'url': url,
                    'detection_count': detection_count,
                    'detection_ratio': f"{detection_count}/{total_engines}",
                    'categories': attributes.get('categories', {}),
                    'first_submission_date': attributes.get('first_submission_date', 0),
                    'last_modification_date': attributes.get('last_modification_date', 0),
                    'severity': severity,
                    'last_analysis_date': attributes.get('last_analysis_date', 0),
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            return {
                'status': 'error',
                'message': 'Unexpected response format from VirusTotal',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error querying VirusTotal for URL {url}: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _query_virustotal_file(self, file_hash):
        """Query VirusTotal for file reputation."""
        if 'virustotal' not in self.api_keys:
            return {'status': 'error', 'message': 'VirusTotal API key not configured'}
        
        api_key = self.api_keys['virustotal']
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {'x-apikey': api_key}
        
        try:
            response = self._make_api_request(url, headers=headers)
            
            # Process and normalize the response
            if 'data' in response:
                data = response['data']
                attributes = data.get('attributes', {})
                
                # Extract key information
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                detection_count = last_analysis_stats.get('malicious', 0)
                total_engines = sum(last_analysis_stats.values())
                
                # Determine a severity score based on detections
                if detection_count >= 5:
                    severity = 'high'
                elif detection_count >= 2:
                    severity = 'medium'
                elif detection_count >= 1:
                    severity = 'low'
                else:
                    severity = 'clean'
                
                return {
                    'status': 'success',
                    'source': 'VirusTotal',
                    'file_hash': file_hash,
                    'detection_count': detection_count,
                    'detection_ratio': f"{detection_count}/{total_engines}",
                    'type_description': attributes.get('type_description', 'Unknown'),
                    'size': attributes.get('size', 0),
                    'file_type': attributes.get('type_tag', 'Unknown'),
                    'names': attributes.get('names', []),
                    'severity': severity,
                    'last_analysis_date': attributes.get('last_analysis_date', 0),
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            return {
                'status': 'error',
                'message': 'Unexpected response format from VirusTotal',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error querying VirusTotal for file hash {file_hash}: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    # AbuseIPDB API methods
    
    def _query_abuseipdb(self, ip_address):
        """Query AbuseIPDB for IP reputation."""
        if 'abuseipdb' not in self.api_keys:
            return {'status': 'error', 'message': 'AbuseIPDB API key not configured'}
        
        api_key = self.api_keys['abuseipdb']
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {'Key': api_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip_address, 'maxAgeInDays': 90, 'verbose': True}
        
        try:
            response = self._make_api_request(url, headers=headers, params=params)
            
            # Process and normalize the response
            if 'data' in response:
                data = response['data']
                
                # Determine severity based on abuse confidence score
                confidence_score = data.get('abuseConfidenceScore', 0)
                if confidence_score >= 90:
                    severity = 'high'
                elif confidence_score >= 60:
                    severity = 'medium'
                elif confidence_score >= 20:
                    severity = 'low'
                else:
                    severity = 'clean'
                
                return {
                    'status': 'success',
                    'source': 'AbuseIPDB',
                    'ip': ip_address,
                    'abuse_confidence_score': confidence_score,
                    'total_reports': data.get('totalReports', 0),
                    'country_code': data.get('countryCode', 'Unknown'),
                    'domain': data.get('domain', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'usage_type': data.get('usageType', 'Unknown'),
                    'severity': severity,
                    'last_reported_at': data.get('lastReportedAt', ''),
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            return {
                'status': 'error',
                'message': 'Unexpected response format from AbuseIPDB',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error querying AbuseIPDB for IP {ip_address}: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    # AlienVault OTX API methods
    
    def _query_otx_ip(self, ip_address):
        """Query AlienVault OTX for IP reputation."""
        if 'otx' not in self.api_keys:
            return {'status': 'error', 'message': 'AlienVault OTX API key not configured'}
        
        api_key = self.api_keys['otx']
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
        headers = {'X-OTX-API-KEY': api_key}
        
        try:
            response = self._make_api_request(url, headers=headers)
            
            # Process and normalize the response
            if 'pulse_info' in response:
                pulse_info = response['pulse_info']
                pulse_count = pulse_info.get('count', 0)
                
                # Determine severity based on pulse count (number of times this IP was reported in threat intelligence)
                if pulse_count >= 10:
                    severity = 'high'
                elif pulse_count >= 5:
                    severity = 'medium'
                elif pulse_count >= 1:
                    severity = 'low'
                else:
                    severity = 'clean'
                
                return {
                    'status': 'success',
                    'source': 'AlienVault OTX',
                    'ip': ip_address,
                    'pulse_count': pulse_count,
                    'reputation': response.get('reputation', 0),
                    'country_code': response.get('country_code', 'Unknown'),
                    'asn': response.get('asn', 'Unknown'),
                    'city': response.get('city', 'Unknown'),
                    'severity': severity,
                    'tags': [p.get('name', '') for p in pulse_info.get('pulses', [])],
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            return {
                'status': 'error',
                'message': 'Unexpected response format from AlienVault OTX',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error querying AlienVault OTX for IP {ip_address}: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _query_otx_domain(self, domain):
        """Query AlienVault OTX for domain reputation."""
        if 'otx' not in self.api_keys:
            return {'status': 'error', 'message': 'AlienVault OTX API key not configured'}
        
        api_key = self.api_keys['otx']
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        headers = {'X-OTX-API-KEY': api_key}
        
        try:
            response = self._make_api_request(url, headers=headers)
            
            # Process and normalize the response
            if 'pulse_info' in response:
                pulse_info = response['pulse_info']
                pulse_count = pulse_info.get('count', 0)
                
                # Determine severity based on pulse count
                if pulse_count >= 10:
                    severity = 'high'
                elif pulse_count >= 5:
                    severity = 'medium'
                elif pulse_count >= 1:
                    severity = 'low'
                else:
                    severity = 'clean'
                
                return {
                    'status': 'success',
                    'source': 'AlienVault OTX',
                    'domain': domain,
                    'pulse_count': pulse_count,
                    'alexa': response.get('alexa', 'Unknown'),
                    'whois': response.get('whois', 'Unknown'),
                    'severity': severity,
                    'tags': [p.get('name', '') for p in pulse_info.get('pulses', [])],
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            return {
                'status': 'error',
                'message': 'Unexpected response format from AlienVault OTX',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error querying AlienVault OTX for domain {domain}: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _query_otx_url(self, url):
        """Query AlienVault OTX for URL reputation."""
        if 'otx' not in self.api_keys:
            return {'status': 'error', 'message': 'AlienVault OTX API key not configured'}
        
        api_key = self.api_keys['otx']
        # URL needs to be encoded for the API
        encoded_url = base64.b64encode(url.encode()).decode()
        api_url = f"https://otx.alienvault.com/api/v1/indicators/url/{encoded_url}/general"
        headers = {'X-OTX-API-KEY': api_key}
        
        try:
            response = self._make_api_request(api_url, headers=headers)
            
            # Process and normalize the response
            if 'pulse_info' in response:
                pulse_info = response['pulse_info']
                pulse_count = pulse_info.get('count', 0)
                
                # Determine severity based on pulse count
                if pulse_count >= 10:
                    severity = 'high'
                elif pulse_count >= 5:
                    severity = 'medium'
                elif pulse_count >= 1:
                    severity = 'low'
                else:
                    severity = 'clean'
                
                return {
                    'status': 'success',
                    'source': 'AlienVault OTX',
                    'url': url,
                    'pulse_count': pulse_count,
                    'severity': severity,
                    'tags': [p.get('name', '') for p in pulse_info.get('pulses', [])],
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            return {
                'status': 'error',
                'message': 'Unexpected response format from AlienVault OTX',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error querying AlienVault OTX for URL {url}: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    # IBM X-Force Exchange API methods
    
    def _query_xforce_ip(self, ip_address):
        """Query IBM X-Force Exchange for IP reputation."""
        if 'ibm_xforce_key' not in self.api_keys or 'ibm_xforce_password' not in self.api_keys:
            return {'status': 'error', 'message': 'IBM X-Force API credentials not configured'}
        
        api_key = self.api_keys['ibm_xforce_key']
        api_password = self.api_keys['ibm_xforce_password']
        url = f"https://api.xforce.ibmcloud.com/ipr/{ip_address}"
        auth = (api_key, api_password)
        
        try:
            response = self._make_api_request(url, auth=auth)
            
            # Process and normalize the response
            if 'score' in response:
                score = response.get('score', 0)
                
                # Determine severity based on X-Force score (0-10)
                if score >= 7:
                    severity = 'high'
                elif score >= 4:
                    severity = 'medium'
                elif score >= 1:
                    severity = 'low'
                else:
                    severity = 'clean'
                
                return {
                    'status': 'success',
                    'source': 'IBM X-Force',
                    'ip': ip_address,
                    'score': score,
                    'categories': response.get('cats', {}),
                    'reason': response.get('reason', ''),
                    'geo': response.get('geo', {}),
                    'severity': severity,
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            return {
                'status': 'error',
                'message': 'Unexpected response format from IBM X-Force',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error querying IBM X-Force for IP {ip_address}: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _query_xforce_domain(self, domain):
        """Query IBM X-Force Exchange for domain reputation."""
        if 'ibm_xforce_key' not in self.api_keys or 'ibm_xforce_password' not in self.api_keys:
            return {'status': 'error', 'message': 'IBM X-Force API credentials not configured'}
        
        api_key = self.api_keys['ibm_xforce_key']
        api_password = self.api_keys['ibm_xforce_password']
        url = f"https://api.xforce.ibmcloud.com/url/{domain}"
        auth = (api_key, api_password)
        
        try:
            response = self._make_api_request(url, auth=auth)
            
            # Process and normalize the response
            if 'result' in response:
                result = response.get('result', {})
                score = result.get('score', 0)
                
                # Determine severity based on X-Force score (0-10)
                if score >= 7:
                    severity = 'high'
                elif score >= 4:
                    severity = 'medium'
                elif score >= 1:
                    severity = 'low'
                else:
                    severity = 'clean'
                
                return {
                    'status': 'success',
                    'source': 'IBM X-Force',
                    'domain': domain,
                    'score': score,
                    'categories': result.get('cats', {}),
                    'severity': severity,
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            return {
                'status': 'error',
                'message': 'Unexpected response format from IBM X-Force',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error querying IBM X-Force for domain {domain}: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _query_xforce_url(self, url):
        """Query IBM X-Force Exchange for URL reputation."""
        if 'ibm_xforce_key' not in self.api_keys or 'ibm_xforce_password' not in self.api_keys:
            return {'status': 'error', 'message': 'IBM X-Force API credentials not configured'}
        
        api_key = self.api_keys['ibm_xforce_key']
        api_password = self.api_keys['ibm_xforce_password']
        # URL needs to be encoded for the API
        encoded_url = requests.utils.quote(url, safe='')
        api_url = f"https://api.xforce.ibmcloud.com/url/{encoded_url}"
        auth = (api_key, api_password)
        
        try:
            response = self._make_api_request(api_url, auth=auth)
            
            # Process and normalize the response
            if 'result' in response:
                result = response.get('result', {})
                score = result.get('score', 0)
                
                # Determine severity based on X-Force score (0-10)
                if score >= 7:
                    severity = 'high'
                elif score >= 4:
                    severity = 'medium'
                elif score >= 1:
                    severity = 'low'
                else:
                    severity = 'clean'
                
                return {
                    'status': 'success',
                    'source': 'IBM X-Force',
                    'url': url,
                    'score': score,
                    'categories': result.get('cats', {}),
                    'severity': severity,
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            return {
                'status': 'error',
                'message': 'Unexpected response format from IBM X-Force',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error querying IBM X-Force for URL {url}: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    # ThreatFox API methods
    
    def _query_threatfox_ip(self, ip_address):
        """Query ThreatFox for IP reputation."""
        if 'threatfox' not in self.api_keys:
            return {'status': 'error', 'message': 'ThreatFox API key not configured'}
        
        api_key = self.api_keys['threatfox']
        url = "https://threatfox-api.abuse.ch/api/v1/"
        data = {
            "query": "search_ioc",
            "search_term": ip_address,
            "days": 90
        }
        
        try:
            response = self._make_api_request(url, method='POST', data=data)
            
            # Process and normalize the response
            if 'data' in response and response.get('query_status') == 'ok':
                data = response['data']
                
                # If no results, return clean
                if not data:
                    return {
                        'status': 'success',
                        'source': 'ThreatFox',
                        'ip': ip_address,
                        'ioc_count': 0,
                        'severity': 'clean',
                        'timestamp': datetime.utcnow().isoformat()
                    }
                
                # Get malware families and confidence
                malware_families = set()
                for ioc in data:
                    if 'malware' in ioc:
                        malware_families.add(ioc['malware'])
                
                # Determine severity based on number of indicators and malware families
                if len(data) >= 5 or len(malware_families) >= 2:
                    severity = 'high'
                elif len(data) >= 2:
                    severity = 'medium'
                else:
                    severity = 'low'
                
                return {
                    'status': 'success',
                    'source': 'ThreatFox',
                    'ip': ip_address,
                    'ioc_count': len(data),
                    'malware_families': list(malware_families),
                    'first_seen': min(ioc.get('first_seen', '') for ioc in data) if data else '',
                    'last_seen': max(ioc.get('last_seen', '') for ioc in data) if data else '',
                    'severity': severity,
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            # If no results or error, return clean
            if response.get('query_status') == 'no_result':
                return {
                    'status': 'success',
                    'source': 'ThreatFox',
                    'ip': ip_address,
                    'ioc_count': 0,
                    'severity': 'clean',
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            return {
                'status': 'error',
                'message': 'Unexpected response format from ThreatFox',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error querying ThreatFox for IP {ip_address}: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _query_threatfox_domain(self, domain):
        """Query ThreatFox for domain reputation."""
        if 'threatfox' not in self.api_keys:
            return {'status': 'error', 'message': 'ThreatFox API key not configured'}
        
        api_key = self.api_keys['threatfox']
        url = "https://threatfox-api.abuse.ch/api/v1/"
        data = {
            "query": "search_ioc",
            "search_term": domain,
            "days": 90
        }
        
        # Results processing is very similar to IP reputation
        return self._query_threatfox_ip(domain)
    
    # Local intelligence database methods
    
    def _query_local_intelligence(self, indicator_type, value):
        """Query local intelligence database."""
        try:
            # In a real implementation, this would query a database
            # For this demonstration, we'll use a simple file-based approach
            local_intel_file = os.path.join(os.path.dirname(__file__), 'local_intelligence.json')
            
            if not os.path.exists(local_intel_file):
                return {
                    'status': 'success',
                    'source': 'Local Intelligence',
                    'indicator_type': indicator_type,
                    'value': value,
                    'found': False,
                    'severity': 'clean',
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            # Load local intelligence
            with open(local_intel_file, 'r') as f:
                local_intel = json.load(f)
            
            # Search for the indicator
            for item in local_intel:
                if item.get('type') == indicator_type and item.get('value') == value:
                    # Found a match
                    reputation = item.get('reputation', {})
                    
                    return {
                        'status': 'success',
                        'source': 'Local Intelligence',
                        'indicator_type': indicator_type,
                        'value': value,
                        'found': True,
                        'reputation': reputation,
                        'severity': reputation.get('severity', 'medium'),
                        'added_at': item.get('timestamp', ''),
                        'timestamp': datetime.utcnow().isoformat()
                    }
            
            # No match found
            return {
                'status': 'success',
                'source': 'Local Intelligence',
                'indicator_type': indicator_type,
                'value': value,
                'found': False,
                'severity': 'clean',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error querying local intelligence for {indicator_type} {value}: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    # Results aggregation methods
    
    def _aggregate_ip_reputation_results(self, ip_address, results):
        """
        Aggregate IP reputation results from multiple sources.
        
        Args:
            ip_address (str): The IP address
            results (dict): Results from multiple sources
            
        Returns:
            dict: Aggregated results
        """
        if not results:
            return {
                'status': 'error',
                'message': 'No results available',
                'timestamp': datetime.utcnow().isoformat()
            }
        
        # Count by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'clean': 0}
        
        for source, result in results.items():
            if result.get('status') == 'success':
                severity = result.get('severity', 'unknown')
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        # Determine overall severity
        if severity_counts['critical'] > 0 or severity_counts['high'] >= 2:
            overall_severity = 'critical'
        elif severity_counts['high'] > 0 or severity_counts['medium'] >= 2:
            overall_severity = 'high'
        elif severity_counts['medium'] > 0 or severity_counts['low'] >= 2:
            overall_severity = 'medium'
        elif severity_counts['low'] > 0:
            overall_severity = 'low'
        else:
            overall_severity = 'clean'
        
        # Calculate risk score (0-100)
        risk_score = min(100, (
            severity_counts['critical'] * 100 +
            severity_counts['high'] * 70 +
            severity_counts['medium'] * 40 +
            severity_counts['low'] * 10
        ) / max(1, len(results)))
        
        # Create summary
        categories = set()
        for source, result in results.items():
            if result.get('status') == 'success' and 'categories' in result:
                if isinstance(result['categories'], dict):
                    categories.update(result['categories'].keys())
                elif isinstance(result['categories'], list):
                    categories.update(result['categories'])
        
        # Generate the aggregated result
        return {
            'status': 'success',
            'ip': ip_address,
            'overall_severity': overall_severity,
            'risk_score': risk_score,
            'severity_counts': severity_counts,
            'categories': list(categories),
            'results': results,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _aggregate_domain_reputation_results(self, domain, results):
        """
        Aggregate domain reputation results from multiple sources.
        
        Args:
            domain (str): The domain name
            results (dict): Results from multiple sources
            
        Returns:
            dict: Aggregated results
        """
        # Very similar to IP reputation aggregation
        return self._aggregate_ip_reputation_results(domain, results)
    
    def _aggregate_url_reputation_results(self, url, results):
        """
        Aggregate URL reputation results from multiple sources.
        
        Args:
            url (str): The URL
            results (dict): Results from multiple sources
            
        Returns:
            dict: Aggregated results
        """
        # Very similar to IP reputation aggregation
        if not results:
            return {
                'status': 'error',
                'message': 'No results available',
                'timestamp': datetime.utcnow().isoformat()
            }
        
        # Extract domain for additional context
        try:
            domain = urlparse(url).netloc
        except:
            domain = ""
        
        # Count by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'clean': 0}
        
        for source, result in results.items():
            if result.get('status') == 'success':
                severity = result.get('severity', 'unknown')
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        # Determine overall severity
        if severity_counts['critical'] > 0 or severity_counts['high'] >= 2:
            overall_severity = 'critical'
        elif severity_counts['high'] > 0 or severity_counts['medium'] >= 2:
            overall_severity = 'high'
        elif severity_counts['medium'] > 0 or severity_counts['low'] >= 2:
            overall_severity = 'medium'
        elif severity_counts['low'] > 0:
            overall_severity = 'low'
        else:
            overall_severity = 'clean'
        
        # Calculate risk score (0-100)
        risk_score = min(100, (
            severity_counts['critical'] * 100 +
            severity_counts['high'] * 70 +
            severity_counts['medium'] * 40 +
            severity_counts['low'] * 10
        ) / max(1, len(results)))
        
        # Generate the aggregated result
        return {
            'status': 'success',
            'url': url,
            'domain': domain,
            'overall_severity': overall_severity,
            'risk_score': risk_score,
            'severity_counts': severity_counts,
            'results': results,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _aggregate_file_reputation_results(self, file_hash, results):
        """
        Aggregate file reputation results from multiple sources.
        
        Args:
            file_hash (str): The file hash
            results (dict): Results from multiple sources
            
        Returns:
            dict: Aggregated results
        """
        # Very similar to IP reputation aggregation
        return self._aggregate_ip_reputation_results(file_hash, results)