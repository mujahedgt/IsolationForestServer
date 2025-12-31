import json
import re
import math
from typing import Dict, Any, Set
from datetime import datetime
from collections import defaultdict


class FeatureExtractor:
    """Extracts numerical features from HTTP request data for the Isolation Forest model"""

    # Class-level cache for tracking request frequencies (in production, use Redis)
    _request_cache: Dict[str, list] = defaultdict(list)
    _cache_window = 3600  # 1 hour window in seconds

    # Known malicious patterns
    _SQL_PATTERNS = [
        r"(\bUNION\b.*\bSELECT\b)", r"(\bOR\b.*=.*)", r"(\bAND\b.*=.*)",
        r"(';|\"--)", r"(\bDROP\b.*\bTABLE\b)", r"(\bEXEC\b.*\()",
        r"(xp_cmdshell)", r"(@@version)"
    ]
    
    _XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>", r"javascript:", r"onerror\s*=",
        r"onload\s*=", r"onclick\s*=", r"<iframe", r"eval\s*\(",
        r"alert\s*\(", r"document\.cookie", r"window\.location"
    ]
    
    _PATH_TRAVERSAL_PATTERNS = [
        r"\.\./", r"\.\.\\", r"%2e%2e", r"%252e", r"..;/", r"..%00"
    ]
    
    _CMD_INJECTION_PATTERNS = [
        r";\s*(cat|ls|whoami|id|pwd|wget|curl)", r"\|\s*(cat|ls|whoami)",
        r"`.*`", r"\$\(.*\)", r"&&\s*\w+", r"\|\|\s*\w+"
    ]

    @staticmethod
    def extract_features(request_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract numerical features from request data for ML model.
        Returns a dictionary of feature names → float values.
        """
        features: Dict[str, float] = {}

        # IP Reputation Score
        features['ip_reputation_score'] = FeatureExtractor._calculate_ip_reputation(
            request_data['ip_address']
        )

        # Payload Complexity Score
        features['payload_complexity_score'] = FeatureExtractor._calculate_payload_complexity(
            request_data.get('payload')
        )

        # Header Anomaly Score
        features['header_anomaly_score'] = FeatureExtractor._calculate_header_anomaly(
            request_data['headers']
        )

        # Endpoint Risk Score
        features['endpoint_risk_score'] = FeatureExtractor._calculate_endpoint_risk(
            request_data['endpoint']
        )

        # Request Frequency Score
        features['frequency_score'] = FeatureExtractor._calculate_frequency_score(
            request_data['ip_address']
        )

        # Additional advanced features
        features['injection_score'] = FeatureExtractor._calculate_injection_score(
            request_data.get('payload'),
            request_data['endpoint'],
            request_data['headers']
        )

        features['entropy_score'] = FeatureExtractor._calculate_entropy_score(
            request_data.get('payload'),
            request_data['endpoint']
        )

        features['http_method_risk'] = FeatureExtractor._calculate_method_risk(
            request_data.get('method', 'GET'),
            request_data['endpoint']
        )

        features['time_anomaly_score'] = FeatureExtractor._calculate_time_anomaly(
            request_data.get('timestamp', datetime.now().isoformat())
        )

        return features

    # ==============================================================
    # Individual Feature Calculators
    # ==============================================================

    @staticmethod
    def _calculate_ip_reputation(ip_address: str) -> float:
        """Return score 0.0 (trusted) → 1.0 (suspicious)."""
        # Localhost
        if ip_address in {'127.0.0.1', '::1', 'localhost'}:
            return 0.0
        
        # Private networks (RFC 1918)
        if ip_address.startswith(('192.168.', '10.')):
            return 0.05
        if ip_address.startswith('172.'):
            try:
                second_octet = int(ip_address.split('.')[1])
                if 16 <= second_octet <= 31:
                    return 0.05
            except (ValueError, IndexError):
                pass
        
        # Link-local
        if ip_address.startswith('169.254.'):
            return 0.1
        
        # IPv6 private
        if ip_address.startswith(('fc00:', 'fd00:', 'fe80:')):
            return 0.05
        
        # Cloud provider IP ranges (common legitimate traffic)
        if ip_address.startswith(('52.', '54.', '3.', '13.', '18.')):  # AWS ranges
            return 0.2
        if ip_address.startswith(('104.', '35.', '34.')):  # GCP ranges
            return 0.2
        if ip_address.startswith(('40.', '52.', '13.', '20.')):  # Azure ranges
            return 0.2
        
        # Known bot/crawler patterns (rough heuristic)
        if ip_address.startswith(('66.249.', '157.55.')):  # Google, Bing crawlers
            return 0.3
        
        # Default for unknown public IPs
        return 0.5

    @staticmethod
    def _calculate_payload_complexity(payload: Dict[str, Any] | None) -> float:
        """Higher = more complex/suspicious payload."""
        if not payload:
            return 0.0

        try:
            payload_str = json.dumps(payload)
            size = len(payload_str)
            nesting_level = FeatureExtractor._get_max_nesting_level(payload)
            key_count = FeatureExtractor._count_keys(payload)
            
            # Size score: normalized over 50KB (more realistic threshold)
            size_score = min(size / 50_000, 1.0)
            
            # Nesting score: deep nesting (>8 levels) is suspicious
            nesting_score = min(nesting_level / 8, 1.0)
            
            # Key proliferation: too many keys suggests parameter pollution
            key_score = min(key_count / 100, 1.0)
            
            # Array length analysis
            array_score = FeatureExtractor._analyze_arrays(payload)
            
            # Weighted combination
            return (size_score * 0.3 + 
                   nesting_score * 0.3 + 
                   key_score * 0.2 + 
                   array_score * 0.2)
        except Exception:
            return 1.0  # Malformed payload → highly suspicious

    @staticmethod
    def _get_max_nesting_level(obj: Any, level: int = 0) -> int:
        """Recursively calculate maximum nesting depth in JSON-like object."""
        if isinstance(obj, dict):
            if not obj:
                return level
            return max(FeatureExtractor._get_max_nesting_level(v, level + 1) for v in obj.values())
        elif isinstance(obj, list):
            if not obj:
                return level
            return max(FeatureExtractor._get_max_nesting_level(item, level + 1) for item in obj)
        else:
            return level

    @staticmethod
    def _count_keys(obj: Any) -> int:
        """Count total number of keys in nested structure."""
        count = 0
        if isinstance(obj, dict):
            count += len(obj)
            for v in obj.values():
                count += FeatureExtractor._count_keys(v)
        elif isinstance(obj, list):
            for item in obj:
                count += FeatureExtractor._count_keys(item)
        return count

    @staticmethod
    def _analyze_arrays(obj: Any) -> float:
        """Detect suspicious array patterns (extremely long arrays)."""
        max_len = 0
        if isinstance(obj, list):
            max_len = max(max_len, len(obj))
            for item in obj:
                max_len = max(max_len, FeatureExtractor._analyze_arrays(item))
        elif isinstance(obj, dict):
            for v in obj.values():
                max_len = max(max_len, FeatureExtractor._analyze_arrays(v))
        return min(max_len / 1000, 1.0)

    @staticmethod
    def _calculate_header_anomaly(headers: Dict[str, str]) -> float:
        """Score based on missing expected headers and suspicious User-Agent."""
        expected = {'user-agent', 'accept', 'host'}
        present = {k.lower() for k in headers.keys()}
        missing_score = len(expected - present) / len(expected)

        user_agent = headers.get('User-Agent') or headers.get('user-agent', '')
        ua_score = 0.0
        
        if not user_agent:
            ua_score = 1.0
        elif len(user_agent) < 10:  # Suspiciously short UA
            ua_score = 0.9
        elif any(bot in user_agent.lower() for bot in ['bot', 'crawler', 'spider', 'scraper', 'headless', 'curl', 'wget', 'python-requests']):
            ua_score = 0.7
        elif user_agent.lower() in ['mozilla', 'mozilla/5.0', 'opera']:  # Incomplete UA
            ua_score = 0.8
        
        # Check for header injection attempts
        injection_score = 0.0
        for key, value in headers.items():
            if any(char in key or char in value for char in ['\r', '\n', '\0']):
                injection_score = 1.0
                break
        
        # Missing Content-Type for POST/PUT/PATCH
        content_type_score = 0.0
        if 'content-type' not in present and any(h.lower() in ['content-length'] for h in present):
            content_type_score = 0.5
        
        return (missing_score * 0.3 + ua_score * 0.4 + injection_score * 0.2 + content_type_score * 0.1)

    @staticmethod
    def _calculate_endpoint_risk(endpoint: str) -> float:
        """Higher score for sensitive/administrative endpoints."""
        endpoint_lower = endpoint.lower()
        
        critical = ['admin', 'delete', 'drop', 'execute', 'eval', 'password', 'token', 
                   'credential', 'secret', 'private', 'internal', 'debug', 'config',
                   'backup', 'restore', 'system', 'root', 'sudo']
        high_risk = ['login', 'auth', 'register', 'reset', 'change', 'update', 
                    'modify', 'edit', 'upload', 'download', 'export', 'import']
        medium_risk = ['user', 'account', 'profile', 'settings', 'payment', 'billing']
        
        if any(k in endpoint_lower for k in critical):
            return 0.95
        if any(k in endpoint_lower for k in high_risk):
            return 0.7
        if any(k in endpoint_lower for k in medium_risk):
            return 0.5
        
        # Check for suspicious patterns
        if '..' in endpoint or '%2e' in endpoint_lower:  # Path traversal
            return 0.95
        if any(ext in endpoint_lower for ext in ['.env', '.git', '.ssh', '.aws', 'web.config', '.htaccess']):
            return 0.9
        if endpoint.count('/') > 10:  # Excessively deep path
            return 0.6
        
        return 0.15

    @staticmethod
    def _calculate_frequency_score(ip_address: str) -> float:
        """Track request frequency per IP and detect rate anomalies."""
        current_time = datetime.now().timestamp()
        
        # Clean old entries outside window
        FeatureExtractor._request_cache[ip_address] = [
            ts for ts in FeatureExtractor._request_cache[ip_address]
            if current_time - ts < FeatureExtractor._cache_window
        ]
        
        # Add current request
        FeatureExtractor._request_cache[ip_address].append(current_time)
        
        request_count = len(FeatureExtractor._request_cache[ip_address])
        
        # Calculate rate per minute
        if request_count <= 1:
            return 0.0
        
        time_span = current_time - FeatureExtractor._request_cache[ip_address][0]
        if time_span < 1:
            time_span = 1
        
        rate_per_minute = (request_count / time_span) * 60
        
        # Scoring thresholds
        if rate_per_minute > 100:  # >100 req/min = DDoS territory
            return 1.0
        elif rate_per_minute > 50:
            return 0.8
        elif rate_per_minute > 20:
            return 0.6
        elif rate_per_minute > 10:
            return 0.4
        elif rate_per_minute > 5:
            return 0.2
        else:
            return 0.1

    @staticmethod
    def _calculate_injection_score(payload: Dict[str, Any] | None, endpoint: str, headers: Dict[str, str]) -> float:
        """Detect SQL injection, XSS, path traversal, and command injection patterns."""
        score = 0.0
        texts_to_check = [endpoint]
        
        # Extract text from payload
        if payload:
            texts_to_check.extend(FeatureExtractor._extract_strings(payload))
        
        # Extract text from headers
        texts_to_check.extend(headers.values())
        
        combined_text = ' '.join(texts_to_check).lower()
        
        # Check for SQL injection
        sql_matches = sum(1 for pattern in FeatureExtractor._SQL_PATTERNS 
                         if re.search(pattern, combined_text, re.IGNORECASE))
        score += min(sql_matches * 0.3, 1.0)
        
        # Check for XSS
        xss_matches = sum(1 for pattern in FeatureExtractor._XSS_PATTERNS 
                         if re.search(pattern, combined_text, re.IGNORECASE))
        score += min(xss_matches * 0.3, 1.0)
        
        # Check for path traversal
        traversal_matches = sum(1 for pattern in FeatureExtractor._PATH_TRAVERSAL_PATTERNS 
                               if re.search(pattern, combined_text, re.IGNORECASE))
        score += min(traversal_matches * 0.25, 1.0)
        
        # Check for command injection
        cmd_matches = sum(1 for pattern in FeatureExtractor._CMD_INJECTION_PATTERNS 
                         if re.search(pattern, combined_text, re.IGNORECASE))
        score += min(cmd_matches * 0.3, 1.0)
        
        return min(score, 1.0)

    @staticmethod
    def _extract_strings(obj: Any) -> list:
        """Recursively extract all string values from nested structure."""
        strings = []
        if isinstance(obj, str):
            strings.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                strings.extend(FeatureExtractor._extract_strings(v))
        elif isinstance(obj, list):
            for item in obj:
                strings.extend(FeatureExtractor._extract_strings(item))
        return strings

    @staticmethod
    def _calculate_entropy_score(payload: Dict[str, Any] | None, endpoint: str) -> float:
        """Calculate Shannon entropy to detect encrypted/encoded malicious payloads."""
        text = endpoint
        if payload:
            text += json.dumps(payload)
        
        if not text:
            return 0.0
        
        # Calculate Shannon entropy
        entropy = 0.0
        char_counts = defaultdict(int)
        for char in text:
            char_counts[char] += 1
        
        length = len(text)
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        # Normalize entropy (max entropy for ASCII is ~6.5 bits)
        normalized_entropy = entropy / 6.5
        
        # High entropy (>0.7) suggests encryption/obfuscation
        if normalized_entropy > 0.7:
            return min((normalized_entropy - 0.7) * 2, 1.0)
        
        return 0.0

    @staticmethod
    def _calculate_method_risk(method: str, endpoint: str) -> float:
        """Assess risk based on HTTP method and endpoint combination."""
        method = method.upper()
        endpoint_lower = endpoint.lower()
        
        # DELETE is inherently high risk
        if method == 'DELETE':
            return 0.8
        
        # PUT/PATCH on sensitive endpoints
        if method in ['PUT', 'PATCH']:
            if any(k in endpoint_lower for k in ['admin', 'user', 'config', 'settings']):
                return 0.7
            return 0.4
        
        # POST to read-only endpoints (suspicious)
        if method == 'POST':
            if any(k in endpoint_lower for k in ['get', 'list', 'view', 'read', 'search']):
                return 0.6
            if any(k in endpoint_lower for k in ['login', 'auth', 'register']):
                return 0.5
            return 0.3
        
        # GET with dangerous patterns
        if method == 'GET':
            if any(k in endpoint_lower for k in ['delete', 'drop', 'remove', 'execute']):
                return 0.8
            return 0.1
        
        # Uncommon methods
        if method in ['TRACE', 'CONNECT', 'OPTIONS']:
            return 0.5
        
        return 0.2

    @staticmethod
    def _calculate_time_anomaly(timestamp: str) -> float:
        """Detect requests at unusual times (potential automated attacks)."""
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            hour = dt.hour
            day_of_week = dt.weekday()
            
            # Night hours (2 AM - 5 AM) are more suspicious
            if 2 <= hour <= 5:
                return 0.6
            
            # Weekend nights
            if day_of_week >= 5 and (0 <= hour <= 6 or 23 <= hour <= 23):
                return 0.5
            
            # Early morning weekdays
            if day_of_week < 5 and 3 <= hour <= 5:
                return 0.4
            
            return 0.1
        except Exception:
            return 0.0