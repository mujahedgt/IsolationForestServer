import json
import re
import math
from typing import Dict, Any, Set, List
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np


class FeatureExtractor:
    """
    Adaptive feature extractor that learns from historical data in the database
    to provide more accurate anomaly detection tailored to your specific traffic patterns.
    """

    def __init__(self, db):
        """Initialize with database connection for calibration."""
        self.db = db
        
        # Calibration data (loaded from DB)
        self.malicious_ips: Set[str] = set()
        self.trusted_ips: Set[str] = set()
        self.high_risk_endpoints: Dict[str, float] = {}
        self.attack_patterns: Dict[str, List[str]] = {
            'sql': [],
            'xss': [],
            'path_traversal': [],
            'cmd_injection': []
        }
        self.normal_payload_stats: Dict[str, float] = {
            'mean_size': 1000,
            'std_size': 500,
            'mean_nesting': 2,
            'std_nesting': 1,
            'mean_keys': 10,
            'std_keys': 5
        }
        self.normal_header_patterns: Set[str] = set()
        self.endpoint_attack_frequency: Dict[str, int] = defaultdict(int)
        self.method_endpoint_risk: Dict[str, Dict[str, float]] = defaultdict(dict)
        
        # Frequency tracking
        self._request_cache: Dict[str, list] = defaultdict(list)
        self._cache_window = 3600  # 1 hour
        self._learned_frequency_thresholds: Dict[str, float] = {}
        
        # Calibration metadata
        self.last_calibration: datetime = None
        self.calibration_sample_size: int = 0
        self.is_calibrated: bool = False
        
        # Base patterns (fallback if DB is empty)
        self._SQL_PATTERNS = [
            r"(\bUNION\b.*\bSELECT\b)", r"(\bOR\b.*=.*)", r"(\bAND\b.*=.*)",
            r"(';|\"--)", r"(\bDROP\b.*\bTABLE\b)", r"(\bEXEC\b.*\()",
            r"(xp_cmdshell)", r"(@@version)"
        ]
        
        self._XSS_PATTERNS = [
            r"<script[^>]*>.*?</script>", r"javascript:", r"onerror\s*=",
            r"onload\s*=", r"onclick\s*=", r"<iframe", r"eval\s*\(",
            r"alert\s*\(", r"document\.cookie", r"window\.location"
        ]
        
        self._PATH_TRAVERSAL_PATTERNS = [
            r"\.\./", r"\.\.\\", r"%2e%2e", r"%252e", r"..;/", r"..%00"
        ]
        
        self._CMD_INJECTION_PATTERNS = [
            r";\s*(cat|ls|whoami|id|pwd|wget|curl)", r"\|\s*(cat|ls|whoami)",
            r"`.*`", r"\$\(.*\)", r"&&\s*\w+", r"\|\|\s*\w+"
        ]

    def calibrate(self, lookback_days: int = 30, min_samples: int = 100) -> Dict[str, Any]:
        """
        Calibrate the feature extractor using historical data from the database.
        
        Args:
            lookback_days: Number of days to look back for calibration data
            min_samples: Minimum number of samples required for calibration
            
        Returns:
            Calibration statistics and metadata
        """
        print(f"🔧 Starting feature extractor calibration (lookback: {lookback_days} days)...")
        
        cutoff_date = datetime.now() - timedelta(days=lookback_days)
        
        # Fetch calibration data
        query = """
            SELECT 
                ip_address, endpoint, http_method, headers_json, payload_json,
                payload_complexity_score, header_anomaly_score, endpoint_risk_score,
                frequency_score, is_anomaly, user_label, analyzed_at
            FROM analyzed_requests
            WHERE analyzed_at >= %s
            ORDER BY analyzed_at DESC
            LIMIT 10000
        """
        
        records = self.db.fetch_all(query, (cutoff_date,))
        
        if len(records) < min_samples:
            print(f"⚠ Insufficient data for calibration. Found {len(records)}, need {min_samples}")
            return {
                "calibrated": False,
                "reason": f"Insufficient samples ({len(records)}/{min_samples})",
                "sample_size": len(records)
            }
        
        # Separate anomalies from normal traffic
        anomalies = []
        normals = []
        
        for record in records:
            # Use user_label if available, otherwise fall back to is_anomaly
            is_attack = record.get('user_label') if record.get('user_label') is not None else record.get('is_anomaly')
            
            if is_attack:
                anomalies.append(record)
            else:
                normals.append(record)
        
        # Calibrate each component
        self._calibrate_ip_reputation(anomalies, normals)
        self._calibrate_endpoint_risk(anomalies, normals)
        self._calibrate_payload_complexity(normals)
        self._calibrate_header_patterns(normals)
        self._calibrate_attack_patterns(anomalies)
        self._calibrate_frequency_thresholds(records)
        self._calibrate_method_endpoint_risk(anomalies)
        
        # Update metadata
        self.last_calibration = datetime.now()
        self.calibration_sample_size = len(records)
        self.is_calibrated = True
        
        print(f"✓ Calibration complete!")
        print(f"  - Malicious IPs learned: {len(self.malicious_ips)}")
        print(f"  - Trusted IPs learned: {len(self.trusted_ips)}")
        print(f"  - High-risk endpoints: {len(self.high_risk_endpoints)}")
        print(f"  - Attack patterns learned: {sum(len(v) for v in self.attack_patterns.values())}")
        
        return {
            "calibrated": True,
            "sample_size": len(records),
            "anomalies_count": len(anomalies),
            "normals_count": len(normals),
            "malicious_ips": len(self.malicious_ips),
            "trusted_ips": len(self.trusted_ips),
            "high_risk_endpoints": len(self.high_risk_endpoints),
            "learned_patterns": sum(len(v) for v in self.attack_patterns.values()),
            "calibration_date": self.last_calibration.isoformat()
        }

    def _calibrate_ip_reputation(self, anomalies: List[Dict], normals: List[Dict]):
        """Learn which IPs are malicious vs trusted from historical data."""
        ip_anomaly_count = defaultdict(int)
        ip_total_count = defaultdict(int)
        
        # Count anomalies per IP
        for record in anomalies:
            ip = record['ip_address']
            ip_anomaly_count[ip] += 1
            ip_total_count[ip] += 1
        
        # Count normal requests per IP
        for record in normals:
            ip = record['ip_address']
            ip_total_count[ip] += 1
        
        # Classify IPs
        for ip, total in ip_total_count.items():
            anomaly_ratio = ip_anomaly_count[ip] / total if total > 0 else 0
            
            if total >= 10:  # Need enough samples
                if anomaly_ratio >= 0.7:  # 70%+ anomalies = malicious
                    self.malicious_ips.add(ip)
                elif anomaly_ratio <= 0.1:  # <10% anomalies = trusted
                    self.trusted_ips.add(ip)

    def _calibrate_endpoint_risk(self, anomalies: List[Dict], normals: List[Dict]):
        """Learn which endpoints are actually targeted by attacks."""
        endpoint_anomaly_count = defaultdict(int)
        endpoint_total_count = defaultdict(int)
        
        for record in anomalies:
            endpoint = record['endpoint']
            endpoint_anomaly_count[endpoint] += 1
            endpoint_total_count[endpoint] += 1
            self.endpoint_attack_frequency[endpoint] += 1
        
        for record in normals:
            endpoint = record['endpoint']
            endpoint_total_count[endpoint] += 1
        
        # Calculate risk scores
        for endpoint, total in endpoint_total_count.items():
            if total >= 5:  # Need enough samples
                anomaly_ratio = endpoint_anomaly_count[endpoint] / total
                # Risk score: 0.0 (never attacked) to 1.0 (always attacked)
                self.high_risk_endpoints[endpoint] = min(anomaly_ratio * 1.2, 1.0)

    def _calibrate_payload_complexity(self, normals: List[Dict]):
        """Learn what "normal" payload complexity looks like for your application."""
        sizes = []
        nestings = []
        key_counts = []
        
        for record in normals:
            if record.get('payload_json'):
                try:
                    payload = json.loads(record['payload_json'])
                    payload_str = json.dumps(payload)
                    sizes.append(len(payload_str))
                    nestings.append(self._get_max_nesting_level(payload))
                    key_counts.append(self._count_keys(payload))
                except:
                    continue
        
        if sizes:
            self.normal_payload_stats = {
                'mean_size': np.mean(sizes),
                'std_size': np.std(sizes),
                'mean_nesting': np.mean(nestings),
                'std_nesting': np.std(nestings),
                'mean_keys': np.mean(key_counts),
                'std_keys': np.std(key_counts)
            }

    def _calibrate_header_patterns(self, normals: List[Dict]):
        """Learn common legitimate User-Agent patterns."""
        user_agents = set()
        
        for record in normals:
            if record.get('headers_json'):
                try:
                    headers = json.loads(record['headers_json'])
                    ua = headers.get('User-Agent') or headers.get('user-agent', '')
                    if ua and len(ua) > 10:
                        # Store normalized patterns (first 50 chars)
                        user_agents.add(ua[:50].lower())
                except:
                    continue
        
        self.normal_header_patterns = user_agents

    def _calibrate_attack_patterns(self, anomalies: List[Dict]):
        """Extract actual attack patterns from confirmed malicious requests."""
        for record in anomalies:
            texts = []
            
            # Extract from endpoint
            texts.append(record['endpoint'])
            
            # Extract from payload
            if record.get('payload_json'):
                try:
                    payload = json.loads(record['payload_json'])
                    texts.extend(self._extract_strings(payload))
                except:
                    pass
            
            combined = ' '.join(texts).lower()
            
            # Look for SQL injection patterns
            if any(re.search(p, combined, re.IGNORECASE) for p in self._SQL_PATTERNS):
                # Extract the actual malicious substring
                for pattern in self._SQL_PATTERNS:
                    matches = re.findall(pattern, combined, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        if len(match) < 100:  # Avoid huge strings
                            self.attack_patterns['sql'].append(match[:50])
            
            # Similar for XSS, path traversal, cmd injection
            if any(re.search(p, combined, re.IGNORECASE) for p in self._XSS_PATTERNS):
                for pattern in self._XSS_PATTERNS:
                    matches = re.findall(pattern, combined, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        if len(match) < 100:
                            self.attack_patterns['xss'].append(match[:50])

    def _calibrate_frequency_thresholds(self, records: List[Dict]):
        """Learn normal request frequency patterns per IP."""
        ip_timestamps = defaultdict(list)
        
        for record in records:
            ip = record['ip_address']
            timestamp = record['analyzed_at']
            if timestamp:
                ip_timestamps[ip].append(timestamp)
        
        # Calculate rates per minute for each IP
        for ip, timestamps in ip_timestamps.items():
            if len(timestamps) >= 2:
                timestamps.sort()
                time_span = (timestamps[-1] - timestamps[0]).total_seconds()
                if time_span > 0:
                    rate_per_minute = (len(timestamps) / time_span) * 60
                    self._learned_frequency_thresholds[ip] = rate_per_minute

    def _calibrate_method_endpoint_risk(self, anomalies: List[Dict]):
        """Learn which HTTP method + endpoint combinations are risky."""
        method_endpoint_attacks = defaultdict(lambda: defaultdict(int))
        
        for record in anomalies:
            method = record['http_method']
            endpoint = record['endpoint']
            method_endpoint_attacks[method][endpoint] += 1
        
        # Convert to risk scores
        for method, endpoints in method_endpoint_attacks.items():
            for endpoint, count in endpoints.items():
                # Higher count = higher risk
                risk = min(count / 10.0, 1.0)  # 10+ attacks = max risk
                self.method_endpoint_risk[method][endpoint] = risk

    # ========================================================================
    # Enhanced Feature Extraction Methods (using calibration)
    # ========================================================================

    def extract_features(self, request_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract features using calibrated thresholds and learned patterns.
        Falls back to base extraction if not calibrated.
        """
        features: Dict[str, float] = {}

        features['ip_reputation_score'] = self._calculate_ip_reputation(request_data['ip_address'])
        features['payload_complexity_score'] = self._calculate_payload_complexity(request_data.get('payload'))
        features['header_anomaly_score'] = self._calculate_header_anomaly(request_data['headers'])
        features['endpoint_risk_score'] = self._calculate_endpoint_risk(request_data['endpoint'])
        features['frequency_score'] = self._calculate_frequency_score(request_data['ip_address'])
        features['injection_score'] = self._calculate_injection_score(
            request_data.get('payload'),
            request_data['endpoint'],
            request_data['headers']
        )
        features['entropy_score'] = self._calculate_entropy_score(
            request_data.get('payload'),
            request_data['endpoint']
        )
        features['http_method_risk'] = self._calculate_method_risk(
            request_data.get('method', 'GET'),
            request_data['endpoint']
        )
        features['time_anomaly_score'] = self._calculate_time_anomaly(
            request_data.get('timestamp', datetime.now().isoformat())
        )

        return features

    def _calculate_ip_reputation(self, ip_address: str) -> float:
        """Enhanced IP reputation using learned malicious/trusted IPs."""
        # Check learned IPs first
        if ip_address in self.malicious_ips:
            return 0.95  # Known malicious
        if ip_address in self.trusted_ips:
            return 0.05  # Known trusted
        
        # Fall back to heuristic scoring
        if ip_address in {'127.0.0.1', '::1', 'localhost'}:
            return 0.0
        
        if ip_address.startswith(('192.168.', '10.')):
            return 0.05
        
        if ip_address.startswith('172.'):
            try:
                second_octet = int(ip_address.split('.')[1])
                if 16 <= second_octet <= 31:
                    return 0.05
            except (ValueError, IndexError):
                pass
        
        if ip_address.startswith('169.254.'):
            return 0.1
        
        if ip_address.startswith(('fc00:', 'fd00:', 'fe80:')):
            return 0.05
        
        # Cloud providers
        if ip_address.startswith(('52.', '54.', '3.', '13.', '18.')):
            return 0.2
        if ip_address.startswith(('104.', '35.', '34.')):
            return 0.2
        if ip_address.startswith(('40.', '52.', '13.', '20.')):
            return 0.2
        
        return 0.5

    def _calculate_endpoint_risk(self, endpoint: str) -> float:
        """Enhanced endpoint risk using learned attack frequencies."""
        endpoint_lower = endpoint.lower()
        
        # Check learned high-risk endpoints
        if endpoint in self.high_risk_endpoints:
            learned_risk = self.high_risk_endpoints[endpoint]
            # Blend learned risk with heuristic risk
            heuristic_risk = self._heuristic_endpoint_risk(endpoint_lower)
            return max(learned_risk, heuristic_risk)  # Take the higher risk
        
        # Fall back to heuristic
        return self._heuristic_endpoint_risk(endpoint_lower)

    def _heuristic_endpoint_risk(self, endpoint_lower: str) -> float:
        """Original heuristic endpoint risk scoring."""
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
        
        if '..' in endpoint_lower or '%2e' in endpoint_lower:
            return 0.95
        if any(ext in endpoint_lower for ext in ['.env', '.git', '.ssh', '.aws', 'web.config', '.htaccess']):
            return 0.9
        if endpoint_lower.count('/') > 10:
            return 0.6
        
        return 0.15

    def _calculate_payload_complexity(self, payload: Dict[str, Any] | None) -> float:
        """Enhanced payload complexity using learned normal patterns."""
        if not payload:
            return 0.0

        try:
            payload_str = json.dumps(payload)
            size = len(payload_str)
            nesting_level = self._get_max_nesting_level(payload)
            key_count = self._count_keys(payload)
            
            if self.is_calibrated:
                # Use statistical scoring based on learned normals
                size_z_score = abs((size - self.normal_payload_stats['mean_size']) / 
                                  (self.normal_payload_stats['std_size'] + 1))
                nesting_z_score = abs((nesting_level - self.normal_payload_stats['mean_nesting']) / 
                                     (self.normal_payload_stats['std_nesting'] + 1))
                keys_z_score = abs((key_count - self.normal_payload_stats['mean_keys']) / 
                                  (self.normal_payload_stats['std_keys'] + 1))
                
                # Z-scores > 3 are highly anomalous
                size_score = min(size_z_score / 3.0, 1.0)
                nesting_score = min(nesting_z_score / 3.0, 1.0)
                key_score = min(keys_z_score / 3.0, 1.0)
            else:
                # Fall back to heuristic scoring
                size_score = min(size / 50_000, 1.0)
                nesting_score = min(nesting_level / 8, 1.0)
                key_score = min(key_count / 100, 1.0)
            
            array_score = self._analyze_arrays(payload)
            
            return (size_score * 0.3 + nesting_score * 0.3 + key_score * 0.2 + array_score * 0.2)
        except Exception:
            return 1.0

    def _calculate_injection_score(self, payload: Dict[str, Any] | None, endpoint: str, headers: Dict[str, str]) -> float:
        """Enhanced injection detection using learned attack patterns."""
        score = 0.0
        texts_to_check = [endpoint]
        
        if payload:
            texts_to_check.extend(self._extract_strings(payload))
        texts_to_check.extend(headers.values())
        
        combined_text = ' '.join(texts_to_check).lower()
        
        # Check learned patterns first (higher weight)
        if self.is_calibrated and self.attack_patterns['sql']:
            for pattern in self.attack_patterns['sql']:
                if pattern.lower() in combined_text:
                    score += 0.4  # Learned patterns get higher weight
        
        if self.is_calibrated and self.attack_patterns['xss']:
            for pattern in self.attack_patterns['xss']:
                if pattern.lower() in combined_text:
                    score += 0.4
        
        # Check base patterns (lower weight)
        sql_matches = sum(1 for pattern in self._SQL_PATTERNS 
                         if re.search(pattern, combined_text, re.IGNORECASE))
        score += min(sql_matches * 0.25, 1.0)
        
        xss_matches = sum(1 for pattern in self._XSS_PATTERNS 
                         if re.search(pattern, combined_text, re.IGNORECASE))
        score += min(xss_matches * 0.25, 1.0)
        
        traversal_matches = sum(1 for pattern in self._PATH_TRAVERSAL_PATTERNS 
                               if re.search(pattern, combined_text, re.IGNORECASE))
        score += min(traversal_matches * 0.2, 1.0)
        
        cmd_matches = sum(1 for pattern in self._CMD_INJECTION_PATTERNS 
                         if re.search(pattern, combined_text, re.IGNORECASE))
        score += min(cmd_matches * 0.25, 1.0)
        
        return min(score, 1.0)

    def _calculate_frequency_score(self, ip_address: str) -> float:
        """Enhanced frequency scoring using learned thresholds per IP."""
        current_time = datetime.now().timestamp()
        
        # Clean old entries
        self._request_cache[ip_address] = [
            ts for ts in self._request_cache[ip_address]
            if current_time - ts < self._cache_window
        ]
        
        self._request_cache[ip_address].append(current_time)
        request_count = len(self._request_cache[ip_address])
        
        if request_count <= 1:
            return 0.0
        
        time_span = current_time - self._request_cache[ip_address][0]
        if time_span < 1:
            time_span = 1
        
        rate_per_minute = (request_count / time_span) * 60
        
        # Use learned threshold for this IP if available
        if self.is_calibrated and ip_address in self._learned_frequency_thresholds:
            normal_rate = self._learned_frequency_thresholds[ip_address]
            # Calculate how much above normal this is
            if rate_per_minute > normal_rate * 3:  # 3x normal rate
                return 1.0
            elif rate_per_minute > normal_rate * 2:
                return 0.8
            elif rate_per_minute > normal_rate * 1.5:
                return 0.6
            else:
                return 0.2
        
        # Fall back to absolute thresholds
        if rate_per_minute > 100:
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

    def _calculate_method_risk(self, method: str, endpoint: str) -> float:
        """Enhanced method risk using learned method-endpoint combinations."""
        method = method.upper()
        
        # Check learned risky combinations
        if self.is_calibrated and method in self.method_endpoint_risk:
            if endpoint in self.method_endpoint_risk[method]:
                learned_risk = self.method_endpoint_risk[method][endpoint]
                heuristic_risk = self._heuristic_method_risk(method, endpoint)
                return max(learned_risk, heuristic_risk)
        
        # Fall back to heuristic
        return self._heuristic_method_risk(method, endpoint)

    def _heuristic_method_risk(self, method: str, endpoint: str) -> float:
        """Original heuristic method risk scoring."""
        endpoint_lower = endpoint.lower()
        
        if method == 'DELETE':
            return 0.8
        
        if method in ['PUT', 'PATCH']:
            if any(k in endpoint_lower for k in ['admin', 'user', 'config', 'settings']):
                return 0.7
            return 0.4
        
        if method == 'POST':
            if any(k in endpoint_lower for k in ['get', 'list', 'view', 'read', 'search']):
                return 0.6
            if any(k in endpoint_lower for k in ['login', 'auth', 'register']):
                return 0.5
            return 0.3
        
        if method == 'GET':
            if any(k in endpoint_lower for k in ['delete', 'drop', 'remove', 'execute']):
                return 0.8
            return 0.1
        
        if method in ['TRACE', 'CONNECT', 'OPTIONS']:
            return 0.5
        
        return 0.2

    # Utility methods (same as base FeatureExtractor)
    
    def _calculate_header_anomaly(self, headers: Dict[str, str]) -> float:
        """Calculate header anomaly score."""
        expected = {'user-agent', 'accept', 'host'}
        present = {k.lower() for k in headers.keys()}
        missing_score = len(expected - present) / len(expected)

        user_agent = headers.get('User-Agent') or headers.get('user-agent', '')
        ua_score = 0.0
        
        if not user_agent:
            ua_score = 1.0
        elif len(user_agent) < 10:
            ua_score = 0.9
        elif any(bot in user_agent.lower() for bot in ['bot', 'crawler', 'spider', 'scraper', 'headless', 'curl', 'wget', 'python-requests']):
            ua_score = 0.7
        elif user_agent.lower() in ['mozilla', 'mozilla/5.0', 'opera']:
            ua_score = 0.8
        
        injection_score = 0.0
        for key, value in headers.items():
            if any(char in key or char in value for char in ['\r', '\n', '\0']):
                injection_score = 1.0
                break
        
        content_type_score = 0.0
        if 'content-type' not in present and any(h.lower() in ['content-length'] for h in present):
            content_type_score = 0.5
        
        return (missing_score * 0.3 + ua_score * 0.4 + injection_score * 0.2 + content_type_score * 0.1)

    def _calculate_entropy_score(self, payload: Dict[str, Any] | None, endpoint: str) -> float:
        """Calculate Shannon entropy."""
        text = endpoint
        if payload:
            text += json.dumps(payload)
        
        if not text:
            return 0.0
        
        entropy = 0.0
        char_counts = defaultdict(int)
        for char in text:
            char_counts[char] += 1
        
        length = len(text)
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        normalized_entropy = entropy / 6.5
        
        if normalized_entropy > 0.7:
            return min((normalized_entropy - 0.7) * 2, 1.0)
        
        return 0.0

    def _calculate_time_anomaly(self, timestamp: str) -> float:
        """Calculate time-based anomaly score."""
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            hour = dt.hour
            day_of_week = dt.weekday()
            
            if 2 <= hour <= 5:
                return 0.6
            
            if day_of_week >= 5 and (0 <= hour <= 6 or 23 <= hour <= 23):
                return 0.5
            
            if day_of_week < 5 and 3 <= hour <= 5:
                return 0.4
            
            return 0.1
        except Exception:
            return 0.0

    def _get_max_nesting_level(self, obj: Any, level: int = 0) -> int:
        """Get maximum nesting depth."""
        if isinstance(obj, dict):
            if not obj:
                return level
            return max(self._get_max_nesting_level(v, level + 1) for v in obj.values())
        elif isinstance(obj, list):
            if not obj:
                return level
            return max(self._get_max_nesting_level(item, level + 1) for item in obj)
        else:
            return level

    def _count_keys(self, obj: Any) -> int:
        """Count total keys in nested structure."""
        count = 0
        if isinstance(obj, dict):
            count += len(obj)
            for v in obj.values():
                count += self._count_keys(v)
        elif isinstance(obj, list):
            for item in obj:
                count += self._count_keys(item)
        return count

    def _analyze_arrays(self, obj: Any) -> float:
        """Analyze array lengths."""
        max_len = 0
        if isinstance(obj, list):
            max_len = max(max_len, len(obj))
            for item in obj:
                max_len = max(max_len, self._analyze_arrays(item))
        elif isinstance(obj, dict):
            for v in obj.values():
                max_len = max(max_len, self._analyze_arrays(v))
        return min(max_len / 1000, 1.0)

    def _extract_strings(self, obj: Any) -> list:
        """Extract all strings from nested structure."""
        strings = []
        if isinstance(obj, str):
            strings.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                strings.extend(self._extract_strings(v))
        elif isinstance(obj, list):
            for item in obj:
                strings.extend(self._extract_strings(item))
        return strings