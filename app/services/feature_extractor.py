import json
from typing import Dict, Any
from datetime import datetime


class FeatureExtractor:
    """Extracts numerical features from HTTP request data for the Isolation Forest model"""

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

        # Request Frequency Score (simplified — in prod: query DB/cache)
        features['frequency_score'] = FeatureExtractor._calculate_frequency_score(
            request_data['ip_address']
        )

        return features

    # ==============================================================
    # Individual Feature Calculators
    # ==============================================================

    @staticmethod
    def _calculate_ip_reputation(ip_address: str) -> float:
        """Return score 0.0 (trusted) → 1.0 (suspicious)."""
        if ip_address in {'127.0.0.1', '::1', 'localhost'}:
            return 0.0
        if ip_address.startswith(('192.168.', '10.', '172.')):
            return 0.1  # Private networks usually trusted
        # In production: query AbuseIPDB, VirusTotal, etc.
        return 0.5  # Default moderate score for public IPs

    @staticmethod
    def _calculate_payload_complexity(payload: Dict[str, Any] | None) -> float:
        """Higher = more complex/suspicious payload."""
        if not payload:
            return 0.0

        try:
            payload_str = json.dumps(payload)
            size = len(payload_str)
            nesting_level = FeatureExtractor._get_max_nesting_level(payload)

            size_score = min(size / 10_000, 1.0)        # Normalize over ~10KB
            nesting_score = min(nesting_level / 10, 1.0)  # Deep nesting is suspicious

            return (size_score + nesting_score) / 2
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
    def _calculate_header_anomaly(headers: Dict[str, str]) -> float:
        """Score based on missing expected headers and suspicious User-Agent."""
        expected = {'user-agent', 'content-type', 'accept', 'host'}
        present = {k.lower() for k in headers.keys()}
        missing_score = len(expected - present) / len(expected)

        user_agent = headers.get('User-Agent') or headers.get('user-agent', '')
        ua_score = 0.0
        if not user_agent:
            ua_score = 1.0
        elif any(bot in user_agent.lower() for bot in ['bot', 'crawler', 'spider', 'scraper', 'headless']):
            ua_score = 0.8

        return (missing_score + ua_score) / 2

    @staticmethod
    def _calculate_endpoint_risk(endpoint: str) -> float:
        """Higher score for sensitive/administrative endpoints."""
        endpoint_lower = endpoint.lower()
        high_risk = ['admin', 'delete', 'drop', 'execute', 'eval', 'password', 'token', 'login', 'auth']
        medium_risk = ['update', 'modify', 'change', 'edit', 'upload']

        if any(k in endpoint_lower for k in high_risk):
            return 0.9
        if any(k in endpoint_lower for k in medium_risk):
            return 0.5
        return 0.2

    @staticmethod
    def _calculate_frequency_score(ip_address: str) -> float:
        """In production: query recent request count from Redis/DB."""
        # Placeholder — real implementation would check rate per IP
        return 0.3