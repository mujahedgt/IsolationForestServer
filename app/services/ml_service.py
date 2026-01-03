import pickle
import json
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from app.services.feature_extractor import FeatureExtractor

from app.database import db


class MLService:
    def __init__(self):
        # Only load model when DB is actually connected
        if not hasattr(self, '_initialized'):
            self._initialized = True
            if db.connection is not None:  # DB already connected?
                self.load_active_model()
            else:
                print("DB not connected yet. Model will be loaded on first use.")

    def load_active_model(self):
        """Load the currently active model from database."""
        try:
            query = "SELECT model_version, model_data FROM models WHERE is_active = TRUE LIMIT 1"
            result = db.fetch_one(query)
            
            if result:
                self.model_version = result['model_version']
                self.model = pickle.loads(result['model_data'])
                print(f"✓ Loaded active model: {self.model_version}")
            else:
                print("⚠ No active model found. Please train a model first.")
        except Exception as e:
            print(f"✗ Error loading model: {e}")
            raise

    def predict(self, features: Dict[str, float]) -> Tuple[bool, float]:
        """
        Predict if a request is anomalous.
        Returns: (is_anomaly: bool, confidence: float [0.0-1.0])
        """
        if self.model is None:
            raise ValueError("No model loaded. Please train a model first.")

        # ALL 9 features in consistent order
        feature_array = np.array([[
            features['ip_reputation_score'],
            features['payload_complexity_score'],
            features['header_anomaly_score'],
            features['endpoint_risk_score'],
            features['frequency_score'],
            features['injection_score'],
            features['entropy_score'],
            features['http_method_risk'],
            features['time_anomaly_score']
        ]])

        # -1 = anomaly, 1 = normal
        prediction = self.model.predict(feature_array)[0]
        # Lower score = more anomalous
        anomaly_score = self.model.score_samples(feature_array)[0]

        # Convert to confidence with enhanced scoring
        confidence = self._calculate_confidence(anomaly_score, prediction, features)

        is_anomaly = prediction == -1
        return is_anomaly, confidence

    def _calculate_confidence(self, anomaly_score: float, prediction: int, features: Dict[str, float]) -> float:
        """
        Calculate enhanced confidence score using both model score and feature analysis.
        Returns confidence in range [0.0, 1.0] where higher = more anomalous.
        """
        # Base confidence from model score (normalize from typical range)
        base_confidence = float(-anomaly_score)
        base_confidence = min(max(base_confidence, 0.0), 1.0)
        
        # Weight critical features for confidence boost
        critical_features_score = (
            features['injection_score'] * 0.35 +
            features['endpoint_risk_score'] * 0.25 +
            features['frequency_score'] * 0.20 +
            features['ip_reputation_score'] * 0.10 +
            features['entropy_score'] * 0.10
        )
        
        # If model predicts anomaly AND critical features are high, boost confidence
        if prediction == -1 and critical_features_score > 0.6:
            confidence = min(base_confidence * 1.2, 1.0)
        # If model predicts normal BUT critical features are very high, still show some confidence
        elif prediction == 1 and critical_features_score > 0.8:
            confidence = max(base_confidence, 0.4)
        else:
            confidence = base_confidence
        
        return float(min(max(confidence, 0.0), 1.0))

    def train_model(
        self,
        model_version: str,
        contamination: float = 0.1,
        n_estimators: int = 150,
        max_samples: int = 256,
        use_corrected_labels: bool = True,
        recalculate_features: bool = False
    ) -> Dict[str, Any]:
        """
        Train a new Isolation Forest model and activate it.
        Enhanced parameters for better anomaly detection with 9 features.
        
        Args:
            recalculate_features: If True, recalculates all features from raw request data
                                 before training. Useful when upgrading feature extraction logic.
        """
        start_time = datetime.now()

        # Recalculate features if requested
        if recalculate_features:
            recalc_result = self._recalculate_all_features()
            print(f"✓ Recalculated features for {recalc_result['updated_count']} records in {recalc_result['duration_seconds']}s")

        training_data = self._fetch_training_data(use_corrected_labels)
        if len(training_data) < 100:
            raise ValueError(f"Insufficient training data. Need at least 100 samples, got {len(training_data)}")

        X = np.array(training_data)

        # Enhanced Isolation Forest configuration
        model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,  # Increased from 100 for better accuracy
            max_samples=max_samples,    # Controls tree depth (256 is good for most datasets)
            max_features=1.0,           # Use all features
            bootstrap=False,            # Don't bootstrap (use all training data)
            random_state=42,
            n_jobs=-1,                  # Use all CPU cores
            warm_start=False
        )
        model.fit(X)

        # Validate model performance
        predictions = model.predict(X)
        anomaly_ratio = (predictions == -1).sum() / len(predictions)
        
        model_data = pickle.dumps(model)
        duration = (datetime.now() - start_time).total_seconds()

        # Deactivate all old models
        db.execute_query("UPDATE models SET is_active = FALSE")

        # Insert new active model
        insert_query = """
            INSERT INTO models (model_version, model_data, training_date, training_samples, is_active)
            VALUES (%s, %s, %s, %s, %s)
        """
        db.execute_query(insert_query, (
            model_version,
            model_data,
            datetime.now(),
            len(training_data),
            True
        ))

        # Update in-memory model
        self.model = model
        self.model_version = model_version

        return {
            "success": True,
            "model_version": model_version,
            "training_samples": len(training_data),
            "detected_anomaly_ratio": round(anomaly_ratio, 4),
            "training_duration_seconds": round(duration, 2),
            "message": "Model trained and activated successfully"
        }

    def retrain_model(self, new_model_version: str, recalculate_features: bool = False) -> Dict[str, Any]:
        """
        Retraining model using corrected user labels.
        
        Args:
            recalculate_features: If True, recalculates all features before retraining.
                                 Recommended when upgrading feature extraction logic.
        """
        old_version = self.model_version or "none"

        count_query = "SELECT COUNT(*) as count FROM analyzed_requests WHERE user_label IS NOT NULL"
        result = db.fetch_one(count_query)
        corrected_count = result["count"] if result else 0

        if corrected_count < 10:
            raise ValueError(f"Insufficient corrected labels. Need at least 10, got {corrected_count}")

        training_result = self.train_model(
            model_version=new_model_version,
            use_corrected_labels=True,
            recalculate_features=recalculate_features
        )

        return {
            "success": True,
            "old_model_version": old_version,
            "new_model_version": new_model_version,
            "training_samples": training_result["training_samples"],
            "corrected_labels_used": corrected_count,
            "message": "Model successfully retrained with user feedback"
        }

    def _fetch_training_data(self, use_corrected_labels: bool) -> List[List[float]]:
        """
        Fetch feature vectors from past analyzed requests.
        Now fetches ALL 9 features for enhanced model training.
        """
        if use_corrected_labels:
            query = """
                SELECT 
                    ip_reputation_score, 
                    payload_complexity_score, 
                    header_anomaly_score, 
                    endpoint_risk_score, 
                    frequency_score,
                    injection_score,
                    entropy_score,
                    http_method_risk,
                    time_anomaly_score
                FROM analyzed_requests
                WHERE user_label IS NOT NULL OR is_anomaly IS NOT NULL
                ORDER BY analyzed_at DESC
                LIMIT 10000
            """
        else:
            query = """
                SELECT 
                    ip_reputation_score, 
                    payload_complexity_score, 
                    header_anomaly_score, 
                    endpoint_risk_score, 
                    frequency_score,
                    injection_score,
                    entropy_score,
                    http_method_risk,
                    time_anomaly_score
                FROM analyzed_requests
                WHERE is_anomaly IS NOT NULL
                ORDER BY analyzed_at DESC
                LIMIT 10000
            """

        results = db.fetch_all(query)
        
        # Extract all 9 features in consistent order
        training_data = [
            [
                row["ip_reputation_score"],
                row["payload_complexity_score"],
                row["header_anomaly_score"],
                row["endpoint_risk_score"],
                row["frequency_score"],
                row["injection_score"],
                row["entropy_score"],
                row["http_method_risk"],
                row["time_anomaly_score"]
            ]
            for row in results
        ]
        return training_data

    def get_feature_importance(self) -> Dict[str, float]:
        """
        Estimate feature importance based on variance in anomaly detection.
        Useful for understanding which features contribute most to detections.
        """
        if self.model is None:
            raise ValueError("No model loaded.")
        
        # Fetch recent data for analysis
        query = """
            SELECT 
                ip_reputation_score, payload_complexity_score, 
                header_anomaly_score, endpoint_risk_score, frequency_score,
                injection_score, entropy_score, http_method_risk, time_anomaly_score,
                is_anomaly
            FROM analyzed_requests
            ORDER BY analyzed_at DESC
            LIMIT 1000
        """
        results = db.fetch_all(query)
        
        if len(results) < 10:
            return {}
        
        # Separate anomalies and normal requests
        anomalies = []
        normals = []
        
        for row in results:
            features = [
                row["ip_reputation_score"], row["payload_complexity_score"],
                row["header_anomaly_score"], row["endpoint_risk_score"],
                row["frequency_score"], row["injection_score"],
                row["entropy_score"], row["http_method_risk"],
                row["time_anomaly_score"]
            ]
            if row["is_anomaly"]:
                anomalies.append(features)
            else:
                normals.append(features)
        
        if not anomalies or not normals:
            return {}
        
        # Calculate mean difference between anomalies and normals
        anomalies_mean = np.mean(anomalies, axis=0)
        normals_mean = np.mean(normals, axis=0)
        differences = np.abs(anomalies_mean - normals_mean)
        
        # Normalize to sum to 1
        total = differences.sum()
        if total > 0:
            importance = differences / total
        else:
            importance = differences
        
        feature_names = [
            'ip_reputation_score', 'payload_complexity_score',
            'header_anomaly_score', 'endpoint_risk_score', 'frequency_score',
            'injection_score', 'entropy_score', 'http_method_risk',
            'time_anomaly_score'
        ]
        
        return {name: float(imp) for name, imp in zip(feature_names, importance)}

    def _recalculate_all_features(self) -> Dict[str, Any]:
        """
        Recalculate all features for existing records using current feature extraction logic.
        Preserves original frequency_score as it's time-contextual.
        Updates records in batches for efficiency.
        """
        
        start_time = datetime.now()
        
        # Fetch all records that need recalculation (with actual column names)
        query = """
            SELECT 
                id, request_id, ip_address, headers_json, payload_json, endpoint, 
                http_method, analyzed_at, frequency_score
            FROM analyzed_requests
            ORDER BY analyzed_at ASC
        """
        
        records = db.fetch_all(query)
        total_records = len(records)
        
        if total_records == 0:
            return {
                "updated_count": 0,
                "duration_seconds": 0,
                "message": "No records to recalculate"
            }
        
        print(f"🔄 Recalculating features for {total_records} records...")
        
        batch_size = 500
        updated_count = 0
        
        for i in range(0, total_records, batch_size):
            batch = records[i:i + batch_size]
            batch_updates = []
            
            for record in batch:
                try:
                    # Parse headers JSON
                    headers = {}
                    if record.get('headers_json'):
                        try:
                            headers = json.loads(record['headers_json'])
                        except (json.JSONDecodeError, TypeError):
                            headers = {}
                    
                    # Parse payload JSON
                    payload = None
                    if record.get('payload_json'):
                        try:
                            payload = json.loads(record['payload_json'])
                        except (json.JSONDecodeError, TypeError):
                            payload = None
                    
                    # Reconstruct request_data for feature extraction
                    request_data = {
                        'ip_address': record['ip_address'],
                        'headers': headers,
                        'payload': payload,
                        'endpoint': record['endpoint'],
                        'method': record['http_method'],
                        'timestamp': record['analyzed_at'].isoformat() if record.get('analyzed_at') else datetime.now().isoformat()
                    }
                    
                    # Extract fresh features
                    features = FeatureExtractor.extract_features(request_data)
                    
                    # Preserve original frequency_score (time-contextual)
                    if record.get('frequency_score') is not None:
                        features['frequency_score'] = record['frequency_score']
                    
                    batch_updates.append({
                        'id': record['id'],
                        'features': features
                    })
                    
                except Exception as e:
                    print(f"⚠ Error recalculating features for record {record['id']}: {e}")
                    continue
            
            # Batch update database
            if batch_updates:
                self._batch_update_features(batch_updates)
                updated_count += len(batch_updates)
            
            # Progress feedback
            progress = min(i + batch_size, total_records)
            print(f"  Progress: {progress}/{total_records} ({int(progress/total_records*100)}%)")
        
        duration = (datetime.now() - start_time).total_seconds()
        
        return {
            "updated_count": updated_count,
            "total_records": total_records,
            "duration_seconds": round(duration, 2),
            "message": f"Successfully recalculated features for {updated_count}/{total_records} records"
        }

    def _batch_update_features(self, batch_updates: List[Dict[str, Any]]) -> None:
        """Update features for a batch of records efficiently."""
        for update in batch_updates:
            features = update['features']
            record_id = update['id']
            
            update_query = """
                UPDATE analyzed_requests 
                SET 
                    ip_reputation_score = %s,
                    payload_complexity_score = %s,
                    header_anomaly_score = %s,
                    endpoint_risk_score = %s,
                    frequency_score = %s,
                    injection_score = %s,
                    entropy_score = %s,
                    http_method_risk = %s,
                    time_anomaly_score = %s
                WHERE id = %s
            """
            
            db.execute_query(update_query, (
                features['ip_reputation_score'],
                features['payload_complexity_score'],
                features['header_anomaly_score'],
                features['endpoint_risk_score'],
                features['frequency_score'],
                features['injection_score'],
                features['entropy_score'],
                features['http_method_risk'],
                features['time_anomaly_score'],
                record_id
            ))


# Global singleton instance
ml_service = MLService()