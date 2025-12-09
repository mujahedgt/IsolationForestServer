import pickle
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

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

        # Ensure consistent feature order
        feature_array = np.array([[
            features['ip_reputation_score'],
            features['payload_complexity_score'],
            features['header_anomaly_score'],
            features['endpoint_risk_score'],
            features['frequency_score']
        ]])

        # -1 = anomaly, 1 = normal
        prediction = self.model.predict(feature_array)[0]
        # Lower score = more anomalous
        anomaly_score = self.model.score_samples(feature_array)[0]

        # Convert to confidence (0 = normal, 1 = highly anomalous)
        confidence = float(-anomaly_score)  # score_samples returns negative values for anomalies
        confidence = min(max(confidence, 0.0), 1.0)

        is_anomaly = prediction == -1
        return is_anomaly, confidence

   def train_model(
        self,
        model_version: str,
        contamination: float = 0.1,
        n_estimators: int = 100,
        use_corrected_labels: bool = True
    ) -> Dict[str, Any]:
        """Train a new Isolation Forest model and activate it."""
        start_time = datetime.now()

        training_data = self._fetch_training_data(use_corrected_labels)
        if len(training_data) < 100:
            raise ValueError(f"Insufficient training data. Need at least 100 samples, got {len(training_data)}")

        X = np.array(training_data)

        model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=42,
            n_jobs=-1
        )
        model.fit(X)

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
            "training_duration_seconds": round(duration, 2),
            "message": "Model trained and activated successfully"
        }

   def retrain_model(self, new_model_version: str) -> Dict[str, Any]:
        """Retrain model using corrected user labels."""
        old_version = self.model_version or "none"

        count_query = "SELECT COUNT(*) as count FROM analyzed_requests WHERE user_label IS NOT NULL"
        result = db.fetch_one(count_query)
        corrected_count = result["count"] if result else 0

        if corrected_count < 10:
            raise ValueError(f"Insufficient corrected labels. Need at least 10, got {corrected_count}")

        training_result = self.train_model(
            model_version=new_model_version,
            use_corrected_labels=True
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
        """Fetch feature vectors from past analyzed requests."""
        if use_corrected_labels:
            query = """
                SELECT 
                    ip_reputation_score, payload_complexity_score, 
                    header_anomaly_score, endpoint_risk_score, frequency_score
                FROM analyzed_requests
                WHERE user_label IS NOT NULL OR is_anomaly IS NOT NULL
                ORDER BY analyzed_at DESC
                LIMIT 10000
            """
        else:
            query = """
                SELECT 
                    ip_reputation_score, payload_complexity_score, 
                    header_anomaly_score, endpoint_risk_score, frequency_score
                FROM analyzed_requests
                WHERE is_anomaly IS NOT NULL
                ORDER BY analyzed_at DESC
                LIMIT 10000
            """

        results = db.fetch_all(query)
        training_data = [
            [
                row["ip_reputation_score"],
                row["payload_complexity_score"],
                row["header_anomaly_score"],
                row["endpoint_risk_score"],
                row["frequency_score"]
            ]
            for row in results
        ]
        return training_data


# Global singleton instanc
ml_service = MLService()