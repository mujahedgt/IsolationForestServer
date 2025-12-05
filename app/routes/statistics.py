from fastapi import APIRouter, HTTPException
from datetime import datetime, timedelta

from app.models.request_models import StatisticsResponse
from app.database import db

router = APIRouter(prefix="/statistics", tags=["Statistics"])

# Server start time (automatically set when module is loaded)
SERVER_START_TIME = datetime.utcnow()


@router.get("/", response_model=StatisticsResponse)
async def get_statistics():
    """
    Get comprehensive server and model performance statistics.
    Perfect for monitoring dashboards and health checks.
    """
    try:
        # 1. Total requests analyzed
        total_result = db.fetch_one("SELECT COUNT(*) AS total FROM analyzed_requests")
        total_requests = total_result["total"] if total_result else 0

        # 2. Anomaly vs Legitimate breakdown
        anomaly_result = db.fetch_one("SELECT COUNT(*) AS count FROM analyzed_requests WHERE is_anomaly = TRUE")
        anomaly_count = anomaly_result["count"] if anomaly_result else 0
        legitimate_count = total_requests - anomaly_count

        anomaly_rate = round(anomaly_count / total_requests, 4) if total_requests > 0 else 0.0

        # 3. Active model information
        model_result = db.fetch_one("""
            SELECT model_version, training_date, training_samples, accuracy_score
            FROM models WHERE is_active = TRUE LIMIT 1
        """)

        if model_result and model_result["model_version"]:
            active_model = {
                "version": model_result["model_version"],
                "training_date": model_result["training_date"].isoformat() + "Z",
                "training_samples": model_result["training_samples"],
                "accuracy_score": float(model_result["accuracy_score"]) if model_result["accuracy_score"] else None
            }
        else:
            active_model = {
                "version": "none",
                "training_date": None,
                "training_samples": 0,
                "accuracy_score": None
            }

        # 4. Label corrections (false positives / false negatives corrected by humans)
        corrections_result = db.fetch_one("""
            SELECT 
                COUNT(*) AS total_corrections,
                SUM(CASE WHEN is_anomaly = TRUE AND user_label = FALSE THEN 1 ELSE 0 END) AS false_positives,
                SUM(CASE WHEN is_anomaly = FALSE AND user_label = TRUE THEN 1 ELSE 0 END) AS false_negatives
            FROM analyzed_requests
            WHERE user_label IS NOT NULL
        """)

        label_corrections = {
            "total_corrections": corrections_result["total_corrections"] or 0,
            "false_positives_corrected": corrections_result["false_positives"] or 0,
            "false_negatives_corrected": corrections_result["false_negatives"] or 0
        }

        # 5. Average prediction confidence
        avg_result = db.fetch_one("SELECT AVG(confidence) AS avg_conf FROM analyzed_requests")
        average_confidence = round(float(avg_result["avg_conf"] or 0.0), 4)

        # 6. Server uptime in hours
        uptime_hours = round((datetime.utcnow() - SERVER_START_TIME).total_seconds() / 3600, 2)

        # 7. Return structured response
        return StatisticsResponse(
            total_requests_analyzed=total_requests,
            anomaly_count=anomaly_count,
            legitimate_count=legitimate_count,
            anomaly_rate=anomaly_rate,
            active_model=active_model,
            label_corrections=label_corrections,
            average_confidence=average_confidence,
            uptime_hours=uptime_hours
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve statistics: {str(e)}"
        )