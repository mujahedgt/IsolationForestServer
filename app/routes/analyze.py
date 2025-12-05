import json
from datetime import datetime
from fastapi import APIRouter, HTTPException

from app.models.request_models import AnalyzeRequest, AnalyzeResponse
from app.services.feature_extractor import FeatureExtractor
from app.services.ml_service import ml_service
from app.database import db

router = APIRouter()


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_request(request: AnalyzeRequest):
    """
    Analyze an incoming HTTP request and determine if it's anomalous
    using the active Isolation Forest model.
    """
    try:
        # 1. Extract numerical features
        features = FeatureExtractor.extract_features(request.dict())

        # 2. Run prediction
        is_anomaly, confidence = ml_service.predict(features)

        # 3. Persist analysis result in database
        payload_size = len(json.dumps(request.payload)) if request.payload else 0
        headers_json = json.dumps(request.headers)

        insert_query = """
            INSERT INTO analyzed_requests (
                request_id, ip_address, endpoint, http_method,
                payload_size, headers_json,
                ip_reputation_score, payload_complexity_score,
                header_anomaly_score, endpoint_risk_score, frequency_score,
                is_anomaly, confidence, model_version, analyzed_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        db.execute_query(insert_query, (
            request.request_id,
            request.ip_address,
            request.endpoint,
            request.http_method,
            payload_size,
            headers_json,
            features['ip_reputation_score'],
            features['payload_complexity_score'],
            features['header_anomaly_score'],
            features['endpoint_risk_score'],
            features['frequency_score'],
            is_anomaly,
            round(confidence, 4),
            ml_service.model_version or "unknown",
            datetime.utcnow()
        ))

        # 4. Return response
        return AnalyzeResponse(
            request_id=request.request_id,
            isAnomaly=is_anomaly,
            confidence=round(confidence, 4),
            model_version=ml_service.model_version or "unknown",
            analyzed_at=datetime.utcnow()
        )

    except ValueError as ve:
        # Specific ML/model errors
        raise HTTPException(status_code=503, detail=f"Model error: {str(ve)}")
    except Exception as e:
        # Catch-all for unexpected errors
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")