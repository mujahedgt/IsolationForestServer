import json
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException

from app.models.request_models import AnalyzeRequest, AnalyzeResponse
from app.services.feature_extractor import FeatureExtractor
from app.services.ml_service import ml_service
from app.services.gathering_service import gathering_service
from app.database import db

router = APIRouter()


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_request(request: AnalyzeRequest):
    """
    Analyze an incoming HTTP request and determine if it's anomalous
    using the active Isolation Forest model.
    
    If gathering mode is active, the request is automatically treated as legitimate
    (no ML analysis is performed) and used for data collection.
    """
    try:
        # Extract all 9 features (backward compatible - uses same input structure)
        features = FeatureExtractor.extract_features(request.dict())
        
        # Check if gathering mode is active
        if gathering_service.is_gathering_mode:
            # GATHERING MODE: Bypass ML analysis, treat as legitimate
            is_anomaly = False
            confidence = 1.0
            model_version = "gathering"
            
            # Increment gathered counter
            gathering_service.increment_gathered_count()
        else:
            # NORMAL MODE: Perform actual ML analysis with enhanced predict method
            ml_service.load_active_model()
            
            # Use the ml_service.predict() which handles all 9 features internally
            is_anomaly, confidence = ml_service.predict(features)
            model_version = ml_service.model_version or "unknown"
        
        # Persist analysis result in database with ALL 9 features
        payload_size = len(json.dumps(request.payload)) if request.payload else 0
        headers_json = json.dumps(request.headers)
        payload_json = json.dumps(request.payload) if request.payload else None
        
        insert_query = """
            INSERT INTO analyzed_requests (
                request_id, ip_address, endpoint, http_method,
                payload_size, headers_json, payload_json,
                ip_reputation_score, payload_complexity_score,
                header_anomaly_score, endpoint_risk_score, frequency_score,
                injection_score, entropy_score, http_method_risk, time_anomaly_score,
                is_anomaly, confidence, model_version, analyzed_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        db.execute_query(insert_query, (
            request.request_id,
            request.ip_address,
            request.endpoint,
            request.http_method,
            payload_size,
            headers_json,
            payload_json,
            features['ip_reputation_score'],
            features['payload_complexity_score'],
            features['header_anomaly_score'],
            features['endpoint_risk_score'],
            features['frequency_score'],
            features['injection_score'],
            features['entropy_score'],
            features['http_method_risk'],
            features['time_anomaly_score'],
            is_anomaly,
            confidence,
            model_version,
            datetime.now(timezone.utc)
        ))
        
        # Return response (same structure as before)
        return AnalyzeResponse(
            request_id=request.request_id,
            isAnomaly=is_anomaly,
            confidence=round(confidence, 4) if not gathering_service.is_gathering_mode else 1.0,
            model_version=model_version,
            analyzed_at=datetime.now(timezone.utc)
        )
        
    except ValueError as ve:
        raise HTTPException(status_code=503, detail=f"Model error: {str(ve)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")