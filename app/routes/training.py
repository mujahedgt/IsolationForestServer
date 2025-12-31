from fastapi import APIRouter, HTTPException

from app.models.request_models import (
    TrainRequest, TrainResponse,
    RetrainRequest, RetrainResponse
)
from app.services.ml_service import ml_service
from app.config import settings

router = APIRouter(prefix="/training", tags=["Training"])


@router.post("/train", response_model=TrainResponse)
async def train_model(request: TrainRequest):
    """
    Training a brand new Isolation Forest model.
    Accepts optional training parameters (contamination, n_estimators).
    
    Optional in training_params:
    - recalculate_features: bool (default False) - Recalculate all features before training
    - max_samples: int (default 256) - Max samples for tree building
    """
    try:
        # Use provided params or fall back to defaults from settings
        training_params = request.training_params or {}

        contamination = training_params.get("contamination", settings.DEFAULT_CONTAMINATION)
        n_estimators = training_params.get("n_estimators", settings.DEFAULT_N_ESTIMATORS)
        max_samples = training_params.get("max_samples", 256)
        recalculate_features = training_params.get("recalculate_features", False)
        result = ml_service.train_model(
            model_version=request.model_version,
            contamination=float(contamination),
            n_estimators=int(n_estimators),
            max_samples=int(max_samples),
            use_corrected_labels=request.use_corrected_labels,
            recalculate_features=bool(recalculate_features)
        )

        return TrainResponse(**result)

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")


@router.post("/retrain", response_model=RetrainResponse)
async def retrain_model(request: RetrainRequest):
    """
    Retrain the model using user-corrected labels (feedback loop).
    This improves detection over time.
    
    Optional: Pass recalculate_features in the request body to refresh features before retraining.
    """
    try:
        # Check if recalculate_features exists in request (backward compatible)
        recalculate_features = False
        if hasattr(request, 'recalculate_features'):
            recalculate_features = request.recalculate_features
        
        result = ml_service.retrain_model(
            new_model_version=request.model_version,
            recalculate_features=recalculate_features
        )

        return RetrainResponse(**result)

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Retraining failed: {str(e)}")