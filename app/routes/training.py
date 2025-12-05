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
    Train a brand new Isolation Forest model.
    Accepts optional training parameters (contamination, n_estimators).
    """
    try:
        # Use provided params or fall back to defaults from settings
        training_params = request.training_params or {}

        contamination = training_params.get("contamination", settings.DEFAULT_CONTAMINATION)
        n_estimators = training_params.get("n_estimators", settings.DEFAULT_N_ESTIMATORS)

        result = ml_service.train_model(
            model_version=request.model_version,
            contamination=float(contamination),
            n_estimators=int(n_estimators),
            use_corrected_labels=request.use_corrected_labels
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
    """
    try:
        result = ml_service.retrain_model(new_model_version=request.model_version)

        return RetrainResponse(**result)

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Retraining failed: {str(e)}")