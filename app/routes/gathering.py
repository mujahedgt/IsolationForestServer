from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.services.gathering_service import gathering_service
from app.services.ml_service import ml_service
from app.database import db

router = APIRouter()

class GatheringModeRequest(BaseModel):
    gathering_mode: bool

class GatheringModeResponse(BaseModel):
    success: bool
    message: str
    gathering_mode: bool
    requests_gathered: Optional[int] = None
    model_trained: Optional[bool] = None
    new_model_version: Optional[str] = None

class GatheringStatusResponse(BaseModel):
    is_gathering_mode: bool
    gathering_started_at: Optional[str] = None
    requests_gathered: int
    duration_seconds: float

@router.post("/gathering/start", response_model=GatheringModeResponse)
async def start_gathering_mode():
    """
    Start gathering mode.
    All incoming requests will be marked as legitimate without analysis.
    """
    try:
        if gathering_service.is_gathering_mode:
            return GatheringModeResponse(
                success=False,
                message="Gathering mode is already active",
                gathering_mode=True,
                requests_gathered=gathering_service.requests_gathered
            )
        
        gathering_service.start_gathering()
        
        return GatheringModeResponse(
            success=True,
            message="Gathering mode started. All requests will be marked as legitimate.",
            gathering_mode=True,
            requests_gathered=0
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start gathering mode: {str(e)}")

@router.post("/gathering/stop", response_model=GatheringModeResponse)
async def stop_gathering_mode(auto_train: bool = True, new_model_version: Optional[str] = None):
    """
    Stop gathering mode and optionally train a new model with gathered data.
    
    Parameters:
    - auto_train: If True, automatically train a new model with gathered data (default: True)
    - new_model_version: Version for the new model (e.g., 'v2.0'). If not provided, auto-generates.
    """
    try:
        if not gathering_service.is_gathering_mode:
            return GatheringModeResponse(
                success=False,
                message="Gathering mode is not active",
                gathering_mode=False
            )
        
        # Stop gathering and get stats
        stats = gathering_service.stop_gathering()
        requests_gathered = stats['requests_gathered']
        
        # Auto-train if requested
        model_trained = False
        actual_model_version = None
        
        if auto_train and requests_gathered > 0:
            # Generate model version if not provided
            if not new_model_version:
                # Get current highest version
                query = "SELECT model_version FROM models ORDER BY id DESC LIMIT 1"
                result = db.fetch_one(query)
                
                if result:
                    # Try to increment version (e.g., v1.0 -> v1.1)
                    current_version = result['model_version']
                    try:
                        # Extract major.minor from v{major}.{minor}
                        parts = current_version.replace('v', '').split('.')
                        major = int(parts[0])
                        minor = int(parts[1]) + 1
                        new_model_version = f"v{major}.{minor}"
                    except:
                        new_model_version = "v1.0"
                else:
                    new_model_version = "v1.0"
            
            # Train new model with gathered data + old data
            try:
                training_result = ml_service.train_model(
                    model_version=new_model_version,
                    use_corrected_labels=True  # Use gathered data with user_label
                )
                model_trained = True
                actual_model_version = new_model_version
                
                print(f"✓ Trained new model {new_model_version} with {training_result['training_samples']} samples")
                
            except Exception as train_error:
                print(f"✗ Failed to train model: {train_error}")
                # Continue anyway - gathering mode stopped successfully
        
        return GatheringModeResponse(
            success=True,
            message=f"Gathering mode stopped. Collected {requests_gathered} requests." + 
                   (f" Trained new model {actual_model_version}." if model_trained else ""),
            gathering_mode=False,
            requests_gathered=requests_gathered,
            model_trained=model_trained,
            new_model_version=actual_model_version
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stop gathering mode: {str(e)}")

@router.get("/gathering/status", response_model=GatheringStatusResponse)
async def get_gathering_status():
    """
    Get current gathering mode status.
    """
    try:
        status = gathering_service.get_status()
        return GatheringStatusResponse(**status)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get gathering status: {str(e)}")

@router.post("/gathering/toggle", response_model=GatheringModeResponse)
async def toggle_gathering_mode(request: GatheringModeRequest):
    """
    Toggle gathering mode on or off.
    
    Request body:
    {
        "gathering_mode": true  // or false
    }
    """
    try:
        if request.gathering_mode:
            # Turn ON
            if gathering_service.is_gathering_mode:
                return GatheringModeResponse(
                    success=False,
                    message="Gathering mode is already active",
                    gathering_mode=True
                )
            
            gathering_service.start_gathering()
            return GatheringModeResponse(
                success=True,
                message="Gathering mode started",
                gathering_mode=True,
                requests_gathered=0
            )
        else:
            # Turn OFF
            if not gathering_service.is_gathering_mode:
                return GatheringModeResponse(
                    success=False,
                    message="Gathering mode is not active",
                    gathering_mode=False
                )
            
            stats = gathering_service.stop_gathering()
            return GatheringModeResponse(
                success=True,
                message=f"Gathering mode stopped. Collected {stats['requests_gathered']} requests.",
                gathering_mode=False,
                requests_gathered=stats['requests_gathered']
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to toggle gathering mode: {str(e)}")