from fastapi import APIRouter, HTTPException, Path
from datetime import datetime

from app.models.request_models import LabelUpdateRequest, LabelUpdateResponse
from app.database import db

router = APIRouter(prefix="/labeling", tags=["Labeling"])


@router.put(
    "/label/{request_id}",
    response_model=LabelUpdateResponse,
    summary="Provide feedback on model prediction",
    description="Mark a request as legitimate or malicious. This data is used to retrain the model."
)
async def update_label(
    request_id: int = Path(..., ge=1, description="Database ID of the analyzed request"),
    request: LabelUpdateRequest = None
):
    """
    Update the user label for a previously analyzed request.
    This enables the feedback loop for continuous model improvement.
    """
    try:
        # 1. Check if the request exists
        check_query = "SELECT id, is_anomaly FROM analyzed_requests WHERE id = %s"
        existing = db.fetch_one(check_query, (request_id,))

        if not existing:
            raise HTTPException(status_code=404, detail="Request not found")

        old_label = bool(existing["is_anomaly"])
        new_label = request.user_label

        # 2. Update the label in database
        update_query = """
            UPDATE analyzed_requests
            SET user_label = %s,
                label_changed_at = %s,
                label_changed_by = %s
            WHERE id = %s
        """
        db.execute_query(update_query, (
            new_label,
            datetime.utcnow(),
            request.changed_by,
            request_id
        ))

        # 3. Return success response
        return LabelUpdateResponse(
            success=True,
            request_id=request_id,
            old_label=old_label,
            new_label=new_label,
            message="Label updated successfully"
        )

    except HTTPException:
        # Re-raise known HTTP errors (like 404)
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Label update failed: {str(e)}"
        )