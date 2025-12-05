from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from datetime import datetime

from app.database import db

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/requests")
async def get_analyzed_requests(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    ip_address: Optional[str] = Query(None),
    is_anomaly: Optional[bool] = Query(None),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0),
    max_confidence: Optional[float] = Query(None, ge=0.0, le=1.0),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    has_user_label: Optional[bool] = Query(None, description="Filter by whether request has user feedback"),
):
    """
    Retrieve analyzed requests with powerful filtering and pagination.
    Used by security team for investigation and model feedback.
    """
    try:
        # Build dynamic WHERE conditions
        where_conditions = []
        params = []

        if ip_address:
            where_conditions.append("ip_address = %s")
            params.append(ip_address)

        if is_anomaly is not None:
            where_conditions.append("is_anomaly = %s")
            params.append(is_anomaly)

        if min_confidence is not None:
            where_conditions.append("confidence >= %s")
            params.append(min_confidence)

        if max_confidence is not None:
            where_conditions.append("confidence <= %s")
            params.append(max_confidence)

        if date_from:
            where_conditions.append("analyzed_at >= %s")
            params.append(date_from)

        if date_to:
            where_conditions.append("analyzed_at <= %s")
            params.append(date_to)

        if has_user_label is not None:
            if has_user_label:
                where_conditions.append("user_label IS NOT NULL")
            else:
                where_conditions.append("user_label IS NULL")

        where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"

        # Count total matching records
        count_query = f"SELECT COUNT(*) AS total FROM analyzed_requests WHERE {where_clause}"
        count_result = db.fetch_one(count_query, tuple(params))
        total_records = count_result["total"] if count_result else 0

        # Pagination
        offset = (page - 1) * page_size
        total_pages = (total_records + page_size - 1) // page_size

        # Fetch paginated data
        data_query = f"""
            SELECT 
                id, request_id, ip_address, endpoint, http_method,
                is_anomaly, confidence, model_version, user_label, analyzed_at
            FROM analyzed_requests
            WHERE {where_clause}
            ORDER BY analyzed_at DESC
            LIMIT %s OFFSET %s
        """
        params_with_pagination = params + [page_size, offset]
        results = db.fetch_all(data_query, tuple(params_with_pagination))

        # Format response
        data = [
            {
                "id": row["id"],
                "request_id": row["request_id"],
                "ip_address": row["ip_address"],
                "endpoint": row["endpoint"],
                "http_method": row["http_method"],
                "is_anomaly": bool(row["is_anomaly"]),
                "confidence": float(row["confidence"]),
                "model_version": row["model_version"],
                "user_label": bool(row["user_label"]) if row["user_label"] is not None else None,
                "analyzed_at": row["analyzed_at"].isoformat() + "Z"
            }
            for row in results
        ]

        return {
            "total_records": total_records,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "data": data
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Audit query failed: {str(e)}"
        )