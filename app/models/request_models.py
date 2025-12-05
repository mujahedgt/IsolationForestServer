from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, Dict, Any
from datetime import datetime


class AnalyzeRequest(BaseModel):
    request_id: str
    ip_address: str
    endpoint: str
    http_method: str
    headers: Dict[str, str]
    payload: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AnalyzeResponse(BaseModel):
    request_id: str
    isAnomaly: bool
    confidence: float
    model_version: Optional[str] = None
    analyzed_at: datetime
    model_config = ConfigDict(protected_namespaces=())

class TrainRequest(BaseModel):
    model_version: str
    use_corrected_labels: bool = True
    training_params: Optional[Dict[str, Any]] = None
    model_config = ConfigDict(protected_namespaces=())


class TrainResponse(BaseModel):
    success: bool
    model_version: str
    training_samples: int
    training_duration_seconds: float
    accuracy_score: Optional[float] = None
    message: str
    model_config = ConfigDict(protected_namespaces=())


class RetrainRequest(BaseModel):
    model_version: str


class RetrainResponse(BaseModel):
    success: bool
    old_model_version: str
    new_model_version: str
    training_samples: int
    corrected_labels_used: int
    accuracy_improvement: Optional[float] = None
    message: str
    model_config = ConfigDict(protected_namespaces=())


class LabelUpdateRequest(BaseModel):
    user_label: bool
    changed_by: str


class LabelUpdateResponse(BaseModel):
    success: bool
    request_id: int
    old_label: bool
    new_label: bool
    message: str


class StatisticsResponse(BaseModel):
    total_requests_analyzed: int
    anomaly_count: int
    legitimate_count: int
    anomaly_rate: float
    active_model: Dict[str, Any]
    label_corrections: Dict[str, int]
    average_confidence: float
    uptime_hours: float