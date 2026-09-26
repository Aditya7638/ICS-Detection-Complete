from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
from app.db.models import UserRole

# ── Auth ──────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str = Field(min_length=9)
    role: UserRole = UserRole.OPERATOR

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str) -> str:
        if not any(not character.isalnum() for character in password):
            raise ValueError("Password must contain at least one special character.")
        return password

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    class Config: from_attributes = True

# ── Sensor reading ─────────────────────────────────────────────────────
class SensorReadingRequest(BaseModel):
    timestamp: Optional[datetime] = None
    # All 42 raw sensor/actuator columns are passed as a flat dict
    # We use model_extra to accept them
    model_config = {"extra": "allow"}

class ValidationIssueOut(BaseModel):
    field: str
    code: str
    message: str
    severity: str

class RuleViolationOut(BaseModel):
    rule_id: str
    status: str
    message: str
    evidence: Dict[str, Any] = {}

class DetectionResponse(BaseModel):
    event_id: str
    timestamp: datetime
    data_valid: bool
    validation_warnings: List[str] = []
    ml_prediction: int
    ml_probability: float
    ml_label: str
    rule_violated: bool
    rule_violation_count: int
    rule_violations: List[RuleViolationOut] = []
    final_label: str
    severity: Optional[str]
    affected_sensors: List[str] = []
    explanation: str
    recommendations: List[str] = []
    processing_ms: float

class CSVRowResult(BaseModel):
    row_index: int
    valid: bool
    errors: List[ValidationIssueOut] = []
    detection: Optional[DetectionResponse] = None
    true_label: Optional[str] = None

class CSVUploadResponse(BaseModel):
    filename: str
    total_rows: int
    valid_rows: int
    invalid_rows: int
    attack_rows: int
    suspicious_rows: int
    normal_rows: int
    results: List[CSVRowResult]

# ── Alarms ────────────────────────────────────────────────────────────
class AlarmResponse(BaseModel):
    id: str
    timestamp: datetime
    title: str
    description: Optional[str]
    severity: str
    status: str
    acknowledged_by: Optional[str]
    acknowledged_at: Optional[datetime]
    resolved_at: Optional[datetime]
    resolution_notes: Optional[str]
    is_false_positive: bool
    created_at: datetime
    class Config: from_attributes = True

class AcknowledgeRequest(BaseModel):
    notes: Optional[str] = None

class ResolveRequest(BaseModel):
    notes: Optional[str] = None
    is_false_positive: bool = False

# ── Analytics ────────────────────────────────────────────────────────
class OverviewStats(BaseModel):
    total_readings: int
    normal_count: int
    suspicious_count: int
    attack_count: int
    active_alarms: int
    critical_alarms: int
    false_positive_count: int

# ── Chat ─────────────────────────────────────────────────────────────
class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None
    context: Optional[Dict[str, Any]] = None

class ChatResponse(BaseModel):
    reply: str
    session_id: str

# ── Model info ───────────────────────────────────────────────────────
class ModelInfoResponse(BaseModel):
    model_loaded: bool
    model_type: str
    model_version: str
    feature_count: int
    raw_feature_count: int
    rolling_window: int
    features: List[str]
    classes: List[int]
    probability_supported: bool
    decision_threshold: float
    fusion_logic: str
    active_rules: List[str]
    validated_performance: Optional[Dict[str, float]]
