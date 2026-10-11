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

# ── Localization ───────────────────────────────────────────────────────
class ComponentEvidenceOut(BaseModel):
    tag: str
    area_key: str
    area_label: str
    component_type: str
    evidence_sources: List[str] = []
    evidence_score: float
    measured_value: Optional[float]
    deviation_note: Optional[str]

class LocalizationOut(BaseModel):
    implicated_components: List[ComponentEvidenceOut] = []
    implicated_areas: List[str] = []
    localization_status: str      # Confirmed | Suspected | Unknown
    summary: str
    methodology_note: str
    limitations: List[str] = []

# ── Attack Type Assessment ─────────────────────────────────────────────
class AttackTypeAssessmentOut(BaseModel):
    attack_type: str
    classification_status: str
    confidence_level: Optional[str]   # HIGH | MEDIUM | LOW | None
    supporting_indicators: List[str] = []
    contradicting_indicators: List[str] = []
    affected_components: List[str] = []
    evidence_sources: List[str] = []
    limitations: List[str] = []
    methodology_note: str

# ── Detection Response ─────────────────────────────────────────────────
class DetectionResponse(BaseModel):
    event_id: str
    timestamp: datetime
    data_valid: bool
    validation_warnings: List[str] = []
    ml_prediction: int
    ml_probability: float
    ml_label: str
    threshold_used: Optional[float] = None
    rule_violated: bool
    rule_violation_count: int
    rule_violations: List[RuleViolationOut] = []
    final_label: str
    severity: Optional[str]
    affected_sensors: List[str] = []
    explanation: str
    recommendations: List[str] = []
    # Risk-aware extensions
    risk_score: Optional[float] = None
    risk_severity: Optional[str] = None
    localization: Optional[LocalizationOut] = None
    attack_type_assessment: Optional[AttackTypeAssessmentOut] = None
    active_config_version: Optional[str] = None
    active_config_id: Optional[str] = None
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

# ── Detection Config (Requirement Profiles) ──────────────────────────

VALID_PROFILES = {"HIGH_RECALL", "LOW_FP", "CRITICAL_ASSET", "BALANCED"}
VALID_CRITICALITY = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_FUSION = {"OR", "RISK_SCORE"}

class CriticalAssetIn(BaseModel):
    asset_tag: str = Field(min_length=2, max_length=32)
    criticality_level: str = Field(default="MEDIUM")
    description: Optional[str] = Field(default=None, max_length=500)

    @field_validator("criticality_level")
    @classmethod
    def validate_criticality(cls, v: str) -> str:
        v = v.upper()
        if v not in VALID_CRITICALITY:
            raise ValueError(f"criticality_level must be one of {VALID_CRITICALITY}")
        return v

class CriticalAssetOut(BaseModel):
    id: str
    asset_tag: str
    criticality_level: str
    description: Optional[str]
    class Config: from_attributes = True

class DetectionConfigCreate(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    profile: str
    min_recall: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    max_fpr: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    min_precision: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    weight_precision: float = Field(default=0.33, ge=0.0, le=1.0)
    weight_recall: float = Field(default=0.34, ge=0.0, le=1.0)
    weight_fpr: float = Field(default=0.33, ge=0.0, le=1.0)
    fusion_strategy: str = Field(default="OR")
    risk_weight_ml: float = Field(default=0.50, ge=0.0, le=1.0)
    risk_weight_rules: float = Field(default=0.35, ge=0.0, le=1.0)
    risk_weight_asset: float = Field(default=0.15, ge=0.0, le=1.0)
    critical_assets: List[CriticalAssetIn] = []

    @field_validator("profile")
    @classmethod
    def validate_profile(cls, v: str) -> str:
        v = v.upper()
        if v not in VALID_PROFILES:
            raise ValueError(f"profile must be one of {VALID_PROFILES}")
        return v

    @field_validator("fusion_strategy")
    @classmethod
    def validate_fusion(cls, v: str) -> str:
        v = v.upper()
        if v not in VALID_FUSION:
            raise ValueError(f"fusion_strategy must be one of {VALID_FUSION}")
        return v

    @model_validator(mode="after")
    def check_weights(self) -> "DetectionConfigCreate":
        # Warn but don't error if balanced weights don't sum to 1
        total = self.weight_precision + self.weight_recall + self.weight_fpr
        if abs(total - 1.0) > 0.05:
            # Round warning; we don't reject, just log
            pass
        return self

class DetectionConfigOut(BaseModel):
    id: str
    version: int
    name: str
    profile: str
    min_recall: Optional[float]
    max_fpr: Optional[float]
    min_precision: Optional[float]
    weight_precision: float
    weight_recall: float
    weight_fpr: float
    threshold: Optional[float]
    fusion_strategy: str
    risk_weight_ml: float
    risk_weight_rules: float
    risk_weight_asset: float
    is_active: bool
    is_baseline: bool
    created_by: Optional[str]
    created_at: datetime
    optimization_outcome: Optional[Dict[str, Any]]
    critical_assets: List[CriticalAssetOut] = []
    class Config: from_attributes = True

# ── Optimizer ─────────────────────────────────────────────────────────

class OptimizationRequest(BaseModel):
    config_id: str
    dataset_path: Optional[str] = None   # defaults to data/NewTestData.csv or ne_data.csv
    threshold_range_min: float = Field(default=0.30, ge=0.0, le=1.0)
    threshold_range_max: float = Field(default=0.95, ge=0.0, le=1.0)
    threshold_step: float = Field(default=0.01, ge=0.001, le=0.10)

class OptimizationResultOut(BaseModel):
    id: str
    config_id: str
    run_at: datetime
    n_val: Optional[int]
    n_test: Optional[int]
    selected_threshold: Optional[float]
    selected_fusion: Optional[str]
    constraints_satisfied: Optional[bool]
    infeasible_reason: Optional[str]
    val_metrics: Optional[Dict[str, Any]]
    test_metrics: Optional[Dict[str, Any]]
    baseline_val_metrics: Optional[Dict[str, Any]]
    baseline_test_metrics: Optional[Dict[str, Any]]
    sweep_results: Optional[List[Dict[str, Any]]]
    alternatives: Optional[List[Dict[str, Any]]]
    methodology_note: Optional[str]
    class Config: from_attributes = True

class ActivationRequest(BaseModel):
    config_id: str
    notes: Optional[str] = None

# ── Evaluation Results ─────────────────────────────────────────────────

class EvalConfigResult(BaseModel):
    label: str
    threshold: float
    fusion: str
    precision: float
    recall: float
    f1: float
    fpr: float
    fnr: float
    tp: int
    fp: int
    tn: int
    fn: int
    constraints_satisfied: Optional[bool] = None
