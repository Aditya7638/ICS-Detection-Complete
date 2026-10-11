from sqlalchemy import (Column, String, Float, Boolean, Integer,
                         DateTime, ForeignKey, Text, JSON, UniqueConstraint)
from sqlalchemy.orm import relationship, DeclarativeBase
from datetime import datetime, timezone
import uuid, enum

class Base(DeclarativeBase):
    pass

def now_utc():
    return datetime.now(timezone.utc)

def new_uuid():
    return str(uuid.uuid4())

class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    OPERATOR = "OPERATOR"

class AlarmStatus(str, enum.Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

class Severity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=new_uuid)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), default="OPERATOR", nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)

class SensorReading(Base):
    __tablename__ = "sensor_readings"
    id = Column(String, primary_key=True, default=new_uuid)
    timestamp = Column(DateTime, nullable=False, index=True)
    source = Column(String(64), default="api")
    sensor_data = Column(JSON, nullable=False)
    is_valid = Column(Boolean, default=True)
    validation_warnings = Column(JSON, default=list)
    created_at = Column(DateTime, default=now_utc)
    prediction = relationship("Prediction", back_populates="reading", uselist=False)

class Prediction(Base):
    __tablename__ = "predictions"
    id = Column(String, primary_key=True, default=new_uuid)
    user_id = Column(String, ForeignKey("users.id"), index=True)
    data_fingerprint = Column(String(64), index=True)
    reading_id = Column(String, ForeignKey("sensor_readings.id"), index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    ml_prediction = Column(Integer, nullable=False)
    ml_probability = Column(Float, nullable=False)
    ml_label = Column(String(16))
    rule_violation_count = Column(Integer, default=0)
    final_label = Column(String(16), nullable=False)
    severity = Column(String(16))
    rule_violations = Column(JSON, default=list)
    affected_sensors = Column(JSON, default=list)
    recommendations = Column(JSON, default=list)
    explanation = Column(Text)
    detection_context = Column(JSON, nullable=True)
    processing_ms = Column(Float)
    reading = relationship("SensorReading", back_populates="prediction")
    alarm = relationship("Alarm", back_populates="prediction", uselist=False)

class Alarm(Base):
    __tablename__ = "alarms"
    id = Column(String, primary_key=True, default=new_uuid)
    prediction_id = Column(String, ForeignKey("predictions.id"), index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(16), nullable=False)
    status = Column(String(32), default="NEW", nullable=False, index=True)
    acknowledged_by = Column(String)
    acknowledged_at = Column(DateTime)
    resolved_by = Column(String)
    resolved_at = Column(DateTime)
    resolution_notes = Column(Text)
    is_false_positive = Column(Boolean, default=False)
    created_at = Column(DateTime, default=now_utc)
    prediction = relationship("Prediction", back_populates="alarm")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=new_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    action = Column(String(128), nullable=False)
    resource = Column(String(128))
    detail = Column(JSON, default=dict)
    ip_address = Column(String(64))
    created_at = Column(DateTime, default=now_utc, index=True)

class ChatSession(Base):
    __tablename__ = "chat_sessions"
    id = Column(String, primary_key=True, default=new_uuid)
    user_id = Column(String, ForeignKey("users.id"))
    created_at = Column(DateTime, default=now_utc)
    messages = relationship("ChatMessage", back_populates="session")

class ChatMessage(Base):
    __tablename__ = "chat_messages"
    id = Column(String, primary_key=True, default=new_uuid)
    session_id = Column(String, ForeignKey("chat_sessions.id"))
    role = Column(String(16), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=now_utc)
    session = relationship("ChatSession", back_populates="messages")


# ── Risk-Aware Detection Config ───────────────────────────────────────

class DetectionConfig(Base):
    """Stores an operator-defined requirement profile and its resolved configuration."""
    __tablename__ = "detection_configs"
    id = Column(String, primary_key=True, default=new_uuid)
    version = Column(Integer, nullable=False, default=1)
    name = Column(String(128), nullable=False)
    # Profile: HIGH_RECALL | LOW_FP | CRITICAL_ASSET | BALANCED
    profile = Column(String(32), nullable=False)
    # Requirement constraints
    min_recall = Column(Float, nullable=True)
    max_fpr = Column(Float, nullable=True)
    min_precision = Column(Float, nullable=True)
    # Balanced profile weights (sum to 1.0)
    weight_precision = Column(Float, default=0.33)
    weight_recall = Column(Float, default=0.34)
    weight_fpr = Column(Float, default=0.33)
    # Resolved configuration
    threshold = Column(Float, nullable=True)          # resolved threshold (None = not yet optimized)
    fusion_strategy = Column(String(32), default="OR")  # OR | RISK_SCORE
    # Risk-score fusion weights (only used when fusion_strategy=RISK_SCORE)
    risk_weight_ml = Column(Float, default=0.50)
    risk_weight_rules = Column(Float, default=0.35)
    risk_weight_asset = Column(Float, default=0.15)
    # Status
    is_active = Column(Boolean, default=False)        # is this the current production config?
    is_baseline = Column(Boolean, default=False)      # is this the preserved baseline?
    created_by = Column(String, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)
    # Optimization outcome summary (JSON)
    optimization_outcome = Column(JSON, default=dict)
    # Relationships
    critical_assets = relationship("CriticalAsset", back_populates="config", cascade="all, delete-orphan")
    optimization_results = relationship("OptimizationResult", back_populates="config", cascade="all, delete-orphan")
    creator = relationship("User", foreign_keys=[created_by])


class CriticalAsset(Base):
    """Operator-designated critical process assets linked to a detection config."""
    __tablename__ = "critical_assets"
    id = Column(String, primary_key=True, default=new_uuid)
    config_id = Column(String, ForeignKey("detection_configs.id"), nullable=False, index=True)
    asset_tag = Column(String(32), nullable=False)     # e.g., "LIT101", "P302"
    # LOW | MEDIUM | HIGH | CRITICAL
    criticality_level = Column(String(16), nullable=False, default="MEDIUM")
    description = Column(Text, nullable=True)
    config = relationship("DetectionConfig", back_populates="critical_assets")


class OptimizationResult(Base):
    """Records a threshold-sweep evaluation run for a given config."""
    __tablename__ = "optimization_results"
    id = Column(String, primary_key=True, default=new_uuid)
    config_id = Column(String, ForeignKey("detection_configs.id"), nullable=False, index=True)
    run_at = Column(DateTime, default=now_utc, index=True)
    dataset_path = Column(String(256), nullable=True)
    n_val = Column(Integer, nullable=True)             # validation set size
    n_test = Column(Integer, nullable=True)            # test set size
    val_metrics = Column(JSON, default=dict)           # {threshold: metrics} on val set
    test_metrics = Column(JSON, default=dict)          # final metrics on held-out test period
    threshold_sweep = Column(JSON, default=list)       # [{threshold, precision, recall, f1, fpr, fnr}]
    selected_threshold = Column(Float, nullable=True)
    selected_fusion = Column(String(32), nullable=True)
    constraints_satisfied = Column(Boolean, nullable=True)
    infeasible_reason = Column(Text, nullable=True)
    alternatives = Column(JSON, default=list)          # best alternatives when infeasible
    run_by = Column(String, ForeignKey("users.id"), nullable=True)
    config = relationship("DetectionConfig", back_populates="optimization_results")
    runner = relationship("User", foreign_keys=[run_by])

    @property
    def sweep_results(self):
        return self.threshold_sweep

    @property
    def baseline_val_metrics(self):
        return (self.val_metrics or {}).get("baseline")

    @property
    def baseline_test_metrics(self):
        return (self.test_metrics or {}).get("baseline")

    @property
    def methodology_note(self):
        return (self.val_metrics or {}).get("methodology")
