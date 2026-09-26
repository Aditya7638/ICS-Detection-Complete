from sqlalchemy import (Column, String, Float, Boolean, Integer,
                         DateTime, ForeignKey, Text, JSON)
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
