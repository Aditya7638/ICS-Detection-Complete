"""
detection_service.py — Single DetectionService used by ALL input paths.
Every route (single row, CSV, WebSocket, simulator) calls detect().
"""

import time
import uuid
import hashlib
import json
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any, Optional

from app.detection.model_engine import get_model_engine, MLResult
from app.detection.rule_adapter import run_rules, RuleEngineResult
from app.detection.fusion_engine import get_fusion_engine, FusionResult
import logging

logger = logging.getLogger(__name__)

def build_data_fingerprint(user_id: str, source: str, timestamp: datetime, sensor_row: dict) -> str:
    payload = {
        "user_id": user_id,
        "source": source,
        "timestamp": timestamp.isoformat(),
        "sensor_row": sensor_row,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class DetectionResult:
    event_id: str
    timestamp: datetime
    data_valid: bool
    validation_warnings: List[str]

    # ML
    ml_prediction: int
    ml_probability: float
    ml_label: str

    # Rules
    rule_violated: bool
    rule_violation_count: int
    rule_violations: List[Dict[str, Any]]

    # Fusion
    final_label: str          # "Normal" | "Suspicious" | "Attack"
    severity: Optional[str]   # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | None
    affected_sensors: List[str]
    explanation: str
    recommendations: List[str]

    # Meta
    processing_ms: float


def detect(sensor_row: dict,
           timestamp: Optional[datetime] = None,
           warnings: Optional[List[str]] = None,
           history: Optional[List[dict]] = None) -> DetectionResult:
    """
    Core detection function. Accepts a dict of 42 raw sensor values.
    Returns a fully structured DetectionResult.
    """
    t0 = time.perf_counter()
    event_id = str(uuid.uuid4())
    ts = timestamp or datetime.now(timezone.utc)
    warns = warnings or []

    model = get_model_engine()
    fusion = get_fusion_engine()

    # 1. ML inference
    ml_result: MLResult = model.predict_single(sensor_row, history=history)

    # 2. Rule engine
    rule_result: RuleEngineResult = run_rules(sensor_row)

    # 3. Fusion
    fused: FusionResult = fusion.fuse(
        ml_probability=ml_result.probability,
        ml_label=ml_result.label,
        rule_violated=rule_result.violated,
        violation_count=rule_result.violation_count,
        violations=rule_result.violations,
    )

    processing_ms = (time.perf_counter() - t0) * 1000

    return DetectionResult(
        event_id=event_id,
        timestamp=ts,
        data_valid=True,
        validation_warnings=warns,
        ml_prediction=ml_result.prediction,
        ml_probability=ml_result.probability,
        ml_label=ml_result.label,
        rule_violated=rule_result.violated,
        rule_violation_count=rule_result.violation_count,
        rule_violations=rule_result.violations,
        final_label=fused.final_label,
        severity=fused.severity,
        affected_sensors=fused.affected_sensors,
        explanation=fused.explanation,
        recommendations=fused.recommendations,
        processing_ms=processing_ms,
    )
