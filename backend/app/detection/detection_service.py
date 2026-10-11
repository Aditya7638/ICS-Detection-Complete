"""
detection_service.py — Single DetectionService used by ALL input paths.
Every route (single row, CSV, WebSocket, simulator) calls detect().

Extended in the risk-aware upgrade to include:
  - risk_score (0-100) — heuristic, not a calibrated probability
  - localization result — affected components and process areas
  - attack_type assessment — evidence-based, not a trained classifier
  - active_config_version — which detection config was in effect
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
from app.detection.risk_scorer import compute_risk_score, RiskScore
from app.detection.localization import localize_event, LocalizationResult
from app.detection.attack_type import assess_attack_type, AttackTypeResult
import logging

logger = logging.getLogger(__name__)

# Active config state — updated when an operator activates a config
_active_config_version: Optional[str] = None
_active_config_id: Optional[str] = None
_active_asset_criticalities: Dict[str, str] = {}
_active_detection_settings = (0.70, "OR")
_active_is_baseline = True


def set_active_config(
    config_id: str,
    version: int,
    asset_criticalities: Dict[str, str],
    threshold: float,
    fusion_strategy: str,
    is_baseline: bool = False,
):
    """Called by the config activation endpoint."""
    global _active_config_version, _active_config_id, _active_asset_criticalities
    global _active_detection_settings, _active_is_baseline
    strategy = fusion_strategy.upper()
    if strategy not in {"OR", "RF_OR_RULES", "RF_ONLY"}:
        raise ValueError(f"Unsupported live fusion strategy: {strategy}")
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("Detection threshold must be between 0 and 1.")
    _active_config_id = config_id
    _active_config_version = f"v{version}"
    _active_asset_criticalities = dict(asset_criticalities)
    _active_detection_settings = (threshold, strategy)
    _active_is_baseline = is_baseline
    logger.info(
        f"Active detection config updated: id={config_id} version={version} "
        f"threshold={threshold} fusion={strategy}"
    )


def get_active_config_info() -> Dict[str, Any]:
    return {
        "config_id": _active_config_id,
        "config_version": _active_config_version,
        "is_baseline": _active_is_baseline,
        "threshold": _active_detection_settings[0],
        "fusion_strategy": _active_detection_settings[1],
        "asset_criticalities": _active_asset_criticalities,
    }


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
    threshold_used: float

    # Rules
    rule_violated: bool
    rule_violation_count: int
    rule_violations: List[Dict[str, Any]]

    # Fusion (baseline OR logic)
    final_label: str          # "Normal" | "Suspicious" | "Attack"
    severity: Optional[str]   # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | None
    affected_sensors: List[str]
    explanation: str
    recommendations: List[str]

    # Risk score (new)
    risk_score: float           # 0-100 heuristic
    risk_severity: Optional[str]  # None | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"

    # Localization (new)
    localization: Optional[Dict[str, Any]]

    # Attack type assessment (new)
    attack_type_assessment: Optional[Dict[str, Any]]

    # Config provenance (new)
    active_config_version: Optional[str]
    active_config_id: Optional[str]
    asset_criticalities: Dict[str, str]

    # Meta
    processing_ms: float


def detect(sensor_row: dict,
           timestamp: Optional[datetime] = None,
           warnings: Optional[List[str]] = None,
           history: Optional[List[dict]] = None) -> DetectionResult:
    """
    Core detection function. Accepts a dict of 42 raw sensor values.
    Returns a fully structured DetectionResult including risk score,
    localization, and attack type assessment.
    """
    t0 = time.perf_counter()
    event_id = str(uuid.uuid4())
    ts = timestamp or datetime.now(timezone.utc)
    warns = warnings or []

    model = get_model_engine()
    fusion = get_fusion_engine()
    active_threshold, active_fusion_strategy = _active_detection_settings

    # 1. ML inference
    ml_result: MLResult = model.predict_single(
        sensor_row,
        history=history,
        threshold=active_threshold,
    )

    # 2. Rule engine
    rule_result: RuleEngineResult = run_rules(sensor_row)

    # 3. Baseline OR fusion (unchanged)
    fused: FusionResult = fusion.fuse(
        ml_probability=ml_result.probability,
        ml_label=ml_result.label,
        rule_violated=rule_result.violated,
        violation_count=rule_result.violation_count,
        violations=rule_result.violations,
        threshold=active_threshold,
        fusion_strategy=active_fusion_strategy,
    )

    # 4. Risk score (heuristic — uses active asset criticalities)
    risk: RiskScore = compute_risk_score(
        ml_probability=ml_result.probability,
        violation_count=rule_result.violation_count,
        affected_sensor_tags=fused.affected_sensors,
        asset_criticalities=_active_asset_criticalities,
    )

    # 5. Localization
    loc: LocalizationResult = localize_event(
        rule_violations=rule_result.violations,
        affected_sensors=fused.affected_sensors,
        sensor_row=sensor_row,
        ml_probability=ml_result.probability,
        ml_triggered=fused.ml_triggered,
    )

    loc_dict = {
        "implicated_components": [
            {
                "tag": c.tag,
                "area_key": c.area_key,
                "area_label": c.area_label,
                "component_type": c.component_type,
                "evidence_sources": c.evidence_sources,
                "evidence_score": c.evidence_score,
                "measured_value": c.measured_value,
                "deviation_note": c.deviation_note,
            }
            for c in loc.implicated_components
        ],
        "implicated_areas": loc.implicated_areas,
        "localization_status": loc.localization_status,
        "summary": loc.summary,
        "methodology_note": loc.methodology_note,
        "limitations": loc.limitations,
    }

    # 6. Attack type assessment
    at: AttackTypeResult = assess_attack_type(
        rule_violations=rule_result.violations,
        ml_probability=ml_result.probability,
        ml_triggered=fused.ml_triggered,
        affected_sensors=fused.affected_sensors,
    )

    at_dict = {
        "attack_type": at.attack_type,
        "classification_status": at.classification_status,
        "confidence_level": at.confidence_level,
        "supporting_indicators": at.supporting_indicators,
        "contradicting_indicators": at.contradicting_indicators,
        "affected_components": at.affected_components,
        "evidence_sources": at.evidence_sources,
        "limitations": at.limitations,
        "methodology_note": at.methodology_note,
    }

    processing_ms = (time.perf_counter() - t0) * 1000

    return DetectionResult(
        event_id=event_id,
        timestamp=ts,
        data_valid=True,
        validation_warnings=warns,
        ml_prediction=ml_result.prediction,
        ml_probability=ml_result.probability,
        ml_label=ml_result.label,
        threshold_used=ml_result.threshold_used,
        rule_violated=rule_result.violated,
        rule_violation_count=rule_result.violation_count,
        rule_violations=rule_result.violations,
        final_label=fused.final_label,
        severity=fused.severity,
        affected_sensors=fused.affected_sensors,
        explanation=fused.explanation,
        recommendations=fused.recommendations,
        risk_score=risk.score,
        risk_severity=risk.severity,
        localization=loc_dict,
        attack_type_assessment=at_dict,
        active_config_version=_active_config_version,
        active_config_id=_active_config_id,
        asset_criticalities={
            tag: _active_asset_criticalities[tag]
            for tag in fused.affected_sensors
            if tag in _active_asset_criticalities
        },
        processing_ms=processing_ms,
    )
