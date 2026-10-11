"""
events.py — Detection Event Detail API.

Endpoints:
  GET /events                  List events with filters
  GET /events/{event_id}       Full event detail including localization and attack type
  GET /events/stats/risk       Risk distribution summary
"""

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from typing import Optional
from datetime import datetime

from app.auth.security import any_authenticated
from app.db.models import User, Prediction
from app.db.session import get_db
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/events", tags=["events"])


@router.get("")
def list_events(
    final_label: Optional[str] = Query(None, description="Filter by Normal/Suspicious/Attack"),
    severity: Optional[str] = Query(None, description="Filter by LOW/MEDIUM/HIGH/CRITICAL"),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    affected_sensor: Optional[str] = Query(None, description="Filter by sensor tag"),
    rule_id: Optional[str] = Query(None, description="Filter by violated rule ID"),
    limit: int = Query(50, le=500),
    offset: int = 0,
    db: Session = Depends(get_db),
    user: User = Depends(any_authenticated),
):
    """
    List detection events with optional filters.
    Returns localization summary and attack type for each event.
    """
    q = db.query(Prediction).filter(Prediction.user_id == user.id)

    if final_label:
        q = q.filter(Prediction.final_label == final_label)
    if severity:
        q = q.filter(Prediction.severity == severity.upper())
    if start_time:
        q = q.filter(Prediction.timestamp >= start_time)
    if end_time:
        q = q.filter(Prediction.timestamp <= end_time)

    ordered = q.order_by(Prediction.timestamp.desc())
    if affected_sensor or rule_id:
        filtered = ordered.all()
        if affected_sensor:
            sensor_tag = affected_sensor.upper()
            filtered = [
                prediction for prediction in filtered
                if sensor_tag in [sensor.upper() for sensor in (prediction.affected_sensors or [])]
            ]
        if rule_id:
            filtered = [
                prediction for prediction in filtered
                if any(
                    violation.get("rule_id") == rule_id
                    for violation in (prediction.rule_violations or [])
                )
            ]
        total = len(filtered)
        preds = filtered[offset:offset + limit]
    else:
        total = q.count()
        preds = ordered.offset(offset).limit(limit).all()

    results = []
    for p in preds:
        result = {
            "id": p.id,
            "timestamp": p.timestamp.isoformat(),
            "final_label": p.final_label,
            "severity": p.severity,
            "ml_probability": round(p.ml_probability, 4),
            "rule_violation_count": p.rule_violation_count,
            "rule_violations": p.rule_violations or [],
            "affected_sensors": p.affected_sensors or [],
            "explanation": p.explanation,
            "recommendations": p.recommendations or [],
            "source": p.reading.source if p.reading else None,
            "event_id": p.reading_id,
        }
        results.append(result)

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "results": results,
    }


@router.get("/stats/risk")
def risk_distribution(
    db: Session = Depends(get_db),
    user: User = Depends(any_authenticated),
):
    """Return distribution of events by final_label and severity."""
    preds = db.query(Prediction).filter(Prediction.user_id == user.id)

    label_dist = (preds.with_entities(Prediction.final_label, func.count(Prediction.id))
                  .group_by(Prediction.final_label).all())
    severity_dist = (preds.with_entities(Prediction.severity, func.count(Prediction.id))
                     .group_by(Prediction.severity).all())

    return {
        "by_label": {label: count for label, count in label_dist},
        "by_severity": {(sev or "None"): count for sev, count in severity_dist},
        "total": preds.count(),
    }


@router.get("/{event_id}")
def get_event(
    event_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(any_authenticated),
):
    """
    Full event detail including:
    - ML result and threshold used
    - All rule violations with evidence
    - Localization (from stored prediction data)
    - Attack type assessment (from stored prediction data)
    - Alarm status if exists
    """
    pred = (db.query(Prediction)
            .filter(
                Prediction.user_id == user.id,
                or_(Prediction.id == event_id, Prediction.reading_id == event_id),
            )
            .first())
    if not pred:
        raise HTTPException(404, "Event not found")

    alarm_info = None
    if pred.alarm:
        alarm_info = {
            "id": pred.alarm.id,
            "title": pred.alarm.title,
            "status": pred.alarm.status,
            "severity": pred.alarm.severity,
            "acknowledged_by": pred.alarm.acknowledged_by,
            "acknowledged_at": pred.alarm.acknowledged_at.isoformat() if pred.alarm.acknowledged_at else None,
        }

    sensor_data = pred.reading.sensor_data if pred.reading else {}

    return {
        "id": pred.id,
        "event_id": pred.reading_id or pred.id,
        "timestamp": pred.timestamp.isoformat(),
        "source": pred.reading.source if pred.reading else None,

        # ML
        "ml_prediction": pred.ml_prediction,
        "ml_probability": round(pred.ml_probability, 4),
        "ml_label": pred.ml_label,
        "threshold_used": (pred.detection_context or {}).get("threshold_used"),

        # Rules
        "rule_violated": pred.rule_violation_count > 0,
        "rule_violation_count": pred.rule_violation_count,
        "rule_violations": pred.rule_violations or [],

        # Fusion result
        "final_label": pred.final_label,
        "severity": pred.severity,
        "affected_sensors": pred.affected_sensors or [],
        "explanation": pred.explanation,
        "recommendations": pred.recommendations or [],
        "detection_context": pred.detection_context,

        # Sensor values (for deviation display)
        "sensor_values": sensor_data,

        # Alarm
        "alarm": alarm_info,
    }
