from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db.session import get_db
from app.db.models import Prediction, Alarm, User
from app.auth.security import any_authenticated
from app.schemas.schemas import OverviewStats

router = APIRouter(prefix="/analytics", tags=["analytics"])

def _unique_prediction_count(query):
    unique_key = func.coalesce(Prediction.data_fingerprint, Prediction.id)
    return query.with_entities(func.count(func.distinct(unique_key))).scalar()

@router.get("/overview", response_model=OverviewStats)
def overview(db: Session = Depends(get_db), user: User = Depends(any_authenticated)):
    predictions = db.query(Prediction).filter(Prediction.user_id == user.id)
    alarms = db.query(Alarm).join(Prediction).filter(Prediction.user_id == user.id)
    total = _unique_prediction_count(predictions)
    normal = _unique_prediction_count(predictions.filter(Prediction.final_label == "Normal"))
    suspicious = _unique_prediction_count(predictions.filter(Prediction.final_label == "Suspicious"))
    attack = _unique_prediction_count(predictions.filter(Prediction.final_label == "Attack"))
    active = _unique_prediction_count(alarms.filter(Alarm.status.in_(["NEW", "ACKNOWLEDGED", "INVESTIGATING"])))
    critical = _unique_prediction_count(alarms.filter(Alarm.severity == "CRITICAL", Alarm.status != "RESOLVED"))
    fp = _unique_prediction_count(alarms.filter(Alarm.is_false_positive == True))
    return OverviewStats(total_readings=total, normal_count=normal, suspicious_count=suspicious,
                         attack_count=attack, active_alarms=active, critical_alarms=critical,
                         false_positive_count=fp)

@router.get("/recent")
def recent_predictions(limit: int = Query(20, le=200), db: Session = Depends(get_db),
                       user: User = Depends(any_authenticated)):
    preds = (db.query(Prediction).filter(Prediction.user_id == user.id)
             .order_by(Prediction.timestamp.desc()).limit(limit).all())
    return [{"id": p.id, "timestamp": p.timestamp.isoformat(), "source": p.reading.source if p.reading else None,
             "ml_label": p.ml_label,
             "ml_probability": p.ml_probability, "final_label": p.final_label,
             "severity": p.severity, "rule_violation_count": p.rule_violation_count,
             "affected_sensors": p.affected_sensors or [],
             "rule_violations": p.rule_violations or [],
             "recommendations": p.recommendations or [],
             "explanation": p.explanation} for p in preds]

@router.get("/alarms")
def alarm_stats(db: Session = Depends(get_db), user: User = Depends(any_authenticated)):
    alarms = db.query(Alarm).join(Prediction).filter(Prediction.user_id == user.id)
    total = alarms.count()
    by_severity = alarms.with_entities(Alarm.severity, func.count(Alarm.id)).group_by(Alarm.severity).all()
    by_status = alarms.with_entities(Alarm.status, func.count(Alarm.id)).group_by(Alarm.status).all()
    return {
        "total": total,
        "by_severity": {str(s): c for s, c in by_severity},
        "by_status": {str(s): c for s, c in by_status},
    }
