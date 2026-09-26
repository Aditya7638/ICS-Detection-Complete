from sqlalchemy.orm import Session
from app.db.models import Alarm
from datetime import datetime, timezone, timedelta
import uuid

COOLDOWN_MINUTES = 2

def maybe_create_alarm(result, prediction_id: str, severity: str, db: Session):
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=COOLDOWN_MINUTES)
    recent = db.query(Alarm).filter(
        Alarm.created_at >= cutoff,
        Alarm.severity == severity,
        Alarm.status != "FALSE_POSITIVE",
    ).first()
    if recent and result.final_label == "Suspicious":
        return None

    title_map = {
        "Attack": f"{severity} Severity Attack Detected",
        "Suspicious": "Suspicious Activity Detected"
    }
    alarm = Alarm(
        id=str(uuid.uuid4()),
        prediction_id=prediction_id,
        timestamp=result.timestamp,
        title=title_map.get(result.final_label, "Anomaly Detected"),
        description=result.explanation[:500],
        severity=severity,
        status="NEW",
    )
    db.add(alarm)
    return alarm
