from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from typing import Optional, List

from app.db.session import get_db
from app.db.models import Alarm, Prediction, User
from app.auth.security import any_authenticated, analyst_or_admin
from app.schemas.schemas import AlarmResponse, AcknowledgeRequest, ResolveRequest

router = APIRouter(prefix="/alarms", tags=["alarms"])

@router.get("", response_model=List[AlarmResponse])
def list_alarms(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: Session = Depends(get_db),
    user: User = Depends(any_authenticated),
):
    q = (db.query(Alarm).join(Prediction)
         .filter(Prediction.user_id == user.id)
         .order_by(Alarm.timestamp.desc()))
    if severity:
        q = q.filter(Alarm.severity == severity.upper())
    if status:
        q = q.filter(Alarm.status == status.upper())
    return q.offset(offset).limit(limit).all()

@router.get("/{alarm_id}", response_model=AlarmResponse)
def get_alarm(alarm_id: str, db: Session = Depends(get_db), user: User = Depends(any_authenticated)):
    alarm = (db.query(Alarm).join(Prediction)
             .filter(Alarm.id == alarm_id, Prediction.user_id == user.id).first())
    if not alarm:
        raise HTTPException(404, "Alarm not found")
    return alarm

@router.post("/{alarm_id}/acknowledge")
def acknowledge_alarm(alarm_id: str, req: AcknowledgeRequest = AcknowledgeRequest(),
                      db: Session = Depends(get_db), user: User = Depends(any_authenticated)):
    alarm = (db.query(Alarm).join(Prediction)
             .filter(Alarm.id == alarm_id, Prediction.user_id == user.id).first())
    if not alarm:
        raise HTTPException(404, "Alarm not found")
    alarm.status = "ACKNOWLEDGED"
    alarm.acknowledged_by = user.username
    alarm.acknowledged_at = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}

@router.post("/{alarm_id}/resolve")
def resolve_alarm(alarm_id: str, req: ResolveRequest, db: Session = Depends(get_db),
                  user: User = Depends(analyst_or_admin)):
    alarm = (db.query(Alarm).join(Prediction)
             .filter(Alarm.id == alarm_id, Prediction.user_id == user.id).first())
    if not alarm:
        raise HTTPException(404, "Alarm not found")
    alarm.status = "FALSE_POSITIVE" if req.is_false_positive else "RESOLVED"
    alarm.is_false_positive = req.is_false_positive
    alarm.resolved_by = user.username
    alarm.resolved_at = datetime.now(timezone.utc)
    alarm.resolution_notes = req.notes
    db.commit()
    return {"ok": True}
