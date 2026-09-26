from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import Alarm, Prediction, SensorReading, User
from app.auth.security import any_authenticated

router = APIRouter(prefix="/monitoring", tags=["monitoring"])

class DeletePredictionsRequest(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=500)

@router.get("/latest")
def latest(limit: int = Query(10, le=100), db: Session = Depends(get_db), user: User = Depends(any_authenticated)):
    preds = (db.query(Prediction).filter(Prediction.user_id == user.id)
             .order_by(Prediction.timestamp.desc()).limit(limit).all())
    return [{"id": p.id, "timestamp": p.timestamp.isoformat(), "final_label": p.final_label,
             "ml_probability": p.ml_probability, "severity": p.severity,
             "rule_violation_count": p.rule_violation_count,
             "affected_sensors": p.affected_sensors or []} for p in preds]

@router.get("/history")
def history(limit: int = Query(100, le=1000), offset: int = 0,
            db: Session = Depends(get_db), user: User = Depends(any_authenticated)):
    query = db.query(Prediction).filter(Prediction.user_id == user.id)
    preds = query.order_by(Prediction.timestamp.desc()).offset(offset).limit(limit).all()
    return {"total": query.count(),
            "results": [{"id": p.id, "timestamp": p.timestamp.isoformat(),
                         "final_label": p.final_label, "severity": p.severity} for p in preds]}

@router.delete("/history")
def delete_history(req: DeletePredictionsRequest, db: Session = Depends(get_db),
                   user: User = Depends(any_authenticated)):
    predictions = (db.query(Prediction)
                   .filter(Prediction.user_id == user.id, Prediction.id.in_(set(req.ids))).all())
    if not predictions:
        return {"ok": True, "deleted": 0}

    prediction_ids = [prediction.id for prediction in predictions]
    reading_ids = [prediction.reading_id for prediction in predictions if prediction.reading_id]
    db.query(Alarm).filter(Alarm.prediction_id.in_(prediction_ids)).delete(synchronize_session=False)
    db.query(Prediction).filter(Prediction.id.in_(prediction_ids)).delete(synchronize_session=False)
    if reading_ids:
        referenced_readings = (db.query(Prediction.reading_id)
                               .filter(Prediction.reading_id.in_(reading_ids)).all())
        referenced_ids = {reading_id for (reading_id,) in referenced_readings}
        orphan_ids = set(reading_ids) - referenced_ids
        if orphan_ids:
            db.query(SensorReading).filter(SensorReading.id.in_(orphan_ids)).delete(synchronize_session=False)
    db.commit()
    return {"ok": True, "deleted": len(prediction_ids)}
