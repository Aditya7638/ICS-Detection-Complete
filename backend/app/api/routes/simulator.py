from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.core.config import get_settings
from app.db.models import User, SensorReading, Prediction, Alarm
from app.auth.security import any_authenticated
from app.detection.validator import validate_sensor_row, normalize_csv_headers, extract_sensor_row
from app.detection.detection_service import build_data_fingerprint, detect
from app.services.alarm_service import maybe_create_alarm
from app.websocket.manager import ws_manager
import pandas as pd, asyncio, uuid, logging
from datetime import timedelta
from pathlib import Path

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/simulator", tags=["simulator"])

class SimulatorState:
    running: bool = False
    paused: bool = False
    speed: float = 1.0
    current_row: int = 0
    total_rows: int = 0
    dataset_path: str = ""

state = SimulatorState()
settings = get_settings()

async def _replay_loop(path: str, speed: float, user_id: str):
    df = pd.read_csv(path)
    df.columns = normalize_csv_headers(list(df.columns))
    ts_col = "Timestamp" if "Timestamp" in df.columns else None
    label_col = "Normal/Attack" if "Normal/Attack" in df.columns else None
    state.total_rows = len(df)
    interval = max(0.05, 1.0 / speed)
    history = []
    cycle = 0
    cycle_duration = timedelta(seconds=interval)
    if ts_col and not df.empty:
        timestamps = pd.to_datetime(df[ts_col], errors="coerce").dropna()
        if len(timestamps) > 1:
            cycle_duration = max(timedelta(seconds=interval), timestamps.max() - timestamps.min() + timedelta(seconds=interval))

    db = SessionLocal()
    try:
        while state.running and not df.empty:
            for idx, row in df.iterrows():
                if not state.running:
                    break
                while state.paused and state.running:
                    await asyncio.sleep(0.2)
                if not state.running:
                    break
                state.current_row = int(idx)
                row_dict = row.to_dict()
                ts = None
                if ts_col and row_dict.get(ts_col):
                    try:
                        ts = pd.to_datetime(row_dict[ts_col]).to_pydatetime()
                        if cycle:
                            ts += cycle_duration * cycle
                    except Exception:
                        pass
                sensor_dict, true_label = extract_sensor_row(row_dict, label_col=label_col, timestamp_col=ts_col)
                vr = validate_sensor_row(sensor_dict)
                if not vr.valid:
                    await asyncio.sleep(interval)
                    continue
                result = detect(vr.cleaned_row, timestamp=ts, history=history)
                history.append(vr.cleaned_row)
                del history[:-5]
                fingerprint = build_data_fingerprint(user_id, "simulator", result.timestamp, vr.cleaned_row)
                if db.query(Prediction).filter(Prediction.data_fingerprint == fingerprint).first():
                    await asyncio.sleep(interval)
                    continue
                reading = SensorReading(id=result.event_id, timestamp=result.timestamp,
                                        source="simulator", sensor_data=vr.cleaned_row, is_valid=True,
                                        validation_warnings=[])
                db.add(reading)
                pred = Prediction(id=str(uuid.uuid4()), reading_id=result.event_id,
                                  user_id=user_id,
                                  data_fingerprint=fingerprint,
                                  timestamp=result.timestamp, ml_prediction=result.ml_prediction,
                                  ml_probability=result.ml_probability, ml_label=result.ml_label,
                                  rule_violation_count=result.rule_violation_count,
                                  final_label=result.final_label, severity=result.severity,
                                  rule_violations=result.rule_violations, affected_sensors=result.affected_sensors,
                                  recommendations=result.recommendations, explanation=result.explanation,
                                  processing_ms=result.processing_ms)
                db.add(pred)
                db.flush()
                if result.final_label in ("Attack", "Suspicious") and result.severity:
                    maybe_create_alarm(result, pred.id, result.severity, db)
                db.commit()
                event = {
                    "type": "detection",
                    "event_id": result.event_id,
                    "timestamp": result.timestamp.isoformat(),
                    "final_label": result.final_label,
                    "ml_probability": result.ml_probability,
                    "severity": result.severity,
                    "rule_violation_count": result.rule_violation_count,
                    "affected_sensors": result.affected_sensors,
                    "rule_violations": result.rule_violations,
                    "recommendations": result.recommendations,
                    "explanation": result.explanation,
                    "source": "simulator",
                    "true_label": str(true_label) if true_label is not None else None,
                    "simulator": True,
                }
                await ws_manager.broadcast(event)
                await asyncio.sleep(interval)
            if state.running:
                cycle += 1
    finally:
        db.close()
        state.running = False

@router.post("/start")
async def start(background_tasks: BackgroundTasks, speed: float = 5.0,
                dataset: str = "",
                user: User = Depends(any_authenticated)):
    if state.running:
        raise HTTPException(400, "Simulator already running. Stop it first.")
    dataset = dataset or settings.SIMULATOR_DATASET
    # Resolve path relative to project root
    project_root = Path(__file__).parent.parent.parent.parent.parent
    csv_path = project_root / dataset
    if not csv_path.exists():
        csv_path = Path(dataset)
    if not csv_path.exists():
        raise HTTPException(404, f"Dataset not found: {dataset}. Configure SIMULATOR_DATASET or upload a CSV.")
    state.running = True
    state.paused = False
    state.speed = speed
    state.dataset_path = str(csv_path)
    background_tasks.add_task(_replay_loop, str(csv_path), speed, user.id)
    return {"ok": True, "message": "Simulator started (REPLAY/DEMO MODE)", "dataset": str(csv_path)}

@router.post("/pause")
def pause(user: User = Depends(any_authenticated)):
    state.paused = not state.paused
    return {"paused": state.paused}

@router.post("/stop")
def stop(user: User = Depends(any_authenticated)):
    state.running = False
    state.paused = False
    return {"ok": True}

@router.get("/status")
def status(user: User = Depends(any_authenticated)):
    return {"running": state.running, "paused": state.paused, "speed": state.speed,
            "current_row": state.current_row, "total_rows": state.total_rows,
            "dataset": state.dataset_path}
