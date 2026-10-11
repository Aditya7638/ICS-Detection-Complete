from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import io, json, pandas as pd, uuid

from app.db.session import get_db
from app.db.models import User, SensorReading, Prediction, Alarm
from app.auth.security import any_authenticated
from app.schemas.schemas import (DetectionResponse, CSVUploadResponse, CSVRowResult,
                                   ValidationIssueOut, RuleViolationOut,
                                   LocalizationOut, AttackTypeAssessmentOut)
from app.detection.validator import validate_sensor_row, normalize_csv_headers, extract_sensor_row
from app.detection.detection_service import build_data_fingerprint, detect
from app.services.alarm_service import maybe_create_alarm
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/inference", tags=["inference"])

SEV_MAP = {"LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}
CSV_BATCH_SIZE = 5

def _build_detection_response(result) -> DetectionResponse:
    loc = None
    if result.localization:
        try:
            loc = LocalizationOut(**result.localization)
        except Exception:
            loc = None
    at = None
    if result.attack_type_assessment:
        try:
            at = AttackTypeAssessmentOut(**result.attack_type_assessment)
        except Exception:
            at = None
    return DetectionResponse(
        event_id=result.event_id,
        timestamp=result.timestamp,
        data_valid=result.data_valid,
        validation_warnings=result.validation_warnings,
        ml_prediction=result.ml_prediction,
        ml_probability=result.ml_probability,
        ml_label=result.ml_label,
        threshold_used=result.threshold_used,
        rule_violated=result.rule_violated,
        rule_violation_count=result.rule_violation_count,
        rule_violations=[RuleViolationOut(**v) for v in result.rule_violations],
        final_label=result.final_label,
        severity=result.severity,
        affected_sensors=result.affected_sensors,
        explanation=result.explanation,
        recommendations=result.recommendations,
        risk_score=getattr(result, "risk_score", None),
        risk_severity=getattr(result, "risk_severity", None),
        localization=loc,
        attack_type_assessment=at,
        active_config_version=getattr(result, "active_config_version", None),
        active_config_id=getattr(result, "active_config_id", None),
        processing_ms=result.processing_ms,
    )

def _persist_result(result, sensor_data: dict, source: str, db: Session, user_id: str):
    fingerprint = build_data_fingerprint(user_id, source, result.timestamp, sensor_data)
    if db.query(Prediction).filter(Prediction.data_fingerprint == fingerprint).first():
        return
    reading = SensorReading(
        id=result.event_id, timestamp=result.timestamp,
        source=source, sensor_data=sensor_data,
        is_valid=True, validation_warnings=result.validation_warnings,
    )
    db.add(reading)
    pred = Prediction(
        id=str(uuid.uuid4()), reading_id=result.event_id,
        user_id=user_id,
        data_fingerprint=fingerprint,
        timestamp=result.timestamp,
        ml_prediction=result.ml_prediction, ml_probability=result.ml_probability,
        ml_label=result.ml_label, rule_violation_count=result.rule_violation_count,
        final_label=result.final_label, severity=result.severity,
        rule_violations=result.rule_violations, affected_sensors=result.affected_sensors,
        recommendations=result.recommendations, explanation=result.explanation,
        detection_context={
            "threshold_used": result.threshold_used,
            "risk_score": result.risk_score,
            "risk_severity": result.risk_severity,
            "localization": result.localization,
            "attack_type_assessment": result.attack_type_assessment,
            "active_config_id": result.active_config_id,
            "active_config_version": result.active_config_version,
            "asset_criticalities": result.asset_criticalities,
        },
        processing_ms=result.processing_ms,
    )
    db.add(pred)
    db.flush()
    if result.final_label in ("Attack", "Suspicious") and result.severity:
        maybe_create_alarm(result, pred.id, result.severity, db)
    db.commit()

def _process_csv_row(row_dict: dict, ts_col: str | None, label_col: str | None,
                     db: Session, user_id: str, history: list[dict]):
    ts = None
    if ts_col and row_dict.get(ts_col):
        try:
            ts = pd.to_datetime(row_dict[ts_col]).to_pydatetime()
        except Exception:
            pass
    sensor_dict, true_label = extract_sensor_row(row_dict, label_col=label_col, timestamp_col=ts_col)
    vr = validate_sensor_row(sensor_dict)
    if not vr.valid:
        return CSVRowResult(
            row_index=int(row_dict["__row_index"]), valid=False,
            errors=[ValidationIssueOut(**vars(e)) for e in vr.errors],
            true_label=str(true_label) if true_label is not None else None,
        ), None

    result = detect(vr.cleaned_row, timestamp=ts, warnings=[w.message for w in vr.warnings], history=history)
    history.append(vr.cleaned_row)
    del history[:-5]
    _persist_result(result, vr.cleaned_row, "csv_upload", db, user_id)
    return CSVRowResult(
        row_index=int(row_dict["__row_index"]), valid=True,
        detection=_build_detection_response(result),
        true_label=str(true_label) if true_label is not None else None,
    ), result

@router.post("/row", response_model=DetectionResponse)
def detect_row(payload: dict, db: Session = Depends(get_db), user: User = Depends(any_authenticated)):
    ts = payload.pop("timestamp", None)
    raw_history = payload.pop("history", [])
    if not isinstance(raw_history, list) or len(raw_history) > 5:
        raise HTTPException(422, "history must be a list of at most 5 preceding sensor rows")
    history = []
    for history_row in raw_history:
        if not isinstance(history_row, dict):
            raise HTTPException(422, "Each history item must be a sensor-row object")
        history_validation = validate_sensor_row(history_row)
        if not history_validation.valid:
            raise HTTPException(422, detail=[{"field": e.field, "code": e.code, "message": e.message} for e in history_validation.errors])
        history.append(history_validation.cleaned_row)
    if ts and isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts)
        except Exception:
            ts = None
    vr = validate_sensor_row(payload)
    if not vr.valid:
        raise HTTPException(422, detail=[{"field": e.field, "code": e.code, "message": e.message} for e in vr.errors])
    result = detect(vr.cleaned_row, timestamp=ts, warnings=[w.message for w in vr.warnings], history=history)
    _persist_result(result, vr.cleaned_row, "api", db, user.id)
    return _build_detection_response(result)

@router.post("/csv", response_model=CSVUploadResponse)
async def detect_csv(file: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(any_authenticated)):
    if not file.filename.endswith(".csv"):
        raise HTTPException(400, "Only CSV files accepted")
    content = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(content))
    except Exception as e:
        raise HTTPException(400, f"Could not parse CSV: {e}")

    df.columns = normalize_csv_headers(list(df.columns))
    ts_col = "Timestamp" if "Timestamp" in df.columns else None
    label_col = "Normal/Attack" if "Normal/Attack" in df.columns else None

    results = []
    history = []
    attack_count = suspicious_count = normal_count = valid_count = invalid_count = 0

    for idx, row in df.iterrows():
        row_dict = row.to_dict()
        ts = None
        if ts_col and row_dict.get(ts_col):
            try:
                ts = pd.to_datetime(row_dict[ts_col]).to_pydatetime()
            except Exception:
                pass
        sensor_dict, true_label = extract_sensor_row(row_dict, label_col=label_col, timestamp_col=ts_col)
        vr = validate_sensor_row(sensor_dict)
        if not vr.valid:
            invalid_count += 1
            results.append(CSVRowResult(
                row_index=int(idx), valid=False,
                errors=[ValidationIssueOut(**vars(e)) for e in vr.errors],
                true_label=str(true_label) if true_label is not None else None,
            ))
            continue
        valid_count += 1
        result = detect(vr.cleaned_row, timestamp=ts, warnings=[w.message for w in vr.warnings], history=history)
        history.append(vr.cleaned_row)
        del history[:-5]
        _persist_result(result, vr.cleaned_row, "csv_upload", db, user.id)
        if result.final_label == "Attack": attack_count += 1
        elif result.final_label == "Suspicious": suspicious_count += 1
        else: normal_count += 1
        results.append(CSVRowResult(
            row_index=int(idx), valid=True,
            detection=_build_detection_response(result),
            true_label=str(true_label) if true_label is not None else None,
        ))

    return CSVUploadResponse(
        filename=file.filename, total_rows=len(df),
        valid_rows=valid_count, invalid_rows=invalid_count,
        attack_rows=attack_count, suspicious_rows=suspicious_count,
        normal_rows=normal_count, results=results,
    )

@router.post("/csv/stream")
async def detect_csv_stream(file: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(any_authenticated)):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(400, "Only CSV files accepted")
    content = await file.read()

    try:
        first_chunk = pd.read_csv(io.BytesIO(content), nrows=0)
    except Exception as e:
        raise HTTPException(400, f"Could not parse CSV: {e}")

    columns = normalize_csv_headers(list(first_chunk.columns))

    def generate_batches():
        try:
            history = []
            for batch_index, chunk in enumerate(pd.read_csv(io.BytesIO(content), chunksize=CSV_BATCH_SIZE), start=1):
                chunk.columns = columns
                ts_col = "Timestamp" if "Timestamp" in chunk.columns else None
                label_col = "Normal/Attack" if "Normal/Attack" in chunk.columns else None
                rows = []
                counts = {"valid": 0, "invalid": 0, "attack": 0, "suspicious": 0, "normal": 0}

                for row_index, row in chunk.iterrows():
                    row_dict = row.to_dict()
                    row_dict["__row_index"] = row_index
                    row_result, detection = _process_csv_row(row_dict, ts_col, label_col, db, user.id, history)
                    rows.append(row_result.model_dump(mode="json"))
                    if row_result.valid:
                        counts["valid"] += 1
                        counts[row_result.detection.final_label.lower()] += 1
                    else:
                        counts["invalid"] += 1

                yield json.dumps({
                    "type": "batch",
                    "batch_index": batch_index,
                    "rows": rows,
                    "counts": counts,
                }) + "\n"
        except Exception as e:
            logger.exception("CSV stream processing failed")
            yield json.dumps({"type": "error", "detail": str(e)}) + "\n"

    return StreamingResponse(generate_batches(), media_type="application/x-ndjson")
