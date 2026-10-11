from fastapi import APIRouter, Depends
from app.detection.model_engine import get_model_engine
from app.detection.fusion_engine import get_fusion_engine
from app.detection.rule_adapter import get_active_rule_ids
from app.schemas.schemas import ModelInfoResponse
from app.auth.security import any_authenticated
from app.db.models import User
from app.detection.detection_service import get_active_config_info
import json
from pathlib import Path

router = APIRouter(tags=["system"])

@router.get("/health")
def health():
    try:
        m = get_model_engine()
        model_ok = m is not None
    except Exception:
        model_ok = False
    return {"status": "ok" if model_ok else "degraded", "model_loaded": model_ok}

@router.get("/system/model-info", response_model=ModelInfoResponse)
def model_info(user: User = Depends(any_authenticated)):
    m = get_model_engine()
    f = get_fusion_engine()
    active_config = get_active_config_info()
    cfg = f.cfg
    return ModelInfoResponse(
        model_loaded=True,
        model_type="RandomForestClassifier",
        model_version="best_model.joblib",
        feature_count=m.total_feature_count,
        raw_feature_count=m.raw_feature_count,
        rolling_window=m.rolling_window,
        features=m.feature_names,
        classes=[0, 1],
        probability_supported=True,
        decision_threshold=active_config["threshold"],
        fusion_logic=active_config["fusion_strategy"],
        active_rules=get_active_rule_ids(),
        validated_performance=cfg.get("validated_performance"),
    )
