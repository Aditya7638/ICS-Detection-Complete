"""
config.py — Detection Configuration (Requirement Profiles) API.

Endpoints:
  POST   /config              Create a new detection profile
  GET    /config              List all configs
  GET    /config/{id}         Get single config
  PATCH  /config/{id}         Update config (only if not active)
  DELETE /config/{id}         Delete config (only if not active/baseline)
  POST   /config/{id}/activate   Activate config (analyst/admin only)
  POST   /config/restore-baseline  Restore the original baseline

Authorization:
  - Read:   any authenticated user
  - Write:  ANALYST or ADMIN
  - Activate: ANALYST or ADMIN only
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.auth.security import any_authenticated, analyst_or_admin
from app.db.models import User, DetectionConfig, CriticalAsset
from app.db.session import get_db
from app.detection.detection_service import set_active_config, get_active_config_info
from app.schemas.schemas import (
    DetectionConfigCreate, DetectionConfigOut, ActivationRequest
)
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/config", tags=["config"])

BASELINE_CONFIG_NAME = "Baseline OR Fusion (t=0.70)"


def _ensure_baseline(db: Session) -> DetectionConfig:
    """Create the preserved baseline config if it doesn't exist."""
    baseline = db.query(DetectionConfig).filter(DetectionConfig.is_baseline == True).first()
    if not baseline:
        baseline = DetectionConfig(
            id=str(uuid.uuid4()),
            version=1,
            name=BASELINE_CONFIG_NAME,
            profile="BALANCED",
            threshold=0.70,
            fusion_strategy="OR",
            is_active=True,
            is_baseline=True,
            optimization_outcome={
                "note": "Original threshold=0.70 OR fusion. Validated performance: "
                        "Precision=98.64%, Recall=91.55%, F1=94.96%, FPR=1.27%.",
                "source": "fusion_config.json validated_performance",
            },
        )
        db.add(baseline)
        db.commit()
        db.refresh(baseline)
    return baseline


@router.get("", response_model=List[DetectionConfigOut])
def list_configs(
    db: Session = Depends(get_db),
    user: User = Depends(any_authenticated),
):
    _ensure_baseline(db)
    return db.query(DetectionConfig).order_by(DetectionConfig.created_at.desc()).all()


@router.get("/active-info")
def active_config_info(user: User = Depends(any_authenticated)):
    """Return metadata about the currently active configuration."""
    return get_active_config_info()


@router.get("/{config_id}", response_model=DetectionConfigOut)
def get_config(
    config_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(any_authenticated),
):
    cfg = db.query(DetectionConfig).filter(DetectionConfig.id == config_id).first()
    if not cfg:
        raise HTTPException(404, "Config not found")
    return cfg


@router.post("", response_model=DetectionConfigOut)
def create_config(
    req: DetectionConfigCreate,
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
):
    _ensure_baseline(db)

    # Determine next version number
    latest = db.query(DetectionConfig).order_by(DetectionConfig.version.desc()).first()
    next_version = (latest.version + 1) if latest else 1

    cfg = DetectionConfig(
        id=str(uuid.uuid4()),
        version=next_version,
        name=req.name,
        profile=req.profile,
        min_recall=req.min_recall,
        max_fpr=req.max_fpr,
        min_precision=req.min_precision,
        weight_precision=req.weight_precision,
        weight_recall=req.weight_recall,
        weight_fpr=req.weight_fpr,
        fusion_strategy=req.fusion_strategy,
        risk_weight_ml=req.risk_weight_ml,
        risk_weight_rules=req.risk_weight_rules,
        risk_weight_asset=req.risk_weight_asset,
        is_active=False,
        is_baseline=False,
        created_by=user.id,
    )
    db.add(cfg)
    db.flush()

    for asset in req.critical_assets:
        db.add(CriticalAsset(
            id=str(uuid.uuid4()),
            config_id=cfg.id,
            asset_tag=asset.asset_tag.upper(),
            criticality_level=asset.criticality_level,
            description=asset.description,
        ))

    db.commit()
    db.refresh(cfg)
    logger.info(f"Config created: id={cfg.id} name={cfg.name} by={user.username}")
    return cfg


@router.patch("/{config_id}", response_model=DetectionConfigOut)
def update_config(
    config_id: str,
    req: DetectionConfigCreate,
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
):
    cfg = db.query(DetectionConfig).filter(DetectionConfig.id == config_id).first()
    if not cfg:
        raise HTTPException(404, "Config not found")
    if cfg.is_active:
        raise HTTPException(409, "Cannot modify the currently active config. Deactivate it first.")
    if cfg.is_baseline:
        raise HTTPException(409, "Cannot modify the preserved baseline config.")

    cfg.name = req.name
    cfg.profile = req.profile
    cfg.min_recall = req.min_recall
    cfg.max_fpr = req.max_fpr
    cfg.min_precision = req.min_precision
    cfg.weight_precision = req.weight_precision
    cfg.weight_recall = req.weight_recall
    cfg.weight_fpr = req.weight_fpr
    cfg.fusion_strategy = req.fusion_strategy
    cfg.risk_weight_ml = req.risk_weight_ml
    cfg.risk_weight_rules = req.risk_weight_rules
    cfg.risk_weight_asset = req.risk_weight_asset
    cfg.threshold = None   # reset — needs re-optimization

    # Replace critical assets
    db.query(CriticalAsset).filter(CriticalAsset.config_id == config_id).delete()
    for asset in req.critical_assets:
        db.add(CriticalAsset(
            id=str(uuid.uuid4()),
            config_id=cfg.id,
            asset_tag=asset.asset_tag.upper(),
            criticality_level=asset.criticality_level,
            description=asset.description,
        ))

    db.commit()
    db.refresh(cfg)
    return cfg


@router.delete("/{config_id}")
def delete_config(
    config_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
):
    cfg = db.query(DetectionConfig).filter(DetectionConfig.id == config_id).first()
    if not cfg:
        raise HTTPException(404, "Config not found")
    if cfg.is_baseline:
        raise HTTPException(409, "Cannot delete the preserved baseline config.")
    if cfg.is_active:
        raise HTTPException(409, "Cannot delete the active config. Restore baseline first.")
    db.delete(cfg)
    db.commit()
    return {"ok": True}


@router.post("/{config_id}/activate")
def activate_config(
    config_id: str,
    req: ActivationRequest = ActivationRequest(config_id=""),
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
):
    """
    Activate a validated configuration for production use.

    IMPORTANT:
    - Only a config that has been successfully optimized (threshold != None) can be activated.
    - Activating changes the in-memory detection state immediately.
    - A full deployment restart is not required, but the change is logged.
    - The previous active config is deactivated (not deleted).
    """
    cfg = db.query(DetectionConfig).filter(DetectionConfig.id == config_id).first()
    if not cfg:
        raise HTTPException(404, "Config not found")
    if cfg.threshold is None and not cfg.is_baseline:
        raise HTTPException(400,
            "Config has no resolved threshold. Run optimization first, then activate.")

    # Deactivate current active
    db.query(DetectionConfig).filter(DetectionConfig.is_active == True).update(
        {"is_active": False}
    )

    cfg.is_active = True
    db.commit()
    db.refresh(cfg)

    # Build asset criticality dict for in-memory state
    asset_crits = {a.asset_tag: a.criticality_level for a in cfg.critical_assets}

    # Update in-memory detection state
    set_active_config(
        config_id=cfg.id,
        version=cfg.version,
        asset_criticalities=asset_crits,
    )

    logger.info(
        f"Config activated: id={cfg.id} name={cfg.name} "
        f"threshold={cfg.threshold} fusion={cfg.fusion_strategy} by={user.username}"
    )
    return {"ok": True, "activated_config_id": cfg.id, "name": cfg.name,
            "threshold": cfg.threshold, "fusion_strategy": cfg.fusion_strategy,
            "note": "Production detection logic updated. Baseline remains available for comparison and rollback."}


@router.post("/restore-baseline")
def restore_baseline(
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
):
    """Restore the original baseline (threshold=0.70, OR fusion)."""
    baseline = _ensure_baseline(db)

    # Deactivate all others
    db.query(DetectionConfig).filter(
        DetectionConfig.is_active == True,
        DetectionConfig.id != baseline.id,
    ).update({"is_active": False})

    baseline.is_active = True
    db.commit()

    # Restore in-memory state to baseline
    set_active_config(config_id=baseline.id, version=baseline.version, asset_criticalities={})

    logger.info(f"Baseline config restored by {user.username}")
    return {"ok": True, "message": "Baseline OR fusion (t=0.70) restored."}
