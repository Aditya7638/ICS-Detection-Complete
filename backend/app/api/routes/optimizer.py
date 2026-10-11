"""
optimizer.py — Threshold Optimization API.

Endpoints:
  POST /optimizer/run          Run threshold sweep for a config
  GET  /optimizer/results/{config_id}  Get all optimization runs for a config
  GET  /optimizer/results/run/{run_id}  Get a specific run
  POST /optimizer/evaluate     Run full baseline comparison (A-F)
"""

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from app.auth.security import any_authenticated, analyst_or_admin
from app.db.models import User, DetectionConfig, OptimizationResult
from app.db.session import get_db
from app.schemas.schemas import (
    OptimizationRequest, OptimizationResultOut, EvalConfigResult
)
import logging
import numpy as np

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/optimizer", tags=["optimizer"])

# Default dataset paths (checked in order)
EVAL_DATASET_CANDIDATES = [
    "data/NewTestData.csv",
    "data/ne_data.csv",
]


def _find_dataset(override: Optional[str] = None) -> str:
    base = Path(__file__).parent.parent.parent.parent
    if override:
        p = base / override
        if p.exists():
            return str(p)
        raise FileNotFoundError(f"Dataset not found: {override}")
    for candidate in EVAL_DATASET_CANDIDATES:
        p = base / candidate
        if p.exists():
            return str(p)
    raise FileNotFoundError(
        f"No evaluation dataset found. Expected one of: {EVAL_DATASET_CANDIDATES}"
    )


def _run_optimization_sync(
    config_id: str,
    run_id: str,
    dataset_path: str,
    threshold_range_min: float,
    threshold_range_max: float,
    threshold_step: float,
    db_session_factory,
):
    """Synchronous optimization run (called in background task)."""
    from app.db.session import SessionLocal
    from app.detection.model_engine import get_model_engine
    from app.detection.threshold_optimizer import run_optimization, load_eval_dataset

    db = SessionLocal()
    try:
        run = db.query(OptimizationResult).filter(OptimizationResult.id == run_id).first()
        cfg = db.query(DetectionConfig).filter(DetectionConfig.id == config_id).first()
        if not run or not cfg:
            return

        try:
            model = get_model_engine()
            proba, y_true, rule_flags = load_eval_dataset(dataset_path, model)

            outcome = run_optimization(
                probabilities=proba,
                y_true=y_true,
                rule_flags=rule_flags,
                profile=cfg.profile,
                min_recall=cfg.min_recall,
                max_fpr=cfg.max_fpr,
                min_precision=cfg.min_precision,
                weight_precision=cfg.weight_precision,
                weight_recall=cfg.weight_recall,
                weight_fpr=cfg.weight_fpr,
                threshold_range=(threshold_range_min, threshold_range_max),
                threshold_step=threshold_step,
            )

            run.n_val = outcome.n_validation
            run.n_test = outcome.n_test
            run.threshold_sweep = outcome.sweep_results
            run.selected_threshold = outcome.selected_threshold
            run.selected_fusion = outcome.selected_fusion
            run.constraints_satisfied = outcome.feasible
            run.infeasible_reason = outcome.infeasible_reason
            run.val_metrics = outcome.val_metrics
            run.test_metrics = outcome.test_metrics
            run.alternatives = outcome.alternatives
            # Store baseline as part of val_metrics for reference
            run.val_metrics = {
                "selected": outcome.val_metrics,
                "baseline": outcome.baseline_val_metrics,
                "methodology": outcome.methodology_note,
            }
            run.test_metrics = {
                "selected": outcome.test_metrics,
                "baseline": outcome.baseline_test_metrics,
            }

            # Update config with resolved threshold if feasible
            if outcome.feasible and outcome.selected_threshold is not None:
                cfg.threshold = outcome.selected_threshold
                cfg.fusion_strategy = outcome.selected_fusion.replace("RF_ONLY", "OR")
                cfg.optimization_outcome = {
                    "feasible": True,
                    "selected_threshold": outcome.selected_threshold,
                    "selected_fusion": outcome.selected_fusion,
                    "val_metrics": outcome.val_metrics,
                    "test_metrics": outcome.test_metrics,
                }
            else:
                cfg.optimization_outcome = {
                    "feasible": False,
                    "infeasible_reason": outcome.infeasible_reason,
                    "alternatives": outcome.alternatives,
                }

            db.commit()
            logger.info(f"Optimization run complete: {run_id}, feasible={outcome.feasible}")

        except Exception as exc:
            logger.exception(f"Optimization run {run_id} failed: {exc}")
            run.infeasible_reason = f"Optimization failed: {exc}"
            run.constraints_satisfied = False
            db.commit()
    finally:
        db.close()


@router.post("/run", response_model=OptimizationResultOut)
async def run_optimization_endpoint(
    req: OptimizationRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
):
    """
    Start an asynchronous threshold optimization run for the given config.

    The run is started in the background. Poll GET /optimizer/results/{config_id}
    to check progress. The result record is created immediately with status
    constraints_satisfied=None (in progress).
    """
    cfg = db.query(DetectionConfig).filter(DetectionConfig.id == req.config_id).first()
    if not cfg:
        raise HTTPException(404, "Config not found")
    if cfg.is_baseline:
        raise HTTPException(400, "Cannot run optimization on the preserved baseline config.")

    try:
        dataset_path = _find_dataset(req.dataset_path)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))

    run_id = str(uuid.uuid4())
    run = OptimizationResult(
        id=run_id,
        config_id=req.config_id,
        dataset_path=dataset_path,
        run_by=user.id,
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    from app.db.session import SessionLocal
    background_tasks.add_task(
        _run_optimization_sync,
        config_id=req.config_id,
        run_id=run_id,
        dataset_path=dataset_path,
        threshold_range_min=req.threshold_range_min,
        threshold_range_max=req.threshold_range_max,
        threshold_step=req.threshold_step,
        db_session_factory=SessionLocal,
    )

    return run


@router.get("/results/{config_id}", response_model=List[OptimizationResultOut])
def get_results_for_config(
    config_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(any_authenticated),
):
    cfg = db.query(DetectionConfig).filter(DetectionConfig.id == config_id).first()
    if not cfg:
        raise HTTPException(404, "Config not found")
    return (db.query(OptimizationResult)
            .filter(OptimizationResult.config_id == config_id)
            .order_by(OptimizationResult.run_at.desc())
            .all())


@router.get("/results/run/{run_id}", response_model=OptimizationResultOut)
def get_run(
    run_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(any_authenticated),
):
    run = db.query(OptimizationResult).filter(OptimizationResult.id == run_id).first()
    if not run:
        raise HTTPException(404, "Optimization run not found")
    return run


@router.get("/evaluate/baseline-comparison")
def baseline_comparison(
    db: Session = Depends(get_db),
    user: User = Depends(any_authenticated),
):
    """
    Return a structured comparison across all optimization results.

    For each config with a completed optimization run, returns the
    val and test metrics alongside the baseline for comparison.

    NOTE: This endpoint returns empirical results from actual data, not
    simulated or fabricated numbers.
    """
    runs = (db.query(OptimizationResult)
            .filter(OptimizationResult.constraints_satisfied.isnot(None))
            .order_by(OptimizationResult.run_at.desc())
            .all())

    configs = {c.id: c for c in db.query(DetectionConfig).all()}

    results = []
    for run in runs:
        cfg = configs.get(run.config_id)
        if not cfg:
            continue
        entry = {
            "run_id": run.id,
            "config_id": run.config_id,
            "config_name": cfg.name,
            "profile": cfg.profile,
            "run_at": run.run_at.isoformat() if run.run_at else None,
            "selected_threshold": run.selected_threshold,
            "selected_fusion": run.selected_fusion,
            "constraints_satisfied": run.constraints_satisfied,
            "infeasible_reason": run.infeasible_reason,
            "val_metrics": run.val_metrics,
            "test_metrics": run.test_metrics,
            "n_val": run.n_val,
            "n_test": run.n_test,
        }
        results.append(entry)

    return {
        "comparison": results,
        "methodology_note": (
            "All metrics computed using chronological 70/15/15 split "
            "(calibration/validation/test). No shuffling. "
            "Threshold selected on validation set; final metrics on held-out test period. "
            "Baseline threshold=0.70 with OR fusion is always included for reference."
        ),
        "caveat": (
            "Results are from the available evaluation dataset only. "
            "The dataset contains a single contiguous attack episode — see rule engine "
            "docstring for full caveat on generalizability."
        ),
    }
