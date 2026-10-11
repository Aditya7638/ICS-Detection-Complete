"""
threshold_optimizer.py — Deterministic Threshold Optimizer.

Uses the existing labeled evaluation dataset (data/NewTestData.csv or
data/ne_data.csv) to evaluate candidate Random Forest thresholds.

DESIGN PRINCIPLES
-----------------
1.  The existing baseline threshold of 0.70 is always evaluated and preserved.
2.  Chronological splits are used to avoid data leakage:
      - First 70%  of rows → calibration/sweep set
      - Next  15%  of rows → validation set
      - Last  15%  of rows → held-out test set (used ONLY for final reporting)
    Note: The 70-15-15 split matches the fusion_config.json "split" entry.
3.  Threshold selection is done on the validation set.
4.  Final metrics are reported on the held-out test set.
5.  If no threshold satisfies the hard constraints, an infeasible result is
    returned with the best-available alternatives.
6.  The production threshold is NEVER changed by this module.
    Activation is a separate, explicit operator action.

LABEL CONVENTION
----------------
The target column is "Normal/Attack" with values "Normal" and "Attack".
The label 1 = Attack, 0 = Normal throughout.

NOTE ON FUSION
--------------
The optimizer evaluates:
  A. RF-only (varying threshold)
  B. RF + Rule Engine with OR fusion (baseline logic)

The fusion evaluation uses the existing rule engine output pre-computed
for each row.  Rule logic is not modified.
"""

import io
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Default threshold range to evaluate
DEFAULT_THRESHOLD_RANGE = (0.30, 0.95)
DEFAULT_THRESHOLD_STEP = 0.01

# Data split fractions (must match fusion_config.json)
SPLIT_TRAIN_FRAC = 0.70
SPLIT_VAL_FRAC = 0.15
# Implicit: test_frac = 1 - SPLIT_TRAIN_FRAC - SPLIT_VAL_FRAC = 0.15


@dataclass
class ThresholdMetrics:
    threshold: float
    precision: float
    recall: float
    f1: float
    fpr: float
    fnr: float
    tp: int
    fp: int
    tn: int
    fn: int


@dataclass
class OptimizationOutcome:
    """Result of one optimizer run."""
    profile: str
    constraints: Dict[str, float]          # profile constraints as provided
    selected_threshold: Optional[float]     # None if infeasible
    selected_fusion: str                    # "OR" | "RISK_SCORE"
    feasible: bool
    infeasible_reason: Optional[str]
    # Sweep results on validation set
    sweep_results: List[Dict[str, Any]]     # list of ThresholdMetrics dicts
    # Validation metrics for selected threshold
    val_metrics: Optional[Dict[str, float]]
    # Test metrics (held-out) for selected threshold
    test_metrics: Optional[Dict[str, float]]
    # Baseline comparison (threshold=0.70)
    baseline_val_metrics: Optional[Dict[str, float]]
    baseline_test_metrics: Optional[Dict[str, float]]
    # Best alternatives when infeasible
    alternatives: List[Dict[str, Any]]
    # Dataset sizes
    n_calibration: int
    n_validation: int
    n_test: int
    methodology_note: str


def _compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, threshold: float) -> ThresholdMetrics:
    """Compute detection metrics from binary arrays."""
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return ThresholdMetrics(
        threshold=threshold,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        fpr=round(fpr, 4),
        fnr=round(fnr, 4),
        tp=tp, fp=fp, tn=tn, fn=fn,
    )


def _metrics_to_dict(m: ThresholdMetrics) -> Dict[str, Any]:
    return {
        "threshold": m.threshold,
        "precision": m.precision,
        "recall": m.recall,
        "f1": m.f1,
        "fpr": m.fpr,
        "fnr": m.fnr,
        "tp": m.tp, "fp": m.fp, "tn": m.tn, "fn": m.fn,
    }


def _satisfies_constraints(
    m: ThresholdMetrics,
    profile: str,
    min_recall: Optional[float],
    max_fpr: Optional[float],
    min_precision: Optional[float],
) -> bool:
    if min_recall is not None and m.recall < min_recall:
        return False
    if max_fpr is not None and m.fpr > max_fpr:
        return False
    if min_precision is not None and m.precision < min_precision:
        return False
    return True


def _score_for_profile(m: ThresholdMetrics, profile: str,
                        w_prec: float = 0.33, w_rec: float = 0.34, w_fpr: float = 0.33) -> float:
    """Higher is better."""
    if profile == "HIGH_RECALL":
        return m.recall - 0.5 * m.fpr
    elif profile == "LOW_FP":
        return m.precision - 0.5 * (1 - m.recall)
    elif profile == "BALANCED":
        return w_prec * m.precision + w_rec * m.recall - w_fpr * m.fpr
    elif profile == "CRITICAL_ASSET":
        # Maximise recall (we want to catch everything on critical assets)
        return m.recall * 2.0 - m.fpr
    return m.f1   # fallback


def run_optimization(
    probabilities: np.ndarray,      # RF probabilities for each row
    y_true: np.ndarray,             # 1=Attack, 0=Normal
    rule_flags: np.ndarray,         # 1 if any rule violated, 0 otherwise
    profile: str = "BALANCED",
    min_recall: Optional[float] = None,
    max_fpr: Optional[float] = None,
    min_precision: Optional[float] = None,
    weight_precision: float = 0.33,
    weight_recall: float = 0.34,
    weight_fpr: float = 0.33,
    threshold_range: Tuple[float, float] = DEFAULT_THRESHOLD_RANGE,
    threshold_step: float = DEFAULT_THRESHOLD_STEP,
) -> OptimizationOutcome:
    """
    Run the deterministic threshold sweep.

    Data is split chronologically:
      [0 .. 70%)  → calibration (not used for selection, for context only)
      [70 .. 85%) → validation (threshold selection)
      [85 .. 100%] → test (final reporting, held-out)

    Both RF-only and RF+Rules (OR) are evaluated.
    Selection is on validation; reporting is on test.
    """
    n = len(probabilities)
    n_cal = int(n * SPLIT_TRAIN_FRAC)
    n_val = int(n * SPLIT_VAL_FRAC)
    n_test = n - n_cal - n_val

    if n_val < 10 or n_test < 10:
        raise ValueError(
            f"Dataset too small for chronological split: {n} rows → "
            f"calibration={n_cal}, validation={n_val}, test={n_test}. "
            "At least 10 rows in each of validation and test are required."
        )

    # Split (chronological — no shuffling)
    proba_val = probabilities[n_cal: n_cal + n_val]
    y_val = y_true[n_cal: n_cal + n_val]
    rules_val = rule_flags[n_cal: n_cal + n_val]

    proba_test = probabilities[n_cal + n_val:]
    y_test = y_true[n_cal + n_val:]
    rules_test = rule_flags[n_cal + n_val:]

    # Warn if val or test set has no attacks
    if y_val.sum() == 0:
        logger.warning("Validation set contains no Attack rows — recall metrics will be 0.")
    if y_test.sum() == 0:
        logger.warning("Test set contains no Attack rows — final recall metrics will be 0.")

    # Generate threshold candidates
    lo, hi = threshold_range
    n_steps = max(1, int((hi - lo) / threshold_step))
    candidates = sorted(set(
        [round(lo + i * threshold_step, 4) for i in range(n_steps + 1)] + [0.70]
    ))

    sweep_results: List[Dict[str, Any]] = []

    for thresh in candidates:
        # RF-only
        rf_pred_val = (proba_val >= thresh).astype(int)
        rf_metrics = _compute_metrics(y_val, rf_pred_val, thresh)

        # RF+Rules OR fusion
        or_pred_val = ((proba_val >= thresh) | (rules_val == 1)).astype(int)
        or_metrics = _compute_metrics(y_val, or_pred_val, thresh)

        sweep_results.append({
            "threshold": thresh,
            "rf_only": _metrics_to_dict(rf_metrics),
            "rf_or_rules": _metrics_to_dict(or_metrics),
        })

    # --- Baseline (threshold=0.70) on val ---
    base_rf_val = (proba_val >= 0.70).astype(int)
    base_or_val = ((proba_val >= 0.70) | (rules_val == 1)).astype(int)
    baseline_val = {
        "rf_only": _metrics_to_dict(_compute_metrics(y_val, base_rf_val, 0.70)),
        "rf_or_rules": _metrics_to_dict(_compute_metrics(y_val, base_or_val, 0.70)),
    }

    # --- Baseline on test ---
    base_rf_test = (proba_test >= 0.70).astype(int)
    base_or_test = ((proba_test >= 0.70) | (rules_test == 1)).astype(int)
    baseline_test = {
        "rf_only": _metrics_to_dict(_compute_metrics(y_test, base_rf_test, 0.70)),
        "rf_or_rules": _metrics_to_dict(_compute_metrics(y_test, base_or_test, 0.70)),
    }

    # --- Select best threshold on validation ---
    best_threshold: Optional[float] = None
    best_fusion: str = "OR"
    best_score: float = -math.inf
    best_val_metrics: Optional[Dict] = None
    feasible_candidates: List[Dict] = []

    for entry in sweep_results:
        for fusion_key, fusion_label in [("rf_only", "RF_ONLY"), ("rf_or_rules", "OR")]:
            m_dict = entry[fusion_key]
            m = ThresholdMetrics(**m_dict)
            if _satisfies_constraints(m, profile, min_recall, max_fpr, min_precision):
                sc = _score_for_profile(m, profile, weight_precision, weight_recall, weight_fpr)
                feasible_candidates.append({"threshold": entry["threshold"],
                                            "fusion": fusion_label, "score": sc,
                                            "metrics": m_dict})
                if sc > best_score:
                    best_score = sc
                    best_threshold = entry["threshold"]
                    best_fusion = fusion_label
                    best_val_metrics = m_dict

    feasible = best_threshold is not None
    infeasible_reason: Optional[str] = None
    alternatives: List[Dict] = []

    if not feasible:
        infeasible_reason = (
            f"No threshold in range {threshold_range} satisfies all constraints: "
            f"min_recall={min_recall}, max_fpr={max_fpr}, min_precision={min_precision}."
        )
        # Provide best alternatives (top 3 by profile score, without constraint check)
        unconstrained: List[Dict] = []
        for entry in sweep_results:
            for fusion_key, fusion_label in [("rf_only", "RF_ONLY"), ("rf_or_rules", "OR")]:
                m_dict = entry[fusion_key]
                m = ThresholdMetrics(**m_dict)
                sc = _score_for_profile(m, profile, weight_precision, weight_recall, weight_fpr)
                unconstrained.append({"threshold": entry["threshold"],
                                      "fusion": fusion_label, "score": sc,
                                      "metrics": m_dict})
        unconstrained.sort(key=lambda x: x["score"], reverse=True)
        alternatives = unconstrained[:3]

    # --- Compute test metrics for selected threshold ---
    test_metrics: Optional[Dict] = None
    if feasible and best_threshold is not None:
        if best_fusion == "RF_ONLY":
            pred_test = (proba_test >= best_threshold).astype(int)
        else:
            pred_test = ((proba_test >= best_threshold) | (rules_test == 1)).astype(int)
        test_metrics = _metrics_to_dict(_compute_metrics(y_test, pred_test, best_threshold))

    return OptimizationOutcome(
        profile=profile,
        constraints={
            "min_recall": min_recall,
            "max_fpr": max_fpr,
            "min_precision": min_precision,
        },
        selected_threshold=best_threshold,
        selected_fusion=best_fusion if feasible else "OR",
        feasible=feasible,
        infeasible_reason=infeasible_reason,
        sweep_results=sweep_results,
        val_metrics=best_val_metrics,
        test_metrics=test_metrics,
        baseline_val_metrics=baseline_val,
        baseline_test_metrics=baseline_test,
        alternatives=alternatives,
        n_calibration=n_cal,
        n_validation=n_val,
        n_test=n_test,
        methodology_note=(
            "Chronological 70/15/15 split (no shuffling). "
            "Threshold selected on validation set [70%-85%]. "
            "Final metrics reported on held-out test period [85%-100%]. "
            "Baseline threshold 0.70 always evaluated for comparison. "
            "No retraining or feature modification performed."
        ),
    )


def load_eval_dataset(
    dataset_path: str,
    model_engine,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Load a labeled CSV, compute RF probabilities and rule flags for each row.

    Returns
    -------
    probabilities : np.ndarray of shape (n,)
        RF predict_proba Attack values.
    y_true : np.ndarray of shape (n,) of 0/1
        Ground truth (1=Attack, 0=Normal).
    rule_flags : np.ndarray of shape (n,) of 0/1
        1 if any active rule violated, else 0.
    """
    import sys
    from pathlib import Path
    _rules_dir = str(Path(__file__).parent.parent.parent / "rules")
    if _rules_dir not in sys.path:
        sys.path.insert(0, _rules_dir)
    from rule_engine_final import evaluate_rules, get_violations

    LABEL_COL = "Normal/Attack"
    TIMESTAMP_COL = "Timestamp"

    df = pd.read_csv(dataset_path)
    df.columns = [c.strip() for c in df.columns]

    if LABEL_COL not in df.columns:
        raise ValueError(
            f"Label column '{LABEL_COL}' not found in {dataset_path}. "
            f"Available columns: {list(df.columns[:10])}..."
        )

    raw_cols = model_engine.raw_sensor_columns
    missing = [c for c in raw_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset missing sensor columns: {missing}")

    # Drop columns not needed for inference (label, timestamp)
    skip = {LABEL_COL}
    if TIMESTAMP_COL in df.columns:
        skip.add(TIMESTAMP_COL)
    feature_df = df.drop(columns=[c for c in skip if c in df.columns])

    # Encode labels
    y_raw = df[LABEL_COL].astype(str).str.strip()
    y_true = (y_raw == "Attack").astype(int).values

    logger.info(f"Dataset loaded: {len(df)} rows, {y_true.sum()} Attack, "
                f"{(y_true == 0).sum()} Normal")

    # Compute RF probabilities (batch)
    from app.detection.model_engine import MLResult
    ml_results = model_engine.predict_batch(feature_df[raw_cols])
    probabilities = np.array([r.probability for r in ml_results])

    # Compute rule flags
    from app.detection.rule_adapter import run_rules
    rule_flags = []
    for _, row in feature_df.iterrows():
        rr = run_rules(row.to_dict())
        rule_flags.append(1 if rr.violated else 0)
    rule_flags = np.array(rule_flags)

    return probabilities, y_true, rule_flags
