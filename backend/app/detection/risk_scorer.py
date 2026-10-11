"""
risk_scorer.py — Computes a normalized operational risk score (0-100).

FORMULA
-------
    risk_score = clamp(w_ml * ml_score + w_rules * rule_score + w_asset * asset_score, 0, 100)

    Where:
        ml_score   = ml_probability * 100
                     (the RF predict_proba value; see LIMITATIONS below)
        rule_score = (violation_count / TOTAL_ACTIVE_RULES) * 100
        asset_score = max criticality weight among affected assets * 100

        Default weights:  w_ml=0.50, w_rules=0.35, w_asset=0.15

LIMITATIONS
-----------
1.  The Random Forest is not probability-calibrated (Platt or isotonic).
    ml_probability is the fraction of trees voting Attack, not a
    validated posterior probability of a real-world attack.
    It MUST NOT be presented to operators as a calibrated probability.

2.  The 16 rule weights are equal (each contributes 1/16 of rule_score).
    No independent evidence validates that equal weighting is optimal.

3.  Asset criticality levels are operator-assigned heuristics.
    The resulting asset_score is advisory only.

4.  The overall risk_score is an operational heuristic that aggregates
    three heterogeneous signals.  It is not a statistically validated
    risk metric and should not be used for safety-critical decisions
    without independent validation.

SEVERITY THRESHOLDS (configurable)
-----------------------------------
    risk_score >= 80 → CRITICAL
    risk_score >= 60 → HIGH
    risk_score >= 40 → MEDIUM
    risk_score >= 20 → LOW / Suspicious
    else             → Normal (no alert)
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

# Total active rules used to normalise rule_score.
# Matches rule_engine_final.ACTIVE_RULES (16 rules).
TOTAL_ACTIVE_RULES = 16

# Default weights — must sum to 1.0
DEFAULT_WEIGHT_ML = 0.50
DEFAULT_WEIGHT_RULES = 0.35
DEFAULT_WEIGHT_ASSET = 0.15

# Criticality level → numeric weight (0-1)
CRITICALITY_WEIGHTS: Dict[str, float] = {
    "LOW": 0.25,
    "MEDIUM": 0.50,
    "HIGH": 0.75,
    "CRITICAL": 1.00,
}

# Risk score → severity (configurable via thresholds dict)
DEFAULT_SEVERITY_THRESHOLDS: Dict[str, float] = {
    "CRITICAL": 80.0,
    "HIGH": 60.0,
    "MEDIUM": 40.0,
    "LOW": 20.0,
}


@dataclass
class RiskScore:
    score: float                         # 0-100
    severity: Optional[str]             # None | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    ml_contribution: float               # ml component (before weight)
    rule_contribution: float             # rule component (before weight)
    asset_contribution: float            # asset component (before weight)
    ml_weight: float
    rule_weight: float
    asset_weight: float
    is_attack: bool                      # True if score meets attack threshold
    formula_note: str                    # brief documentation token


def compute_risk_score(
    ml_probability: float,
    violation_count: int,
    affected_sensor_tags: List[str],
    asset_criticalities: Dict[str, str],   # tag → "LOW"|"MEDIUM"|"HIGH"|"CRITICAL"
    weight_ml: float = DEFAULT_WEIGHT_ML,
    weight_rules: float = DEFAULT_WEIGHT_RULES,
    weight_asset: float = DEFAULT_WEIGHT_ASSET,
    severity_thresholds: Optional[Dict[str, float]] = None,
) -> RiskScore:
    """
    Compute the normalized risk score.

    Parameters
    ----------
    ml_probability : float
        Raw RF predict_proba Attack probability (0-1).
    violation_count : int
        Number of rule violations (0..TOTAL_ACTIVE_RULES).
    affected_sensor_tags : list[str]
        Sensor/actuator tags flagged by the rule engine or ML.
    asset_criticalities : dict[str, str]
        Mapping from asset tag → criticality level for operator-configured
        critical assets.  Only affected sensors present in this map contribute.
    weight_ml, weight_rules, weight_asset : float
        Component weights.  The user is responsible for ensuring they are
        sensible; no normalization is enforced here so that the caller can
        pass profile-specific values.
    severity_thresholds : dict or None
        Override thresholds {level: min_score}.  Defaults to DEFAULT_SEVERITY_THRESHOLDS.
    """
    thresholds = severity_thresholds or DEFAULT_SEVERITY_THRESHOLDS

    # --- Component scores (0-100 each) ---
    ml_score = float(ml_probability) * 100.0

    rule_score = (min(violation_count, TOTAL_ACTIVE_RULES) / TOTAL_ACTIVE_RULES) * 100.0

    # Asset score: max criticality weight among tags that appear in the
    # operator's critical asset map.
    asset_score = 0.0
    for tag in affected_sensor_tags:
        level = asset_criticalities.get(tag)
        if level:
            weight = CRITICALITY_WEIGHTS.get(level.upper(), 0.0)
            asset_score = max(asset_score, weight * 100.0)

    # --- Weighted combination ---
    raw = (weight_ml * ml_score +
           weight_rules * rule_score +
           weight_asset * asset_score)
    score = max(0.0, min(100.0, raw))

    # --- Severity ---
    severity: Optional[str] = None
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if score >= thresholds.get(level, DEFAULT_SEVERITY_THRESHOLDS[level]):
            severity = level
            break

    is_attack = severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    return RiskScore(
        score=round(score, 2),
        severity=severity,
        ml_contribution=round(ml_score, 2),
        rule_contribution=round(rule_score, 2),
        asset_contribution=round(asset_score, 2),
        ml_weight=weight_ml,
        rule_weight=weight_rules,
        asset_weight=weight_asset,
        is_attack=is_attack,
        formula_note=(
            "risk_score = clamp(w_ml*ml_prob*100 + w_rules*(violations/16)*100 "
            "+ w_asset*max_criticality*100, 0, 100). "
            "UNCALIBRATED heuristic — not a validated probability."
        ),
    )
