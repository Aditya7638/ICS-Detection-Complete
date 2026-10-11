"""
fusion_engine.py — Implements the fusion logic defined in fusion_config.json.

fusion_logic: "OR"
  → ATTACK if (ML prob >= threshold) OR (any rule violation)
  → NORMAL otherwise

Severity mapping:
  ML >= 0.90 + rules → CRITICAL
  ML >= 0.70 + rules → HIGH
  ML >= 0.70 (no rules) → MEDIUM
  rules only → MEDIUM
  else → LOW (suspicious)
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class FusionResult:
    final_label: str          # "Normal" | "Suspicious" | "Attack"
    severity: Optional[str]   # None | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    ml_triggered: bool
    rule_triggered: bool
    ml_probability: float
    violation_count: int
    explanation: str
    recommendations: List[str]
    affected_sensors: List[str]


class FusionEngine:
    def __init__(self, config_path: str):
        with open(config_path) as f:
            self.cfg = json.load(f)
        self.threshold: float = self.cfg["decision_threshold"]   # 0.70
        self.fusion_logic: str = self.cfg["fusion_logic"]        # "OR"
        logger.info(f"Fusion engine loaded: {self.cfg['model_name']}, threshold={self.threshold}, logic={self.fusion_logic}")

    def fuse(self,
             ml_probability: float,
             ml_label: str,
             rule_violated: bool,
             violation_count: int,
             violations: List[Dict[str, Any]],
             threshold: Optional[float] = None,
             fusion_strategy: Optional[str] = None) -> FusionResult:

        active_threshold = self.threshold if threshold is None else threshold
        active_strategy = self.fusion_logic if fusion_strategy is None else fusion_strategy.upper()
        if active_strategy not in {"OR", "RF_OR_RULES", "RF_ONLY"}:
            raise ValueError(f"Unsupported live fusion strategy: {active_strategy}")
        ml_triggered = ml_probability >= active_threshold
        rule_contributes = active_strategy != "RF_ONLY"

        is_attack = ml_triggered or (rule_violated and rule_contributes)

        if not is_attack:
            # Still suspicious if ML close to threshold
            if ml_probability >= 0.50:
                final_label = "Suspicious"
                severity = "LOW"
            else:
                final_label = "Normal"
                severity = None
        else:
            final_label = "Attack"
            if ml_triggered and rule_violated and rule_contributes:
                severity = "CRITICAL" if ml_probability >= 0.90 else "HIGH"
            elif ml_triggered:
                severity = "HIGH" if ml_probability >= 0.85 else "MEDIUM"
            else:
                severity = "MEDIUM"

        # Affected sensors from violations
        affected = []
        for v in violations:
            for k in v.get("evidence", {}).keys():
                if k not in ("threshold",) and k not in affected:
                    affected.append(k)

        explanation = self._build_explanation(
            final_label, ml_probability, ml_triggered, rule_violated, violations,
            active_threshold, active_strategy,
        )
        recommendations = self._build_recommendations(final_label, severity, violations, affected)

        return FusionResult(
            final_label=final_label,
            severity=severity,
            ml_triggered=ml_triggered,
            rule_triggered=rule_violated,
            ml_probability=ml_probability,
            violation_count=violation_count,
            explanation=explanation,
            recommendations=recommendations,
            affected_sensors=affected,
        )

    def _build_explanation(self, label, prob, ml_trig, rule_trig, violations, threshold, strategy) -> str:
        parts = [f"Detection: {label}."]
        parts.append(f"ML anomaly score: {prob*100:.1f}% (threshold: {threshold*100:.1f}%).")
        parts.append(f"Fusion strategy: {strategy}.")
        if ml_trig:
            parts.append("ML model flagged this reading as anomalous.")
        if rule_trig:
            v_ids = ", ".join(v["rule_id"] for v in violations)
            parts.append(f"Rule violations: {v_ids}.")
            if strategy != "RF_ONLY":
                parts.append("Rule violations contributed to the fused detection.")
            else:
                parts.append("Rule violations were observed but are not used by the RF_ONLY fusion strategy.")
            for v in violations:
                parts.append(f"  [{v['rule_id']}] {v['message']}")
        if not ml_trig and not rule_trig:
            parts.append("No anomaly indicators detected.")
        return " ".join(parts)

    def _build_recommendations(self, label, severity, violations, affected) -> List[str]:
        if label == "Normal":
            return []
        recs = []
        if affected:
            recs.append(f"Verify affected sensor readings: {', '.join(affected)}.")
        recs.append("Compare against neighboring process variables for context.")
        recs.append("Review recent changes in control environment or setpoints.")
        if violations:
            recs.append(f"Investigate rule violations: {', '.join(v['rule_id'] for v in violations)}.")
        recs.append("Check for correlated alarms in adjacent time windows.")
        recs.append("Follow the organization's incident-response procedure.")
        if severity in ("HIGH", "CRITICAL"):
            recs.append("Escalate to security analyst immediately.")
        return recs


_fusion: Optional[FusionEngine] = None

def get_fusion_engine() -> FusionEngine:
    global _fusion
    if _fusion is None:
        raise RuntimeError("Fusion engine not initialized.")
    return _fusion

def init_fusion_engine(config_path: str):
    global _fusion
    _fusion = FusionEngine(config_path)
    return _fusion
