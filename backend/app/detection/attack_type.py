"""
attack_type.py — Evidence-based Attack Type Assessment.

IMPORTANT CAVEATS
-----------------
1.  The existing Random Forest is trained with a BINARY target (Normal=0,
    Attack=1).  It does NOT distinguish cyberattacks from physical/process
    attacks.  No such labeled training data is present in this repository.

2.  This module implements a TRANSPARENT, RULE-BASED EVIDENCE ASSESSMENT —
    not a trained classifier.  Every evidence mapping is explicitly documented
    and can be reviewed by operators.

3.  Confidence values are NOT returned as numerical probabilities because no
    calibrated classifier exists.  Instead, a qualitative confidence token
    is returned (HIGH / MEDIUM / LOW) together with the evidence that
    supports it.

4.  Abnormal sensor readings alone are insufficient to determine whether the
    cause is a cyberattack or a physical anomaly.

5.  If no supporting evidence exists, the result is UNKNOWN / INSUFFICIENT
    EVIDENCE, not a forced classification.

EVIDENCE MAPPINGS (documented)
-------------------------------
Cyberattack indicators:
  - Actuator state anomalies that contradict sensor readings
    (e.g., pump ON while level is wrong direction — may suggest spoofed
    control command, but physical explanation possible too).
  - Multiple simultaneous cross-stage actuator anomalies (harder to
    explain physically).
  - Operator-confirmed classification.

Physical/process attack indicators:
  - Sensor values outside physically plausible ranges (beyond normal
    operating band) without corresponding actuator anomalies.
  - Physical tampering confirmed by operator.

Mixed / ambiguous:
  - Both actuator and sensor anomalies present.
  - Pattern does not clearly fit either category.

Unknown / insufficient evidence:
  - ML flag only, no rule violations.
  - Fewer than 2 independent evidence sources.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

# Possible outcomes
ATTACK_TYPE_CYBER = "Cyberattack"
ATTACK_TYPE_PHYSICAL = "Physical/Process Attack"
ATTACK_TYPE_MIXED = "Mixed or Ambiguous Indicators"
ATTACK_TYPE_UNKNOWN = "Unknown / Insufficient Evidence"

CLASSIFICATION_CONFIRMED = "Confirmed"      # operator-confirmed
CLASSIFICATION_SUSPECTED = "Suspected"      # automated evidence exists
CLASSIFICATION_UNKNOWN = "Unknown"


# Rules that primarily involve ACTUATOR state anomalies
# (pump/valve states inconsistent with sensor readings)
ACTUATOR_ANOMALY_RULES = {
    "R10", "R11", "R20b",
    "R_NEW_01", "R_NEW_02", "R_NEW_03", "R_NEW_04",
    "R_NEW_05", "R_NEW_06", "R_NEW_08", "R_NEW_09",
    "R_NEW_10", "R_NEW_11", "R_NEW_12", "R_NEW_13", "R_NEW_15",
}

# Rules that involve sensor reading thresholds (may indicate spoofing or physical)
SENSOR_THRESHOLD_RULES = {
    "R10", "R11", "R20b",      # LIT301, DPIT301, AIT501/503
    "R_NEW_03",                 # PIT501
    "R_NEW_04",                 # AIT402
    "R_NEW_06", "R_NEW_09", "R_NEW_10",  # LIT101
    "R_NEW_11",                 # LIT301
}

# Rules involving cross-area coordination
# (harder to produce physically without explicit cause)
CROSS_AREA_RULES = {
    # R10/R11 involve P3 level + P3 valve — same area, not cross-area
    # R20b involves P5 chemistry + P5 pump — same area
    # R_NEW_04 involves P4 chemistry + P4 UV — same area
}


@dataclass
class AttackTypeResult:
    attack_type: str                    # one of the 4 constants above
    classification_status: str         # Confirmed | Suspected | Unknown
    # Qualitative confidence: HIGH | MEDIUM | LOW | None (when unknown)
    confidence_level: Optional[str]
    supporting_indicators: List[str]
    contradicting_indicators: List[str]
    affected_components: List[str]
    evidence_sources: List[str]
    limitations: List[str]
    methodology_note: str


def assess_attack_type(
    rule_violations: List[Dict],
    ml_probability: float,
    ml_triggered: bool,
    affected_sensors: List[str],
    operator_classification: Optional[str] = None,    # set if operator has classified
) -> AttackTypeResult:
    """
    Perform evidence-based attack type assessment.

    This function does NOT output a trained classifier result.  It maps
    available evidence to documented hypotheses and returns a structured
    result with explicit limitations.

    Parameters
    ----------
    rule_violations : list[dict]
        Violations from rule_adapter.run_rules().
    ml_probability : float
        RF attack probability (uncalibrated).
    ml_triggered : bool
        Whether ML threshold was exceeded.
    affected_sensors : list[str]
        Tags flagged by fusion engine.
    operator_classification : str or None
        Optional: operator-confirmed classification from a previous incident.
    """
    supporting: List[str] = []
    contradicting: List[str] = []
    evidence_sources: List[str] = []
    components: List[str] = list(affected_sensors)

    # 1. Operator classification overrides automated assessment
    if operator_classification:
        evidence_sources.append("Operator-confirmed classification")
        return AttackTypeResult(
            attack_type=operator_classification,
            classification_status=CLASSIFICATION_CONFIRMED,
            confidence_level="HIGH",
            supporting_indicators=[f"Operator confirmed: {operator_classification}"],
            contradicting_indicators=[],
            affected_components=components,
            evidence_sources=evidence_sources,
            limitations=_standard_limitations(),
            methodology_note=_methodology_note(),
        )

    # 2. Collect violated rule IDs
    violated_rule_ids = {v.get("rule_id", "") for v in rule_violations}
    n_violations = len(violated_rule_ids)

    # 3. No evidence → unknown
    if not ml_triggered and n_violations == 0:
        return AttackTypeResult(
            attack_type=ATTACK_TYPE_UNKNOWN,
            classification_status=CLASSIFICATION_UNKNOWN,
            confidence_level=None,
            supporting_indicators=[],
            contradicting_indicators=["No rule violations and ML below threshold."],
            affected_components=components,
            evidence_sources=[],
            limitations=_standard_limitations(),
            methodology_note=_methodology_note(),
        )

    # 4. Categorize violations
    actuator_violations = violated_rule_ids & ACTUATOR_ANOMALY_RULES
    sensor_violations = violated_rule_ids & SENSOR_THRESHOLD_RULES
    both = actuator_violations & sensor_violations  # rules appearing in both sets

    # 5. Build evidence
    if ml_triggered:
        evidence_sources.append(f"ML model (probability: {ml_probability*100:.1f}%; uncalibrated)")
        supporting.append(
            f"ML model exceeded threshold (p={ml_probability*100:.1f}%). "
            "This indicates statistical anomaly but does not distinguish "
            "cyber from physical cause."
        )

    for v in rule_violations:
        rid = v.get("rule_id", "")
        msg = v.get("message", "")
        evidence_sources.append(f"Rule {rid}")
        supporting.append(f"[{rid}] {msg}")

    # Actuator anomalies → may support cyberattack hypothesis
    if actuator_violations:
        supporting.append(
            f"Actuator state anomalies detected ({', '.join(sorted(actuator_violations))}). "
            "Inconsistency between actuator state and sensor reading may indicate "
            "spoofed commands, but physical causes are also possible."
        )

    # Pure sensor deviations without corresponding actuator anomaly
    sensor_only = sensor_violations - actuator_violations
    if sensor_only:
        supporting.append(
            f"Sensor threshold violations without actuator anomaly "
            f"({', '.join(sorted(sensor_only))}). "
            "Consistent with either physical anomaly or sensor spoofing."
        )
        contradicting.append(
            "Sensor-only violations cannot distinguish cyberattack from physical cause."
        )

    # 6. Determine attack type
    has_actuator_anomaly = len(actuator_violations) > 0
    has_sensor_anomaly = len(sensor_only) > 0
    multi_area = _is_multi_area(violated_rule_ids)

    if n_violations == 0 and ml_triggered:
        # ML-only flag
        attack_type = ATTACK_TYPE_UNKNOWN
        classification_status = CLASSIFICATION_UNKNOWN
        confidence_level = None
        contradicting.append(
            "ML-only flag: no rule violations. Cannot classify attack type."
        )

    elif has_actuator_anomaly and has_sensor_anomaly:
        # Both actuator and sensor anomalies
        attack_type = ATTACK_TYPE_MIXED
        classification_status = CLASSIFICATION_SUSPECTED
        confidence_level = "LOW"

    elif has_actuator_anomaly and not has_sensor_anomaly:
        # Actuator anomalies only → lean cyber but not confirmed
        if multi_area and n_violations >= 3:
            attack_type = ATTACK_TYPE_CYBER
            classification_status = CLASSIFICATION_SUSPECTED
            confidence_level = "LOW"
            supporting.append(
                "Multiple simultaneous actuator anomalies across process stages. "
                "This pattern is less likely to arise from a single physical cause, "
                "but could still result from cascading process faults."
            )
            contradicting.append(
                "Cyberattack classification is SUSPECTED, not confirmed. "
                "Physical cascading faults can produce similar patterns."
            )
        else:
            attack_type = ATTACK_TYPE_MIXED
            classification_status = CLASSIFICATION_SUSPECTED
            confidence_level = "LOW"

    elif has_sensor_anomaly and not has_actuator_anomaly:
        # Sensor-only → lean physical but insufficient
        attack_type = ATTACK_TYPE_PHYSICAL
        classification_status = CLASSIFICATION_SUSPECTED
        confidence_level = "LOW"
        contradicting.append(
            "Sensor reading anomalies can result from sensor failure, physical "
            "process upset, or deliberate spoofing. Physical/process attack is "
            "tentative without additional evidence."
        )

    else:
        attack_type = ATTACK_TYPE_UNKNOWN
        classification_status = CLASSIFICATION_UNKNOWN
        confidence_level = None

    return AttackTypeResult(
        attack_type=attack_type,
        classification_status=classification_status,
        confidence_level=confidence_level,
        supporting_indicators=supporting,
        contradicting_indicators=contradicting,
        affected_components=sorted(set(components)),
        evidence_sources=evidence_sources,
        limitations=_standard_limitations(),
        methodology_note=_methodology_note(),
    )


def _is_multi_area(rule_ids) -> bool:
    """Check if violated rules span more than one process area."""
    from app.detection.localization import RULE_SENSOR_MAP, _TAG_TO_AREA
    areas = set()
    for rid in rule_ids:
        rule_map = RULE_SENSOR_MAP.get(rid, {})
        for tag in rule_map.get("sensors", []) + rule_map.get("actuators", []):
            area = _TAG_TO_AREA.get(tag)
            if area:
                areas.add(area)
    return len(areas) > 1


def _standard_limitations() -> List[str]:
    return [
        "The Random Forest model is trained with a binary Normal/Attack target. "
        "It does NOT distinguish cyberattacks from physical attacks.",
        "No labeled cyberattack vs. physical-attack dataset is present in this "
        "repository. A trained classifier for this distinction would require "
        "such labeled data and independent evaluation.",
        "Actuator anomalies may result from physical process upsets, not only "
        "from malicious commands.",
        "This assessment is based on rule-engine evidence and is advisory only. "
        "Operator review is required for any incident response decision.",
        "Sensor readings alone are insufficient to establish attack type.",
    ]


def _methodology_note() -> str:
    return (
        "Attack type assessment uses a transparent, rule-based evidence mapping. "
        "Evidence sources are the 16 active rules from rule_engine_final.py and "
        "the RF model probability. No trained attack-type classifier is used. "
        "Classification status 'Suspected' requires at least one rule violation "
        "or ML trigger. 'Confirmed' requires operator review."
    )
