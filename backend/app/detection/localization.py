"""
localization.py — Attack Localization & Process Impact.

Determines which process components are implicated in a detection event
and produces a ranked list with evidence.

DATA SOURCE
-----------
The mapping below is derived entirely from:
  1.  rule_engine_final.py  — which sensors/actuators each rule checks.
  2.  The SWaT sensor naming convention (P1..P6 stages).

This is a LOGICAL TOPOLOGY OVERVIEW, not a physical plant schematic.
No physical plant layout data is present in this repository.

LIMITATIONS
-----------
-   The component with the highest evidence score is NOT necessarily the
    physical origin of the attack; it is the component for which the most
    automated evidence was found.
-   Sensor deviations alone cannot determine whether the cause is a
    cyberattack (sensor spoofing) or a physical/process anomaly.
-   "Confirmed" localization requires operator review.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

# ── Process Area Mapping ────────────────────────────────────────────────────
# Derived from SWaT naming convention and rule_engine_final sensor/actuator usage.
# Labels are logical stage names, not physical location identifiers.

PROCESS_AREAS: Dict[str, Dict] = {
    "P1_RAW_WATER": {
        "label": "P1 — Raw Water Intake",
        "sensors": ["FIT101", "LIT101"],
        "actuators": ["MV101", "P101", "P102"],
        "description": "Raw water feed tank, level control and intake pumps.",
    },
    "P2_CHEMICAL_DOSING": {
        "label": "P2 — Chemical Dosing",
        "sensors": ["AIT201", "AIT202", "AIT203", "FIT201"],
        "actuators": ["MV201", "P203", "P204", "P205", "P206"],
        "description": "NaCl/NaOCl dosing for water treatment.",
    },
    "P3_UF_BACKWASH": {
        "label": "P3 — UF / Backwash",
        "sensors": ["DPIT301", "FIT301", "LIT301"],
        "actuators": ["MV301", "MV302", "MV303", "MV304", "P302"],
        "description": "Ultrafiltration membrane and backwash control.",
    },
    "P4_DECHLORINATION": {
        "label": "P4 — De-chlorination / UV",
        "sensors": ["AIT401", "AIT402", "FIT401", "LIT401"],
        "actuators": ["P402", "UV401"],
        "description": "UV-based dechlorination before RO.",
    },
    "P5_RO_FEED": {
        "label": "P5 — RO Feed",
        "sensors": ["AIT501", "AIT502", "AIT503", "AIT504",
                    "FIT501", "FIT502", "FIT503", "FIT504",
                    "PIT501", "PIT502", "PIT503"],
        "actuators": ["P501"],
        "description": "Reverse-osmosis feed, pressure and quality monitoring.",
    },
    "P6_POST_RO": {
        "label": "P6 — Post-RO / Distribution",
        "sensors": ["FIT601"],
        "actuators": ["P602"],
        "description": "Post-treatment flow and distribution.",
    },
}

# Build reverse mapping: tag → area_key
_TAG_TO_AREA: Dict[str, str] = {}
for area_key, info in PROCESS_AREAS.items():
    for tag in info["sensors"] + info["actuators"]:
        _TAG_TO_AREA[tag] = area_key

# Rule → sensors and actuators it checks (from rule_engine_final.py inspection)
RULE_SENSOR_MAP: Dict[str, Dict[str, List[str]]] = {
    "R10":      {"sensors": ["LIT301"], "actuators": ["MV302", "P302"]},
    "R11":      {"sensors": ["DPIT301"], "actuators": ["MV303"]},
    "R20b":     {"sensors": ["AIT501", "AIT503"], "actuators": ["P501"]},
    "R_NEW_01": {"sensors": ["AIT201"], "actuators": ["P205"]},
    "R_NEW_02": {"sensors": ["AIT201"], "actuators": ["P203"]},
    "R_NEW_03": {"sensors": ["PIT501"], "actuators": ["P501"]},
    "R_NEW_04": {"sensors": ["AIT402"], "actuators": ["UV401"]},
    "R_NEW_05": {"sensors": ["DPIT301"], "actuators": ["MV304"]},
    "R_NEW_06": {"sensors": ["LIT101"], "actuators": ["P102"]},
    "R_NEW_08": {"sensors": ["DPIT301"], "actuators": ["MV303"]},
    "R_NEW_09": {"sensors": ["LIT101"], "actuators": ["P101"]},
    "R_NEW_10": {"sensors": ["LIT101"], "actuators": ["P102"]},
    "R_NEW_11": {"sensors": ["LIT301"], "actuators": ["MV302"]},
    "R_NEW_12": {"sensors": ["DPIT301"], "actuators": ["MV304"]},
    "R_NEW_13": {"sensors": ["AIT203"], "actuators": ["P205"]},
    "R_NEW_15": {"sensors": ["AIT202"], "actuators": ["P205"]},
}

# Localization confidence / status
LOCALIZATION_CONFIRMED = "Confirmed"
LOCALIZATION_SUSPECTED = "Suspected"
LOCALIZATION_UNKNOWN = "Unknown"


@dataclass
class ComponentEvidence:
    tag: str
    area_key: str
    area_label: str
    component_type: str        # "sensor" | "actuator"
    evidence_sources: List[str]
    evidence_score: float      # 0-100 (heuristic strength only)
    measured_value: Optional[float]
    deviation_note: Optional[str]


@dataclass
class LocalizationResult:
    implicated_components: List[ComponentEvidence]   # ranked by evidence_score desc
    implicated_areas: List[str]                       # area labels with evidence
    localization_status: str                          # Confirmed | Suspected | Unknown
    summary: str
    methodology_note: str
    limitations: List[str]


def _get_area_for_tag(tag: str) -> Optional[Tuple[str, str]]:
    """Return (area_key, area_label) for a tag, or None if unmapped."""
    key = _TAG_TO_AREA.get(tag)
    if key:
        return key, PROCESS_AREAS[key]["label"]
    return None


def localize_event(
    rule_violations: List[Dict],
    affected_sensors: List[str],
    sensor_row: Optional[Dict] = None,
    ml_probability: float = 0.0,
    ml_triggered: bool = False,
) -> LocalizationResult:
    """
    Produce a ranked list of implicated components and process areas.

    Parameters
    ----------
    rule_violations : list[dict]
        Each dict has keys: rule_id, status, message, evidence.
    affected_sensors : list[str]
        Tags already extracted by the fusion engine from rule evidence.
    sensor_row : dict or None
        Raw sensor values for this reading.
    ml_probability : float
        RF attack probability (used for ML-only flagging note only).
    ml_triggered : bool
        Whether the ML threshold was exceeded.
    """
    tag_evidence: Dict[str, List[str]] = {}  # tag → list of evidence strings
    tag_values: Dict[str, Optional[float]] = {}

    # 1. Evidence from rule violations
    for v in rule_violations:
        rule_id = v.get("rule_id", "")
        msg = v.get("message", "")
        rule_map = RULE_SENSOR_MAP.get(rule_id, {})
        all_tags = rule_map.get("sensors", []) + rule_map.get("actuators", [])
        for tag in all_tags:
            tag_evidence.setdefault(tag, []).append(f"Rule {rule_id}: {msg}")

        # Also pick up tags from the evidence dict
        for tag, val in v.get("evidence", {}).items():
            if tag == "threshold":
                continue
            tag_evidence.setdefault(tag, []).append(f"Rule {rule_id} evidence: {tag}={val}")
            if sensor_row is None:
                try:
                    tag_values[tag] = float(val)
                except (TypeError, ValueError):
                    pass

    # 2. Tags from affected_sensors (fusion engine output) not already covered
    for tag in affected_sensors:
        if tag not in tag_evidence:
            src = "Flagged by fusion engine"
            if ml_triggered:
                src += f" (ML probability: {ml_probability*100:.1f}%)"
            tag_evidence[tag] = [src]

    # 3. Pull measured values from sensor_row
    if sensor_row:
        for tag in tag_evidence:
            if tag in sensor_row:
                try:
                    tag_values[tag] = float(sensor_row[tag])
                except (TypeError, ValueError):
                    tag_values[tag] = None

    # 4. Build ComponentEvidence list
    components: List[ComponentEvidence] = []
    for tag, sources in tag_evidence.items():
        area_info = _get_area_for_tag(tag)
        if area_info:
            area_key, area_label = area_info
            ctype = ("actuator" if tag in PROCESS_AREAS[area_key]["actuators"]
                     else "sensor")
        else:
            area_key = "UNKNOWN"
            area_label = "Unknown Process Area"
            ctype = "unknown"

        # Evidence score heuristic:
        #   1 point per source, capped at 50; +30 if ML also triggered
        score = min(len(sources) * 20.0, 60.0)
        if ml_triggered:
            score = min(score + 30.0, 100.0)

        val = tag_values.get(tag)
        dev_note: Optional[str] = None
        if val is not None:
            dev_note = f"Measured value: {val}"

        components.append(ComponentEvidence(
            tag=tag,
            area_key=area_key,
            area_label=area_label,
            component_type=ctype,
            evidence_sources=sources,
            evidence_score=round(score, 1),
            measured_value=val,
            deviation_note=dev_note,
        ))

    # Sort by evidence_score desc
    components.sort(key=lambda c: c.evidence_score, reverse=True)

    # Implicated areas (deduplicated, preserving order)
    seen_areas: List[str] = []
    for c in components:
        if c.area_label not in seen_areas:
            seen_areas.append(c.area_label)

    # Localization status
    n_violations = len(rule_violations)
    if n_violations >= 2 and ml_triggered:
        status = LOCALIZATION_CONFIRMED
    elif n_violations >= 1 or ml_triggered:
        status = LOCALIZATION_SUSPECTED
    else:
        status = LOCALIZATION_UNKNOWN

    summary = _build_summary(components, seen_areas, n_violations, ml_triggered, ml_probability)

    return LocalizationResult(
        implicated_components=components,
        implicated_areas=seen_areas,
        localization_status=status,
        summary=summary,
        methodology_note=(
            "Components are ranked by a heuristic evidence score derived from "
            "rule violations and ML probability. This is NOT a causal attribution."
        ),
        limitations=[
            "The component with the highest evidence score is not necessarily the physical origin.",
            "Sensor deviations alone cannot distinguish cyberattack from physical anomaly.",
            "Process area mapping is a logical topology overview (SWaT naming convention), "
            "not a validated physical plant schematic.",
            "Localization confidence improves with operator review and additional telemetry.",
        ],
    )


def _build_summary(components, areas, n_violations, ml_triggered, ml_prob) -> str:
    parts = []
    if n_violations > 0:
        parts.append(f"{n_violations} rule violation(s) detected.")
    if ml_triggered:
        parts.append(f"ML model flagged event (probability: {ml_prob*100:.1f}%).")
    if components:
        top = components[0]
        parts.append(
            f"Highest-evidence component: {top.tag} ({top.area_label})."
        )
    if areas:
        parts.append(f"Affected process areas: {', '.join(areas[:3])}.")
    return " ".join(parts) if parts else "No localization evidence available."
