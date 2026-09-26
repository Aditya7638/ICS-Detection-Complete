"""
candidate_rules.py — UNVALIDATED candidate rules (R_NEW_01 .. R_NEW_15).

These are implemented exactly as specified, using the CORRECTED global
SWaT encoding already confirmed in rule_engine.py:
    Pumps / UV / other binary actuators: 1 = OFF, 2 = ON
    Valves (MV...):                      1 = CLOSED, 2 = OPEN, 0 = transition/unknown

None of these have been validated against Normal-vs-Attack violation rates
yet. Do NOT add any of them to rule_engine.py's active `rules` list until
each one has been run through validate_rule_on_dataframe() and shown to have
a real, non-backwards signal (attack_rate meaningfully > normal_rate).

Known risk flagged up front: R_NEW_06, R_NEW_07, R_NEW_09, R_NEW_10 are the
same *shape* of rule as the already-invalidated R1/R3 ("actuator ON/OFF
while level is on the far side of its own normal operating threshold") —
that pattern previously produced 51-66% normal violation rates because it
fires throughout ordinary fill/drain hysteresis, not just during genuine
faults. Treat these four with extra suspicion during validation.
"""

from dataclasses import dataclass
from typing import Dict, Optional

ON = 2
OFF = 1
OPEN = 2
CLOSED = 1


@dataclass
class RuleResult:
    rule_id: str
    status: str          # VIOLATION / OK / UNKNOWN
    message: str = ""
    evidence: Optional[dict] = None


def get_value(data: Dict, key: str):
    value = data.get(key)
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _result(rule_id, violation, message, evidence=None, unknown=False):
    status = "UNKNOWN" if unknown else ("VIOLATION" if violation else "OK")
    return RuleResult(rule_id=rule_id, status=status, message=message, evidence=evidence)


# ------------------------------------------------------------------
# P2 — chemical dosing
# ------------------------------------------------------------------

def rule_R_NEW_01(sensors, actuators):
    """P205 == 2 (ON) AND AIT201 < 260.382"""
    ait201 = get_value(sensors, "AIT201")
    p205 = get_value(actuators, "P205")
    if ait201 is None or p205 is None:
        return _result("R_NEW_01", False, "Insufficient data.", unknown=True)
    violation = (p205 == ON) and (ait201 < 260.382)
    return _result("R_NEW_01", violation, "P205 ON while AIT201 below threshold.",
                    {"AIT201": ait201, "P205": p205, "threshold": 260.382})


def rule_R_NEW_02(sensors, actuators):
    """P203 == 1 (OFF) AND AIT201 < 261.247"""
    ait201 = get_value(sensors, "AIT201")
    p203 = get_value(actuators, "P203")
    if ait201 is None or p203 is None:
        return _result("R_NEW_02", False, "Insufficient data.", unknown=True)
    violation = (p203 == OFF) and (ait201 < 261.247)
    return _result("R_NEW_02", violation, "P203 OFF while AIT201 below threshold.",
                    {"AIT201": ait201, "P203": p203, "threshold": 261.247})


def rule_R_NEW_13(sensors, actuators):
    """P205 == 2 (ON) AND AIT203 > 334.401"""
    ait203 = get_value(sensors, "AIT203")
    p205 = get_value(actuators, "P205")
    if ait203 is None or p205 is None:
        return _result("R_NEW_13", False, "Insufficient data.", unknown=True)
    violation = (p205 == ON) and (ait203 > 334.401)
    return _result("R_NEW_13", violation, "P205 ON while AIT203 above threshold.",
                    {"AIT203": ait203, "P205": p205, "threshold": 334.401})


def rule_R_NEW_14(sensors, actuators):
    """P203 == 1 (OFF) AND FIT201 > 2.440"""
    fit201 = get_value(sensors, "FIT201")
    p203 = get_value(actuators, "P203")
    if fit201 is None or p203 is None:
        return _result("R_NEW_14", False, "Insufficient data.", unknown=True)
    violation = (p203 == OFF) and (fit201 > 2.440)
    return _result("R_NEW_14", violation, "P203 OFF while FIT201 above threshold.",
                    {"FIT201": fit201, "P203": p203, "threshold": 2.440})


def rule_R_NEW_15(sensors, actuators):
    """P205 == 1 (OFF) AND AIT202 > 8.486"""
    ait202 = get_value(sensors, "AIT202")
    p205 = get_value(actuators, "P205")
    if ait202 is None or p205 is None:
        return _result("R_NEW_15", False, "Insufficient data.", unknown=True)
    violation = (p205 == OFF) and (ait202 > 8.486)
    return _result("R_NEW_15", violation, "P205 OFF while AIT202 above threshold.",
                    {"AIT202": ait202, "P205": p205, "threshold": 8.486})


# ------------------------------------------------------------------
# P1 — raw water intake (structurally similar to invalidated R1/R3 — verify carefully)
# ------------------------------------------------------------------

def rule_R_NEW_06(sensors, actuators):
    """P102 == 2 (ON) AND LIT101 < 689.871"""
    lit101 = get_value(sensors, "LIT101")
    p102 = get_value(actuators, "P102")
    if lit101 is None or p102 is None:
        return _result("R_NEW_06", False, "Insufficient data.", unknown=True)
    violation = (p102 == ON) and (lit101 < 689.871)
    return _result("R_NEW_06", violation, "P102 ON while LIT101 below threshold.",
                    {"LIT101": lit101, "P102": p102, "threshold": 689.871})


def rule_R_NEW_07(sensors, actuators):
    """P101 == 1 (OFF) AND LIT101 > 842.827"""
    lit101 = get_value(sensors, "LIT101")
    p101 = get_value(actuators, "P101")
    if lit101 is None or p101 is None:
        return _result("R_NEW_07", False, "Insufficient data.", unknown=True)
    violation = (p101 == OFF) and (lit101 > 842.827)
    return _result("R_NEW_07", violation, "P101 OFF while LIT101 above threshold.",
                    {"LIT101": lit101, "P101": p101, "threshold": 842.827})


def rule_R_NEW_09(sensors, actuators):
    """P101 == 2 (ON) AND LIT101 > 866.191"""
    lit101 = get_value(sensors, "LIT101")
    p101 = get_value(actuators, "P101")
    if lit101 is None or p101 is None:
        return _result("R_NEW_09", False, "Insufficient data.", unknown=True)
    violation = (p101 == ON) and (lit101 > 866.191)
    return _result("R_NEW_09", violation, "P101 ON while LIT101 above threshold.",
                    {"LIT101": lit101, "P101": p101, "threshold": 866.191})


def rule_R_NEW_10(sensors, actuators):
    """P102 == 1 (OFF) AND LIT101 > 860.527"""
    lit101 = get_value(sensors, "LIT101")
    p102 = get_value(actuators, "P102")
    if lit101 is None or p102 is None:
        return _result("R_NEW_10", False, "Insufficient data.", unknown=True)
    violation = (p102 == OFF) and (lit101 > 860.527)
    return _result("R_NEW_10", violation, "P102 OFF while LIT101 above threshold.",
                    {"LIT101": lit101, "P102": p102, "threshold": 860.527})


# ------------------------------------------------------------------
# P3 — UF / backwash
# ------------------------------------------------------------------

def rule_R_NEW_05(sensors, actuators):
    """MV304 == 2 (OPEN) AND DPIT301 > 41.738"""
    dpit301 = get_value(sensors, "DPIT301")
    mv304 = get_value(actuators, "MV304")
    if dpit301 is None or mv304 is None:
        return _result("R_NEW_05", False, "Insufficient data.", unknown=True)
    violation = (mv304 == OPEN) and (dpit301 > 41.738)
    return _result("R_NEW_05", violation, "MV304 OPEN while DPIT301 above threshold.",
                    {"DPIT301": dpit301, "MV304": mv304, "threshold": 41.738})


def rule_R_NEW_08(sensors, actuators):
    """MV303 == 2 (OPEN) AND DPIT301 > 2.654"""
    dpit301 = get_value(sensors, "DPIT301")
    mv303 = get_value(actuators, "MV303")
    if dpit301 is None or mv303 is None:
        return _result("R_NEW_08", False, "Insufficient data.", unknown=True)
    violation = (mv303 == OPEN) and (dpit301 > 2.654)
    return _result("R_NEW_08", violation, "MV303 OPEN while DPIT301 above threshold.",
                    {"DPIT301": dpit301, "MV303": mv303, "threshold": 2.654})


def rule_R_NEW_11(sensors, actuators):
    """MV302 == 2 (OPEN) AND LIT301 > 1009.357"""
    lit301 = get_value(sensors, "LIT301")
    mv302 = get_value(actuators, "MV302")
    if lit301 is None or mv302 is None:
        return _result("R_NEW_11", False, "Insufficient data.", unknown=True)
    violation = (mv302 == OPEN) and (lit301 > 1009.357)
    return _result("R_NEW_11", violation, "MV302 OPEN while LIT301 above threshold.",
                    {"LIT301": lit301, "MV302": mv302, "threshold": 1009.357})


def rule_R_NEW_12(sensors, actuators):
    """MV304 == 0 (transition/unknown state) AND DPIT301 > 14.494

    NOTE: this checks the raw value 0 directly, NOT "closed" or "open" —
    state 0 is the transition/intermediate reading. This is a different
    kind of check than the others (catching valve movement while fouling
    is elevated) rather than a steady-state violation. Keep this
    distinction in mind when validating: comparing it to Normal/Attack
    violation rate is still valid, just interpret what "violation" means
    here differently in your write-up.
    """
    dpit301 = get_value(sensors, "DPIT301")
    mv304 = get_value(actuators, "MV304")
    if dpit301 is None or mv304 is None:
        return _result("R_NEW_12", False, "Insufficient data.", unknown=True)
    violation = (mv304 == 0) and (dpit301 > 14.494)
    return _result("R_NEW_12", violation, "MV304 in transition while DPIT301 above threshold.",
                    {"DPIT301": dpit301, "MV304": mv304, "threshold": 14.494})


# ------------------------------------------------------------------
# P5 — RO / dechlorination
# ------------------------------------------------------------------

def rule_R_NEW_03(sensors, actuators):
    """P501 == 2 (ON) AND PIT501 > 251.673"""
    pit501 = get_value(sensors, "PIT501")
    p501 = get_value(actuators, "P501")
    if pit501 is None or p501 is None:
        return _result("R_NEW_03", False, "Insufficient data.", unknown=True)
    violation = (p501 == ON) and (pit501 > 251.673)
    return _result("R_NEW_03", violation, "P501 ON while PIT501 above threshold.",
                    {"PIT501": pit501, "P501": p501, "threshold": 251.673})


def rule_R_NEW_04(sensors, actuators):
    """UV401 == 1 (OFF) AND AIT402 > 155.991"""
    ait402 = get_value(sensors, "AIT402")
    uv401 = get_value(actuators, "UV401")
    if ait402 is None or uv401 is None:
        return _result("R_NEW_04", False, "Insufficient data.", unknown=True)
    violation = (uv401 == OFF) and (ait402 > 155.991)
    return _result("R_NEW_04", violation, "UV401 OFF while AIT402 above threshold.",
                    {"AIT402": ait402, "UV401": uv401, "threshold": 155.991})


# ------------------------------------------------------------------
# Dispatcher
# ------------------------------------------------------------------

CANDIDATE_RULES = {
    "R_NEW_01": (rule_R_NEW_01, ["AIT201"], ["P205"]),
    "R_NEW_02": (rule_R_NEW_02, ["AIT201"], ["P203"]),
    "R_NEW_03": (rule_R_NEW_03, ["PIT501"], ["P501"]),
    "R_NEW_04": (rule_R_NEW_04, ["AIT402"], ["UV401"]),
    "R_NEW_05": (rule_R_NEW_05, ["DPIT301"], ["MV304"]),
    "R_NEW_06": (rule_R_NEW_06, ["LIT101"], ["P102"]),
    "R_NEW_07": (rule_R_NEW_07, ["LIT101"], ["P101"]),
    "R_NEW_08": (rule_R_NEW_08, ["DPIT301"], ["MV303"]),
    "R_NEW_09": (rule_R_NEW_09, ["LIT101"], ["P101"]),
    "R_NEW_10": (rule_R_NEW_10, ["LIT101"], ["P102"]),
    "R_NEW_11": (rule_R_NEW_11, ["LIT301"], ["MV302"]),
    "R_NEW_12": (rule_R_NEW_12, ["DPIT301"], ["MV304"]),
    "R_NEW_13": (rule_R_NEW_13, ["AIT203"], ["P205"]),
    "R_NEW_14": (rule_R_NEW_14, ["FIT201"], ["P203"]),
    "R_NEW_15": (rule_R_NEW_15, ["AIT202"], ["P205"]),
}


def evaluate_candidate_rules(sensors: dict, actuators: dict):
    """Run every candidate rule against one row. Returns list[RuleResult]."""
    return [fn(sensors, actuators) for fn, _, _ in CANDIDATE_RULES.values()]
