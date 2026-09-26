"""
rule_engine_final.py — SWaT Physical-Process Rule Engine (FINAL)

16 validated rules, combining two sources:

  Physically-derived (from the original Rule Engine Specification, empirically
  recalibrated against this dataset after fixing a global actuator/valve
  encoding bug — see project notes):
      R10, R11, R20b

  Mined from decision-boundary analysis on this dataset, validated with
  0% (or near-0%) normal-row violation rate and >=94% precision:
      R_NEW_01, 02, 03, 04, 05, 06, 08, 09, 10, 11, 12, 13, 15

  Excluded after validation (either backwards, or fired on a large share of
  normal operation due to static single-row checks catching ordinary
  fill/drain hysteresis rather than genuine faults):
      R1, R2, R3, R4, R6, R7 (orig), R8, R9 (orig), R12 (orig), R13 (orig),
      R14 (orig), R15 (orig), R16, R17, R18, R19, R20a, R21, R22, R23, R24,
      R_NEW_07, R_NEW_14

Global actuator/valve encoding (validated directly against the data — see
project notes on the MV101/LIT101 and P101/P102 correlation checks):
      Pumps / UV / other binary actuators: 1 = OFF, 2 = ON
      Valves (MV...):                      1 = CLOSED, 2 = OPEN
      0 = transition/intermediate reading for any actuator (treated as
          UNKNOWN by the *_is_on/*_is_open helpers; NOT interpreted as OFF)

Fusion usage: flag a row as ATTACK if (RF probability >= 0.70) OR
(any rule below returns VIOLATION). Validated result on this dataset:
Precision 98.64%, Recall 91.55%, F1 94.96%, FPR 1.27% (vs. RF alone:
Precision 99.17%, Recall 79.64%, F1 88.34%, FPR 0.67%).

CAVEAT: validated against a 20k-row sample containing a single contiguous
Normal block and a single contiguous Attack block (i.e., one attack episode,
not the ~35-40 distinct scenarios in the full official SWaT dataset). The
13 mined rules in particular were fit against decision boundaries in this
same sample and are more likely to be sample-specific than the three
physically-derived rules. Re-validate against the full dataset before
reporting these numbers as final / generalizable.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional

# --- Global encoding (validated) ---
ON = 2
OFF = 1
OPEN = 2
CLOSED = 1

VIOLATION = "VIOLATION"
OK = "OK"
UNKNOWN = "UNKNOWN"


@dataclass
class RuleResult:
    rule_id: str
    status: str
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


def actuator_is_on(actuators: Dict, tag: str) -> Optional[bool]:
    value = get_value(actuators, tag)
    if value is None or value == 0:
        return None
    if value == ON:
        return True
    if value == OFF:
        return False
    return None


def valve_is_open(actuators: Dict, tag: str) -> Optional[bool]:
    value = get_value(actuators, tag)
    if value is None or value == 0:
        return None
    if value == OPEN:
        return True
    if value == CLOSED:
        return False
    return None


def _result(rule_id, violation, message, evidence=None, unknown=False):
    status = UNKNOWN if unknown else (VIOLATION if violation else OK)
    return RuleResult(rule_id=rule_id, status=status, message=message, evidence=evidence)


# ============================================================
# Physically-derived rules (recalibrated thresholds)
# ============================================================

def rule_R10(sensors, actuators):
    """MV302 should not remain OPEN / P302 should not remain ON while LIT301 > 1000 (overflow)."""
    lit301 = get_value(sensors, "LIT301")
    mv302_open = valve_is_open(actuators, "MV302")
    p302_on = actuator_is_on(actuators, "P302")
    if lit301 is None or mv302_open is None or p302_on is None:
        return _result("R10", False, "Insufficient evidence.", unknown=True)
    violation = lit301 > 1000 and (mv302_open or p302_on)
    return _result("R10", violation, "LIT301 above overflow threshold while inflow still active.",
                    {"LIT301": lit301, "MV302_open": mv302_open, "P302_on": p302_on, "threshold": 1000})


def rule_R11(sensors, actuators):
    """MV303 should not be OPEN while DPIT301 is below the (recalibrated) fouling threshold."""
    dpit301 = get_value(sensors, "DPIT301")
    mv303_open = valve_is_open(actuators, "MV303")
    if dpit301 is None or mv303_open is None:
        return _result("R11", False, "Insufficient evidence.", unknown=True)
    violation = mv303_open and dpit301 < 19.87
    return _result("R11", violation, "MV303 open while DPIT301 below fouling threshold.",
                    {"DPIT301": dpit301, "MV303_open": mv303_open, "threshold": 19.87})


def rule_R20b(sensors, actuators):
    """P501 should not run while AIT501 or AIT503 is outside its safe band."""
    ait501 = get_value(sensors, "AIT501")
    ait503 = get_value(sensors, "AIT503")
    p501_on = actuator_is_on(actuators, "P501")
    if ait501 is None or ait503 is None or p501_on is None:
        return _result("R20b", False, "Insufficient evidence.", unknown=True)
    bad = (ait501 < 7.8 or ait501 > 8.2) or (ait503 < 255 or ait503 > 291)
    violation = p501_on and bad
    return _result("R20b", violation, "P501 ON while AIT501/AIT503 outside safe band.",
                    {"AIT501": ait501, "AIT503": ait503, "P501_on": p501_on})


# ============================================================
# Mined rules (validated: ~0% normal violation, high precision)
# ============================================================

def rule_R_NEW_01(sensors, actuators):
    ait201, p205 = get_value(sensors, "AIT201"), get_value(actuators, "P205")
    if ait201 is None or p205 is None:
        return _result("R_NEW_01", False, "Insufficient data.", unknown=True)
    violation = (p205 == ON) and (ait201 < 260.382)
    return _result("R_NEW_01", violation, "P205 ON while AIT201 below threshold.",
                    {"AIT201": ait201, "P205": p205})


def rule_R_NEW_02(sensors, actuators):
    ait201, p203 = get_value(sensors, "AIT201"), get_value(actuators, "P203")
    if ait201 is None or p203 is None:
        return _result("R_NEW_02", False, "Insufficient data.", unknown=True)
    violation = (p203 == OFF) and (ait201 < 261.247)
    return _result("R_NEW_02", violation, "P203 OFF while AIT201 below threshold.",
                    {"AIT201": ait201, "P203": p203})


def rule_R_NEW_03(sensors, actuators):
    pit501, p501 = get_value(sensors, "PIT501"), get_value(actuators, "P501")
    if pit501 is None or p501 is None:
        return _result("R_NEW_03", False, "Insufficient data.", unknown=True)
    violation = (p501 == ON) and (pit501 > 251.673)
    return _result("R_NEW_03", violation, "P501 ON while PIT501 above threshold.",
                    {"PIT501": pit501, "P501": p501})


def rule_R_NEW_04(sensors, actuators):
    ait402, uv401 = get_value(sensors, "AIT402"), get_value(actuators, "UV401")
    if ait402 is None or uv401 is None:
        return _result("R_NEW_04", False, "Insufficient data.", unknown=True)
    violation = (uv401 == OFF) and (ait402 > 155.991)
    return _result("R_NEW_04", violation, "UV401 OFF while AIT402 above threshold.",
                    {"AIT402": ait402, "UV401": uv401})


def rule_R_NEW_05(sensors, actuators):
    dpit301, mv304 = get_value(sensors, "DPIT301"), get_value(actuators, "MV304")
    if dpit301 is None or mv304 is None:
        return _result("R_NEW_05", False, "Insufficient data.", unknown=True)
    violation = (mv304 == OPEN) and (dpit301 > 41.738)
    return _result("R_NEW_05", violation, "MV304 OPEN while DPIT301 above threshold.",
                    {"DPIT301": dpit301, "MV304": mv304})


def rule_R_NEW_06(sensors, actuators):
    lit101, p102 = get_value(sensors, "LIT101"), get_value(actuators, "P102")
    if lit101 is None or p102 is None:
        return _result("R_NEW_06", False, "Insufficient data.", unknown=True)
    violation = (p102 == ON) and (lit101 < 689.871)
    return _result("R_NEW_06", violation, "P102 ON while LIT101 below threshold.",
                    {"LIT101": lit101, "P102": p102})


def rule_R_NEW_08(sensors, actuators):
    dpit301, mv303 = get_value(sensors, "DPIT301"), get_value(actuators, "MV303")
    if dpit301 is None or mv303 is None:
        return _result("R_NEW_08", False, "Insufficient data.", unknown=True)
    violation = (mv303 == OPEN) and (dpit301 > 2.654)
    return _result("R_NEW_08", violation, "MV303 OPEN while DPIT301 above threshold.",
                    {"DPIT301": dpit301, "MV303": mv303})


def rule_R_NEW_09(sensors, actuators):
    lit101, p101 = get_value(sensors, "LIT101"), get_value(actuators, "P101")
    if lit101 is None or p101 is None:
        return _result("R_NEW_09", False, "Insufficient data.", unknown=True)
    violation = (p101 == ON) and (lit101 > 866.191)
    return _result("R_NEW_09", violation, "P101 ON while LIT101 above threshold.",
                    {"LIT101": lit101, "P101": p101})


def rule_R_NEW_10(sensors, actuators):
    lit101, p102 = get_value(sensors, "LIT101"), get_value(actuators, "P102")
    if lit101 is None or p102 is None:
        return _result("R_NEW_10", False, "Insufficient data.", unknown=True)
    violation = (p102 == OFF) and (lit101 > 860.527)
    return _result("R_NEW_10", violation, "P102 OFF while LIT101 above threshold.",
                    {"LIT101": lit101, "P102": p102})


def rule_R_NEW_11(sensors, actuators):
    lit301, mv302 = get_value(sensors, "LIT301"), get_value(actuators, "MV302")
    if lit301 is None or mv302 is None:
        return _result("R_NEW_11", False, "Insufficient data.", unknown=True)
    violation = (mv302 == OPEN) and (lit301 > 1009.357)
    return _result("R_NEW_11", violation, "MV302 OPEN while LIT301 above threshold.",
                    {"LIT301": lit301, "MV302": mv302})


def rule_R_NEW_12(sensors, actuators):
    """NOTE: checks raw actuator value == 0 (transition state) directly, not OPEN/CLOSED."""
    dpit301, mv304 = get_value(sensors, "DPIT301"), get_value(actuators, "MV304")
    if dpit301 is None or mv304 is None:
        return _result("R_NEW_12", False, "Insufficient data.", unknown=True)
    violation = (mv304 == 0) and (dpit301 > 14.494)
    return _result("R_NEW_12", violation, "MV304 in transition while DPIT301 above threshold.",
                    {"DPIT301": dpit301, "MV304": mv304})


def rule_R_NEW_13(sensors, actuators):
    ait203, p205 = get_value(sensors, "AIT203"), get_value(actuators, "P205")
    if ait203 is None or p205 is None:
        return _result("R_NEW_13", False, "Insufficient data.", unknown=True)
    violation = (p205 == ON) and (ait203 > 334.401)
    return _result("R_NEW_13", violation, "P205 ON while AIT203 above threshold.",
                    {"AIT203": ait203, "P205": p205})


def rule_R_NEW_15(sensors, actuators):
    ait202, p205 = get_value(sensors, "AIT202"), get_value(actuators, "P205")
    if ait202 is None or p205 is None:
        return _result("R_NEW_15", False, "Insufficient data.", unknown=True)
    violation = (p205 == OFF) and (ait202 > 8.486)
    return _result("R_NEW_15", violation, "P205 OFF while AIT202 above threshold.",
                    {"AIT202": ait202, "P205": p205})


# ============================================================
# Rule Engine
# ============================================================

ACTIVE_RULES = [
    "R10", "R11", "R20b",
    "R_NEW_01", "R_NEW_02", "R_NEW_03", "R_NEW_04", "R_NEW_05",
    "R_NEW_06", "R_NEW_08", "R_NEW_09", "R_NEW_10", "R_NEW_11",
    "R_NEW_12", "R_NEW_13", "R_NEW_15",
]

_RULE_FUNCTIONS = [
    rule_R10, rule_R11, rule_R20b,
    rule_R_NEW_01, rule_R_NEW_02, rule_R_NEW_03, rule_R_NEW_04, rule_R_NEW_05,
    rule_R_NEW_06, rule_R_NEW_08, rule_R_NEW_09, rule_R_NEW_10, rule_R_NEW_11,
    rule_R_NEW_12, rule_R_NEW_13, rule_R_NEW_15,
]


def evaluate_rules(sensors: Dict, actuators: Dict) -> List[RuleResult]:
    """Run all 16 active rules against one row of sensor/actuator readings."""
    results = []
    for rule in _RULE_FUNCTIONS:
        try:
            results.append(rule(sensors, actuators))
        except Exception as exc:
            results.append(RuleResult(rule_id=rule.__name__.replace("rule_", ""),
                                       status=UNKNOWN, message=f"Rule execution error: {exc}"))
    return results


def rule_count(results: List[RuleResult]) -> int:
    return sum(r.status == VIOLATION for r in results)


def get_violations(results: List[RuleResult]):
    return [r for r in results if r.status == VIOLATION]


REQUIRED_SENSOR_COLUMNS = [
    "LIT101", "LIT301", "DPIT301", "AIT201", "AIT202", "AIT203",
    "AIT402", "AIT501", "AIT503", "PIT501",
]
REQUIRED_ACTUATOR_COLUMNS = [
    "P101", "P102", "P203", "P205", "P501", "UV401",
    "MV302", "MV303", "MV304",
]


if __name__ == "__main__":
    sensors = {
        "LIT101": 900, "LIT301": 1020, "DPIT301": 45,
        "AIT201": 250, "AIT202": 9.0, "AIT203": 340,
        "AIT402": 160, "AIT501": 9.0, "AIT503": 300, "PIT501": 260,
    }
    actuators = {
        "P101": OFF, "P102": ON, "P203": OFF, "P205": ON, "P501": ON, "UV401": OFF,
        "MV302": OPEN, "MV303": OPEN, "MV304": OPEN,
    }
    results = evaluate_rules(sensors, actuators)
    for r in results:
        print(f"{r.rule_id:10s} {r.status:10s} {r.message}")
    print("\nTotal violations:", rule_count(results))
