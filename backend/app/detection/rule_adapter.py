"""
rule_adapter.py — Adapter around the existing rule_engine_final.py.
Does NOT rewrite rule logic. Simply calls evaluate_rules() and formats output.
"""

import sys
import os
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Any

# Add rules directory to path so rule_engine_final imports work
_rules_dir = str(Path(__file__).parent.parent.parent / "rules")
if _rules_dir not in sys.path:
    sys.path.insert(0, _rules_dir)

from rule_engine_final import (
    evaluate_rules,
    get_violations,
    rule_count,
    ACTIVE_RULES,
    REQUIRED_SENSOR_COLUMNS,
    REQUIRED_ACTUATOR_COLUMNS,
    RuleResult,
)

SENSOR_TAGS = set(REQUIRED_SENSOR_COLUMNS)
ACTUATOR_TAGS = set(REQUIRED_ACTUATOR_COLUMNS)

# All sensor/actuator columns the rule engine knows about
ALL_RULE_COLUMNS = REQUIRED_SENSOR_COLUMNS + REQUIRED_ACTUATOR_COLUMNS


@dataclass
class RuleEngineResult:
    violated: bool
    violation_count: int
    violations: List[Dict[str, Any]]
    all_results: List[Dict[str, Any]]


def _split_row(row: dict) -> tuple[dict, dict]:
    """Split a flat sensor dict into (sensors, actuators) for the rule engine."""
    sensors = {k: v for k, v in row.items() if k in SENSOR_TAGS}
    actuators = {k: v for k, v in row.items() if k in ACTUATOR_TAGS}
    return sensors, actuators


def run_rules(row: dict) -> RuleEngineResult:
    """Run all 16 active rules against one flat sensor/actuator row dict."""
    sensors, actuators = _split_row(row)
    results: List[RuleResult] = evaluate_rules(sensors, actuators)
    violations = get_violations(results)

    def _fmt(r: RuleResult) -> dict:
        return {
            "rule_id": r.rule_id,
            "status": r.status,
            "message": r.message,
            "evidence": r.evidence or {},
        }

    return RuleEngineResult(
        violated=len(violations) > 0,
        violation_count=len(violations),
        violations=[_fmt(v) for v in violations],
        all_results=[_fmt(r) for r in results],
    )


def get_active_rule_ids() -> List[str]:
    return list(ACTIVE_RULES)
