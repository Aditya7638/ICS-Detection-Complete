"""
validator.py — Validates incoming sensor data before model inference.
"""

import math
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple

RAW_SENSOR_COLUMNS = [
    "FIT101","LIT101","MV101","P101","P102","AIT201","AIT202","AIT203",
    "FIT201","MV201","P203","P204","P205","P206","DPIT301","FIT301",
    "LIT301","MV301","MV302","MV303","MV304","P302","AIT401","AIT402",
    "FIT401","LIT401","P402","UV401","AIT501","AIT502","AIT503","AIT504",
    "FIT501","FIT502","FIT503","FIT504","P501","PIT501","PIT502","PIT503",
    "FIT601","P602",
]

@dataclass
class ValidationIssue:
    field: str
    code: str
    message: str
    severity: str = "error"  # "error" | "warning"

@dataclass
class ValidationResult:
    valid: bool
    usable: bool
    errors: List[ValidationIssue] = field(default_factory=list)
    warnings: List[ValidationIssue] = field(default_factory=list)
    cleaned_row: Optional[Dict[str, float]] = None


def validate_sensor_row(row: dict) -> ValidationResult:
    errors: List[ValidationIssue] = []
    warnings: List[ValidationIssue] = []
    cleaned: Dict[str, float] = {}

    for col in RAW_SENSOR_COLUMNS:
        if col not in row or row[col] is None or str(row[col]).strip() == "":
            errors.append(ValidationIssue(col, "MISSING", f"{col} is required.", "error"))
            continue
        try:
            val = float(row[col])
        except (ValueError, TypeError):
            errors.append(ValidationIssue(col, "INVALID_TYPE", f"{col} must be numeric.", "error"))
            continue
        if math.isnan(val):
            errors.append(ValidationIssue(col, "NAN", f"{col} is NaN.", "error"))
            continue
        if math.isinf(val):
            errors.append(ValidationIssue(col, "INF", f"{col} is infinite.", "error"))
            continue
        cleaned[col] = val

    valid = len(errors) == 0
    return ValidationResult(
        valid=valid,
        usable=valid,
        errors=errors,
        warnings=warnings,
        cleaned_row=cleaned if valid else None,
    )


def normalize_csv_headers(columns: List[str]) -> List[str]:
    return [c.strip() for c in columns]


def extract_sensor_row(row: dict, label_col: Optional[str] = "Normal/Attack",
                        timestamp_col: Optional[str] = "Timestamp") -> Tuple[dict, Optional[str]]:
    """
    Extract (sensor_dict, label) from a CSV row dict, excluding timestamp and label.
    """
    skip = set()
    if timestamp_col:
        skip.add(timestamp_col)
    if label_col:
        skip.add(label_col)

    label = row.get(label_col) if label_col else None
    sensor = {k: v for k, v in row.items() if k not in skip}
    return sensor, label
