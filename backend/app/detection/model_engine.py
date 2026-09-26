"""
model_engine.py — Loads best_model.joblib (RandomForestClassifier, 168 features)
and computes raw ML predictions + probabilities.

Model facts (from inspection):
  - Type: RandomForestClassifier (sklearn 1.7.2), n_estimators=200
  - Features: 168 (42 raw sensors + 126 rolling features: roll_mean5, roll_std5, diff5)
  - Classes: [0, 1]  → 0=Normal, 1=Attack
  - No embedded scaler or preprocessing
  - Decision threshold from fusion_config: 0.70
  - predict_proba() available
"""

import joblib
import numpy as np
import pandas as pd
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)

@dataclass
class MLResult:
    prediction: int          # 0 or 1
    probability: float       # P(class=1=Attack)
    label: str               # "Normal" | "Attack"
    threshold_used: float

class ModelEngine:
    def __init__(self, model_path: str, threshold: float = 0.70):
        self.model_path = Path(model_path)
        self.threshold = threshold
        self.model = None
        self.feature_names: List[str] = []
        self.raw_feature_count = 42      # base sensor columns
        self.total_feature_count = 168   # including rolling features
        self.rolling_window = 5
        self._load()

    def _load(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.model = joblib.load(self.model_path)
        self.feature_names = list(self.model.feature_names_in_)
        logger.info(f"Model loaded: {type(self.model).__name__}, {len(self.feature_names)} features")

    @property
    def raw_sensor_columns(self) -> List[str]:
        """The 42 original sensor/actuator columns (no rolling suffix)."""
        return [f for f in self.feature_names if "_roll_" not in f and "_diff" not in f]

    def compute_rolling_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Given a DataFrame with the 42 raw columns, compute the 126 rolling features
        (roll_mean5, roll_std5, diff5) for each column and return the full 168-column DF.
        For a single row, rolling features equal the raw value (mean of 1 = itself, std=0, diff=0).
        """
        raw_cols = self.raw_sensor_columns
        # Ensure raw cols present
        missing = [c for c in raw_cols if c not in df.columns]
        if missing:
            raise ValueError(f"Missing raw sensor columns: {missing}")

        result = df[raw_cols].copy()
        w = self.rolling_window

        rolling_features = {}
        for col in raw_cols:
            s = result[col]
            rolling_features[f"{col}_roll_mean5"] = s.rolling(w, min_periods=1).mean()
            rolling_features[f"{col}_roll_std5"] = s.rolling(w, min_periods=1).std().fillna(0)
            rolling_features[f"{col}_diff5"] = s.diff(w).fillna(0)

        result = pd.concat([result, pd.DataFrame(rolling_features, index=result.index)], axis=1)

        # Return in exact model feature order
        return result[self.feature_names]

    def predict_single(self, sensor_row: dict, history: Optional[List[dict]] = None) -> MLResult:
        """Predict one row, optionally using preceding rows for rolling features."""
        prior_rows = (history or [])[-self.rolling_window:]
        df = pd.DataFrame([*prior_rows, sensor_row])
        df_full = self.compute_rolling_features(df)
        return self._run_inference(df_full.iloc[[-1]])

    def predict_batch(self, df_raw: pd.DataFrame) -> List[MLResult]:
        """Predict from a DataFrame of raw sensor rows (rolling computed across rows)."""
        df_full = self.compute_rolling_features(df_raw)
        results = []
        for i in range(len(df_full)):
            results.append(self._run_inference(df_full.iloc[[i]]))
        return results

    def _run_inference(self, df_168: pd.DataFrame) -> MLResult:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            proba = self.model.predict_proba(df_168)[0]
        p_attack = float(proba[1])
        pred = 1 if p_attack >= self.threshold else 0
        return MLResult(
            prediction=pred,
            probability=p_attack,
            label="Attack" if pred == 1 else "Normal",
            threshold_used=self.threshold,
        )

# Singleton
_engine: Optional[ModelEngine] = None

def get_model_engine() -> ModelEngine:
    global _engine
    if _engine is None:
        raise RuntimeError("Model engine not initialized. Call init_model_engine() first.")
    return _engine

def init_model_engine(model_path: str, threshold: float = 0.70):
    global _engine
    _engine = ModelEngine(model_path, threshold)
    return _engine
