import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pandas as pd

from app.detection import detection_service
from app.detection.detection_service import get_active_config_info, set_active_config
from app.detection.fusion_engine import FusionEngine
from app.detection.model_engine import ModelEngine


class FusionRuntimeConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = Path(self.temp_dir.name) / "fusion.json"
        self.config_path.write_text(json.dumps({
            "model_name": "test-model",
            "decision_threshold": 0.70,
            "fusion_logic": "OR",
        }))
        self.engine = FusionEngine(str(self.config_path))

    def tearDown(self):
        set_active_config(
            "baseline-test",
            1,
            {},
            threshold=0.70,
            fusion_strategy="OR",
            is_baseline=True,
        )
        self.temp_dir.cleanup()

    def test_rf_only_uses_optimized_threshold_without_rule_trigger(self):
        result = self.engine.fuse(
            ml_probability=0.65,
            ml_label="Normal",
            rule_violated=True,
            violation_count=1,
            violations=[{"rule_id": "R-1", "message": "Rule evidence", "evidence": {}}],
            threshold=0.60,
            fusion_strategy="RF_ONLY",
        )

        self.assertEqual(result.final_label, "Attack")
        self.assertEqual(result.severity, "MEDIUM")
        self.assertIn("threshold: 60.0%", result.explanation)
        self.assertIn("not used by the RF_ONLY", result.explanation)

    def test_rf_only_does_not_promote_a_rule_only_event(self):
        result = self.engine.fuse(
            ml_probability=0.30,
            ml_label="Normal",
            rule_violated=True,
            violation_count=1,
            violations=[{"rule_id": "R-1", "message": "Rule evidence", "evidence": {}}],
            threshold=0.40,
            fusion_strategy="RF_ONLY",
        )

        self.assertEqual(result.final_label, "Normal")
        self.assertEqual(result.severity, None)
        self.assertTrue(result.rule_triggered)

    def test_model_reports_the_threshold_used_for_each_prediction(self):
        class FixedModel:
            def predict_proba(self, _frame):
                return [[0.45, 0.55]]

        model = ModelEngine.__new__(ModelEngine)
        model.model = FixedModel()
        model.threshold = 0.70

        optimized = model._run_inference(pd.DataFrame([[1]]), threshold=0.40)
        baseline = model._run_inference(pd.DataFrame([[1]]))

        self.assertEqual(optimized.threshold_used, 0.40)
        self.assertEqual(optimized.label, "Attack")
        self.assertEqual(baseline.threshold_used, 0.70)
        self.assertEqual(baseline.label, "Normal")

    def test_active_config_exposes_applied_threshold_and_fusion(self):
        set_active_config(
            "optimized-config",
            3,
            {"LIT101": "HIGH"},
            threshold=0.42,
            fusion_strategy="RF_ONLY",
        )

        active = get_active_config_info()
        self.assertEqual(active["threshold"], 0.42)
        self.assertEqual(active["fusion_strategy"], "RF_ONLY")
        self.assertFalse(active["is_baseline"])

    def test_detection_passes_the_active_config_to_model_and_fusion(self):
        set_active_config(
            "optimized-config",
            3,
            {},
            threshold=0.42,
            fusion_strategy="RF_ONLY",
        )
        model = SimpleNamespace(predict_single=unittest.mock.Mock(return_value=SimpleNamespace(
            threshold_used=0.42,
            probability=0.50,
            prediction=1,
            label="Attack",
        )))
        fusion_result = SimpleNamespace(
            final_label="Attack",
            severity="MEDIUM",
            affected_sensors=[],
            explanation="Anomaly detected.",
            recommendations=[],
            ml_triggered=True,
        )
        fusion = SimpleNamespace(fuse=unittest.mock.Mock(return_value=fusion_result))
        localization = SimpleNamespace(
            implicated_components=[],
            implicated_areas=[],
            localization_status="Unknown",
            summary="No localization evidence.",
            methodology_note="",
            limitations=[],
        )
        attack_type = SimpleNamespace(
            attack_type="Unknown",
            classification_status="Unknown",
            confidence_level="Unknown",
            supporting_indicators=[],
            contradicting_indicators=[],
            affected_components=[],
            evidence_sources=[],
            limitations=[],
            methodology_note="",
        )
        with (
            patch.object(detection_service, "get_model_engine", return_value=model),
            patch.object(detection_service, "get_fusion_engine", return_value=fusion),
            patch.object(detection_service, "run_rules", return_value=SimpleNamespace(
                violated=False, violation_count=0, violations=[],
            )),
            patch.object(detection_service, "compute_risk_score", return_value=SimpleNamespace(
                score=20.0, severity="LOW",
            )),
            patch.object(detection_service, "localize_event", return_value=localization),
            patch.object(detection_service, "assess_attack_type", return_value=attack_type),
        ):
            result = detection_service.detect({"LIT101": 10.0})

        model.predict_single.assert_called_once_with(
            {"LIT101": 10.0},
            history=None,
            threshold=0.42,
        )
        self.assertEqual(fusion.fuse.call_args.kwargs["threshold"], 0.42)
        self.assertEqual(fusion.fuse.call_args.kwargs["fusion_strategy"], "RF_ONLY")
        self.assertEqual(result.threshold_used, 0.42)


if __name__ == "__main__":
    unittest.main()
