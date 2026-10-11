import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.routes.chat import _build_context, _build_event_context, _fallback_reply
from app.api.routes.inference import _persist_result
from app.db.models import Base, Prediction, SensorReading, User


class ChatContextTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.session = sessionmaker(bind=self.engine)()
        self.user = User(
            id="analyst-1",
            username="analyst",
            email="analyst@example.invalid",
            password_hash="unused",
            role="SECURITY_ANALYST",
        )
        self.session.add(self.user)
        self.session.flush()

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    def make_prediction(self, **overrides):
        values = {
            "id": "prediction-1",
            "reading_id": "reading-1",
            "user_id": self.user.id,
            "timestamp": datetime(2026, 10, 11, tzinfo=timezone.utc),
            "ml_prediction": 1,
            "ml_probability": 0.82,
            "ml_label": "Attack",
            "rule_violation_count": 0,
            "final_label": "Suspicious",
            "severity": "MEDIUM",
            "rule_violations": [],
            "affected_sensors": [],
            "recommendations": [],
            "explanation": "ML detector flagged unusual input.",
            "detection_context": {},
        }
        values.update(overrides)
        return Prediction(**values)

    def test_missing_telemetry_is_explicitly_unavailable(self):
        event = _build_event_context(self.make_prediction(), "reading-1")
        self.assertEqual(event["sensor_values"], "Unavailable")
        self.assertEqual(event["configured_threshold"], "Unavailable")
        self.assertIn("Unavailable", _fallback_reply(event, "provider unavailable"))

    def test_zero_rule_violations_are_not_invented(self):
        event = _build_event_context(self.make_prediction(), "reading-1")
        self.assertEqual(event["rule_violation_count"], 0)
        self.assertEqual(event["rule_violations"], [])
        reply = _fallback_reply(event, "provider unavailable")
        self.assertNotIn("Rule evidence:", reply)
        self.assertIn("unavailable", reply.lower())

    def test_high_ml_score_is_not_claimed_as_confirmed_attack(self):
        event = _build_event_context(
            self.make_prediction(ml_probability=0.99, final_label="Attack"),
            "reading-1",
        )
        reply = _fallback_reply(event, "provider unavailable")
        self.assertIn("0.99", reply)
        self.assertIn("not a calibrated attack probability", reply)
        self.assertNotIn("attack confirmed", reply.lower())
        self.assertIn("Attack type undetermined.", reply)

    def test_unknown_attack_type_is_explicit(self):
        event = _build_event_context(self.make_prediction(), "reading-1")
        self.assertIn("Attack type undetermined.", _fallback_reply(event, "provider unavailable"))

    def test_concrete_sensor_and_deviation_evidence_are_preserved(self):
        reading = SensorReading(
            id="reading-1",
            timestamp=datetime(2026, 10, 11, tzinfo=timezone.utc),
            source="test",
            sensor_data={"LIT101": 987.5},
        )
        prediction = self.make_prediction(
            reading=reading,
            affected_sensors=["LIT101"],
            rule_violation_count=1,
            rule_violations=[{
                "rule_id": "R-TEST",
                "message": "LIT101 exceeds the recorded operating limit",
                "evidence": {"value": 987.5},
            }],
            detection_context={
                "threshold_used": 0.7,
                "localization": {
                    "localization_status": "Suspected",
                    "summary": "LIT101 is implicated in P1.",
                    "implicated_components": [{
                        "tag": "LIT101",
                        "measured_value": 987.5,
                        "deviation_note": "Recorded level is above the rule limit.",
                        "evidence_sources": ["R-TEST"],
                    }],
                },
            },
        )
        event = _build_event_context(prediction, "reading-1")
        reply = _fallback_reply(event, "provider unavailable")
        self.assertEqual(event["sensor_values"]["LIT101"], 987.5)
        self.assertEqual(event["sensor_deviations"][0]["deviation_note"], "Recorded level is above the rule limit.")
        self.assertIn("LIT101", reply)
        self.assertIn("R-TEST", reply)

    def test_selected_event_context_is_resolved_from_current_users_record(self):
        reading = SensorReading(
            id="reading-1",
            timestamp=datetime(2026, 10, 11, tzinfo=timezone.utc),
            source="test",
            sensor_data={"FIT101": 12.5},
        )
        self.session.add(self.make_prediction(reading=reading, affected_sensors=["FIT101"]))
        self.session.commit()

        context = _build_context({"event_id": "reading-1", "final_label": "fabricated"}, self.session, self.user)
        self.assertEqual(context["detection_status"], "Suspicious")
        self.assertEqual(context["sensor_values"]["FIT101"], 12.5)
        self.assertEqual(context["context_source"], "authenticated event record")

    def test_inference_persists_model_and_risk_context_with_event(self):
        result = SimpleNamespace(
            event_id="reading-1",
            timestamp=datetime(2026, 10, 11, tzinfo=timezone.utc),
            validation_warnings=[],
            ml_prediction=1,
            ml_probability=0.91,
            ml_label="Attack",
            threshold_used=0.7,
            rule_violation_count=0,
            final_label="Suspicious",
            severity="MEDIUM",
            rule_violations=[],
            affected_sensors=["LIT101"],
            recommendations=["Compare LIT101 with adjacent process readings."],
            explanation="Unusual model score.",
            risk_score=46.25,
            risk_severity="MEDIUM",
            localization={"localization_status": "Unknown"},
            attack_type_assessment={"attack_type": "Unknown"},
            active_config_id="config-1",
            active_config_version="v2",
            asset_criticalities={"LIT101": "HIGH"},
            processing_ms=3.5,
        )
        _persist_result(result, {"LIT101": 987.5}, "test", self.session, self.user.id)

        prediction = self.session.query(Prediction).filter_by(reading_id="reading-1").one()
        context = _build_event_context(prediction, "reading-1")
        self.assertEqual(context["configured_threshold"], 0.7)
        self.assertEqual(context["risk_score"], 46.25)
        self.assertEqual(context["asset_criticalities"], {"LIT101": "HIGH"})
        self.assertEqual(context["sensor_values"]["LIT101"], 987.5)

    def test_event_owned_by_another_user_is_not_returned(self):
        context = _build_context({"event_id": "not-owned"}, self.session, self.user)
        self.assertEqual(context["context_source"], "event record unavailable to this authenticated user")
        self.assertEqual(context["sensor_values"], "Unavailable")


if __name__ == "__main__":
    unittest.main()
