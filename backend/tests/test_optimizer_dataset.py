import unittest
from pathlib import Path

from app.api.routes.optimizer import _find_dataset


class OptimizerDatasetTests(unittest.TestCase):
    def test_default_dataset_is_resolved_from_project_root(self):
        project_root = Path(__file__).resolve().parents[2]
        expected = project_root / "data" / "ne_data.csv"

        self.assertTrue(expected.is_file())
        self.assertEqual(Path(_find_dataset()), expected)

    def test_unlabeled_override_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Normal/Attack"):
            _find_dataset("data/NewTestData.csv")


if __name__ == "__main__":
    unittest.main()
