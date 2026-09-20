import copy
import unittest
from pathlib import Path
import tempfile

from run_comparison import compare
from replay_comparison import inside


class ComparisonNegativeControls(unittest.TestCase):
    def test_missing_duplicate_mutated_and_reordered_observations(self):
        events = [{"api": "ReadFile", "success": True, "error": 0, "byteCount": 1, "preview": "01"},
                  {"api": "CloseHandle", "success": True, "error": 1105, "byteCount": 0, "preview": ""}]
        self.assertEqual(compare(events, events)["missing"], 0)
        self.assertEqual(compare(events, events[:1])["missing"], 1)
        self.assertEqual(compare(events, events + [events[0]])["unexpected"], 1)
        self.assertEqual(compare(events, list(reversed(events)))["orderMismatches"], 2)
        changed = copy.deepcopy(events)
        changed[0]["preview"] = "ff"
        self.assertEqual(compare(events, changed)["missing"], 1)
        self.assertEqual(compare(events, changed)["unexpected"], 1)
        changed = copy.deepcopy(events)
        changed[0]["error"] = 5
        self.assertEqual(compare(events, changed)["orderMismatches"], 1)

    def test_evidence_paths_cannot_escape_the_import_root(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            file = root / "inside.json"
            file.write_text("{}", encoding="utf-8")
            self.assertEqual(inside(root, "inside.json"), file.resolve())
            for path in ("../outside.json", str(file.resolve())):
                with self.assertRaises(ValueError):
                    inside(root, path)


if __name__ == "__main__":
    unittest.main()
