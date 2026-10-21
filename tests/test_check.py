"""The public Linux check command fails closed on missing inputs."""

from __future__ import annotations

import subprocess
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CheckCliTests(unittest.TestCase):
    def test_missing_lab_is_reported_without_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "check.py"),
                 "--lab", str(Path(tmp) / "absent"),
                 "--telltale", str(Path(tmp) / "absent-binary"),
                 "--out", str(Path(tmp) / "results")],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("lab source directory does not exist", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    @unittest.skipUnless(os.environ.get("TELLTALE_BIN") and os.environ.get("TELLTALE_LAB_ROOT")
                         and os.environ.get("TELLTALE_SOURCE"), "set binary, lab, and source for integration")
    def test_candidate_rule_is_assessed_in_both_formats(self) -> None:
        lab = Path(os.environ["TELLTALE_LAB_ROOT"])
        baseline = json.loads((lab / "scenarios" / "baseline.routine_read_and_install.json").read_text())
        baseline["id"] = "test.marker"
        baseline["title"] = "Synthetic marker observation"
        baseline["description"] = "A synthetic tool request contains a test marker."
        baseline["disposition"] = "unknown"
        baseline["review"] = {"expectation": "hunt", "rationale": "The marker is the independent test fact."}
        baseline["expected_facts"] = ["The tool request contains TELLTALE_TEST_MARKER."]
        baseline["steps"] = [
            {"type": "user", "text": "Record the test marker."},
            {"type": "tool", "tool": "shell", "command": "printf TELLTALE_TEST_MARKER",
             "result": {"status": "ok", "exit_code": 0, "output": "TELLTALE_TEST_MARKER"}},
        ]
        baseline["rule_expectations"] = {"must_match": ["tdx.test.marker"], "must_not_match": []}
        pack = """version: 1
description: Synthetic runner test rule.
defaults:
  case_insensitive: true
  enabled: true
rules:
  - id: tdx.test.marker
    category: execution
    severity: low
    score: 15
    targets: [command, arguments]
    regex: 'TELLTALE_TEST_MARKER'
    tags: [test]
    explanation: Synthetic marker in an agent tool request.
    falsepositives: [Authorized marker tests.]
modifiers: []
"""
        with tempfile.TemporaryDirectory() as tmp:
            content = Path(tmp) / "content"
            (content / "scripts").mkdir(parents=True)
            (content / "scenarios" / "adversarial").mkdir(parents=True)
            (content / "packs" / "experimental").mkdir(parents=True)
            for name in ("scripts/check.py", "scripts/community_package.py",
                         "pins.json", "community-package.json"):
                shutil.copyfile(ROOT / name, content / name)
            (content / "scenarios" / "adversarial" / "test.marker.json").write_text(json.dumps(baseline))
            (content / "packs" / "experimental" / "marker.yaml").write_text(pack)
            out = Path(tmp) / "output"
            result = subprocess.run(
                [sys.executable, str(content / "scripts" / "check.py"),
                 "--lab", str(lab), "--telltale", os.environ["TELLTALE_BIN"],
                 "--telltale-source", os.environ["TELLTALE_SOURCE"], "--out", str(out)],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads((out / "summary.json").read_text())
            self.assertTrue(summary["candidate_content_present"])
            self.assertRegex(summary["candidate_package_sha256"], r"^[0-9a-f]{64}$")
            matches = [row for row in summary["results"] if row["id"] == "test.marker"]
            self.assertEqual({row["source_id"] for row in matches}, {"codex.sessions", "opencode.sqlite"})
            self.assertEqual([row["status"] for row in matches], ["detected", "not_evaluable"])
            opencode_match = next(row for row in matches if row["source_id"] == "opencode.sqlite")
            self.assertEqual(opencode_match["reason"], "acquisition_failed")
            self.assertEqual(opencode_match["generation_profile"], "upstream")
            self.assertEqual(opencode_match["generator"], "opencode-sqlite-v2.0.27/1")
            self.assertTrue(summary["review_required"])

            # A missed expectation remains a finding in the report. It does not
            # cause the runner to relabel the independently authored scenario.
            (content / "packs" / "experimental" / "marker.yaml").write_text(
                pack.replace("regex: 'TELLTALE_TEST_MARKER'", "regex: 'NEVER_MATCH_MARKER'")
            )
            missed_out = Path(tmp) / "missed-output"
            missed = subprocess.run(
                [sys.executable, str(content / "scripts" / "check.py"),
                 "--lab", str(lab), "--telltale", os.environ["TELLTALE_BIN"],
                 "--telltale-source", os.environ["TELLTALE_SOURCE"], "--out", str(missed_out)],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(missed.returncode, 0, missed.stderr)
            missed_summary = json.loads((missed_out / "summary.json").read_text())
            self.assertTrue(missed_summary["review_required"])
            missed_rows = [row for row in missed_summary["results"] if row["id"] == "test.marker"]
            self.assertEqual([row["status"] for row in missed_rows], ["missed", "not_evaluable"])


if __name__ == "__main__":
    unittest.main()
