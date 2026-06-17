#!/usr/bin/env python3
"""Tests for run_sql_files.py — preflight read-only guard, apply dry-run /
fail-closed, throttle retry, results-json schema. Run:
    python3 -m unittest scripts.test_run_sql_files
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import run_sql_files as R  # noqa: E402


def _sql(d: Path, rel: str, body: str) -> Path:
    p = d / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


class Preflight(unittest.TestCase):
    def test_rejects_destructive_without_executing(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            f = _sql(d, "x/preflight.sql", "DELETE FROM aws.ec2_native.volumes WHERE volumeId='v';")
            with mock.patch("audit.run_stackql") as rs:
                results, passed = R.run_preflight([f], "", 3, 60, False, d)
            self.assertFalse(passed)
            self.assertEqual(results[0]["exit_code"], 2)
            self.assertIn("destructive", results[0]["errors"])
            rs.assert_not_called()  # never executed

    def test_pass_when_rows_returned(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            f = _sql(d, "x/preflight.sql", "SELECT volumeId FROM aws.ec2_native.volumes;")
            with mock.patch("audit.run_stackql", return_value=([{"volumeId": "v1"}], None, 0)):
                results, passed = R.run_preflight([f], "", 3, 60, False, d)
            self.assertTrue(passed)
            self.assertEqual(results[0]["statements"][0]["rows"], [{"volumeId": "v1"}])

    def test_expect_empty_pass_on_zero_rows(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            f = _sql(d, "x/preflight.sql", "SELECT volumeId FROM aws.ec2_native.volumes;")
            with mock.patch("audit.run_stackql", return_value=([], None, 0)):
                _, passed = R.run_preflight([f], "", 3, 60, True, d)
            self.assertTrue(passed)


class Apply(unittest.TestCase):
    def test_dry_run_never_executes(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            f = _sql(d, "x/apply.sql", "DELETE FROM aws.ec2_native.volumes WHERE volumeId='v';")
            with mock.patch("audit.run_stackql") as rs:
                results, passed, mutations = R.run_apply([f], "", 3, 60, True, True, [], d)
            self.assertTrue(passed)
            self.assertEqual(mutations, 0)
            self.assertFalse(results[0]["statements"][0]["executed"])
            rs.assert_not_called()

    def test_fail_closed_without_preflight(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            f = _sql(d, "x/apply.sql", "DELETE FROM aws.ec2_native.volumes WHERE volumeId='v';")
            with mock.patch("audit.run_stackql") as rs:
                results, passed, mutations = R.run_apply([f], "", 3, 60, False, True, [], d)
            self.assertFalse(passed)
            self.assertEqual(mutations, 0)
            self.assertEqual(results[0]["exit_code"], 3)
            self.assertIn("fail-closed", results[0]["errors"])
            rs.assert_not_called()

    def test_executes_with_passing_preflight(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            _sql(d, "x/preflight.sql", "SELECT 1;")
            f = _sql(d, "x/apply.sql", "DELETE FROM aws.ec2_native.volumes WHERE volumeId='v';")
            pf = [{"file": str(d / "x/preflight.sql"), "exit_code": 0,
                   "statements": [{"rows": [{"volumeId": "v"}]}]}]
            with mock.patch("audit.run_stackql", return_value=([], None, 0)):
                results, passed, mutations = R.run_apply([f], "", 3, 60, False, True, pf, d)
            self.assertTrue(passed)
            self.assertEqual(mutations, 1)
            self.assertTrue(results[0]["statements"][0]["executed"])


class Throttle(unittest.TestCase):
    def test_retries_then_exhausts(self):
        throttle = (None, "HTTP 400 ThrottlingException: Rate exceeded", 0)
        with mock.patch("audit.run_stackql", return_value=throttle) as rs, \
                mock.patch("run_sql_files.time.sleep") as slp:
            rows, err, rc = R._run_statement("SELECT 1;", "", Path("/tmp/x.log"), retries=3)
        self.assertIsNotNone(err)
        self.assertEqual(rs.call_count, 4)        # initial + 3 retries
        self.assertEqual(slp.call_count, 3)


class Schema(unittest.TestCase):
    def test_results_json_round_trips(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            f = _sql(d, "x/preflight.sql", "SELECT volumeId FROM aws.ec2_native.volumes;")
            with mock.patch("audit.run_stackql", return_value=([{"volumeId": "v1"}], None, 0)):
                results, _ = R.run_preflight([f], "", 3, 60, False, d)
            doc = json.loads(json.dumps(results))   # round-trip
            e = doc[0]
            self.assertEqual({"file", "mode", "exit_code", "duration_ms", "statements", "errors"} & set(e),
                             {"file", "mode", "exit_code", "duration_ms", "statements", "errors"})
            self.assertEqual(e["mode"], "preflight")
            self.assertIn("statement", e["statements"][0])


class MainIntegration(unittest.TestCase):
    # one read fixture (preflight) + one dry-run write fixture (apply) per cloud
    READ = {
        "aws": "SELECT volumeId FROM aws.ec2_native.volumes WHERE status='available';",
        "gcp": "SELECT name FROM google.compute.disks WHERE project='p';",
        "azure": "SELECT id FROM azure.compute.disks WHERE subscriptionId='s';",
    }
    WRITE = {
        "aws": "DELETE FROM aws.ec2_native.volumes WHERE data__Identifier='vol-1';",
        "gcp": "DELETE FROM google.compute.disks WHERE project='p' AND disk='d';",
        "azure": "DELETE FROM azure.compute.disks WHERE subscriptionId='s' AND resourceGroupName='rg' AND diskName='d';",
    }

    def _run_main(self, env, workdir):
        full = {**env, "RUN_SQL_WORKDIR": str(workdir),
                "RUNNER_TEMP": str(workdir), "GITHUB_OUTPUT": str(workdir / "out.txt")}
        (workdir / "out.txt").write_text("")
        with mock.patch.dict("os.environ", full, clear=False):
            return R.main()

    def test_preflight_read_fixture_per_cloud(self):
        for cloud, sql in self.READ.items():
            with tempfile.TemporaryDirectory() as d:
                d = Path(d)
                _sql(d, "rem/preflight.sql", sql)
                with mock.patch("audit.run_stackql", return_value=([{"x": 1}], None, 0)):
                    rc = self._run_main({"RUN_SQL_MODE": "preflight",
                                         "RUN_SQL_GLOB": "rem/preflight.sql"}, d)
                self.assertEqual(rc, 0, cloud)
                doc = json.loads((d / "preflight-results.json").read_text())
                self.assertEqual(doc[0]["mode"], "preflight")
                self.assertIn("pass=true", (d / "out.txt").read_text())

    def test_apply_dryrun_write_fixture_per_cloud(self):
        for cloud, sql in self.WRITE.items():
            with tempfile.TemporaryDirectory() as d:
                d = Path(d)
                _sql(d, "rem/apply.sql", sql)
                with mock.patch("audit.run_stackql") as rs:
                    rc = self._run_main({"RUN_SQL_MODE": "apply",
                                         "RUN_SQL_GLOB": "rem/apply.sql",
                                         "RUN_SQL_DRY_RUN": "true"}, d)
                self.assertEqual(rc, 0, cloud)
                rs.assert_not_called()           # dry-run never executes
                out = (d / "out.txt").read_text()
                self.assertIn("mutations-applied=0", out)
                self.assertIn("pass=true", out)


if __name__ == "__main__":
    unittest.main()
