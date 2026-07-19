#!/usr/bin/env python3
"""Tests for throttle-as-empty detection and UNKNOWN-finding emission.

Run from the repo root:
    python3 -m unittest scripts.test_throttle
or directly:
    python3 scripts/test_throttle.py

Stdlib only (unittest + mock). No live stackql / cloud calls — subprocess.run is
mocked to emulate stackql returning exit 0 with throttle stderr and no rows.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
REPO_ROOT = SCRIPTS.parent

import audit  # noqa: E402
import discover  # noqa: E402
from budget import Budget  # noqa: E402


def _proc(rc: int, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    """Stand-in for subprocess.CompletedProcess."""
    return SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)


THROTTLE_STDERR = (
    'http response status code: 400, response body: '
    '{"__type":"com.amazon.coral.availability#ThrottlingException","message":"Rate exceeded"}'
)


class RunStackqlThrottle(unittest.TestCase):
    def _run(self, proc):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch("audit.subprocess.run", return_value=proc):
                return audit.run_stackql("SELECT 1;", "", Path(d) / "q.log")

    def test_throttle_empty_becomes_error(self):
        rows, err, rc = self._run(_proc(0, stdout="", stderr=THROTTLE_STDERR))
        self.assertIsNone(rows)
        self.assertIsNotNone(err)
        self.assertIn("ThrottlingException", err)
        self.assertEqual(rc, 0)

    def test_throttle_with_nonempty_stdout_becomes_error(self):
        # The v0.7.1 miss: stackql exits 0 with throttle on stderr AND non-empty
        # stdout (e.g. null / a sparse row). Must still be reported as an error.
        rows, err, rc = self._run(_proc(0, stdout="null", stderr=THROTTLE_STDERR))
        self.assertIsNone(rows)
        self.assertIn("ThrottlingException", err)
        self.assertEqual(rc, 0)

    def test_clean_empty_is_not_an_error(self):
        rows, err, rc = self._run(_proc(0, stdout="[]", stderr=""))
        self.assertEqual(rows, [])
        self.assertIsNone(err)

    def test_log_retains_stdout_and_stderr(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "q.log"
            with mock.patch("audit.subprocess.run",
                            return_value=_proc(0, '{"x":1}', THROTTLE_STDERR)):
                audit.run_stackql("SELECT 1;", "", log)
            text = log.read_text()
            self.assertIn("ThrottlingException", text)
            self.assertIn("exit: 0", text)
            self.assertIn("--- stdout ---", text)
            self.assertIn('{"x":1}', text)


class FetchBucketDetailRetry(unittest.TestCase):
    def setUp(self):
        self.budget = Budget.from_env({})  # all limits -1 (unlimited)
        self.tmp = tempfile.TemporaryDirectory()
        self.log_dir = Path(self.tmp.name)
        self.sleeps: list[float] = []

    def tearDown(self):
        self.tmp.cleanup()

    def test_retries_then_exhausts(self):
        # Every attempt returns a throttle-empty response (real run_stackql turns
        # it into an error); fetch should retry RETRY_DELAYS times then give up.
        proc = _proc(0, stdout="", stderr=THROTTLE_STDERR)
        with mock.patch("audit.subprocess.run", return_value=proc) as run, \
                mock.patch("discover.time.sleep", side_effect=self.sleeps.append):
            detail, err, stop = discover.fetch_bucket_detail("b1", "us-east-1", "", self.log_dir, self.budget)
        self.assertIsNone(detail)
        # After the retry budget is spent the final attempt's throttle error is
        # returned (run_s3 turns it into an UNKNOWN finding); detail is dropped.
        self.assertIsNotNone(err)
        self.assertIn("ThrottlingException", err)
        self.assertEqual(run.call_count, 4)          # initial + 3 retries
        self.assertEqual(len(self.sleeps), 3)        # one sleep per retry
        # schedule is 2,5,12 with ±25% jitter
        for base, slept in zip(discover.RETRY_DELAYS, self.sleeps):
            self.assertGreaterEqual(slept, base * 0.75)
            self.assertLessEqual(slept, base * 1.25)

    def test_succeeds_after_throttle(self):
        seq = [
            _proc(0, stdout="", stderr=THROTTLE_STDERR),
            _proc(0, stdout='[{"bucket_name":"b1","region":"us-east-1"}]', stderr=""),
        ]
        with mock.patch("audit.subprocess.run", side_effect=seq), \
                mock.patch("discover.time.sleep", side_effect=self.sleeps.append):
            detail, err, stop = discover.fetch_bucket_detail("b1", "us-east-1", "", self.log_dir, self.budget)
        self.assertIsNone(err)
        self.assertEqual(detail["bucket_name"], "b1")
        self.assertEqual(len(self.sleeps), 1)


class AuditScopeSurfacesErrors(unittest.TestCase):
    def test_throttled_check_becomes_error_record(self):
        check = {"_file": "aws/x.yaml", "name": "X", "query": "SELECT 1 WHERE region='${AWS_REGION}';"}
        budget = Budget.from_env({})
        with tempfile.TemporaryDirectory() as d:
            with mock.patch("audit.run_stackql", return_value=(None, THROTTLE_STDERR, 0)):
                out, errors = discover.audit_scope(
                    "region", "AWS_REGION", "us-east-1", [check], "", None, Path(d), budget)
        self.assertEqual(out, {})
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["failed_check"], "aws/x.yaml")


class RunS3EmitsUnknown(unittest.TestCase):
    def test_terminal_failure_emits_unknown_per_bucket(self):
        with tempfile.TemporaryDirectory() as d:
            stream = Path(d) / "s3-findings.jsonl"
            env = {
                "AWS_REGION": "us-east-1",
                "STACKQL_AUDIT_PROVIDERS": "aws",
                "FAIL_ON_SEVERITY": "NONE",
                "ACTION_PATH": str(REPO_ROOT),
                "STACKQL_AUDIT_STREAM": str(stream),
                "STACKQL_AUDIT_LOG_DIR": str(Path(d) / "log"),
                "STACKQL_AUDIT_STREAM_DIR": str(Path(d) / "streams"),
                "RUN_STAMP": "test",
            }
            with mock.patch.dict(os.environ, env, clear=False), \
                    mock.patch("discover.list_bucket_names", return_value=["b1", "b2"]), \
                    mock.patch("discover.fetch_bucket_detail",
                               return_value=(None, "Rate exceeded", None)):
                rc = discover.run_s3()
            self.assertEqual(rc, 0)  # UNKNOWN never trips FAIL_ON_SEVERITY
            lines = [json.loads(x) for x in stream.read_text().splitlines() if x.strip()]
            unknown = [l for l in lines if l.get("check") == "_meta/enum-error"]
            self.assertEqual(len(unknown), 2)
            self.assertEqual({u["bucket"] for u in unknown}, {"b1", "b2"})
            self.assertTrue(all(u["severity"] == "UNKNOWN" for u in unknown))


class SeverityOrder(unittest.TestCase):
    def test_unknown_sorts_below_none_and_never_fails(self):
        self.assertEqual(audit.SEVERITY_ORDER["UNKNOWN"], -1)
        self.assertLess(audit.SEVERITY_ORDER["UNKNOWN"], audit.SEVERITY_ORDER["NONE"])
        # gate is `>= fail_threshold`; lowest real threshold is LOW (1)
        self.assertFalse(audit.SEVERITY_ORDER["UNKNOWN"] >= audit.SEVERITY_ORDER["LOW"])


if __name__ == "__main__":
    unittest.main()
