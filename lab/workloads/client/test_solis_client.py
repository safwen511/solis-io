#!/usr/bin/env python3

import importlib.util
import json
import pathlib
import sys
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("solis_client.py")
SPEC = importlib.util.spec_from_file_location("solis_client", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CLIENT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CLIENT
SPEC.loader.exec_module(CLIENT)


class AggregateTests(unittest.TestCase):
    def test_fixed_process_name_uses_comm_metadata_only(self):
        fake_libc = mock.Mock()
        fake_libc.prctl.return_value = 0
        with mock.patch.object(CLIENT.ctypes, "CDLL", return_value=fake_libc):
            CLIENT.set_process_name()

        fake_libc.prctl.assert_called_once()
        self.assertEqual(fake_libc.prctl.call_args.args[0], CLIENT.PR_SET_NAME)

    def test_aggregate_is_deterministic_and_bucketed(self):
        aggregate = CLIENT.Aggregate(scheduled=3)
        aggregate.record_result(4_000_000, 200, None)
        aggregate.record_result(15_000_000, 503, None)
        aggregate.record_result(700_000_000, None, "timeout")

        report = aggregate.as_dict(1.0)
        self.assertEqual(report["completed_requests"], 3)
        self.assertEqual(report["successful_requests"], 1)
        self.assertEqual(report["failed_requests"], 2)
        self.assertEqual(report["latency_min_ms"], 4)
        self.assertEqual(report["latency_max_ms"], 700)
        self.assertEqual(
            report["status_codes"],
            [{"status": 200, "count": 1}, {"status": 503, "count": 1}],
        )
        self.assertEqual(
            report["error_categories"],
            [{"category": "timeout", "count": 1}],
        )
        self.assertEqual(sum(row["count"] for row in report["histogram"]), 3)

    def test_workload_retains_no_response_payload(self):
        with mock.patch.object(CLIENT, "request_once", return_value=(200, None)):
            report = CLIENT.run_workload(1, 2.0, 1, 1.0)

        self.assertEqual(report["summary"]["scheduled_requests"], 2)
        self.assertEqual(report["summary"]["successful_requests"], 2)
        self.assertFalse(report["privacy"]["request_bodies_collected"])
        self.assertFalse(report["privacy"]["response_bodies_retained"])
        rendered = json.dumps(report, sort_keys=True)
        self.assertNotIn("inserted_id", rendered)
        self.assertNotIn("db_write_ms", rendered)


if __name__ == "__main__":
    unittest.main()
