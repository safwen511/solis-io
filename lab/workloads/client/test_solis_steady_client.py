#!/usr/bin/env python3

import importlib.util
import json
import os
import pathlib
import sys
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("solis_steady_client.py")
SPEC = importlib.util.spec_from_file_location("solis_steady_client", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CLIENT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CLIENT
SPEC.loader.exec_module(CLIENT)


class SteadyClientTests(unittest.TestCase):
    def config(self):
        return CLIENT.Config(
            tenant="tenant-a",
            target_host="192.168.130.20",
            target_vm="a-web",
            database_vm="a-db",
            rate_rps=2,
            concurrency=4,
            timeout_seconds=3,
            log_interval_seconds=300,
        )

    def test_environment_is_bounded_and_requires_fixed_targets(self):
        values = {
            "SOLIS_TENANT": "tenant-a",
            "SOLIS_TARGET_HOST": "192.168.130.20",
            "SOLIS_TARGET_VM": "a-web",
            "SOLIS_DATABASE_VM": "a-db",
            "SOLIS_RATE_RPS": "2",
        }
        with mock.patch.dict(os.environ, values, clear=True):
            config = CLIENT.Config.from_environment()
        self.assertEqual(config.target_vm, "a-web")
        self.assertEqual(config.rate_rps, 2)

        values["SOLIS_RATE_RPS"] = "200"
        with mock.patch.dict(os.environ, values, clear=True):
            with self.assertRaisesRegex(ValueError, "between 0.1 and 20"):
                CLIENT.Config.from_environment()

    def test_summary_is_bounded_and_privacy_safe(self):
        metrics = CLIENT.RollingMetrics()
        metrics.record_scheduled()
        metrics.record_result(10_000_000, True)
        rendered = CLIENT.render_summary(self.config(), metrics)
        report = json.loads(rendered)
        self.assertEqual(report["summary"]["completed_requests"], 1)
        self.assertFalse(any(report["privacy"].values()))
        for forbidden in ("request_pointer", "0xffff", "/proc/", "inserted_id"):
            self.assertNotIn(forbidden, rendered.lower())

    def test_request_drains_but_does_not_return_response_payload(self):
        response = mock.Mock(status=200)
        response.read.side_effect = [b"discarded", b""]
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch.object(
            CLIENT.http.client, "HTTPConnection", return_value=connection
        ):
            self.assertTrue(CLIENT.request_once(self.config()))
        self.assertEqual(response.read.call_count, 2)
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
