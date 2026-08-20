#!/usr/bin/env python3
"""Run low-rate, continuous lab HTTP/database-write traffic.

Configuration comes from the project-owned systemd unit. The program keeps
only rolling aggregate counters, drains response bodies for HTTP correctness,
and never retains request bodies, response bodies, SQL text, table data, or
secrets.
"""

from __future__ import annotations

import ctypes
import http.client
import json
import math
import os
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone


PROCESS_NAME = "solis-steady"
PR_SET_NAME = 15


def utc_now() -> str:
    """Return the current UTC timestamp in the stable report format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def set_process_name() -> None:
    """Set a fixed comm name for provider-side metadata without exposing arguments."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(
        PR_SET_NAME,
        ctypes.c_char_p(PROCESS_NAME.encode("ascii")),
        0,
        0,
        0,
    ) != 0:
        raise RuntimeError("could not set the fixed steady-workload process name")


def bounded_float(name: str, value: str, minimum: float, maximum: float) -> float:
    """Build an argument parser that rejects floats outside the configured safe range."""
    try:
        parsed = float(value)
    except ValueError as error:
        raise ValueError(f"{name} must be numeric") from error
    if not math.isfinite(parsed) or not minimum <= parsed <= maximum:
        raise ValueError(f"{name} must be between {minimum:g} and {maximum:g}")
    return parsed


def bounded_int(name: str, value: str, minimum: int, maximum: int) -> int:
    """Build an argument parser that rejects integers outside the configured safe range."""
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return parsed


@dataclass(frozen=True)
class Config:
    tenant: str
    target_host: str
    target_vm: str
    database_vm: str
    rate_rps: float
    concurrency: int
    timeout_seconds: float
    log_interval_seconds: int

    @classmethod
    def from_environment(cls) -> "Config":
        """Load only the fixed, allowlisted workload settings from the service environment."""
        tenant = os.environ.get("SOLIS_TENANT", "").strip()
        target_host = os.environ.get("SOLIS_TARGET_HOST", "").strip()
        target_vm = os.environ.get("SOLIS_TARGET_VM", "").strip()
        database_vm = os.environ.get("SOLIS_DATABASE_VM", "").strip()
        if not all((tenant, target_host, target_vm, database_vm)):
            raise ValueError("tenant and fixed target identity must be configured")
        return cls(
            tenant=tenant,
            target_host=target_host,
            target_vm=target_vm,
            database_vm=database_vm,
            rate_rps=bounded_float(
                "SOLIS_RATE_RPS", os.environ.get("SOLIS_RATE_RPS", "2"), 0.1, 20
            ),
            concurrency=bounded_int(
                "SOLIS_MAX_CONCURRENCY",
                os.environ.get("SOLIS_MAX_CONCURRENCY", "4"),
                1,
                20,
            ),
            timeout_seconds=bounded_float(
                "SOLIS_TIMEOUT_SECONDS",
                os.environ.get("SOLIS_TIMEOUT_SECONDS", "3"),
                0.1,
                30,
            ),
            log_interval_seconds=bounded_int(
                "SOLIS_LOG_INTERVAL_SECONDS",
                os.environ.get("SOLIS_LOG_INTERVAL_SECONDS", "300"),
                60,
                3600,
            ),
        )


class RollingMetrics:
    def __init__(self) -> None:
        """Initialize bounded in-memory workload state without retaining request or response payloads."""
        self._lock = threading.Lock()
        self.started = time.monotonic()
        self.scheduled = 0
        self.completed = 0
        self.successful = 0
        self.failed = 0
        self.saturated = 0
        self.total_latency_ns = 0
        self.max_latency_ns = 0

    def record_scheduled(self) -> None:
        """Count one scheduled request in the current bounded reporting interval."""
        with self._lock:
            self.scheduled += 1

    def record_saturated(self) -> None:
        """Count a request skipped because the configured concurrency ceiling was reached."""
        with self._lock:
            self.saturated += 1

    def record_result(self, latency_ns: int, successful: bool) -> None:
        """Aggregate one request outcome without retaining request or response payloads."""
        with self._lock:
            self.completed += 1
            self.successful += int(successful)
            self.failed += int(not successful)
            self.total_latency_ns += latency_ns
            self.max_latency_ns = max(self.max_latency_ns, latency_ns)

    def snapshot_and_reset(self) -> dict[str, object]:
        """Return the bounded interval aggregate and atomically reset its counters."""
        with self._lock:
            elapsed = max(time.monotonic() - self.started, 0.001)
            completed = self.completed
            result = {
                "elapsed_seconds": elapsed,
                "scheduled_requests": self.scheduled,
                "completed_requests": completed,
                "successful_requests": self.successful,
                "failed_requests": self.failed,
                "client_saturated": self.saturated,
                "achieved_requests_per_second": completed / elapsed,
                "latency_avg_ms": (
                    self.total_latency_ns / completed / 1_000_000
                    if completed
                    else 0.0
                ),
                "latency_max_ms": self.max_latency_ns / 1_000_000,
            }
            self.started = time.monotonic()
            self.scheduled = 0
            self.completed = 0
            self.successful = 0
            self.failed = 0
            self.saturated = 0
            self.total_latency_ns = 0
            self.max_latency_ns = 0
            return result


def request_once(config: Config) -> bool:
    """Send one fixed request and drain the response without retaining its body."""
    connection = http.client.HTTPConnection(
        config.target_host, 80, timeout=config.timeout_seconds
    )
    try:
        connection.request(
            "GET",
            "/write",
            headers={
                "Host": config.target_host,
                "User-Agent": "solis-steady-lab-client/1",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        while response.read(65_536):
            pass
        return 200 <= response.status < 300
    except (TimeoutError, ConnectionError, http.client.HTTPException, OSError):
        return False
    finally:
        connection.close()


def render_summary(config: Config, metrics: RollingMetrics) -> str:
    """Serialize the bounded workload aggregate without payloads, secrets, or SQL text."""
    return json.dumps(
        {
            "schema_version": "1",
            "observed_at_utc": utc_now(),
            "tenant": config.tenant,
            "target": {
                "vm": config.target_vm,
                "database_vm": config.database_vm,
            },
            "requested_rate_per_second": config.rate_rps,
            "summary": metrics.snapshot_and_reset(),
            "privacy": {
                "request_bodies_collected": False,
                "response_bodies_retained": False,
                "sql_text_collected": False,
                "table_data_collected": False,
                "secrets_collected": False,
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def run(config: Config, stop: threading.Event) -> None:
    """Run steady traffic until the stop event is set, emitting only bounded aggregates."""
    metrics = RollingMetrics()
    capacity = threading.BoundedSemaphore(config.concurrency)
    next_request = time.monotonic()
    next_log = next_request + config.log_interval_seconds

    def worker() -> None:
        """Execute one scheduled request and release its concurrency slot on every exit path."""
        started = time.monotonic_ns()
        try:
            successful = request_once(config)
            metrics.record_result(time.monotonic_ns() - started, successful)
        finally:
            capacity.release()

    with ThreadPoolExecutor(
        max_workers=config.concurrency, thread_name_prefix=PROCESS_NAME
    ) as executor:
        while not stop.is_set():
            now = time.monotonic()
            if now >= next_log:
                print(render_summary(config, metrics), flush=True)
                next_log = now + config.log_interval_seconds
            if now < next_request:
                stop.wait(min(next_request - now, 0.25))
                continue
            metrics.record_scheduled()
            if capacity.acquire(blocking=False):
                executor.submit(worker)
            else:
                metrics.record_saturated()
            period = 1.0 / config.rate_rps
            next_request += period
            if next_request < now - period:
                next_request = now + period

    print(render_summary(config, metrics), flush=True)


def main() -> None:
    """Validate configuration and run the workload with cooperative signal handling."""
    config = Config.from_environment()
    set_process_name()
    stop = threading.Event()

    def request_stop(_signal_number, _frame) -> None:
        """Translate a termination signal into the workload's cooperative stop event."""
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    run(config, stop)


if __name__ == "__main__":
    main()
