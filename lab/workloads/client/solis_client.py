#!/usr/bin/env python3
"""Generate bounded, fixed-rate tenant-A HTTP/database-write traffic.

The client records only aggregate timing, status, and error counters. Response
bodies are drained for correct HTTP connection handling and immediately
discarded; they are never retained or included in output.
"""

from __future__ import annotations

import argparse
import ctypes
import http.client
import json
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone


TARGET_HOST = "192.168.130.20"
TARGET_PORT = 80
TARGET_PATH = "/write"
SCHEMA_VERSION = "1"
PROCESS_NAME = "solis-client"
PR_SET_NAME = 15

BUCKETS_NS = (
    5_000_000,
    10_000_000,
    20_000_000,
    50_000_000,
    100_000_000,
    250_000_000,
    500_000_000,
    1_000_000_000,
    2_000_000_000,
    5_000_000_000,
)
BUCKET_LABELS = (
    "<5 ms",
    "<10 ms",
    "<20 ms",
    "<50 ms",
    "<100 ms",
    "<250 ms",
    "<500 ms",
    "<1 s",
    "<2 s",
    "<5 s",
    "5 s+",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def set_process_name() -> None:
    """Give the fixed lab workload an exact, non-payload process identity."""
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.prctl(
        PR_SET_NAME,
        ctypes.c_char_p(PROCESS_NAME.encode("ascii")),
        0,
        0,
        0,
    )
    if result != 0:
        errno_value = ctypes.get_errno()
        raise RuntimeError(
            f"could not set the fixed workload process name (errno {errno_value})"
        )


@dataclass
class Aggregate:
    scheduled: int = 0
    completed: int = 0
    successful: int = 0
    failed: int = 0
    client_saturated: int = 0
    total_latency_ns: int = 0
    min_latency_ns: int | None = None
    max_latency_ns: int = 0
    buckets: list[int] = field(
        default_factory=lambda: [0] * (len(BUCKETS_NS) + 1)
    )
    status_codes: dict[int, int] = field(default_factory=dict)
    error_categories: dict[str, int] = field(default_factory=dict)

    def record_result(
        self, latency_ns: int, status_code: int | None, error_category: str | None
    ) -> None:
        self.completed += 1
        self.total_latency_ns += latency_ns
        if self.min_latency_ns is None or latency_ns < self.min_latency_ns:
            self.min_latency_ns = latency_ns
        if latency_ns > self.max_latency_ns:
            self.max_latency_ns = latency_ns

        bucket_index = len(BUCKETS_NS)
        for index, upper_bound in enumerate(BUCKETS_NS):
            if latency_ns < upper_bound:
                bucket_index = index
                break
        self.buckets[bucket_index] += 1

        if status_code is not None:
            self.status_codes[status_code] = self.status_codes.get(status_code, 0) + 1
        if error_category is not None:
            self.error_categories[error_category] = (
                self.error_categories.get(error_category, 0) + 1
            )

        if status_code is not None and 200 <= status_code < 300 and error_category is None:
            self.successful += 1
        else:
            self.failed += 1

    def percentile_ms(self, percentile: float) -> float:
        if self.completed == 0:
            return 0.0
        wanted = max(1, math.ceil(self.completed * percentile))
        seen = 0
        for index, count in enumerate(self.buckets):
            seen += count
            if seen < wanted:
                continue
            if index < len(BUCKETS_NS):
                estimate = BUCKETS_NS[index]
            else:
                estimate = self.max_latency_ns
            return min(estimate, self.max_latency_ns) / 1_000_000
        return self.max_latency_ns / 1_000_000

    def as_dict(self, elapsed_seconds: float) -> dict[str, object]:
        completed = self.completed
        histogram = []
        for label, count in zip(BUCKET_LABELS, self.buckets, strict=True):
            histogram.append(
                {
                    "range": label,
                    "count": count,
                    "percent": (count / completed * 100) if completed else 0.0,
                }
            )
        return {
            "scheduled_requests": self.scheduled,
            "completed_requests": completed,
            "successful_requests": self.successful,
            "failed_requests": self.failed,
            "client_saturated": self.client_saturated,
            "achieved_requests_per_second": (
                completed / elapsed_seconds if elapsed_seconds > 0 else 0.0
            ),
            "latency_min_ms": (
                (self.min_latency_ns or 0) / 1_000_000
            ),
            "latency_avg_ms": (
                self.total_latency_ns / completed / 1_000_000 if completed else 0.0
            ),
            "latency_p50_ms": self.percentile_ms(0.50),
            "latency_p95_ms": self.percentile_ms(0.95),
            "latency_p99_ms": self.percentile_ms(0.99),
            "latency_max_ms": self.max_latency_ns / 1_000_000,
            "percentiles_approximate": True,
            "histogram": histogram,
            "status_codes": [
                {"status": status, "count": self.status_codes[status]}
                for status in sorted(self.status_codes)
            ],
            "error_categories": [
                {"category": category, "count": self.error_categories[category]}
                for category in sorted(self.error_categories)
            ],
        }


class Metrics:
    def __init__(self, duration_seconds: int) -> None:
        self._lock = threading.Lock()
        self.total = Aggregate()
        self.windows = [Aggregate() for _ in range(duration_seconds)]

    def scheduled(self, window: int) -> None:
        with self._lock:
            self.total.scheduled += 1
            self.windows[window].scheduled += 1

    def saturated(self, window: int) -> None:
        with self._lock:
            self.total.client_saturated += 1
            self.windows[window].client_saturated += 1

    def result(
        self,
        window: int,
        latency_ns: int,
        status_code: int | None,
        error_category: str | None,
    ) -> None:
        with self._lock:
            self.total.record_result(latency_ns, status_code, error_category)
            self.windows[window].record_result(
                latency_ns, status_code, error_category
            )


def request_once(timeout_seconds: float) -> tuple[int | None, str | None]:
    connection = http.client.HTTPConnection(
        TARGET_HOST, TARGET_PORT, timeout=timeout_seconds
    )
    try:
        connection.request(
            "GET",
            TARGET_PATH,
            headers={
                "Host": TARGET_HOST,
                "User-Agent": "solis-lab-client/1",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        while response.read(65_536):
            pass
        return response.status, None
    except TimeoutError:
        return None, "timeout"
    except ConnectionError:
        return None, "connection"
    except http.client.HTTPException:
        return None, "http_protocol"
    except OSError:
        return None, "network"
    finally:
        connection.close()


def run_workload(
    duration_seconds: int,
    rate_rps: float,
    concurrency: int,
    timeout_seconds: float,
) -> dict[str, object]:
    metrics = Metrics(duration_seconds)
    capacity = threading.BoundedSemaphore(concurrency)
    started_utc = utc_now()
    started = time.monotonic()
    deadline = started + duration_seconds

    def worker(window: int) -> None:
        request_started = time.monotonic_ns()
        try:
            try:
                status_code, error_category = request_once(timeout_seconds)
            except Exception:  # Keep unexpected client faults sanitized in output.
                status_code, error_category = None, "client_internal"
            latency_ns = time.monotonic_ns() - request_started
            metrics.result(window, latency_ns, status_code, error_category)
        finally:
            capacity.release()

    with ThreadPoolExecutor(
        max_workers=concurrency, thread_name_prefix="solis-client"
    ) as executor:
        request_number = 0
        while True:
            target_time = started + request_number / rate_rps
            if target_time >= deadline:
                break
            remaining = target_time - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            window = min(
                duration_seconds - 1,
                max(0, int(time.monotonic() - started)),
            )
            metrics.scheduled(window)
            if capacity.acquire(blocking=False):
                executor.submit(worker, window)
            else:
                metrics.saturated(window)
            request_number += 1

    finished = time.monotonic()
    elapsed_seconds = finished - started
    windows = []
    for index, aggregate in enumerate(metrics.windows):
        windows.append(
            {
                "offset_seconds": index,
                **aggregate.as_dict(1.0),
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "observed_at_utc": started_utc,
        "duration_seconds": duration_seconds,
        "elapsed_seconds": elapsed_seconds,
        "target": {
            "vm": "a-web",
            "endpoint": "http://192.168.130.20/write",
            "database_vm": "a-db",
        },
        "requested_rate_per_second": rate_rps,
        "max_concurrency": concurrency,
        "request_timeout_seconds": timeout_seconds,
        "summary": metrics.total.as_dict(elapsed_seconds),
        "windows": windows,
        "caveats": [
            "This is a bounded lab workload, not a model of a specific production user population.",
            "Latency is measured from a-client through a-web and its PostgreSQL write to a-db.",
            "Percentiles are approximate fixed-bucket estimates.",
            "Response bodies are drained for HTTP correctness and discarded immediately; none are retained or reported.",
        ],
        "privacy": {
            "request_bodies_collected": False,
            "response_bodies_retained": False,
            "sql_text_collected": False,
            "table_data_collected": False,
            "secrets_collected": False,
        },
    }


def bounded_int(name: str, minimum: int, maximum: int):
    def parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError(f"{name} must be an integer") from error
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"{name} must be between {minimum} and {maximum}"
            )
        return parsed

    return parse


def bounded_float(name: str, minimum: float, maximum: float):
    def parse(value: str) -> float:
        try:
            parsed = float(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError(f"{name} must be numeric") from error
        if not math.isfinite(parsed) or not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"{name} must be between {minimum:g} and {maximum:g}"
            )
        return parsed

    return parse


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate fixed-rate a-client -> a-web -> a-db lab traffic."
    )
    parser.add_argument(
        "--duration",
        type=bounded_int("duration", 1, 3600),
        default=60,
        help="collection duration in seconds (default: 60)",
    )
    parser.add_argument(
        "--rate",
        type=bounded_float("rate", 0.1, 200.0),
        default=30.0,
        help="scheduled requests per second (default: 30)",
    )
    parser.add_argument(
        "--concurrency",
        type=bounded_int("concurrency", 1, 100),
        default=20,
        help="maximum requests in flight (default: 20)",
    )
    parser.add_argument(
        "--timeout",
        type=bounded_float("timeout", 0.1, 30.0),
        default=5.0,
        help="per-request timeout in seconds (default: 5)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    set_process_name()
    report = run_workload(
        duration_seconds=args.duration,
        rate_rps=args.rate,
        concurrency=args.concurrency,
        timeout_seconds=args.timeout,
    )
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
