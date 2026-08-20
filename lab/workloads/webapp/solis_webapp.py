#!/usr/bin/env python3
"""Small tenant workload service for Solis I/O demonstrations."""

import json
import os
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import psycopg2


TENANT = os.environ.get("SOLIS_TENANT", "").strip()
DB_CONFIG = {
    "host": os.environ.get("SOLIS_DB_HOST", "").strip(),
    "port": int(os.environ.get("SOLIS_DB_PORT", "5432")),
    "dbname": os.environ.get("SOLIS_DB_NAME", "solisapp"),
    "user": os.environ.get("SOLIS_DB_USER", "solis"),
    "password": os.environ.get("SOLIS_DB_PASSWORD", "solispass"),
}
WEB_PORT = int(os.environ.get("SOLIS_WEB_PORT", "8080"))


class SolisHandler(BaseHTTPRequestHandler):
    """Serve health checks and small PostgreSQL-backed workload requests."""

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler defines this name.
        """Serve only the fixed health, write, and statistics endpoints."""
        path = urlsplit(self.path).path
        if path == "/health":
            self._send_json(200, {"status": "ok", "tenant": TENANT})
        elif path == "/write":
            self._write_row(path)
        elif path == "/stats":
            self._send_stats()
        else:
            self._send_json(404, {"error": "not found", "path": path})

    def _write_row(self, path):
        """Insert one synthetic database row without logging SQL text or request payloads."""
        try:
            connection = psycopg2.connect(**DB_CONFIG)
            try:
                started = time.perf_counter()
                with connection:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            """
                            INSERT INTO request_log (tenant, path)
                            VALUES (%s, %s)
                            RETURNING id, created_at
                            """,
                            (TENANT, path),
                        )
                        inserted_id, created_at = cursor.fetchone()
                db_write_ms = (time.perf_counter() - started) * 1000
            finally:
                connection.close()

            self._send_json(
                200,
                {
                    "tenant": TENANT,
                    "inserted_id": inserted_id,
                    "db_write_ms": round(db_write_ms, 3),
                    "timestamp": self._timestamp(created_at),
                },
            )
        except psycopg2.Error as error:
            self.log_error("database write failed: %s", error)
            self._send_json(500, {"error": "database write failed", "tenant": TENANT})

    def _send_stats(self):
        """Return bounded aggregate counters for lab health validation."""
        try:
            connection = psycopg2.connect(**DB_CONFIG)
            try:
                with connection:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT count(*) FROM request_log WHERE tenant = %s",
                            (TENANT,),
                        )
                        total_rows = cursor.fetchone()[0]
            finally:
                connection.close()
            self._send_json(200, {"tenant": TENANT, "total_rows": total_rows})
        except psycopg2.Error as error:
            self.log_error("database stats query failed: %s", error)
            self._send_json(500, {"error": "database query failed", "tenant": TENANT})

    def _send_json(self, status, payload):
        """Write a compact JSON response and discard it after transmission."""
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _timestamp(value):
        """Convert a database timestamp to a stable JSON representation."""
        if isinstance(value, datetime):
            return value.isoformat()
        return str(value)


def main():
    """Validate configuration and run the workload with cooperative signal handling."""
    if not TENANT:
        raise SystemExit("SOLIS_TENANT must be set")
    if not DB_CONFIG["host"]:
        raise SystemExit("SOLIS_DB_HOST must be set")
    if not 1 <= WEB_PORT <= 65535:
        raise SystemExit("SOLIS_WEB_PORT must be between 1 and 65535")

    server = ThreadingHTTPServer(("0.0.0.0", WEB_PORT), SolisHandler)
    print(f"Solis workload serving tenant {TENANT} on port {WEB_PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
