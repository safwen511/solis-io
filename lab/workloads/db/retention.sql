\set ON_ERROR_STOP on

-- The steady lab clients are intentionally continuous. Keep only a short
-- rolling window so the demonstration cannot grow request_log indefinitely.
DELETE FROM request_log
WHERE created_at < now() - interval '2 hours';
