-- Store only synthetic tenant/path labels and timestamps for the lab workload.
-- No request body, response body, SQL text, table payload, or secret is kept.
CREATE TABLE IF NOT EXISTS request_log (
    id bigserial PRIMARY KEY,
    tenant text NOT NULL,
    path text NOT NULL,
    created_at timestamptz DEFAULT now()
);
