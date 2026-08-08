CREATE TABLE IF NOT EXISTS request_log (
    id bigserial PRIMARY KEY,
    tenant text NOT NULL,
    path text NOT NULL,
    created_at timestamptz DEFAULT now()
);
