-- Run ledger schema + seed row.
-- Loaded automatically by the postgres image on first boot of an empty data
-- directory (./seeds is mounted at /docker-entrypoint-initdb.d).
-- Every statement is idempotent: re-running this file never duplicates the seed row.

CREATE TABLE IF NOT EXISTS runs (
    run_id           text PRIMARY KEY,
    sandbox_name     text NOT NULL CHECK (sandbox_name ~ '^sbx-[a-z0-9]{8,}$'),
    problem_id       text NOT NULL,
    state            text NOT NULL CHECK (state IN
                         ('created', 'ready', 'running', 'succeeded', 'failed', 'deleted')),
    execution_target text NOT NULL CHECK (execution_target = 'celesto_sandbox'),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS runs_sandbox_name_idx ON runs (sandbox_name);

INSERT INTO runs (run_id, sandbox_name, problem_id, state, execution_target)
VALUES ('run-seeddemo1', 'sbx-seeddemo1', 'seed-problem', 'deleted', 'celesto_sandbox')
ON CONFLICT (run_id) DO NOTHING;
