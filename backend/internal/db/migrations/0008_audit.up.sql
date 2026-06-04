-- 0008 audit log: append-only, range-partitioned by month. A tamper trigger
-- rejects UPDATE/DELETE. A DEFAULT partition guarantees writes succeed even
-- before a month-specific partition exists (ops may pre-create monthly ones).
CREATE TABLE audit_log (
    id                   uuid NOT NULL,
    occurred_at          timestamptz NOT NULL DEFAULT now(),
    actor_user_id        uuid REFERENCES users(id) ON DELETE SET NULL,
    actor_label          text NOT NULL DEFAULT '',  -- denormalized, survives deletion
    impersonator_user_id uuid,
    action               text NOT NULL,             -- dotted verb e.g. iam.user.create
    target_type          text NOT NULL DEFAULT '',
    target_id            text NOT NULL DEFAULT '',
    target_label         text NOT NULL DEFAULT '',
    result               text NOT NULL DEFAULT 'success'
                            CHECK (result IN ('success','failure','denied')),
    ip                   inet,
    user_agent           text NOT NULL DEFAULT '',
    request_id           text NOT NULL DEFAULT '',
    metadata             jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE TABLE audit_log_default PARTITION OF audit_log DEFAULT;

CREATE INDEX idx_audit_occurred ON audit_log (occurred_at DESC);
CREATE INDEX idx_audit_actor ON audit_log (actor_user_id, occurred_at DESC);
CREATE INDEX idx_audit_action ON audit_log (action, occurred_at DESC);
CREATE INDEX idx_audit_target ON audit_log (target_type, target_id);
CREATE INDEX idx_audit_metadata ON audit_log USING gin (metadata);

CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only (% rejected)', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_immutable
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
