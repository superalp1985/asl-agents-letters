-- Bind local snapshot reservations to their authority, not just their task.
ALTER TABLE resources ADD COLUMN source_grant_epoch INTEGER CHECK(source_grant_epoch >= 1);
-- v1 never stored an import epoch; retain metadata but require a new local import.
UPDATE policy_state SET revision=revision+1
 WHERE EXISTS(SELECT 1 FROM resources WHERE active=1 AND origin='local');
UPDATE resources SET active=0 WHERE active=1 AND origin='local';
CREATE TABLE snapshot_imports (
    reservation_id TEXT PRIMARY KEY REFERENCES reservations(reservation_id),
    grant_id TEXT NOT NULL REFERENCES grants(grant_id),
    grant_epoch INTEGER NOT NULL CHECK(grant_epoch >= 1),
    physical_bytes INTEGER NOT NULL CHECK(physical_bytes > 0),
    install_content_id TEXT CHECK(length(install_content_id)=64
        AND length(CAST(install_content_id AS BLOB))=64
        AND install_content_id NOT GLOB '*[^0-9a-f]*')
) STRICT;
-- A claim survives its owner; only consume or completed rollback clears it.
CREATE UNIQUE INDEX snapshot_install_claim ON snapshot_imports(install_content_id)
    WHERE install_content_id IS NOT NULL;
CREATE INDEX snapshot_recovery_reference ON snapshots(content_id COLLATE NOCASE);
CREATE INDEX snapshot_recovery_due ON reservations(expires_at_ms, reservation_id)
    WHERE kind='snapshot' AND state='held';
CREATE TABLE snapshot_recovery_cursor (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    through_ms INTEGER NOT NULL,
    after_ms INTEGER NOT NULL,
    after_id TEXT NOT NULL CHECK(length(after_id)=32)
) STRICT;
CREATE INDEX snapshot_imports_grant ON snapshot_imports(grant_id);
CREATE INDEX reservations_kind_state ON reservations(kind, state);
CREATE INDEX resources_active_source ON resources(grant_id, source_relative) WHERE active = 1 AND origin = 'local';
