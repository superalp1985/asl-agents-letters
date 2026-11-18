-- Drop orphaned/mismatched FTS rows and text from invalid local references.
-- Non-local references have separate policy; do not require a local grant for them.
DELETE FROM resource_fts WHERE NOT EXISTS (
    SELECT 1 FROM resources r
    WHERE r.row_id=resource_fts.rowid AND r.resource_key=resource_fts.resource_key
      AND (r.origin<>'local' OR (r.active=1 AND EXISTS (
          SELECT 1 FROM grants g WHERE g.grant_id=r.grant_id
            AND g.status='active' AND g.epoch=r.source_grant_epoch
      )))
);

-- Reconciliation and replacement both deactivate the old reference.
CREATE TRIGGER local_fts_deactivate AFTER UPDATE OF active ON resources
WHEN OLD.origin='local' AND OLD.active=1 AND NEW.active=0
BEGIN
    DELETE FROM resource_fts WHERE rowid=OLD.row_id;
END;

CREATE TRIGGER local_fts_delete AFTER DELETE ON resources WHEN OLD.origin='local'
BEGIN
    DELETE FROM resource_fts WHERE rowid=OLD.row_id;
END;

CREATE TRIGGER local_fts_revoke AFTER UPDATE OF status ON grants
WHEN OLD.status='active' AND NEW.status='revoked'
BEGIN
    DELETE FROM resource_fts WHERE rowid IN (
        SELECT row_id FROM resources WHERE grant_id=OLD.grant_id AND active=1 AND origin='local'
    );
END;
