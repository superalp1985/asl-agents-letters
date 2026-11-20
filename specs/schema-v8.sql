ALTER TABLE grants
ADD COLUMN allow_derived_disclosure INTEGER NOT NULL DEFAULT 0
CHECK(allow_derived_disclosure IN (0, 1));

ALTER TABLE write_grants ADD COLUMN root_volume TEXT;
ALTER TABLE write_grants ADD COLUMN root_file_id TEXT;

CREATE TABLE derived_write_refs (
    resource_key TEXT PRIMARY KEY REFERENCES resources(resource_key),
    write_grant_id TEXT NOT NULL REFERENCES write_grants(write_grant_id),
    relative_name TEXT NOT NULL,
    file_size INTEGER NOT NULL CHECK(file_size >= 0),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    UNIQUE(write_grant_id, relative_name)
) STRICT, WITHOUT ROWID;

CREATE INDEX derivation_sources_source
ON derivation_sources(source_resource_key);

CREATE TRIGGER derived_fts_deactivate AFTER UPDATE OF active ON resources
WHEN OLD.origin='derived' AND OLD.active=1 AND NEW.active=0
BEGIN
    DELETE FROM resource_fts WHERE rowid=OLD.row_id;
END;

CREATE TRIGGER derived_fts_delete AFTER DELETE ON resources
WHEN OLD.origin='derived'
BEGIN
    DELETE FROM resource_fts WHERE rowid=OLD.row_id;
END;
