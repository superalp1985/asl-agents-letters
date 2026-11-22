-- Upload decisions bind the authenticated device in addition to its agent or
-- group membership. The UI-visible label is only a filename, never a path.
ALTER TABLE transfer_consents ADD COLUMN target_peer_id TEXT;
ALTER TABLE transfer_consents ADD COLUMN upload_filename TEXT;
ALTER TABLE transfer_consents ADD COLUMN upload_size INTEGER CHECK(upload_size >= 0);

CREATE INDEX upload_consent_lookup
    ON transfer_consents(source_grant_id, grant_epoch, content_id, target_peer_id,
                         group_id, group_epoch, expires_at_ms)
    WHERE direction='upload';
