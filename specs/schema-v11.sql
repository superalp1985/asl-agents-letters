-- Existing consents have no destination/source binding and cannot authorize a direct download.
ALTER TABLE transfer_consents ADD COLUMN destination_filename TEXT;
ALTER TABLE transfer_consents ADD COLUMN source_peers_json TEXT;
ALTER TABLE transfer_consents ADD COLUMN download_size INTEGER CHECK(download_size >= 0);
CREATE INDEX direct_download_consent_lookup
    ON transfer_consents(destination_write_grant_id, content_id, grant_epoch, expires_at_ms)
    WHERE direction='download' AND group_id IS NULL AND destination_filename IS NOT NULL;
