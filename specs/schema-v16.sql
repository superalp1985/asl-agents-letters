-- Group downloads carry the exact local group membership epoch that
-- authorized the source. A member change closes the old transfer.
ALTER TABLE transfers ADD COLUMN group_id TEXT REFERENCES asl_groups(group_id);
ALTER TABLE transfers ADD COLUMN group_epoch INTEGER;

CREATE INDEX group_download_consent_lookup
    ON transfer_consents(group_id, group_epoch, destination_write_grant_id,
                         content_id, grant_epoch, expires_at_ms)
    WHERE direction='download' AND group_id IS NOT NULL
      AND destination_filename IS NOT NULL;

CREATE INDEX group_transfer_epoch_lookup
    ON transfers(group_id, group_epoch, expires_at_ms)
    WHERE group_id IS NOT NULL;
