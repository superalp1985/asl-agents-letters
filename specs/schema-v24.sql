-- A signed reference is display metadata, never a local grant or a downloaded file.
ALTER TABLE observed_remote_profiles ADD COLUMN avatar_content_id BLOB
    CHECK(avatar_content_id IS NULL OR length(avatar_content_id) = 32);
