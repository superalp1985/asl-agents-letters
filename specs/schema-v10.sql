ALTER TABLE transfers
DROP COLUMN manifest_relative;

ALTER TABLE transfers
ADD COLUMN part_file_id TEXT
CHECK(part_file_id IS NULL OR length(part_file_id) = 32);

ALTER TABLE transfers
ADD COLUMN manifest_bytes BLOB
CHECK(manifest_bytes IS NULL OR length(manifest_bytes) <= 2097152);
