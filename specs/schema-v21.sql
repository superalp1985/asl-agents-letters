ALTER TABLE group_events ADD COLUMN browse_expires_at_ms INTEGER
    CHECK (browse_expires_at_ms IS NULL OR (
        browse_kind IS NOT NULL AND browse_expires_at_ms >= created_at_ms
        AND browse_expires_at_ms <= expires_at_ms
    ));

UPDATE group_events SET browse_expires_at_ms=expires_at_ms WHERE browse_kind IS NOT NULL;
