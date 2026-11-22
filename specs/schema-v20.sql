ALTER TABLE group_events ADD COLUMN browse_kind TEXT
    CHECK (browse_kind IS NULL OR (kind='application' AND browse_kind IN
        ('query','answer','offer','fetch_request','fetch_grant','fetch_pending','error')));
