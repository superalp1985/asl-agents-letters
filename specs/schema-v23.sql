-- Leave group_events and its referenced keys in place: dropping the table
-- would cascade into mls_sync_log. Copy only the activity projection.
CREATE TEMP TABLE group_browse_v23 AS
    SELECT event_id,browse_kind,browse_expires_at_ms
    FROM group_events WHERE browse_kind IS NOT NULL;

ALTER TABLE group_events DROP COLUMN browse_expires_at_ms;
ALTER TABLE group_events DROP COLUMN browse_kind;
ALTER TABLE group_events ADD COLUMN browse_kind TEXT
    CHECK (browse_kind IS NULL OR (kind='application' AND browse_kind IN
        ('query','answer','offer','fetch_request','fetch_grant','fetch_pending','error','expression')));
ALTER TABLE group_events ADD COLUMN browse_expires_at_ms INTEGER
    CHECK (browse_expires_at_ms IS NULL OR (
        browse_kind IS NOT NULL AND browse_expires_at_ms >= created_at_ms
        AND browse_expires_at_ms <= expires_at_ms
    ));

UPDATE group_events AS event
SET browse_kind=browse.browse_kind,browse_expires_at_ms=browse.browse_expires_at_ms
FROM temp.group_browse_v23 AS browse WHERE event.event_id=browse.event_id;
DROP TABLE temp.group_browse_v23;
