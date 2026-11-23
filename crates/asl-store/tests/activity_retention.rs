use asl_store::open_store;
use rusqlite::Connection;

#[test]
fn activity_cleanup_honors_each_deadline_and_preserves_live_references() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("asl.sqlite3");
    let mut store = open_store(&path).unwrap();
    let fixture = Connection::open(&path).unwrap();
    fixture
        .execute_batch(
            "PRAGMA foreign_keys=ON;
             INSERT INTO agents(agent_id) VALUES ('11111111111111111111111111111111');
             INSERT INTO device_identities
                 SELECT 'peer',agent_id,lower(hex(zeroblob(32))),X'',1,1000,NULL,0 FROM agents;
             INSERT INTO peers(peer_id,agent_id) SELECT 'peer',agent_id FROM agents;
             INSERT INTO tasks(task_id,direction,audience_json,state,created_at_ms,expires_at_ms)
                 VALUES (printf('%032x',1),'local','{}','done',0,100),
                        (printf('%032x',2),'local','{}','searching',0,200);
             INSERT INTO asl_groups(group_id,creator_peer_id,local_name,state,created_at_ms,updated_at_ms)
                 VALUES (printf('%032x',1),'peer','Test room','active',0,0);
             INSERT INTO messages
                 SELECT printf('%032x',id),printf('%032x',task),'peer','out','query',X'01',0,deadline
                    FROM (SELECT 1 AS id,1 AS task,100 AS deadline
                          UNION ALL SELECT 2,2,101 UNION ALL SELECT 3,1,100
                          UNION ALL SELECT 4,2,100);
             INSERT INTO outbox VALUES (printf('%032x',1),0,0,100),(printf('%032x',3),0,0,101);
             INSERT INTO direct_inbound_observations
                 (agent_id,peer_id,message_id,root_task_id,observed_at_ms,expires_at_ms,
                  intent,result_shape,constraint_count,topics_json)
                 SELECT agent_id,'peer',printf('%032x',id),printf('%032x',1),0,deadline,1,1,0,'[]'
                    FROM agents CROSS JOIN (SELECT 1 AS id,100 AS deadline UNION ALL SELECT 2,101);
             INSERT INTO group_events
                 (event_id,group_id,mls_epoch,sender_peer_id,kind,ciphertext,
                  created_at_ms,expires_at_ms,browse_kind,browse_expires_at_ms)
                 VALUES (printf('%032x',1),printf('%032x',1),0,'peer','application',X'01',0,200,'query',100),
                        (printf('%032x',2),printf('%032x',1),0,'peer','application',X'02',0,200,'query',101);",
        )
        .unwrap();

    store.prune_expired_activity(100).unwrap();
    store.prune_expired_activity(100).unwrap();
    let counts = fixture
        .query_row(
            "SELECT (SELECT SUM(expires_at_ms) FROM direct_inbound_observations),
                    (SELECT group_concat(id) FROM (
                        SELECT substr(message_id,32) AS id FROM messages ORDER BY message_id)),
                    (SELECT SUM(expires_at_ms) FROM outbox),
                    (SELECT SUM(browse_expires_at_ms) FROM group_events),
                    (SELECT SUM(expires_at_ms) FROM group_events WHERE ciphertext IN (X'01',X'02')),
                    (SELECT COUNT(*) FROM tasks)",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(counts, (101, "2,3,4".into(), 101, 101, 400, 2));
    let group_markers: (Option<String>, String) = fixture
        .query_row(
            "SELECT (SELECT browse_kind FROM group_events WHERE event_id=printf('%032x',1)),
                    (SELECT browse_kind FROM group_events WHERE event_id=printf('%032x',2))",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(group_markers, (None, "query".into()));

    store.prune_expired_activity(200).unwrap();
    let left: i64 = fixture
        .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
        .unwrap();
    assert_eq!(left, 0);
}
