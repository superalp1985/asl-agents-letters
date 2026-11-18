#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use asl_policy::FileIdentity;
use asl_policy::reconcile::{
    ActivePage, HINT_CAPACITY, PAGE_SIZE, ReconcileBackend, ReconcileDriver, SourceCheck,
    check_source,
};
use asl_types::error::AslError;
use asl_types::ids::{Hash32, Id128};
use asl_types::task::ResourceKey;

fn key(id: i64) -> ResourceKey {
    ResourceKey(Id128(i128::from(id).to_be_bytes()))
}

#[derive(Default)]
struct Broker {
    active: BTreeMap<i64, ResourceKey>,
    checked: Vec<ResourceKey>,
    pages: Vec<(Option<i64>, i64)>,
    sweeps: usize,
    fail_key: Option<ResourceKey>,
    fail_page: bool,
    bad_page: Option<Vec<i64>>,
}

impl Broker {
    fn rows(n: i64) -> Self {
        Self {
            active: (1..=n).map(|id| (id, key(id))).collect(),
            ..Self::default()
        }
    }
}

impl ReconcileBackend for Broker {
    fn last_active_row(&mut self) -> Result<Option<i64>, AslError> {
        self.sweeps += 1;
        Ok(self.active.last_key_value().map(|(&row, _)| row))
    }

    fn active_page(
        &mut self,
        after: Option<i64>,
        through: i64,
        page: &mut ActivePage,
    ) -> Result<(), AslError> {
        self.pages.push((after, through));
        if std::mem::take(&mut self.fail_page) {
            return Err(AslError::InvalidDatabase);
        }
        if let Some(ids) = self.bad_page.take() {
            for id in ids {
                page.push(id, key(id))?;
            }
            return Ok(());
        }
        for (&id, key) in self
            .active
            .range(..=through)
            .filter(|(id, _)| after.is_none_or(|after| **id > after))
            .take(PAGE_SIZE)
        {
            page.push(id, key.clone())?;
        }
        Ok(())
    }

    fn reconcile_one(&mut self, key: &ResourceKey) -> Result<(), AslError> {
        self.checked.push(key.clone());
        if self.fail_key.as_ref() == Some(key) {
            return Err(AslError::InvalidDatabase);
        }
        Ok(())
    }
}

#[test]
fn lost_events_still_get_a_sweep_at_30_seconds_despite_other_hints() {
    let t = Instant::now();
    let mut driver = ReconcileDriver::new(t);
    let mut db = Broker::rows(2);
    driver.poll(t, &mut db).unwrap();
    assert_eq!(db.checked, [key(1), key(2)]);
    db.checked.clear();

    for _ in 0..1000 {
        driver.hints().changed(key(1));
    }
    driver
        .poll(t + Duration::from_millis(29_999), &mut db)
        .unwrap();
    assert_eq!(db.checked, [key(1)]);
    assert_eq!(db.sweeps, 1);
    driver.poll(t + Duration::from_secs(30), &mut db).unwrap();
    assert_eq!(db.checked, [key(1), key(1), key(2)]);
    assert_eq!(db.sweeps, 2);
}

#[test]
fn overflow_behind_cursor_coalesces_to_one_followup_with_a_fresh_high_water() {
    let t = Instant::now();
    let mut driver = ReconcileDriver::new(t);
    let last = PAGE_SIZE as i64 + 2;
    let mut db = Broker::rows(last);
    driver.poll(t, &mut db).unwrap();
    assert_eq!(db.checked.len(), PAGE_SIZE);
    db.active.insert(last + 1, key(last + 1));
    db.active.remove(&(last - 1));

    for i in 1..=2 * HINT_CAPACITY as i64 {
        driver.hints().changed(key(i));
    }
    driver.poll(t, &mut db).unwrap();
    assert_eq!(db.pages[1], (Some(PAGE_SIZE as i64), last));
    assert_eq!(db.checked.last(), Some(&key(last)));
    assert_eq!(db.sweeps, 1);
    db.checked.clear();
    for _ in 0..4 {
        driver.poll(t, &mut db).unwrap();
    }
    assert_eq!(db.sweeps, 2);
    assert_eq!(db.checked, db.active.values().cloned().collect::<Vec<_>>());
}

#[test]
fn tick_during_a_sweep_keeps_its_cursor_and_coalesces_missed_intervals() {
    let t = Instant::now();
    let mut driver = ReconcileDriver::new(t);
    let mut db = Broker::rows(PAGE_SIZE as i64 + 1);
    driver.poll(t, &mut db).unwrap();
    let later = t + Duration::from_secs(300);
    driver.poll(later, &mut db).unwrap();
    assert_eq!(db.sweeps, 1);
    assert_eq!(db.checked.len(), PAGE_SIZE + 1);
    for _ in 0..4 {
        driver.poll(later, &mut db).unwrap();
    }
    assert_eq!(db.sweeps, 2);
    assert_eq!(db.checked.len(), 2 * (PAGE_SIZE + 1));
}

#[test]
fn failed_page_retries_its_cursor_and_a_failed_key_does_not_hide_its_neighbors() {
    let t = Instant::now();
    let mut driver = ReconcileDriver::new(t);
    let mut db = Broker::rows(PAGE_SIZE as i64 + 2);
    db.fail_key = Some(key(1));
    assert!(driver.poll(t, &mut db).is_err());
    assert_eq!(db.checked.len(), PAGE_SIZE);
    db.fail_page = true;
    assert!(driver.poll(t, &mut db).is_err());
    driver.poll(t, &mut db).unwrap();
    assert_eq!(db.pages[1], db.pages[2]);
    assert_eq!(db.checked.len(), PAGE_SIZE + 2);
    db.fail_key = None;
    driver.poll(t + Duration::from_secs(30), &mut db).unwrap();
    assert_eq!(db.checked.iter().filter(|k| **k == key(1)).count(), 2);
}

#[test]
fn missing_or_unauthorized_source_is_never_a_match() {
    let identity = FileIdentity {
        volume_serial: 1,
        file_id: [0; 16],
    };
    for err in [
        AslError::NotFound,
        AslError::GrantRevoked,
        AslError::PolicyDenied,
    ] {
        assert_eq!(
            check_source(Err(err), &identity, 0, &Hash32([0; 32])).unwrap(),
            SourceCheck::Deactivate
        );
    }
    assert!(
        check_source(
            Err(AslError::PlatformUnavailable),
            &identity,
            0,
            &Hash32([0; 32])
        )
        .is_err()
    );
}

#[test]
fn rejects_invalid_pages_without_processing_a_partial_page_or_moving_the_cursor() {
    let t = Instant::now();
    let tail = PAGE_SIZE as i64 + 1;
    for bad in [
        vec![1, 1],
        vec![2, 1],
        vec![1, tail + 1],
        (1..=tail).collect(),
    ] {
        let mut driver = ReconcileDriver::new(t);
        let mut db = Broker::rows(tail);
        db.bad_page = Some(bad);
        assert!(matches!(
            driver.poll(t, &mut db),
            Err(AslError::InvalidDatabase)
        ));
        assert!(db.checked.is_empty());
        driver.poll(t, &mut db).unwrap();
        assert_eq!(db.pages, [(None, tail), (None, tail)]);
        db.bad_page = Some(vec![1]);
        assert!(matches!(
            driver.poll(t, &mut db),
            Err(AslError::InvalidDatabase)
        ));
        assert_eq!(db.checked.len(), PAGE_SIZE);
    }
}

#[cfg(windows)]
#[test]
fn pinned_source_checks_identity_length_and_full_file_hash_independently() {
    use asl_policy::{SourceGrant, SourceRules, open_authorized_source};
    use std::path::Path;

    // Read-only fixture: use this test's own source, with a disjoint protected root.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let rules = || SourceRules::new(["rs".to_owned()], 1024 * 1024).unwrap();
    let grant = SourceGrant::open(&root.join("tests"), &root.join("src"), rules()).unwrap();
    let restored = SourceGrant::restore(
        &root.join("tests"),
        &root.join("src"),
        rules(),
        grant.identity(),
    )
    .unwrap();
    let open = || open_authorized_source(&restored, Path::new("reconcile.rs"));
    let identity = open().unwrap().identity().clone();
    let bytes = include_bytes!("reconcile.rs");
    let len = bytes.len() as u64;
    let hash = Hash32(*blake3::hash(bytes).as_bytes());
    assert_eq!(
        check_source(open(), &identity, len, &hash).unwrap(),
        SourceCheck::Unchanged
    );
    let mut other = identity.clone();
    other.file_id[0] ^= 1;
    let mut wrong_hash = hash;
    wrong_hash.0[31] ^= 1;
    for (id, size, digest) in [
        (&other, len, hash),
        (&identity, len + 1, hash),
        (&identity, len, wrong_hash),
    ] {
        assert_eq!(
            check_source(open(), id, size, &digest).unwrap(),
            SourceCheck::Deactivate
        );
    }
}

#[cfg(windows)]
#[test]
fn retain_watches_keeps_only_listed_roots_and_empty_closes_all() {
    use asl_policy::{SourceGrant, SourceRules};
    use std::path::Path;

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let protected = root.parent().unwrap().join("asl-types");
    let open = |dir| {
        SourceGrant::open(
            &root.join(dir),
            &protected,
            SourceRules::new(["rs".into()], 1024).unwrap(),
        )
        .unwrap()
    };
    let a = open("src");
    let b = open("tests");
    let mut driver = ReconcileDriver::new(Instant::now());
    driver.watch_grant(&a).unwrap();
    driver.watch_grant(&b).unwrap();
    driver.retain_watches(std::slice::from_ref(b.identity()));
    assert!(!driver.unwatch_grant(a.identity()));
    assert!(driver.unwatch_grant(b.identity()));
    driver.watch_grant(&a).unwrap();
    driver.retain_watches(&[]);
    assert!(!driver.unwatch_grant(a.identity()));
}

#[cfg(windows)]
#[test]
fn native_subtree_changes_coalesce_before_the_timer_and_detach_cleanly() {
    use asl_policy::{SourceGrant, SourceRules};
    use std::fs;
    use std::path::Path;

    let base =
        Path::new(r"E:\ASL\work\tmp").join(format!("t11-watch-{:032x}", rand::random::<u128>()));
    fs::create_dir(&base).unwrap();
    let source = base.join("source");
    let nested = source.join("nested");
    let protected = base.join("protected");
    for dir in [&source, &nested, &protected] {
        fs::create_dir(dir).unwrap();
    }
    let grant = SourceGrant::open(
        &source,
        &protected,
        SourceRules::new(["txt".into()], 1024).unwrap(),
    )
    .unwrap();
    let t = Instant::now();
    let mut driver = ReconcileDriver::new(t);
    let mut db = Broker::rows(1);
    driver.watch_grant(&grant).unwrap();
    driver.watch_grant(&grant).unwrap();
    driver.poll(t, &mut db).unwrap();
    let file = nested.join("note.txt");
    fs::write(&file, b"new").unwrap();
    let mut sample = t;
    for second in 1..=5 {
        driver.wait_for_work();
        sample = t + Duration::from_secs(second);
        driver.poll(sample, &mut db).unwrap();
        if db.sweeps == 2 {
            break;
        }
    }
    assert_eq!(
        db.sweeps, 2,
        "nested create must trigger before the periodic tick"
    );

    for n in 0..100u8 {
        fs::write(&file, [n]).unwrap();
        driver
            .poll(sample + Duration::from_millis(999), &mut db)
            .unwrap();
    }
    assert_eq!(
        db.sweeps, 2,
        "a write storm must not trigger extra sweeps during cooldown"
    );
    driver.poll(t + Duration::from_secs(15), &mut db).unwrap();
    assert_eq!(
        db.sweeps, 3,
        "native watch must rearm after the first signal"
    );
    assert!(driver.unwatch_grant(grant.identity()));
    assert!(!driver.unwatch_grant(grant.identity()));
    fs::write(&file, b"detached").unwrap();
    driver.poll(t + Duration::from_secs(20), &mut db).unwrap();
    assert_eq!(db.sweeps, 3);
    drop(grant);
    // Remove only the individual entries created by this test, never a tree.
    fs::remove_file(file).unwrap();
    for dir in [&nested, &source, &protected, &base] {
        fs::remove_dir(dir).unwrap();
    }
}
