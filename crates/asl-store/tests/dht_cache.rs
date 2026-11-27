use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use asl_store::open_store;
use asl_types::ids::PeerId;

static NEXT_DATABASE_ID: AtomicU64 = AtomicU64::new(1);

struct TestDatabase {
    path: PathBuf,
}

impl TestDatabase {
    fn new() -> Self {
        let directory = std::env::var_os("ASL_TEST_FIXTURE_BASE")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("asl-dht-cache");
        fs::create_dir_all(&directory).unwrap();
        let id = NEXT_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            path: directory.join(format!("cache-{}-{id}.sqlite3", std::process::id())),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        for suffix in ["-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", self.path.display()));
        }
    }
}

fn peer(value: &str) -> PeerId {
    PeerId::from_bytes(bs58::decode(value).into_vec().unwrap()).unwrap()
}

#[test]
fn provider_cache_keeps_multiple_peers_and_replaces_one_observation() {
    let database = TestDatabase::new();
    let store = open_store(database.path()).unwrap();
    let key = [7; 32];
    let first = peer("12D3KooWGHqmBWQ8VMPcaJqq1MBAXinrGaBsD9cMZoZRnbydnv89");
    let second = peer("12D3KooWJ1jPzo4GNd8Zh66dhmDUfPHEjkzurJzMy5ws5bWGV4kS");

    store
        .cache_dht_provider(
            key,
            first.clone(),
            &["/ip4/127.0.0.1/tcp/4001".into()],
            2_000,
            1_000,
        )
        .unwrap();
    store
        .cache_dht_provider(
            key,
            second.clone(),
            &["/ip4/127.0.0.1/tcp/4002".into()],
            2_000,
            1_001,
        )
        .unwrap();
    store
        .cache_dht_provider(
            key,
            first.clone(),
            &["/ip4/127.0.0.1/tcp/4003".into()],
            3_000,
            1_002,
        )
        .unwrap();

    let providers = store.cached_dht_providers(1_500, 16).unwrap();
    assert_eq!(providers.len(), 2);
    assert_eq!(
        providers
            .iter()
            .find(|provider| provider.provider_id == first)
            .unwrap()
            .addresses,
        vec!["/ip4/127.0.0.1/tcp/4003"]
    );
    assert_eq!(
        providers
            .iter()
            .find(|provider| provider.provider_id == second)
            .unwrap()
            .addresses,
        vec!["/ip4/127.0.0.1/tcp/4002"]
    );

    store.prune_dht_cache(2_500).unwrap();
    let providers = store.cached_dht_providers(2_500, 16).unwrap();
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0].provider_id, first);
}
