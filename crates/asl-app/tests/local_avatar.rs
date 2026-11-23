#![cfg(windows)]

use std::{fs, path::PathBuf, process::Command};

use asl_app::{identity::AgentIdentity, paths::AppPaths};
use asl_store::{dashboard::LocalIdentityProjection, open_store, open_store_read_only};
use image::{ExtendedColorType, ImageEncoder, codecs::png::PngEncoder};
use serde_json::{Value, json};

struct Fixture {
    base: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir();
        let root = base.join(format!("asl-avatar-{:032x}", rand::random::<u128>()));
        fs::create_dir(&root).unwrap();
        let fixture = Self { base, root };
        // The real sandbox rejects multiply linked Cargo artifacts.
        fs::copy(
            env!("CARGO_BIN_EXE_asl-core"),
            fixture.root.join("asl-core.exe"),
        )
        .unwrap();
        fs::copy(
            env!("CARGO_BIN_EXE_asl-extractor"),
            fixture.root.join("asl-extractor.exe"),
        )
        .unwrap();
        fixture
    }

    fn run(&self, action: &str, image: Option<&std::path::Path>) -> std::process::Output {
        Command::new(self.root.join("asl-core.exe"))
            .env("ASL_HOME", self.root.join("home"))
            .args(["--avatar", action])
            .args(image)
            .output()
            .unwrap()
    }

    fn ok(&self, action: &str, image: Option<&std::path::Path>) -> Value {
        let output = self.run(action, image);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let (Ok(base), Ok(root)) = (self.base.canonicalize(), self.root.canonicalize())
            && root.parent() == Some(base.as_path())
            && root
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("asl-avatar-"))
        {
            let _ = fs::remove_dir_all(root);
        }
    }
}

#[test]
fn built_in_presets_persist_privately_and_replacing_one_drops_approval() {
    let fixture = Fixture::new();
    let paths = AppPaths::open(&fixture.root.join("home")).unwrap();
    let db = paths.state().join("asl.sqlite3");
    open_store(&db).unwrap();
    let owner = AgentIdentity::load_or_create_protected(&paths.agent_root_key())
        .unwrap()
        .agent_id();
    open_store(&db)
        .unwrap()
        .set_local_identity_projection(&LocalIdentityProjection {
            agent_id: bs58::encode(owner.0).into_string(),
            peer_id: String::new(),
            network_state: "local".into(),
            binding_code: String::new(),
        })
        .unwrap();

    let preset = |number: &str| fixture.ok("preset", Some(std::path::Path::new(number)));
    preset("1");
    let first = fixture.ok("status", None);
    assert_eq!(first["approved"], false);
    fixture.ok("approve", first["token"].as_str().map(std::path::Path::new));
    assert_eq!(fixture.ok("status", None)["approved"], true);
    preset("12");
    let replacement = fixture.ok("status", None);
    assert_eq!(replacement["approved"], false);
    assert_ne!(replacement["token"], first["token"]);
    assert!(
        !fixture
            .run("preset", Some(std::path::Path::new("13")))
            .status
            .success()
    );
    assert_eq!(fixture.ok("status", None), replacement);
}

#[test]
fn local_avatar_cli_replaces_and_clears_one_private_selection() {
    let fixture = Fixture::new();
    let home = fixture.root.join("home");
    let paths = AppPaths::open(&home).unwrap();
    let database = paths.state().join("asl.sqlite3");
    open_store(&database).unwrap();
    assert_eq!(fixture.ok("status", None), json!({"configured": false}));
    let initial_revision = open_store_read_only(&database)
        .unwrap()
        .policy_revision()
        .unwrap();

    let original = fixture.root.join("picture-one.png");
    let replacement = fixture.root.join("picture-two.png");
    for (path, value) in [(&original, 73), (&replacement, 143)] {
        PngEncoder::new(fs::File::create(path).unwrap())
            .write_image(
                &vec![value; 256 * 192 * 3],
                256,
                192,
                ExtendedColorType::Rgb8,
            )
            .unwrap();
    }

    assert_eq!(
        fixture.ok("set", Some(&original)),
        json!({"configured": true})
    );
    let store = open_store_read_only(&database).unwrap();
    let saved = || {
        open_store_read_only(&database)
            .unwrap()
            .avatar_review()
            .unwrap()
            .unwrap()
            .bytes
    };
    let first = saved();
    assert!(first.len() <= 64 * 1024);
    assert_ne!(first, fs::read(&original).unwrap());
    let image = image::load_from_memory(&first).unwrap().to_rgb8();
    assert_eq!(image.dimensions(), (128, 96));
    assert_eq!(image.get_pixel(0, 0).0, [73; 3]);

    let invalid = fixture.root.join("invalid.png");
    fs::write(&invalid, b"not an image").unwrap();
    assert!(!fixture.run("set", Some(&invalid)).status.success());
    let oversized = fixture.root.join("oversized.png");
    fs::File::create(&oversized)
        .unwrap()
        .set_len(4 * 1024 * 1024 + 1)
        .unwrap();
    assert!(!fixture.run("set", Some(&oversized)).status.success());
    let private = home.join("identity").join("private.png");
    fs::copy(&replacement, &private).unwrap();
    assert!(!fixture.run("set", Some(&private)).status.success());
    let alias = fixture.root.join("alias.png");
    fs::hard_link(&private, &alias).unwrap();
    assert!(!fixture.run("set", Some(&alias)).status.success());
    assert_eq!(saved(), first);

    fixture.ok("set", Some(&replacement));
    assert_ne!(saved(), first);
    assert_eq!(fixture.ok("status", None), json!({"configured": true}));
    let owner = AgentIdentity::load_or_create_protected(&paths.agent_root_key())
        .unwrap()
        .agent_id();
    open_store(&database)
        .unwrap()
        .set_local_identity_projection(&LocalIdentityProjection {
            agent_id: bs58::encode(owner.0).into_string(),
            peer_id: String::new(),
            network_state: "registry_anchor_missing".into(),
            binding_code: String::new(),
        })
        .unwrap();
    let review = fixture.ok("status", None);
    assert_eq!(review["approved"], false);
    let token = std::path::Path::new(review["token"].as_str().unwrap());
    assert_eq!(fixture.ok("approve", Some(token)), json!({"approved":true}));
    assert_eq!(fixture.ok("status", None)["approved"], true);
    assert_eq!(fixture.ok("withdraw", None), json!({"approved":false}));
    assert!(!fixture.run("approve", Some(token)).status.success());
    let second_review = fixture.ok("status", None);
    let second_token = std::path::Path::new(second_review["token"].as_str().unwrap());
    fixture.ok("approve", Some(second_token));
    fixture.ok("set", Some(&original));
    assert_eq!(fixture.ok("status", None)["approved"], false);
    assert!(!fixture.run("approve", Some(second_token)).status.success());
    assert_eq!(fixture.ok("clear", None), json!({"configured": false}));
    assert_eq!(fixture.ok("status", None), json!({"configured": false}));
    assert!(store.get_setting("ui.local_avatar_v1").unwrap().is_none());
    assert_eq!(store.policy_revision().unwrap(), initial_revision);
    assert!(fs::read_dir(paths.snapshots()).unwrap().next().is_none());
}
