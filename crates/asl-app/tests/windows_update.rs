#![cfg(windows)]

use std::{
    fs,
    os::windows::fs::OpenOptionsExt,
    path::Path,
    process::{Command, Output},
};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};

const BASELINE: &str = "base";

#[test]
#[ignore = "requires Windows PowerShell 7 and rustc on PATH"]
fn offline_update_switches_only_after_core_preflight() {
    let fixture = tempfile::tempdir().unwrap();
    let dist = fixture.path().join("install");
    let data = fixture.path().join("profile");
    let sources = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/windows");
    fs::create_dir_all(&dist).unwrap();
    fs::create_dir(&data).unwrap();
    let database = data.join("asl.sqlite3");
    fs::write(&database, b"must not be accessed by package update").unwrap();
    fs::copy(env!("CARGO_BIN_EXE_asl-core"), dist.join("asl-core.exe")).unwrap();
    let host = dist.join("asl.exe");
    fs::copy(env!("CARGO_BIN_EXE_asl"), &host).unwrap();
    fs::write(dist.join("package-layout.txt"), "asl-windows-layout-v4").unwrap();
    fs::write(dist.join("active-release.txt"), BASELINE).unwrap();
    for name in ["Portable-Layout.ps1", "Update-ASL.ps1"] {
        fs::copy(sources.join(name), dist.join(name)).unwrap();
    }
    let run = |args: &[&Path]| {
        Command::new("pwsh")
            .args(["-NoProfile", "-NonInteractive", "-File"])
            .arg(dist.join("Update-ASL.ps1"))
            .args(args)
            .env("ASL_HOME", &data)
            .output()
            .unwrap()
    };
    let key = SigningKey::from_bytes(&[42; 32]);
    let key_file = fixture.path().join("trusted.ed25519");
    fs::write(&key_file, key.verifying_key().as_bytes()).unwrap();
    passed(run(&[Path::new("-PinReleaseKey"), &key_file]));
    assert!(
        !run(&[Path::new("-PinReleaseKey"), &key_file])
            .status
            .success()
    );

    let staged = fixture.path().join("candidate");
    fs::create_dir(&staged).unwrap();
    let stub = fixture.path().join("preflight.rs");
    let stub_executable = fixture.path().join("preflight.exe");
    let build_stub = |source: &str, executable: &Path| {
        fs::write(&stub, source).unwrap();
        passed(
            Command::new("rustc")
                .arg(&stub)
                .arg("-o")
                .arg(&stub_executable)
                .output()
                .unwrap(),
        );
        fs::copy(&stub_executable, executable).unwrap();
    };
    let build_core = |version: &str| {
        build_stub(
            &format!(
                r#"fn main() {{
        assert_eq!(std::env::args().nth(1).as_deref(), Some("--version"));
        assert!(std::env::var_os("ASL_HOME").is_none());
        println!("{version}");
    }}"#
            ),
            &staged.join("asl-core.exe"),
        );
        build_stub(
            &format!(
                r#"fn main() {{
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], "mcp");
        assert_eq!(args[1], "--home");
        assert_eq!(args[2], std::env::var_os("EXPECTED_HOME").unwrap());
        assert_eq!(std::env::var("ASL_MCP_KEY").unwrap(), "fixture-only");
        println!("{version}");
    }}"#
            ),
            &staged.join("asl.exe"),
        );
    };
    let archive = fixture.path().join("update.zip");
    let build_archive = || {
        let _ = fs::remove_file(&archive);
        passed(
            Command::new("pwsh")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    r#"
        $ErrorActionPreference = 'Stop'
        . $env:TEST_LAYOUT
        foreach ($member in (Get-PortablePackageMembers)) {
            $path = Join-Path $env:TEST_STAGING $member
            if (-not [IO.File]::Exists($path)) {
                if ($member -eq 'vcruntime140.dll') {
                    [IO.File]::Copy((Join-Path $env:WINDIR 'System32\vcruntime140.dll'), $path)
                } else {
                    [IO.File]::WriteAllText($path, $member)
                }
            }
        }
        [IO.File]::WriteAllText((Join-Path $env:TEST_STAGING 'package-layout.txt'), (Get-PortableLayoutVersion))
        [IO.File]::WriteAllText((Join-Path $env:TEST_STAGING 'active-release.txt'), 'base')
        $sbom = [ordered]@{
            bomFormat = 'CycloneDX'
            specVersion = '1.6'
            version = 1
            metadata = [ordered]@{
                component = [ordered]@{ type = 'application'; name = 'ASL'; version = '1.0.1' }
                properties = @([ordered]@{ name = 'asl:package_layout'; value = (Get-PortableLayoutVersion) })
            }
            components = @()
        }
        [IO.File]::WriteAllText(
            (Join-Path $env:TEST_STAGING 'sbom.cdx.json'),
            (($sbom | ConvertTo-Json -Depth 8 -Compress) + "`n"),
            [Text.UTF8Encoding]::new($false)
        )
        $hashLines = foreach ($member in (Get-PortablePackageMembers)) {
            if ($member -ne 'SHA256SUMS.txt') {
                $hash = (Get-FileHash -LiteralPath (Join-Path $env:TEST_STAGING $member) -Algorithm SHA256).Hash.ToLowerInvariant()
                '{0}  {1}' -f $hash, $member
            }
        }
        [IO.File]::WriteAllText(
            (Join-Path $env:TEST_STAGING 'SHA256SUMS.txt'),
            (($hashLines -join "`n") + "`n"),
            [Text.Encoding]::ASCII
        )
        [IO.Compression.ZipFile]::CreateFromDirectory($env:TEST_STAGING, $env:TEST_ZIP)
    "#,
                ])
                .env("TEST_LAYOUT", sources.join("Portable-Layout.ps1"))
                .env("TEST_STAGING", &staged)
                .env("TEST_ZIP", &archive)
                .output()
                .unwrap(),
        );
    };
    build_core("1.0.1");
    build_archive();

    let manifest = fixture.path().join("manifest.json");
    let signature = fixture.path().join("manifest.sig");
    let sign = |version: &str| {
        let bytes = fs::read(&archive).unwrap();
        let encoded = serde_json::to_vec(&json!({
            "format_version": 1,
            "version": version,
            "platform": "windows-x86_64",
            "archive_bytes": bytes.len(),
            "sha256": alloy_primitives::hex::encode(Sha256::digest(bytes)),
        }))
        .unwrap();
        fs::write(&manifest, &encoded).unwrap();
        let payload = [b"ASL-WINDOWS-UPDATE-v1\0".as_slice(), &encoded].concat();
        fs::write(&signature, key.sign(&payload).to_bytes()).unwrap();
    };
    let apply = || {
        run(&[
            Path::new("-Package"),
            &archive,
            Path::new("-Manifest"),
            &manifest,
            Path::new("-Signature"),
            &signature,
        ])
    };
    let launch_host = || {
        Command::new(&host)
            .args(["mcp", "--home"])
            .arg(&data)
            .env("EXPECTED_HOME", &data)
            .env("ASL_MCP_KEY", "fixture-only")
            .output()
            .unwrap()
    };
    let assert_host_version = |version: &str| {
        let result = launch_host();
        assert_eq!(String::from_utf8_lossy(&result.stdout).trim(), version);
        assert!(result.stderr.is_empty());
        passed(result);
    };
    let pointer = dist.join("active-release.txt");
    sign("1.0.2");
    let output = apply();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("staged Core version"),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&pointer).unwrap(), BASELINE);
    assert!(!fs::read_dir(&dist).unwrap().any(|item| {
        item.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".staging-")
    }));

    sign("1.0.1");
    let signed = fs::read(&signature).unwrap();
    fs::write(&signature, [0; 64]).unwrap();
    assert!(!apply().status.success());
    assert_eq!(fs::read_to_string(&pointer).unwrap(), BASELINE);
    fs::write(&signature, signed).unwrap();
    passed(apply());
    let release = fs::read_to_string(&pointer).unwrap();
    assert_ne!(release, BASELINE);
    let (release_dir, version) = release.split_once('\n').unwrap();
    assert_eq!(version, "1.0.1");
    let active_core = dist.join(release_dir).join("asl-core.exe");
    assert!(active_core.is_file());
    assert!(dist.join("asl-core.exe").is_file());
    assert_host_version("1.0.1");

    // The active candidate only implements --version; trust stays in the bootstrap.
    let denied = apply();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("signature or version verification"));
    assert_eq!(fs::read_to_string(&pointer).unwrap(), release);
    build_core("1.0.2");
    let extra = staged.join("extra.pdb");
    fs::write(&extra, b"unlisted").unwrap();
    build_archive();
    sign("1.0.2");
    let denied = apply();
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("Unexpected or repeated package entry")
    );
    assert_eq!(fs::read_to_string(&pointer).unwrap(), release);
    fs::remove_file(extra).unwrap();
    build_archive();
    sign("1.0.2");
    fs::remove_file(active_core).unwrap();
    let held = fs::OpenOptions::new()
        .read(true)
        .share_mode(1) // FILE_SHARE_READ, without FILE_SHARE_DELETE.
        .open(&pointer)
        .unwrap();
    let blocked = apply();
    assert!(!blocked.status.success());
    assert_eq!(fs::read_to_string(&pointer).unwrap(), release);
    let found = fs::read_dir(&dist)
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| entry.file_type().unwrap().is_dir())
        .map(|entry| entry.file_name().into_string().unwrap())
        .filter(|name| name.starts_with("release-"))
        .collect::<Vec<_>>();
    assert_eq!(
        found,
        [release_dir],
        "{}\n{}",
        String::from_utf8_lossy(&blocked.stdout),
        String::from_utf8_lossy(&blocked.stderr)
    );
    drop(held);
    passed(apply());
    let second_release = fs::read_to_string(&pointer).unwrap();
    assert_ne!(second_release, release);
    let (second_dir, version) = second_release.split_once('\n').unwrap();
    assert_eq!(version, "1.0.2");
    assert!(dist.join(second_dir).join("asl-core.exe").is_file());
    assert_host_version("1.0.2");

    build_core("1.0.1");
    build_archive();
    sign("1.0.1");
    let denied = apply();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("signature or version verification"));
    assert_eq!(fs::read_to_string(&pointer).unwrap(), second_release);
    fs::remove_file(&pointer).unwrap();
    assert!(!apply().status.success());
    let rejected = launch_host();
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(!pointer.exists());
    assert_eq!(
        fs::read(&database).unwrap(),
        b"must not be accessed by package update"
    );
}

fn passed(output: Output) {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
