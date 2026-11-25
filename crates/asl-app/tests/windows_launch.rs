#![cfg(windows)]

use std::{
    fs,
    path::Path,
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};

#[test]
#[ignore = "requires PowerShell 7 and rustc on PATH"]
fn viewer_only_opens_the_active_release_without_starting_core() {
    let fixture = tempfile::tempdir().unwrap();
    let install = fixture.path().join("portable install");
    let release_name = "release-00112233445566778899aabbccddeeff";
    let release = install.join(release_name);
    let home = fixture.path().join("existing profile");
    fs::create_dir_all(&release).unwrap();
    fs::create_dir(&home).unwrap();
    let packaging = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/windows");
    for name in ["Start-ASL.ps1", "Portable-Layout.ps1"] {
        fs::copy(packaging.join(name), install.join(name)).unwrap();
    }
    fs::write(
        install.join("active-release.txt"),
        format!("{release_name}\n1.0.1"),
    )
    .unwrap();
    fs::write(install.join("package-layout.txt"), "asl-windows-layout-v2").unwrap();
    fs::write(release.join("package-layout.txt"), "asl-windows-layout-v2").unwrap();
    fs::write(release.join("active-release.txt"), "base").unwrap();

    let viewer = release.join("asl-ui.exe");
    let marker = fixture.path().join("viewer-report");
    let source = fixture.path().join("viewer_fixture.rs");
    fs::write(
        &source,
        r#"fn main() {
    assert_eq!(std::env::var_os("ASL_HOME"), std::env::var_os("TEST_PROFILE"));
    std::fs::write(
        std::env::var_os("TEST_VIEWER_REPORT").unwrap(),
        std::env::current_exe().unwrap().to_string_lossy().as_bytes(),
    ).unwrap();
}"#,
    )
    .unwrap();
    assert_success(
        Command::new("rustc")
            .arg(&source)
            .arg("-o")
            .arg(&viewer)
            .output()
            .unwrap(),
    );

    // Neither install nor active release has a Core executable.
    assert_success(
        Command::new("pwsh")
            .args(["-NoProfile", "-NonInteractive", "-Command"])
            .arg(
                r#"
$ErrorActionPreference = 'Stop'
& $env:TEST_LAUNCHER -ViewerOnly -DataDirectory $env:TEST_PROFILE
if ($env:ASL_HOME -cne 'original-shell-value') { throw 'ASL_HOME leaked' }
"#,
            )
            .env("ASL_HOME", "original-shell-value")
            .env("TEST_LAUNCHER", install.join("Start-ASL.ps1"))
            .env("TEST_PROFILE", &home)
            .env("TEST_VIEWER_REPORT", &marker)
            .output()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let actual = loop {
        if let Ok(report) = fs::read_to_string(&marker)
            && !report.is_empty()
        {
            break report;
        }
        assert!(Instant::now() < deadline, "viewer did not open the profile");
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(
        Path::new(&actual).canonicalize().unwrap(),
        viewer.canonicalize().unwrap()
    );
}

fn assert_success(output: Output) {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires PowerShell 7 on PATH"]
fn package_publication_waits_for_a_transient_sharing_violation() {
    let fixture = tempfile::tempdir().unwrap();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert_success(
        Command::new("pwsh")
            .args(["-NoProfile", "-NonInteractive", "-Command"])
            .arg(
                r#"
$ErrorActionPreference = 'Stop'
$source = Join-Path $env:TEST_DIR 'staged.zip'
$target = Join-Path $env:TEST_DIR 'published.zip'
$signal = Join-Path $env:TEST_DIR 'ready'
[IO.File]::WriteAllText($source, 'completed archive')
$hold = [IO.File]::OpenRead($source)
$job = Start-ThreadJob -ScriptBlock {
    $ErrorActionPreference = 'Stop'
    . $env:TEST_SCRIPT
    [IO.File]::WriteAllText($using:signal, '')
    Move-AslBuildOutput -Source $using:source -Destination $using:target
}
try {
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    while (-not [IO.File]::Exists($signal) -and $job.State -notin @('Failed','Completed') -and $deadline.Elapsed.TotalSeconds -lt 8) {
        Start-Sleep -Milliseconds 20
    }
    if (-not [IO.File]::Exists($signal)) { Receive-Job $job; throw 'Move job did not start.' }
    Start-Sleep -Milliseconds 300
    if (Test-Path -LiteralPath $target) { throw 'Published while the file was still locked.' }
    $hold.Dispose()
    Receive-Job $job -Wait
    if ([IO.File]::Exists($source) -or [IO.File]::ReadAllText($target) -cne 'completed archive') {
        throw 'The completed archive was not published.'
    }
}
finally {
    $hold.Dispose()
    Remove-Job $job -Force
}
"#,
            )
            .env("TEST_SCRIPT", repo.join("scripts/move-build-output.ps1"))
            .env("TEST_DIR", fixture.path())
            .output()
            .unwrap(),
    );
}
