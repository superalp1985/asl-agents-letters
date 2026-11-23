#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
#[path = "../ui/mod.rs"]
mod ui;

#[cfg(windows)]
use std::{ffi::OsString, path::PathBuf};

#[cfg(windows)]
fn main() -> eframe::Result {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    ui::run(data_home(&args, std::env::var_os("ASL_HOME")))
}

#[cfg(windows)]
fn data_home(args: &[OsString], configured_home: Option<OsString>) -> Option<PathBuf> {
    match args {
        [] => configured_home
            .filter(|home| !home.is_empty())
            .map(Into::into),
        [flag, home] if flag == "--home" && !home.is_empty() => Some(home.into()),
        _ => None,
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The ASL desktop viewer requires Windows.");
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn explicit_home_overrides_inherited_home_for_a_desktop_shortcut() {
        let home = r"E:\ASL\profile with spaces";
        let args = ["--home".into(), home.into()];
        assert_eq!(
            data_home(&args, Some(r"F:\another-profile".into())),
            Some(PathBuf::from(home))
        );
    }

    #[test]
    fn missing_or_invalid_home_does_not_silently_switch_profiles() {
        let configured = r"E:\ASL\profile".into();
        assert_eq!(data_home(&[], None), None);
        assert_eq!(data_home(&[], Some(OsString::new())), None);
        assert_eq!(data_home(&["--home".into()], Some(configured)), None);
    }

    #[test]
    fn launcher_environment_still_opens_the_configured_profile() {
        let home = r"E:\ASL\profile";
        assert_eq!(data_home(&[], Some(home.into())), Some(home.into()));
    }
}
