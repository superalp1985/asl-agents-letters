#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
#[path = "../ui/mod.rs"]
mod ui;

#[cfg(windows)]
fn main() -> eframe::Result {
    ui::run(std::env::var_os("ASL_HOME").map(Into::into))
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The ASL desktop viewer requires Windows.");
}
