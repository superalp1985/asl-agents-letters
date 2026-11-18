#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    if let Err(error) = asl_app::ipc::run_net_child() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
