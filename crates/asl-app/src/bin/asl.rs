fn main() {
    if let Err(error) = asl_app::supervisor::run_from_environment() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
