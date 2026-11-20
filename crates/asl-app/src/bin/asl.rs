fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = match args.as_slice() {
        [] => asl_app::supervisor::run_from_environment(),
        #[cfg(windows)]
        [command, flag, home] if command == "mcp" && flag == "--home" => {
            asl_app::mcp::run_stdio(home.into())
        }
        _ => Err(asl_types::error::AslError::InvalidMessage),
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
