#[cfg(windows)]
#[path = "asl/portable.rs"]
mod portable;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), asl_types::error::AslError> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => asl_app::supervisor::run_from_environment(),
        #[cfg(windows)]
        [command, flag, home] if command == "mcp" && flag == "--home" => {
            match portable::active_agent()? {
                Some(executable) => {
                    let status = std::process::Command::new(executable)
                        .args(&args)
                        .status()?;
                    std::process::exit(status.code().unwrap_or(1));
                }
                None => asl_app::mcp::run_stdio(home.into()),
            }
        }
        _ => Err(asl_types::error::AslError::InvalidMessage),
    }
}
