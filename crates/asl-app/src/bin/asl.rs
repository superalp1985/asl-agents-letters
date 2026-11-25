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
        [command, setup_args @ ..] if command == "setup" => {
            #[cfg(windows)]
            {
                asl_app::profile_setup::run(setup_args)
            }
            #[cfg(not(windows))]
            {
                Err(asl_types::error::AslError::PlatformUnavailable)
            }
        }
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
