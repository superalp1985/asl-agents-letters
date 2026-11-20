#[path = "asl-core/download_control.rs"]
mod download_control;

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = match args.as_slice() {
        [] => asl_app::supervisor::run_from_environment(),
        [flag, mode] if flag == "--direct-inbound" => mode
            .to_str()
            .ok_or(asl_types::error::AslError::InvalidMessage)
            .and_then(asl_app::supervisor::set_direct_inbound_from_environment),
        [flag, args @ ..] if flag == "--downloads" => download_control::run(args),
        _ => Err(asl_types::error::AslError::InvalidMessage),
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
