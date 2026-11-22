#[path = "asl-core/access_control.rs"]
mod access_control;
#[path = "asl-core/bindings_control.rs"]
mod bindings_control;
#[path = "asl-core/checkpoint_control.rs"]
mod checkpoint_control;
#[path = "asl-core/download_control.rs"]
mod download_control;
#[cfg(windows)]
#[path = "asl-core/group_control.rs"]
mod group_control;
#[path = "asl-core/network_control.rs"]
mod network_control;
#[path = "asl-core/provider_control.rs"]
mod provider_control;
#[path = "asl-core/retention_control.rs"]
mod retention_control;
#[path = "asl-core/upload_control.rs"]
mod upload_control;

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = match args.as_slice() {
        [] => asl_app::supervisor::run_from_environment(),
        [flag, mode] if flag == "--direct-inbound" => mode
            .to_str()
            .ok_or(asl_types::error::AslError::InvalidMessage)
            .and_then(asl_app::supervisor::set_direct_inbound_from_environment),
        [flag, args @ ..] if flag == "--downloads" => download_control::run(args),
        [flag, args @ ..] if flag == "--access" => access_control::run(args),
        [flag, args @ ..] if flag == "--bindings" => bindings_control::run(args),
        [flag, args @ ..] if flag == "--checkpoint" => checkpoint_control::run(args),
        [flag, args @ ..] if flag == "--uploads" => upload_control::run(args),
        [flag, args @ ..] if flag == "--providers" => provider_control::run(args),
        [flag, kind, days] if flag == "--retention" => retention_control::set_days(kind, days),
        [flag, key, mode] if flag == "--network" && key == "relay-only" => {
            network_control::set_relay_only(mode)
        }
        [flag, key, mode] if flag == "--network" && key == "pause" => {
            network_control::set_pause(mode)
        }
        #[cfg(windows)]
        [flag, field, value] if flag == "--group-inbound" => {
            group_control::set_inbound(field, value)
        }
        #[cfg(windows)]
        [flag] if flag == "--groups" => group_control::run(),
        _ => Err(asl_types::error::AslError::InvalidMessage),
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
