#[path = "asl-core/access_control.rs"]
mod access_control;
#[path = "asl-core/act_history_control.rs"]
mod act_history_control;
#[path = "asl-core/avatar_control.rs"]
mod avatar_control;
#[path = "asl-core/bindings_control.rs"]
mod bindings_control;
#[path = "asl-core/checkpoint_control.rs"]
mod checkpoint_control;
#[path = "asl-core/contact_invite_control.rs"]
mod contact_invite_control;
#[path = "asl-core/download_control.rs"]
mod download_control;
#[cfg(windows)]
#[path = "asl-core/group_admin.rs"]
mod group_admin;
#[cfg(windows)]
#[path = "asl-core/group_control.rs"]
mod group_control;
#[path = "asl-core/identity_registration_control.rs"]
mod identity_registration_control;
#[cfg(windows)]
#[path = "asl-core/migration_control.rs"]
mod migration_control;
#[path = "asl-core/network_control.rs"]
mod network_control;
#[path = "asl-core/profile_control.rs"]
mod profile_control;
#[path = "asl-core/provider_control.rs"]
mod provider_control;
#[path = "asl-core/retention_control.rs"]
mod retention_control;
#[path = "asl-core/upload_control.rs"]
mod upload_control;

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = match args.as_slice() {
        [flag] if flag == "--version" => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [flag, output] if flag == "--initialize-profile" && output == "--json" => {
            asl_app::profile_setup::initialize_core_profile(true)
        }
        [flag, output] if flag == "--initialize-profile" && output == "--text" => {
            asl_app::profile_setup::initialize_core_profile(false)
        }
        [flag] if flag == "--initialize-profile" => {
            asl_app::profile_setup::initialize_core_profile(false)
        }
        [] => asl_app::supervisor::run_from_environment(),
        [flag, mode] if flag == "--direct-inbound" => mode
            .to_str()
            .ok_or(asl_types::error::AslError::InvalidMessage)
            .and_then(asl_app::supervisor::set_direct_inbound_from_environment),
        [flag, args @ ..] if flag == "--downloads" => download_control::run(args),
        [flag, args @ ..] if flag == "--access" => access_control::run(args),
        [flag, args @ ..] if flag == "--act-history" => act_history_control::run(args),
        [flag, args @ ..] if flag == "--avatar" => avatar_control::run(args),
        [flag, args @ ..] if flag == "--bindings" => bindings_control::run(args),
        [flag, args @ ..] if flag == "--contact-invites" => contact_invite_control::run(args),
        [flag, args @ ..] if flag == "--checkpoint" => checkpoint_control::run(args),
        [flag, args @ ..] if flag == "--profile" => profile_control::run(args),
        [flag, args @ ..] if flag == "--identity-registration" => {
            identity_registration_control::run(args)
        }
        [flag, args @ ..] if flag == "--uploads" => upload_control::run(args),
        [flag, args @ ..] if flag == "--providers" => provider_control::run(args),
        [flag, destination] if flag == "--diagnostics" => export_diagnostics(destination),
        [flag, key, manifest, signature, package] if flag == "--verify-update" => {
            use std::path::Path;
            asl_app::update::verify_local_package(
                Path::new(key),
                Path::new(manifest),
                Path::new(signature),
                Path::new(package),
            )
            .map(|version| println!("{version}"))
        }
        [flag, key, manifest, signature, package, installed]
            if flag == "--verify-update-receipt" =>
        {
            use std::path::Path;
            installed
                .to_str()
                .ok_or(asl_types::error::AslError::InvalidMessage)
                .and_then(|installed| {
                    asl_app::update::verify_local_receipt(
                        Path::new(key),
                        Path::new(manifest),
                        Path::new(signature),
                        Path::new(package),
                        installed,
                    )
                })
                .and_then(|receipt| {
                    println!(
                        "{}",
                        serde_json::to_string(&receipt).map_err(std::io::Error::other)?
                    );
                    Ok(())
                })
        }
        #[cfg(windows)]
        [flag, args @ ..] if flag == "--migration" => migration_control::run(args),
        [flag, kind, days] if flag == "--retention" => retention_control::set_days(kind, days),
        [flag, key, mode] if flag == "--network" && key == "relay-only" => {
            network_control::set_relay_only(mode)
        }
        [flag, key, mode] if flag == "--network" && key == "pause" => {
            network_control::set_pause(mode)
        }
        [flag, args @ ..] if flag == "--network" => network_control::configure(args),
        #[cfg(windows)]
        [flag, field, value] if flag == "--group-inbound" => {
            group_control::set_inbound(field, value)
        }
        #[cfg(windows)]
        [flag, args @ ..] if flag == "--group-admin" => group_admin::run(args),
        #[cfg(windows)]
        [flag, args @ ..] if flag == "--group-invites" => group_control::review(args),
        #[cfg(windows)]
        [flag] if flag == "--groups" => group_control::run(),
        _ => Err(asl_types::error::AslError::InvalidMessage),
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn export_diagnostics(destination: &std::ffi::OsStr) -> Result<(), asl_types::error::AslError> {
    let root =
        std::env::var_os("ASL_HOME").ok_or(asl_types::error::AslError::InvalidStorageRoot)?;
    let paths = asl_app::paths::AppPaths::open_existing(std::path::Path::new(&root))?;
    asl_app::diagnostics::export(&paths, std::path::Path::new(destination))
}
