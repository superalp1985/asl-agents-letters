use std::{env, ffi::OsStr, fs, path::PathBuf};

use asl_app::{
    network_settings::{NetworkAddressScopeV1, NetworkSettingsV1},
    paths::AppPaths,
};
use asl_policy::snapshot_files::PinnedHome;
use asl_store::open_store;
use asl_types::error::AslError;

pub(super) fn set_relay_only(mode: &OsStr) -> Result<(), AslError> {
    set_network_flag(mode, |paths, store, enabled| {
        if enabled {
            NetworkSettingsV1::load(&paths.network_settings_configuration())?
                .with_relay_only_override(true)?;
        }
        store.set_force_relay_only(enabled)
    })
}

pub(super) fn set_pause(mode: &OsStr) -> Result<(), AslError> {
    set_network_flag(mode, |_, store, enabled| {
        store.set_network_pause_requested(enabled)
    })
}

pub(super) fn configure(args: &[std::ffi::OsString]) -> Result<(), AslError> {
    let args = args
        .iter()
        .map(|arg| arg.to_str().ok_or(AslError::InvalidMessage))
        .collect::<Result<Vec<_>, _>>()?;
    let home = PathBuf::from(env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?);
    let paths = AppPaths::open_existing(&home)?;
    let path = paths.network_settings_configuration();
    let mut settings = NetworkSettingsV1::load(&path)?;

    match args.as_slice() {
        [] | ["status"] => {
            println!(
                "{}",
                serde_json::to_string(&settings).map_err(|_| AslError::InvalidMessage)?
            );
            return Ok(());
        }
        ["scope", scope] => settings.address_scope = parse_scope(scope)?,
        ["listen", mode, tcp, quic] => {
            settings.listen_on_interfaces = parse_on_off(mode)?;
            settings.tcp_port = parse_port(tcp)?;
            settings.quic_port = parse_port(quic)?;
        }
        ["groups", mode] => settings.loopback_groups = parse_on_off(mode)?,
        ["bootstrap", operation, address] => {
            let policy = settings.address_policy();
            mutate_address_list(
                &mut settings.bootstrap_multiaddrs,
                operation,
                address,
                policy,
            )?;
        }
        ["relay", operation, address] => {
            mutate_relay_list(&mut settings.relay_addresses, operation, address)?;
        }
        _ => return Err(AslError::InvalidMessage),
    }
    settings.validate()?;
    fs::write(
        &path,
        serde_json::to_vec_pretty(&settings).map_err(|_| AslError::InvalidMessage)?,
    )?;
    println!(
        "{}",
        serde_json::to_string(&settings).map_err(|_| AslError::InvalidMessage)?
    );
    Ok(())
}

fn parse_scope(value: &str) -> Result<NetworkAddressScopeV1, AslError> {
    match value {
        "loopback" => Ok(NetworkAddressScopeV1::LoopbackOnly),
        "lan" => Ok(NetworkAddressScopeV1::LanOnly),
        "internet" => Ok(NetworkAddressScopeV1::InternetOnly),
        "hybrid" => Ok(NetworkAddressScopeV1::Hybrid),
        "relay" => Ok(NetworkAddressScopeV1::RelayOnly),
        _ => Err(AslError::InvalidMessage),
    }
}

fn parse_on_off(value: &str) -> Result<bool, AslError> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(AslError::InvalidMessage),
    }
}

fn parse_port(value: &str) -> Result<u16, AslError> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or(AslError::InvalidMessage)
}

fn mutate_address_list(
    addresses: &mut Vec<String>,
    operation: &str,
    address: &str,
    policy: asl_net::address_policy::AddressPolicy,
) -> Result<(), AslError> {
    asl_net::transport::parse_bootstrap_multiaddr(address, policy)
        .map_err(|_| AslError::InvalidMessage)?;
    mutate_list(addresses, operation, address)
}

fn mutate_relay_list(
    addresses: &mut Vec<String>,
    operation: &str,
    address: &str,
) -> Result<(), AslError> {
    asl_net::relay::relay_endpoint_config(address).map_err(|_| AslError::InvalidMessage)?;
    mutate_list(addresses, operation, address)
}

fn mutate_list(
    addresses: &mut Vec<String>,
    operation: &str,
    address: &str,
) -> Result<(), AslError> {
    match operation {
        "add" if !addresses.iter().any(|item| item == address) => {
            addresses.push(address.to_owned());
        }
        "remove" => {
            addresses.retain(|item| item != address);
        }
        "add" => {}
        _ => return Err(AslError::InvalidMessage),
    }
    Ok(())
}

fn set_network_flag(
    mode: &OsStr,
    set: impl FnOnce(&AppPaths, asl_store::Store, bool) -> Result<(), AslError>,
) -> Result<(), AslError> {
    let enabled = match mode.to_str() {
        Some("on") => true,
        Some("off") => false,
        _ => return Err(AslError::InvalidMessage),
    };
    let home = PathBuf::from(env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?);
    let paths = AppPaths::open_existing(&home)?;
    let _pin = PinnedHome::open(&home)?;
    set(
        &paths,
        open_store(&paths.state().join("asl.sqlite3"))?,
        enabled,
    )
}
