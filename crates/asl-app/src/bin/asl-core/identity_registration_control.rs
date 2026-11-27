use std::{env, ffi::OsString, path::PathBuf};

use asl_app::{
    identity::{AgentIdentity, DeviceIdentity},
    identity_registration::{
        IdentityRegistrationRequest, default_deadline, prepare_device_directory,
    },
    network_identity::NetworkIdentityConfigurationV1,
    paths::AppPaths,
};
use asl_types::error::AslError;
use serde_json::{Value, json};

pub(super) fn run(args: &[OsString]) -> Result<(), AslError> {
    let args = args
        .iter()
        .map(|arg| arg.to_str().ok_or(AslError::InvalidMessage))
        .collect::<Result<Vec<_>, _>>()?;
    if let ["submit", rpc_url, raw_transaction] = args.as_slice() {
        return submit_raw_transaction(rpc_url, raw_transaction);
    }
    if let ["wait", rpc_url, transaction_hash] = args.as_slice() {
        return wait_for_transaction(rpc_url, transaction_hash);
    }
    let root = PathBuf::from(env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?);
    let paths = AppPaths::open_existing(&root)?;
    let identity = AgentIdentity::load_protected(&paths.agent_root_key())?;
    if let ["prepare-directory"] = args.as_slice() {
        return prepare_directory(&paths, &identity, 1);
    }
    if let ["prepare-directory", sequence] = args.as_slice() {
        let sequence = sequence
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or(AslError::InvalidMessage)?;
        return prepare_directory(&paths, &identity, sequence);
    }
    let configuration =
        NetworkIdentityConfigurationV1::load(&paths.network_identity_configuration())?
            .ok_or(AslError::InvalidIdentity)?;

    let request = match args.as_slice() {
        ["bootstrap"] => {
            if std::fs::symlink_metadata(paths.signed_device_directory()).is_err() {
                prepare_directory(&paths, &identity, 1)?;
            }
            IdentityRegistrationRequest::build(
                &identity,
                configuration.resolver.deployment,
                directory_commitment(&paths)?,
                default_deadline()?,
            )?
        }
        ["request"] => IdentityRegistrationRequest::build(
            &identity,
            configuration.resolver.deployment,
            directory_commitment(&paths)?,
            default_deadline()?,
        )?,
        ["request", commitment] => IdentityRegistrationRequest::build(
            &identity,
            configuration.resolver.deployment,
            parse_hex32(commitment)?,
            default_deadline()?,
        )?,
        ["request", commitment, deadline] => IdentityRegistrationRequest::build(
            &identity,
            configuration.resolver.deployment,
            parse_hex32(commitment)?,
            parse_deadline(deadline)?,
        )?,
        ["update", sequence, commitment, deadline] => IdentityRegistrationRequest::build_update(
            &identity,
            configuration.resolver.deployment,
            parse_hex32(commitment)?,
            sequence
                .parse::<u64>()
                .ok()
                .ok_or(AslError::InvalidMessage)?,
            parse_deadline(deadline)?,
        )?,
        ["revoke", sequence, deadline] => IdentityRegistrationRequest::build_revoke(
            &identity,
            configuration.resolver.deployment,
            sequence
                .parse::<u64>()
                .ok()
                .ok_or(AslError::InvalidMessage)?,
            parse_deadline(deadline)?,
        )?,
        _ => return Err(AslError::InvalidMessage),
    };
    println!(
        "{}",
        serde_json::to_string(&request).map_err(|_| AslError::InvalidMessage)?
    );
    Ok(())
}

fn submit_raw_transaction(rpc_url: &str, raw_transaction: &str) -> Result<(), AslError> {
    let url = reqwest::Url::parse(rpc_url).map_err(|_| AslError::InvalidMessage)?;
    if url.scheme() != "https"
        && !(url.scheme() == "http"
            && url
                .host_str()
                .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost")))
    {
        return Err(AslError::InvalidIdentity);
    }
    let raw = raw_transaction
        .strip_prefix("0x")
        .unwrap_or(raw_transaction);
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return Err(AslError::InvalidMessage);
    }
    alloy_primitives::hex::decode(raw).map_err(|_| AslError::InvalidMessage)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| AslError::SandboxUnavailable)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| AslError::SandboxUnavailable)?;
    let response = runtime.block_on(async {
        client
            .post(url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": "asl-identity-registration",
                "method": "eth_sendRawTransaction",
                "params": [format!("0x{raw}")]
            }))
            .send()
            .await
            .map_err(|_| AslError::SandboxUnavailable)
    })?;
    let status = response.status();
    let body: Value = runtime
        .block_on(response.json())
        .map_err(|_| AslError::InvalidMessage)?;
    if !status.is_success() || body.get("error").is_some() {
        return Err(AslError::PolicyDenied);
    }
    println!(
        "{}",
        serde_json::to_string(&body).map_err(|_| AslError::InvalidMessage)?
    );
    Ok(())
}

fn wait_for_transaction(rpc_url: &str, transaction_hash: &str) -> Result<(), AslError> {
    let url = rpc_url_for_cli(rpc_url)?;
    let hash = transaction_hash
        .strip_prefix("0x")
        .unwrap_or(transaction_hash);
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AslError::InvalidMessage);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| AslError::SandboxUnavailable)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| AslError::SandboxUnavailable)?;
    runtime.block_on(async {
        for _ in 0..150 {
            let response = client
                .post(url.clone())
                .json(&json!({
                    "jsonrpc": "2.0",
                    "id": "asl-identity-registration-wait",
                    "method": "eth_getTransactionReceipt",
                    "params": [format!("0x{hash}")]
                }))
                .send()
                .await
                .map_err(|_| AslError::SandboxUnavailable)?;
            let body: Value = response
                .json()
                .await
                .map_err(|_| AslError::InvalidMessage)?;
            if let Some(receipt) = body.get("result").and_then(Value::as_object) {
                let status = receipt
                    .get("status")
                    .and_then(Value::as_str)
                    .ok_or(AslError::InvalidMessage)?;
                match status {
                    "0x1" => {
                        println!(
                            "{}",
                            serde_json::to_string(&body).map_err(|_| AslError::InvalidMessage)?
                        );
                        return Ok(());
                    }
                    "0x0" => return Err(AslError::PolicyDenied),
                    _ => return Err(AslError::InvalidMessage),
                }
            }
            if body.get("error").is_some() {
                return Err(AslError::PolicyDenied);
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        Err(AslError::ExpiredMessage)
    })
}

fn rpc_url_for_cli(rpc_url: &str) -> Result<reqwest::Url, AslError> {
    let url = reqwest::Url::parse(rpc_url).map_err(|_| AslError::InvalidMessage)?;
    if url.scheme() != "https"
        && !(url.scheme() == "http"
            && url
                .host_str()
                .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost")))
    {
        return Err(AslError::InvalidIdentity);
    }
    Ok(url)
}

fn directory_commitment(paths: &AppPaths) -> Result<[u8; 32], AslError> {
    let bytes = std::fs::read(paths.signed_device_directory())?;
    let record = asl_types::record::decode_record(&bytes)?;
    let asl_types::record::RecordPayload::DeviceDirectory(directory) = record.record.payload else {
        return Err(AslError::InvalidIdentity);
    };
    Ok(asl_types::record::device_directory_commitment(&directory)?.0)
}

fn prepare_directory(
    paths: &AppPaths,
    identity: &AgentIdentity,
    registry_sequence: u64,
) -> Result<(), AslError> {
    let device = DeviceIdentity::load_protected(&paths.device_key())?;
    let (bytes, commitment) =
        prepare_device_directory(identity, &device, registry_sequence, now_millis()?)?;
    let path = paths.signed_device_directory();
    if std::fs::symlink_metadata(&path).is_ok() {
        return Err(AslError::PolicyDenied);
    }
    std::fs::write(&path, bytes)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "asl-device-directory-preparation-v1",
            "registry_sequence": registry_sequence,
            "state_commitment": format!("0x{}", alloy_primitives::hex::encode(commitment)),
            "directory": path.to_string_lossy()
        }))
        .map_err(|_| AslError::InvalidMessage)?
    );
    Ok(())
}

fn now_millis() -> Result<u64, AslError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AslError::ExpiredMessage)?
        .as_millis()
        .try_into()
        .map_err(|_| AslError::InvalidMessage)
}

fn parse_hex32(value: &str) -> Result<[u8; 32], AslError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != 64 {
        return Err(AslError::InvalidMessage);
    }
    let mut bytes = [0; 32];
    alloy_primitives::hex::decode_to_slice(value, &mut bytes)
        .map_err(|_| AslError::InvalidMessage)?;
    Ok(bytes)
}

fn parse_deadline(value: &str) -> Result<u64, AslError> {
    value
        .parse::<u64>()
        .ok()
        .filter(|deadline| *deadline > 0)
        .ok_or(AslError::InvalidMessage)
}
