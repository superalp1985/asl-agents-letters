use std::{env, ffi::OsString, path::PathBuf};

use asl_app::{model_endpoint_access::ModelEndpointAccess, paths::AppPaths};
use asl_types::error::AslError;

pub(super) fn run(args: &[OsString]) -> Result<(), AslError> {
    let home = PathBuf::from(env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?);
    let access = ModelEndpointAccess::new(&AppPaths::open_existing(&home)?);
    match args {
        [action] if action == "list" => {
            let status =
                serde_json::to_string(&access.list()?).map_err(|_| AslError::InvalidPolicyState)?;
            println!("{status}");
            Ok(())
        }
        [action, id, fingerprint] if action == "allow" => access.allow(
            id.to_str().ok_or(AslError::InvalidMessage)?,
            fingerprint.to_str().ok_or(AslError::InvalidMessage)?,
        ),
        [action, id] if action == "revoke" => {
            access.revoke(id.to_str().ok_or(AslError::InvalidMessage)?)
        }
        _ => Err(AslError::InvalidMessage),
    }
}
