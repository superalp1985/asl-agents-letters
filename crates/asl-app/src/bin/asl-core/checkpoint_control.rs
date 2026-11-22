use std::{
    env,
    ffi::{OsStr, OsString},
    path::PathBuf,
};

use asl_app::{checkpoint_access, paths::AppPaths};
use asl_types::error::AslError;

pub(super) fn run(args: &[OsString]) -> Result<(), AslError> {
    let home = PathBuf::from(env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?);
    let paths = AppPaths::open_existing(&home)?;
    match args {
        [action] if action == "status" => {
            let status = serde_json::to_string(&checkpoint_access::status(&paths)?)
                .map_err(|_| AslError::InvalidPolicyState)?;
            println!("{status}");
            Ok(())
        }
        [action, context, slot, root] if action == "stage" => {
            let candidate = checkpoint_access::parse_candidate(text(slot)?, text(root)?)?;
            checkpoint_access::stage(&paths, text(context)?, candidate)
        }
        [action] if action == "cancel" => checkpoint_access::cancel(&paths),
        _ => Err(AslError::InvalidMessage),
    }
}

fn text(value: &OsStr) -> Result<&str, AslError> {
    value.to_str().ok_or(AslError::InvalidMessage)
}
