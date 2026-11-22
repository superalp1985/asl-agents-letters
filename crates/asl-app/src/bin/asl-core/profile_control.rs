use std::{env, ffi::OsString, path::PathBuf};

use asl_app::{identity::AgentIdentity, paths::AppPaths};
use asl_policy::snapshot_files::PinnedHome;
use asl_store::{open_store, open_store_read_only};
use asl_types::error::AslError;

pub(super) fn run(args: &[OsString]) -> Result<(), AslError> {
    let home = PathBuf::from(env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?);
    let paths = AppPaths::open_existing(&home)?;
    let _pin = PinnedHome::open(&home)?;
    let database = paths.state().join("asl.sqlite3");
    match args {
        [action] if action == "status" => {
            let store = open_store_read_only(&database)?;
            let json = serde_json::to_string(&store.profile_signing_status()?)
                .map_err(|_| AslError::InvalidPolicyState)?;
            println!("{json}");
            Ok(())
        }
        [action] if action == "revoke" => {
            let mut store = open_store(&database)?;
            store.revoke_profile_signing_approval()
        }
        [action, reviewed_agent, topics @ ..]
            if action == "approve-local-signing" || action == "approve-publication" =>
        {
            let topics = parse_topics(topics)?;
            let identity = AgentIdentity::load_protected(&paths.agent_root_key())?;
            let agent_id = identity.agent_id();
            let current = bs58::encode(agent_id.as_bytes()).into_string();
            if reviewed_agent.to_str() != Some(current.as_str()) {
                return Err(AslError::InvalidIdentity);
            }
            let mut store = open_store(&database)?;
            if action == "approve-publication" {
                store.approve_profile_publication(agent_id, topics)
            } else {
                store.set_profile_signing_approval(agent_id, topics)
            }
        }
        _ => Err(AslError::InvalidMessage),
    }
}

fn parse_topics(topics: &[OsString]) -> Result<Vec<u32>, AslError> {
    topics
        .iter()
        .map(|topic| {
            topic
                .to_str()
                .and_then(|topic| topic.parse().ok())
                .ok_or(AslError::InvalidMessage)
        })
        .collect()
}
