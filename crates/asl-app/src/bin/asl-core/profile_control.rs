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
        [action, target] if action == "lookup" => {
            let target = super::bindings_control::parse_agent(
                target.to_str().ok_or(AslError::InvalidMessage)?,
            )?;
            if AgentIdentity::load_protected(&paths.agent_root_key())?.agent_id() == target {
                return Err(AslError::PolicyDenied);
            }
            let request = open_store(&database)?.request_profile_lookup(target, rand::random())?;
            println!("{}", lookup_json(&request));
            Ok(())
        }
        [action] if action == "lookup-status" => {
            let status = open_store_read_only(&database)?.profile_lookup_status()?;
            println!("{}", serde_json::json!(status.as_ref().map(lookup_json)));
            Ok(())
        }
        [action] if action == "received" => {
            println!(
                "{}",
                serde_json::json!(open_store_read_only(&database)?.visible_remote_profiles()?)
            );
            Ok(())
        }
        [action] if action == "status" => {
            let store = open_store_read_only(&database)?;
            let json = serde_json::to_string(&store.profile_signing_status()?)
                .map_err(|_| AslError::InvalidPolicyState)?;
            println!("{json}");
            Ok(())
        }
        [action] if action == "revoke" => {
            let mut store = open_store(&database)?;
            store.revoke_profile_signing_approval()?;
            report_change(&store)
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
            }?;
            report_change(&store)
        }
        _ => Err(AslError::InvalidMessage),
    }
}

fn lookup_json(request: &asl_store::profile_lookup::ProfileLookup) -> serde_json::Value {
    serde_json::json!({"target": bs58::encode(request.target.as_bytes()).into_string(), "state": request.state, "expires_ms":request.expires_ms})
}

fn report_change(store: &asl_store::Store) -> Result<(), AslError> {
    println!(
        "{}",
        if store.profile_signing_status()?.change_pending {
            r#"{"status":"pending_network_drain"}"#
        } else {
            r#"{"status":"applied"}"#
        }
    );
    Ok(())
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
