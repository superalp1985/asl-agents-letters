use asl_agent::QueryScope;
use asl_types::protocol::{ASL_PROTOCOL_MAJOR, ASL_PROTOCOL_MINOR};
use serde_json::{Value, json};

use crate::network_identity::NetworkAdmissionStatus;

pub(super) fn report(
    admission: NetworkAdmissionStatus,
    scope: QueryScope,
    push: bool,
    recovery: bool,
    capabilities: &Value,
) -> Value {
    let (readiness, next_step) = match admission {
        NetworkAdmissionStatus::TrustConfigurationMissing => (
            "network_profile_missing",
            "configure_trusted_network_profile",
        ),
        NetworkAdmissionStatus::DeviceDirectoryMissing => {
            ("device_directory_missing", "complete_device_registration")
        }
        NetworkAdmissionStatus::DeviceDirectoryUnavailable => (
            "device_directory_unavailable",
            "restore_signed_device_directory",
        ),
        NetworkAdmissionStatus::ChainUnavailable => {
            ("network_unavailable", "retry_when_network_is_available")
        }
        NetworkAdmissionStatus::RegistryAnchorMissing => {
            ("registration_required", "complete_identity_registration")
        }
        NetworkAdmissionStatus::Active => ("network_ready", "none"),
    };
    let mut available = vec!["query"];
    if !recovery {
        available.push("fetch");
    }
    if push {
        available.push("inbound_events");
    }
    for name in [
        "send_expression",
        "send_context_expression",
        "request_context",
        "act_history",
        "receive_offer",
        "task_recovery",
        "recovery_query",
        "recovery_results",
        "recovery_download",
        "recovery_download_decision",
    ] {
        if capabilities[name] == true {
            available.push(name);
        }
    }
    json!({
        "schema": "asl-agent-bootstrap-v1",
        "schema_version": 1,
        "protocol_version": { "major": ASL_PROTOCOL_MAJOR, "minor": ASL_PROTOCOL_MINOR },
        "local_identity": "ready",
        "network_readiness": readiness,
        "next_step": next_step,
        "query_scope": match scope {
            QueryScope::ContactsOnly => "contacts_only",
            QueryScope::Public => "public",
        },
        "available_capabilities": available,
    })
}
