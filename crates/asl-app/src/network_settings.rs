use std::{
    fs::{self, File},
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
};

use asl_net::address_policy::AddressPolicy;
use asl_net::relay::{MAX_RELAY_ENDPOINT_BYTES, relay_endpoint_config};
use asl_net::transport::parse_bootstrap_multiaddr;
use asl_types::error::AslError;
use serde::{Deserialize, Serialize};

const MAX_NETWORK_SETTINGS_BYTES: u64 = 16_384;
const MAX_BOOTSTRAP_ADDRESSES: usize = 32;
const MAX_BOOTSTRAP_NODES: usize = 32;
const MAX_BOOTSTRAP_ADDRESSES_PER_NODE: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAddressScopeV1 {
    LoopbackOnly,
    LanOnly,
    InternetOnly,
    Hybrid,
    RelayOnly,
}

impl From<NetworkAddressScopeV1> for AddressPolicy {
    fn from(scope: NetworkAddressScopeV1) -> Self {
        match scope {
            NetworkAddressScopeV1::LoopbackOnly => Self::LoopbackOnly,
            NetworkAddressScopeV1::LanOnly => Self::LanOnly,
            NetworkAddressScopeV1::InternetOnly => Self::InternetOnly,
            NetworkAddressScopeV1::Hybrid => Self::Hybrid,
            NetworkAddressScopeV1::RelayOnly => Self::RelayOnly,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSettingsV1 {
    pub version: u16,
    pub address_scope: NetworkAddressScopeV1,
    pub listen_on_interfaces: bool,
    pub tcp_port: u16,
    pub quic_port: u16,
    #[serde(default)]
    pub relay_addresses: Vec<String>,
    #[serde(default)]
    pub bootstrap_multiaddrs: Vec<String>,
    /// Compatibility key name. This enables group streams for the configured
    /// address scope; it is not restricted to loopback.
    #[serde(default)]
    pub loopback_groups: bool,
}

impl Default for NetworkSettingsV1 {
    fn default() -> Self {
        Self {
            version: 1,
            address_scope: NetworkAddressScopeV1::LoopbackOnly,
            listen_on_interfaces: false,
            tcp_port: 0,
            quic_port: 0,
            relay_addresses: Vec::new(),
            bootstrap_multiaddrs: Vec::new(),
            loopback_groups: false,
        }
    }
}

impl NetworkSettingsV1 {
    pub fn load(path: &Path) -> Result<Self, AslError> {
        let Some(bytes) = read_optional_file(path)? else {
            return Ok(Self::default());
        };
        let settings: Self =
            serde_json::from_slice(&bytes).map_err(|_| AslError::InvalidIdentity)?;
        if settings.version != 1 {
            return Err(AslError::InvalidIdentity);
        }
        settings.validate()?;
        Ok(settings)
    }

    pub fn address_policy(&self) -> AddressPolicy {
        self.address_scope.into()
    }

    pub fn with_relay_only_override(mut self, enabled: bool) -> Result<Self, AslError> {
        if enabled {
            self.address_scope = NetworkAddressScopeV1::RelayOnly;
            self.listen_on_interfaces = false;
            self.bootstrap_multiaddrs.clear();
        }
        self.validate()?;
        Ok(self)
    }

    pub fn listener_address(&self, port: u16) -> SocketAddr {
        let ip = match self.address_scope {
            NetworkAddressScopeV1::LoopbackOnly => Ipv4Addr::LOCALHOST,
            NetworkAddressScopeV1::LanOnly
            | NetworkAddressScopeV1::InternetOnly
            | NetworkAddressScopeV1::Hybrid
            | NetworkAddressScopeV1::RelayOnly => Ipv4Addr::UNSPECIFIED,
        };
        SocketAddr::new(IpAddr::V4(ip), port)
    }

    pub fn validate(&self) -> Result<(), AslError> {
        const MAX_RELAY_ADDRESSES: usize = 8;
        if self.relay_addresses.len() > MAX_RELAY_ADDRESSES
            || self.bootstrap_multiaddrs.len() > MAX_BOOTSTRAP_ADDRESSES
            || self
                .relay_addresses
                .iter()
                .any(|address| address.len() > MAX_RELAY_ENDPOINT_BYTES)
            || (self.address_scope == NetworkAddressScopeV1::RelayOnly
                && (self.listen_on_interfaces || self.relay_addresses.is_empty()))
        {
            return Err(AslError::InvalidIdentity);
        }
        let mut unique = std::collections::HashSet::new();
        for address in &self.relay_addresses {
            let parsed = relay_endpoint_config(address).map_err(|_| AslError::InvalidIdentity)?;
            if !unique.insert(parsed) {
                return Err(AslError::InvalidIdentity);
            }
        }
        for address in &self.bootstrap_multiaddrs {
            parse_bootstrap_multiaddr(address, self.address_policy())
                .map_err(|_| AslError::InvalidIdentity)?;
        }
        Ok(())
    }

    /// Explicit settings win over a packaged seed file. The seed file is
    /// intentionally empty in this repository until real operators publish it.
    pub fn apply_packaged_bootstrap(&mut self, path: &Path, now_ms: u64) -> Result<(), AslError> {
        if !self.bootstrap_multiaddrs.is_empty() {
            return Ok(());
        }
        let Some(bytes) = read_optional_file(path)? else {
            return Ok(());
        };
        let seeds: NetworkSeedsV1 =
            serde_json::from_slice(&bytes).map_err(|_| AslError::InvalidIdentity)?;
        seeds.validate(now_ms)?;
        for node in seeds.nodes {
            for address in node.multiaddrs {
                let (peer, _, _) = match parse_bootstrap_multiaddr(&address, self.address_policy())
                {
                    Ok(endpoint) => endpoint,
                    Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => continue,
                    Err(_) => return Err(AslError::InvalidIdentity),
                };
                if peer
                    != asl_types::ids::PeerId::from_bytes(
                        bs58::decode(&node.peer_id)
                            .into_vec()
                            .map_err(|_| AslError::InvalidIdentity)?,
                    )
                    .map_err(|_| AslError::InvalidIdentity)?
                {
                    return Err(AslError::InvalidIdentity);
                }
                self.bootstrap_multiaddrs.push(address);
            }
        }
        self.validate()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkSeedsV1 {
    version: u16,
    network_id: String,
    generated_at_ms: u64,
    expires_at_ms: u64,
    nodes: Vec<NetworkSeedNodeV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkSeedNodeV1 {
    operator_id: String,
    peer_id: String,
    multiaddrs: Vec<String>,
    roles: Vec<String>,
}

impl NetworkSeedsV1 {
    fn validate(&self, now_ms: u64) -> Result<(), AslError> {
        if self.version != 1
            || self.network_id.is_empty()
            || self.network_id.len() > 128
            || self.generated_at_ms > now_ms
            || self.expires_at_ms <= now_ms
            || self.nodes.is_empty()
            || self.nodes.len() > MAX_BOOTSTRAP_NODES
        {
            return Err(AslError::InvalidIdentity);
        }
        for node in &self.nodes {
            if node.operator_id.is_empty()
                || node.operator_id.len() > 128
                || node.multiaddrs.is_empty()
                || node.multiaddrs.len() > MAX_BOOTSTRAP_ADDRESSES_PER_NODE
                || !node.roles.iter().any(|role| role == "bootstrap")
            {
                return Err(AslError::InvalidIdentity);
            }
        }
        Ok(())
    }
}

fn read_optional_file(path: &Path) -> Result<Option<Vec<u8>>, AslError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_NETWORK_SETTINGS_BYTES {
        return Err(AslError::InvalidIdentity);
    }
    let file = File::open(path)?;
    let mut reader = file.take(MAX_NETWORK_SETTINGS_BYTES.saturating_add(1));
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    reader.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_NETWORK_SETTINGS_BYTES {
        return Err(AslError::InvalidIdentity);
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let base = std::env::temp_dir().join("asl-test-network-settings");
            let root = base.join(format!(
                "settings-{}-{}",
                std::process::id(),
                NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).unwrap();
            Self(root)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let Some(name) = self.0.file_name().and_then(|name| name.to_str()) else {
                return;
            };
            let base = self
                .0
                .parent()
                .and_then(|parent| parent.canonicalize().ok());
            let root = self.0.canonicalize().ok();
            if name.starts_with("settings-")
                && base
                    .as_ref()
                    .zip(root.as_ref())
                    .is_some_and(|(base, root)| {
                        root.starts_with(base) && root.parent() == Some(base.as_path())
                    })
            {
                let _ = fs::remove_dir_all(root.unwrap());
            }
        }
    }

    #[test]
    fn missing_settings_keep_loopback_and_listening_disabled() {
        let directory = TestDirectory::new();
        let settings = NetworkSettingsV1::load(&directory.0.join("settings.json")).unwrap();
        assert_eq!(settings, NetworkSettingsV1::default());
        assert_eq!(settings.address_policy(), AddressPolicy::LoopbackOnly);
        assert!(!settings.loopback_groups);
    }

    #[test]
    fn settings_load_versioned_scope_and_listener_choices() {
        let directory = TestDirectory::new();
        let path = directory.0.join("settings.json");
        let settings = NetworkSettingsV1 {
            version: 1,
            address_scope: NetworkAddressScopeV1::LanOnly,
            listen_on_interfaces: true,
            tcp_port: 0,
            quic_port: 40_000,
            relay_addresses: vec![],
            bootstrap_multiaddrs: vec![],
            loopback_groups: false,
        };
        fs::write(&path, serde_json::to_vec(&settings).unwrap()).unwrap();
        assert_eq!(NetworkSettingsV1::load(&path).unwrap(), settings);
        assert_eq!(settings.address_policy(), AddressPolicy::LanOnly);
    }

    #[test]
    fn settings_require_explicit_loopback_group_opt_in() {
        let directory = TestDirectory::new();
        let path = directory.0.join("settings.json");
        let mut value = serde_json::to_value(NetworkSettingsV1::default()).unwrap();
        value.as_object_mut().unwrap().remove("loopback_groups");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(!NetworkSettingsV1::load(&path).unwrap().loopback_groups);

        value["loopback_groups"] = serde_json::json!(true);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(NetworkSettingsV1::load(&path).unwrap().loopback_groups);

        value["loopback_groups"] = serde_json::json!("true");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(NetworkSettingsV1::load(&path).is_err());
    }

    #[test]
    fn settings_allow_group_opt_in_with_lan_internet_and_relay() {
        let mut settings = NetworkSettingsV1 {
            loopback_groups: true,
            ..NetworkSettingsV1::default()
        };
        for scope in [
            NetworkAddressScopeV1::LanOnly,
            NetworkAddressScopeV1::InternetOnly,
            NetworkAddressScopeV1::Hybrid,
        ] {
            settings.address_scope = scope;
            assert!(settings.validate().is_ok());
        }

        let relay_peer_id = libp2p_identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        settings.relay_addresses = vec![format!("/ip4/127.0.0.1/tcp/4001/p2p/{relay_peer_id}")];
        for scope in [
            NetworkAddressScopeV1::LoopbackOnly,
            NetworkAddressScopeV1::RelayOnly,
            NetworkAddressScopeV1::InternetOnly,
        ] {
            settings.address_scope = scope;
            if scope == NetworkAddressScopeV1::RelayOnly {
                settings.listen_on_interfaces = false;
            }
            assert!(settings.validate().is_ok());
        }
    }

    #[test]
    fn listener_address_is_loopback_or_policy_scoped_interface_binding() {
        let mut settings = NetworkSettingsV1::default();
        assert_eq!(
            settings.listener_address(4_001),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4_001)
        );

        settings.address_scope = NetworkAddressScopeV1::InternetOnly;
        assert_eq!(
            settings.listener_address(4_001),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4_001)
        );
    }

    #[test]
    fn settings_reject_unknown_fields_wrong_versions_and_oversized_files() {
        let directory = TestDirectory::new();
        let path = directory.0.join("settings.json");
        let mut value = serde_json::to_value(NetworkSettingsV1::default()).unwrap();
        value["unexpected"] = serde_json::json!(true);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(NetworkSettingsV1::load(&path).is_err());

        let mut value = serde_json::to_value(NetworkSettingsV1::default()).unwrap();
        value["version"] = serde_json::json!(2);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(NetworkSettingsV1::load(&path).is_err());

        fs::write(&path, vec![b' '; MAX_NETWORK_SETTINGS_BYTES as usize + 1]).unwrap();
        assert!(NetworkSettingsV1::load(&path).is_err());
    }

    #[test]
    fn relay_only_requires_configured_relays_and_disables_interface_listening() {
        let relay_peer_id = libp2p_identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let mut settings = NetworkSettingsV1 {
            address_scope: NetworkAddressScopeV1::RelayOnly,
            relay_addresses: vec![format!("/ip4/127.0.0.1/tcp/4001/p2p/{relay_peer_id}")],
            ..NetworkSettingsV1::default()
        };
        assert!(settings.validate().is_ok());

        settings.listen_on_interfaces = true;
        assert!(settings.validate().is_err());

        settings.listen_on_interfaces = false;
        settings.relay_addresses.clear();
        assert!(settings.validate().is_err());
    }
}
