use std::{
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
};

use asl_net::{
    relay::{RelayServerLimits, parse_relay_listen_multiaddr},
    transport::TransportKind,
};
use asl_types::error::AslError;
use serde::Deserialize;

const MAX_INFRA_CONFIG_BYTES: u64 = 65_536;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum InfrastructureModeV1 {
    RelayOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InfrastructureConfigV1 {
    pub schema_version: u16,
    pub mode: InfrastructureModeV1,
    pub data_root: PathBuf,
    pub identity_file: PathBuf,
    pub listen: Vec<String>,
    #[serde(default)]
    pub external_addresses: Vec<String>,
    pub relay: RelayServerConfigV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayServerConfigV1 {
    pub enabled: bool,
    pub max_reservations: usize,
    pub max_reservations_per_peer: usize,
    pub reservation_duration_seconds: u64,
    pub max_circuits: usize,
    pub max_circuits_per_peer: usize,
    pub max_circuit_seconds: u64,
    pub max_circuit_bytes: u64,
}

impl InfrastructureConfigV1 {
    pub fn load(path: &Path) -> Result<Self, AslError> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_INFRA_CONFIG_BYTES {
            return Err(AslError::InvalidMessage);
        }
        let file = File::open(path)?;
        let mut reader = file.take(MAX_INFRA_CONFIG_BYTES.saturating_add(1));
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        reader.read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_INFRA_CONFIG_BYTES {
            return Err(AslError::InvalidMessage);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| AslError::InvalidMessage)?;
        Self::parse(text)
    }

    pub fn parse(text: &str) -> Result<Self, AslError> {
        if text.len() as u64 > MAX_INFRA_CONFIG_BYTES {
            return Err(AslError::InvalidMessage);
        }
        let config: Self = toml_edit::de::from_str(text).map_err(|_| AslError::InvalidMessage)?;
        config.validate()?;
        Ok(config)
    }

    pub fn relay_limits(&self) -> RelayServerLimits {
        RelayServerLimits {
            max_reservations: self.relay.max_reservations,
            max_reservations_per_peer: self.relay.max_reservations_per_peer,
            reservation_duration: std::time::Duration::from_secs(
                self.relay.reservation_duration_seconds,
            ),
            max_circuits: self.relay.max_circuits,
            max_circuits_per_peer: self.relay.max_circuits_per_peer,
            max_circuit_duration: std::time::Duration::from_secs(self.relay.max_circuit_seconds),
            max_circuit_bytes: self.relay.max_circuit_bytes,
        }
    }

    pub fn listen_addresses(&self) -> Result<Vec<(TransportKind, std::net::SocketAddr)>, AslError> {
        self.listen
            .iter()
            .map(|address| {
                parse_relay_listen_multiaddr(address).map_err(|_| AslError::InvalidMessage)
            })
            .collect()
    }

    pub fn external_addresses(
        &self,
    ) -> Result<Vec<(TransportKind, std::net::SocketAddr)>, AslError> {
        self.external_addresses
            .iter()
            .map(|address| {
                let (kind, socket) =
                    parse_relay_listen_multiaddr(address).map_err(|_| AslError::InvalidMessage)?;
                if socket.ip().is_unspecified()
                    || socket.ip().is_multicast()
                    || matches!(socket.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
                    || matches!(socket.ip(), std::net::IpAddr::V6(ip) if ip.is_unicast_link_local())
                {
                    return Err(AslError::InvalidMessage);
                }
                Ok((kind, socket))
            })
            .collect()
    }

    pub fn identity_path(&self) -> PathBuf {
        self.data_root.join(&self.identity_file)
    }

    fn validate(&self) -> Result<(), AslError> {
        if self.schema_version != 1
            || !self.data_root.is_absolute()
            || self.data_root.parent().is_none()
            || self
                .data_root
                .components()
                .any(|component| matches!(component, Component::ParentDir))
            || self.identity_file.is_absolute()
            || self.identity_file.as_os_str().is_empty()
            || self
                .identity_file
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            || self.listen.is_empty()
            || self.listen.len() > 16
            || !self.relay.enabled
            || self.relay_limits().validate().is_err()
        {
            return Err(AslError::InvalidMessage);
        }

        let addresses = self.listen_addresses()?;
        for (index, address) in addresses.iter().enumerate() {
            if addresses[..index].contains(address) {
                return Err(AslError::InvalidMessage);
            }
        }
        let external_addresses = self.external_addresses()?;
        for (index, address) in external_addresses.iter().enumerate() {
            if external_addresses[..index].contains(address) {
                return Err(AslError::InvalidMessage);
            }
        }
        if external_addresses.is_empty()
            && addresses
                .iter()
                .all(|(_, address)| address.ip().is_unspecified())
        {
            return Err(AslError::InvalidMessage);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub fn load_or_create_relay_identity(
    config: &InfrastructureConfigV1,
) -> Result<libp2p_identity::Keypair, AslError> {
    use std::{
        fs::{OpenOptions, create_dir_all},
        io::Write,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    use zeroize::Zeroizing;

    let data_root = &config.data_root;
    create_dir_all(data_root)?;
    ensure_no_symlink_components(data_root)?;
    if !fs::metadata(data_root)?.is_dir() {
        return Err(AslError::InvalidStorageRoot);
    }

    let identity_path = config.identity_path();
    let parent = identity_path.parent().ok_or(AslError::InvalidStorageRoot)?;
    create_dir_all(parent)?;
    ensure_no_symlink_components(&identity_path)?;

    match fs::symlink_metadata(&identity_path) {
        Ok(metadata) => load_existing_relay_identity(&identity_path, metadata.mode()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let identity = libp2p_identity::Keypair::generate_ed25519();
            let encoded = Zeroizing::new(
                identity
                    .to_protobuf_encoding()
                    .map_err(|_| AslError::InvalidIdentity)?,
            );
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            match options.open(&identity_path) {
                Ok(mut file) => {
                    if let Err(error) = file.write_all(&encoded).and_then(|_| file.sync_all()) {
                        drop(file);
                        let _ = fs::remove_file(&identity_path);
                        return Err(error.into());
                    }
                    Ok(identity)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let metadata = fs::symlink_metadata(&identity_path)?;
                    load_existing_relay_identity(&identity_path, metadata.mode())
                }
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn load_existing_relay_identity(
    path: &Path,
    mode: u32,
) -> Result<libp2p_identity::Keypair, AslError> {
    use std::os::unix::fs::MetadataExt;
    use zeroize::Zeroizing;

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || mode & 0o077 != 0
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 4_096
    {
        return Err(AslError::KeyProtectionFailed);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    File::open(path)?.take(4_097).read_to_end(&mut bytes)?;
    if bytes.len() > 4_096 {
        return Err(AslError::InvalidIdentity);
    }
    libp2p_identity::Keypair::from_protobuf_encoding(&bytes).map_err(|_| AslError::InvalidIdentity)
}

#[cfg(target_os = "linux")]
fn ensure_no_symlink_components(path: &Path) -> Result<(), AslError> {
    for component in path.ancestors() {
        match fs::symlink_metadata(component) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(AslError::InvalidStorageRoot);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CONFIG: &str = r#"
schema_version = 1
mode = "relay-only"
data_root = "/var/lib/asl-infra"
identity_file = "identity.key"
listen = ["/ip4/0.0.0.0/tcp/4001", "/ip4/0.0.0.0/udp/4001/quic-v1"]
external_addresses = ["/ip4/203.0.113.1/tcp/4001", "/ip4/203.0.113.1/udp/4001/quic-v1"]

[relay]
enabled = true
max_reservations = 128
max_reservations_per_peer = 4
reservation_duration_seconds = 3600
max_circuits = 64
max_circuits_per_peer = 4
max_circuit_seconds = 300
max_circuit_bytes = 134217728
"#;

    fn test_data_root() -> &'static str {
        if cfg!(windows) {
            r"C:\ASL\infra"
        } else {
            "/var/lib/asl-infra"
        }
    }

    fn valid_config() -> String {
        VALID_CONFIG.replace(
            r#"data_root = "/var/lib/asl-infra""#,
            &format!("data_root = {:?}", test_data_root()),
        )
    }

    #[test]
    fn relay_config_parses_and_resolves_transport_addresses() {
        let config = InfrastructureConfigV1::parse(&valid_config()).unwrap();
        assert_eq!(config.schema_version, 1);
        assert_eq!(config.mode, InfrastructureModeV1::RelayOnly);
        assert_eq!(
            config.identity_path(),
            config.data_root.join("identity.key")
        );
        assert_eq!(config.listen_addresses().unwrap().len(), 2);
        assert_eq!(config.external_addresses().unwrap().len(), 2);
        assert_eq!(config.relay_limits(), RelayServerLimits::default());
    }

    #[test]
    fn relay_config_rejects_unknown_fields_versions_paths_and_invalid_limits() {
        let valid = valid_config();
        assert!(
            InfrastructureConfigV1::parse(
                &valid.replace("schema_version = 1", "schema_version = 2")
            )
            .is_err()
        );
        assert!(
            InfrastructureConfigV1::parse(&valid.replace(
                "identity_file = \"identity.key\"",
                "identity_file = \"../identity.key\""
            ))
            .is_err()
        );
        let filesystem_root = if cfg!(windows) { r"C:\" } else { "/" };
        let valid_root = format!("data_root = {:?}", test_data_root());
        assert!(
            InfrastructureConfigV1::parse(
                &valid.replace(&valid_root, &format!("data_root = {filesystem_root:?}"))
            )
            .is_err()
        );
        assert!(
            InfrastructureConfigV1::parse(
                &valid.replace("/ip4/0.0.0.0/tcp/4001", "/dns4/relay.example/tcp/4001")
            )
            .is_err()
        );
        assert!(
            InfrastructureConfigV1::parse(
                &valid.replace(
                    "external_addresses = [\"/ip4/203.0.113.1/tcp/4001\", \"/ip4/203.0.113.1/udp/4001/quic-v1\"]",
                    "external_addresses = []"
                )
            )
            .is_err()
        );
        assert!(
            InfrastructureConfigV1::parse(
                &valid.replace("/ip4/203.0.113.1/tcp/4001", "/ip4/0.0.0.0/tcp/4001")
            )
            .is_err()
        );
        assert!(
            InfrastructureConfigV1::parse(&valid.replace("max_circuits = 64", "max_circuits = 0",))
                .is_err()
        );
        assert!(InfrastructureConfigV1::parse(&format!("{valid}\nunknown = true")).is_err());
        assert!(
            InfrastructureConfigV1::parse(&" ".repeat(MAX_INFRA_CONFIG_BYTES as usize + 1))
                .is_err()
        );
    }
}
