use std::{
    fs::{self, File},
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
};

use asl_net::address_policy::AddressPolicy;
use asl_types::error::AslError;
use serde::{Deserialize, Serialize};

const MAX_NETWORK_SETTINGS_BYTES: u64 = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAddressScopeV1 {
    LoopbackOnly,
    LanOnly,
    InternetOnly,
    Hybrid,
}

impl From<NetworkAddressScopeV1> for AddressPolicy {
    fn from(scope: NetworkAddressScopeV1) -> Self {
        match scope {
            NetworkAddressScopeV1::LoopbackOnly => Self::LoopbackOnly,
            NetworkAddressScopeV1::LanOnly => Self::LanOnly,
            NetworkAddressScopeV1::InternetOnly => Self::InternetOnly,
            NetworkAddressScopeV1::Hybrid => Self::Hybrid,
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
}

impl Default for NetworkSettingsV1 {
    fn default() -> Self {
        Self {
            version: 1,
            address_scope: NetworkAddressScopeV1::LoopbackOnly,
            listen_on_interfaces: false,
            tcp_port: 0,
            quic_port: 0,
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
        Ok(settings)
    }

    pub fn address_policy(&self) -> AddressPolicy {
        self.address_scope.into()
    }

    pub fn listener_address(&self, port: u16) -> SocketAddr {
        let ip = match self.address_scope {
            NetworkAddressScopeV1::LoopbackOnly => Ipv4Addr::LOCALHOST,
            NetworkAddressScopeV1::LanOnly
            | NetworkAddressScopeV1::InternetOnly
            | NetworkAddressScopeV1::Hybrid => Ipv4Addr::UNSPECIFIED,
        };
        SocketAddr::new(IpAddr::V4(ip), port)
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
        };
        fs::write(&path, serde_json::to_vec(&settings).unwrap()).unwrap();
        assert_eq!(NetworkSettingsV1::load(&path).unwrap(), settings);
        assert_eq!(settings.address_policy(), AddressPolicy::LanOnly);
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
}
