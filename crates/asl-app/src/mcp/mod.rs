mod client;
mod contract;
mod grant;
mod inbox;
mod recovery;
mod secure;
mod server;
mod session;
mod stdio;
#[cfg(test)]
pub(crate) mod test_host;

use std::{path::PathBuf, time::Duration};

use asl_types::error::AslError;

pub(crate) use self::{grant::HostGrant, recovery::Recovery, server::McpWorker};

pub fn run_stdio(root: PathBuf) -> Result<(), AslError> {
    if !root.is_absolute() {
        return Err(AslError::InvalidStorageRoot);
    }
    let (key, recovery) = grant::host_key()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(stdio::run(client::Client::new(root, key, recovery)));
    runtime.shutdown_timeout(Duration::from_secs(1));
    result
}
