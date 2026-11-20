//! MLS group rooms and membership state.

mod application;
#[cfg(windows)]
pub mod local_state;

pub use application::GroupApplication;
pub use openmls::prelude::ProtocolVersion;
