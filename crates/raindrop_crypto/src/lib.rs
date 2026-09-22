//! Raindrop's end-to-end encryption core.
//!
//! - [`session::Session`] is the entry point: one per server profile on a device.
//! - [`identity`]: user identity keys, device certificates and safety numbers.
//! - [`validation`]: who a group member really is (a trait, so plugins can add rules).
//! - [`backup`]: the recovery-key / passphrase sealed key backup.
//! - [`store`]: the SQLCipher-encrypted local database, including the decrypted message cache.
//!
//! Nothing here touches the network; see the `session` module docs for how commits flow.

pub mod backup;
pub mod error;
pub mod identity;
pub mod link;
pub mod provider;
mod random;
pub mod session;
pub mod store;
pub mod validation;

pub use error::{CryptoError, Result};
pub use session::{CIPHERSUITE, DeviceIdentity, GroupMember, Incoming, PendingCommit, Session};
