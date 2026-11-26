use thiserror::Error;

/// Everything that can go wrong in the crypto core. Variants are coarse on purpose: callers branch
/// on *what kind* of failure it was (a wrong key, a message from an untrusted device, a stale
/// epoch), and the detail string is for logs, never for the UI to parse.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The local database could not be opened with the key given — the key is wrong, or the file
    /// is not a Raindrop store.
    #[error("the local store could not be unlocked")]
    StoreLocked,

    #[error("local store error: {0}")]
    Store(String),

    /// Input from the network or the user was malformed.
    #[error("malformed input: {0}")]
    Malformed(String),

    /// A signature, certificate or credential did not verify.
    #[error("verification failed: {0}")]
    Verification(String),

    /// A user's identity key differs from the one pinned for them. Never resolved silently: the
    /// user has to look at the new safety number and accept it.
    ///
    /// Carries both keys so the client can show the two safety numbers and, on acceptance, pass the
    /// exact key back to `Session::accept_changed_identity`: `pinned_key` is what this device
    /// trusted until now, `presented_key` is what the certificate in front of it carried.
    #[error("the identity key of user {user_id} changed")]
    IdentityChanged {
        user_id: String,
        pinned_key: Vec<u8>,
        presented_key: Vec<u8>,
    },

    /// A backup could not be opened: wrong recovery key or passphrase, or a damaged blob.
    #[error("the backup could not be decrypted")]
    BackupLocked,

    /// No group, key or identity with that name exists locally.
    #[error("not found: {0}")]
    NotFound(String),

    /// Reading or writing a file failed (an attachment being encrypted or decrypted).
    #[error("file error: {0}")]
    Io(String),

    /// The server delivered a commit claiming to be this device's own that this device does not
    /// hold (it discarded it after the server had in fact accepted it, or another member forged
    /// it). The local group cannot follow it: reset the group (`Session::reset_group`, which keeps the
    /// cached messages) and rejoin it.
    #[error("own commit echoed that this device does not hold; rejoin the group")]
    ResyncRequired,

    /// An MLS operation failed.
    #[error("mls error: {0}")]
    Mls(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

impl From<rusqlite::Error> for CryptoError {
    fn from(e: rusqlite::Error) -> Self {
        CryptoError::Store(e.to_string())
    }
}

impl From<serde_json::Error> for CryptoError {
    fn from(e: serde_json::Error) -> Self {
        CryptoError::Malformed(e.to_string())
    }
}

/// Wraps any OpenMLS error type, which are numerous and generic over the storage error.
pub(crate) fn mls<E: std::fmt::Debug>(e: E) -> CryptoError {
    CryptoError::Mls(format!("{e:?}"))
}
