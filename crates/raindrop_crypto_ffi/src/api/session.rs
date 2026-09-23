//! What Dart can call. A thin layer over [`raindrop_crypto::Session`]: plain data in and out, an
//! error enum Dart can switch on, and a mutex so the one session per server can be shared by the
//! isolate's calls, which flutter_rust_bridge runs on a thread pool.

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use flutter_rust_bridge::frb;
use raindrop_crypto::backup::{self, PassphraseCost, RecoveryKey};
use raindrop_crypto::{CryptoError, Incoming, Session};

/// What kind of failure a [`CryptoFailure`] is. Dart shows different things for each: a changed
/// identity is a trust decision for the user, a locked store is a missing key, and everything else
/// is a bug or bad input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoFailureKind {
    /// The local store's key is wrong, or the file is not a Raindrop store.
    StoreLocked,
    /// A user's identity key differs from the one pinned for them; see `user_id`.
    IdentityChanged,
    /// Wrong recovery key or passphrase, or a damaged backup.
    BackupLocked,
    Verification,
    NotFound,
    Malformed,
    Other,
}

/// Why a call failed. A struct rather than a data-carrying enum so the generated Dart needs no
/// `freezed` build step.
#[derive(Debug)]
pub struct CryptoFailure {
    pub kind: CryptoFailureKind,
    pub message: String,
    /// For [`CryptoFailureKind::IdentityChanged`]: whose key changed.
    pub user_id: Option<String>,
}

impl From<CryptoError> for CryptoFailure {
    fn from(error: CryptoError) -> Self {
        let message = error.to_string();
        let (kind, user_id) = match error {
            CryptoError::StoreLocked => (CryptoFailureKind::StoreLocked, None),
            CryptoError::IdentityChanged { user_id } => (CryptoFailureKind::IdentityChanged, Some(user_id)),
            CryptoError::BackupLocked => (CryptoFailureKind::BackupLocked, None),
            CryptoError::Verification(_) => (CryptoFailureKind::Verification, None),
            CryptoError::NotFound(_) => (CryptoFailureKind::NotFound, None),
            CryptoError::Malformed(_) => (CryptoFailureKind::Malformed, None),
            CryptoError::Store(_) | CryptoError::Io(_) | CryptoError::Mls(_) => (CryptoFailureKind::Other, None),
        };
        Self { kind, message, user_id }
    }
}

impl CryptoFailure {
    fn malformed(message: &str) -> Self {
        Self {
            kind: CryptoFailureKind::Malformed,
            message: message.to_owned(),
            user_id: None,
        }
    }
}

type Result<T> = std::result::Result<T, CryptoFailure>;

pub struct DeviceIdentity {
    pub user_id: String,
    pub device_id: String,
    pub user_identity_key: Vec<u8>,
    pub device_signature_key: Vec<u8>,
    pub certificate: Vec<u8>,
}

impl From<raindrop_crypto::DeviceIdentity> for DeviceIdentity {
    fn from(d: raindrop_crypto::DeviceIdentity) -> Self {
        Self {
            user_id: d.user_id,
            device_id: d.device_id,
            user_identity_key: d.user_identity_key,
            device_signature_key: d.device_signature_key,
            certificate: d.certificate,
        }
    }
}

pub struct PendingCommit {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub epoch_after: i64,
}

impl From<raindrop_crypto::PendingCommit> for PendingCommit {
    fn from(p: raindrop_crypto::PendingCommit) -> Self {
        Self {
            commit: p.commit,
            welcome: p.welcome,
            epoch_after: p.epoch_after as i64,
        }
    }
}

pub struct ExternalJoin {
    pub group_id: Vec<u8>,
    pub pending: PendingCommit,
}

pub struct GroupMember {
    pub leaf_index: u32,
    pub user_id: String,
    pub device_id: String,
}

impl From<raindrop_crypto::GroupMember> for GroupMember {
    fn from(m: raindrop_crypto::GroupMember) -> Self {
        Self {
            leaf_index: m.leaf_index,
            user_id: m.user_id,
            device_id: m.device_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessedKind {
    /// Somebody's message: `sender` and `payload` are set.
    Application,
    /// A commit moved the group to `epoch`: `added`, `removed` and `removed_self` are set.
    Commit,
    /// A proposal, stored until somebody commits it.
    Proposal,
    /// This device's own application message echoed back.
    OwnMessage,
}

/// What a message from the delivery stream turned out to be. Flat, like [`CryptoFailure`], so the
/// generated Dart needs no build step; the Dart facade turns it into a sealed class.
pub struct ProcessedMessage {
    pub kind: ProcessedKind,
    pub group_id: Vec<u8>,
    pub epoch: i64,
    pub sender: Option<GroupMember>,
    pub payload: Option<Vec<u8>>,
    pub added: Vec<GroupMember>,
    pub removed: Vec<GroupMember>,
    pub removed_self: bool,
}

pub struct CachedMessage {
    pub group_id: Vec<u8>,
    pub message_id: String,
    pub sender_user_id: String,
    pub sender_device_id: String,
    pub epoch: i64,
    pub sent_at_unix_ms: i64,
    pub payload: Vec<u8>,
}

impl From<raindrop_crypto::store::CachedMessage> for CachedMessage {
    fn from(m: raindrop_crypto::store::CachedMessage) -> Self {
        Self {
            group_id: m.group_id,
            message_id: m.message_id,
            sender_user_id: m.sender_user_id,
            sender_device_id: m.sender_device_id,
            epoch: m.epoch as i64,
            sent_at_unix_ms: m.sent_at_unix_ms,
            payload: m.payload,
        }
    }
}

pub struct PinnedIdentity {
    pub user_id: String,
    pub identity_key: Vec<u8>,
    pub verified: bool,
    pub first_seen_unix: i64,
}

impl From<raindrop_crypto::store::PinnedIdentity> for PinnedIdentity {
    fn from(p: raindrop_crypto::store::PinnedIdentity) -> Self {
        Self {
            user_id: p.user_id,
            identity_key: p.identity_key,
            verified: p.verified,
            first_seen_unix: p.first_seen_unix,
        }
    }
}

/// A new device's link offer (upload it) and the commitment to put in the link code.
pub struct LinkOffer {
    pub offer: Vec<u8>,
    pub commitment: Vec<u8>,
}

/// A freshly sealed backup, and — for a recovery-key backup — the 24 words to show the user once.
pub struct SealedBackup {
    pub blob: Vec<u8>,
    pub recovery_words: Option<String>,
}

/// One device's encryption state on one server. Open one per signed-in server; it is safe to call
/// from several Dart futures at once.
#[frb(opaque)]
pub struct CryptoSession {
    inner: Mutex<Session>,
}

impl CryptoSession {
    /// Opens (creating on first use) the encrypted store at `path` with the 32-byte `key`.
    pub fn open(path: String, key: Vec<u8>) -> Result<CryptoSession> {
        let key: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoFailure::malformed("the store key is 32 bytes"))?;
        let session = Session::open(&PathBuf::from(path), &key)?;
        Ok(Self {
            inner: Mutex::new(session),
        })
    }

    #[frb(ignore)]
    fn session(&self) -> MutexGuard<'_, Session> {
        // A panic while holding the lock leaves nothing half-written that SQLite's own
        // transactions did not already roll back, so carrying on is safe.
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    // ── Identity ──

    pub fn device(&self) -> Option<DeviceIdentity> {
        self.session().device().cloned().map(Into::into)
    }

    pub fn create_identity(&self, user_id: String, device_id: String) -> Result<DeviceIdentity> {
        Ok(self.session().create_identity(&user_id, &device_id)?.into())
    }

    pub fn restore_identity_with_recovery_key(
        &self,
        blob: Vec<u8>,
        recovery_words: String,
        device_id: String,
    ) -> Result<DeviceIdentity> {
        let contents = backup::open_with_recovery_key(&blob, &RecoveryKey::from_words(&recovery_words)?)?;
        Ok(self.session().restore_identity(&contents, &device_id)?.into())
    }

    pub fn restore_identity_with_passphrase(
        &self,
        blob: Vec<u8>,
        passphrase: String,
        device_id: String,
    ) -> Result<DeviceIdentity> {
        let contents = backup::open_with_passphrase(&blob, &passphrase)?;
        Ok(self.session().restore_identity(&contents, &device_id)?.into())
    }

    /// Seals this user's keys under a new recovery key. Show `recovery_words` once, then drop them.
    pub fn seal_backup_with_recovery_key(&self) -> Result<SealedBackup> {
        let key = RecoveryKey::generate();
        let blob = backup::seal_with_recovery_key(&self.session().backup_contents()?, &key)?;
        Ok(SealedBackup {
            blob,
            recovery_words: Some(key.to_words()),
        })
    }

    pub fn seal_backup_with_passphrase(&self, passphrase: String) -> Result<SealedBackup> {
        let contents = self.session().backup_contents()?;
        let blob = backup::seal_with_passphrase(&contents, &passphrase, PassphraseCost::default())?;
        Ok(SealedBackup {
            blob,
            recovery_words: None,
        })
    }

    /// Signs the server's session-binding challenge with this device's key.
    pub fn sign_session_challenge(&self, nonce: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.session().sign_session_challenge(&nonce)?)
    }

    /// Signs a message attestation over `canonical` with this device's key.
    pub fn sign_message_attestation(&self, canonical: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.session().sign_message_attestation(&canonical)?)
    }

    /// Signs the attestation of a message that carries files (context `raindrop/message-attestation/v2`).
    pub fn sign_message_attestation_v2(&self, canonical: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.session().sign_message_attestation_v2(&canonical)?)
    }

    /// New device: makes its key and a link offer for an existing device to approve.
    pub fn begin_device_link(&self, user_id: String, device_id: String) -> Result<LinkOffer> {
        let (offer, commitment) = self.session().begin_device_link(&user_id, &device_id)?;
        Ok(LinkOffer {
            offer,
            commitment: commitment.to_vec(),
        })
    }

    /// Existing device: checks the offer against the link code's commitment and approves it.
    pub fn approve_device_link(&self, offer: Vec<u8>, commitment: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.session().approve_device_link(&offer, &commitment)?)
    }

    /// New device: opens the approval and becomes a full device of the user.
    pub fn complete_device_link(&self, approval: Vec<u8>) -> Result<DeviceIdentity> {
        Ok(self.session().complete_device_link(&approval)?.into())
    }

    pub fn pinned_identity(&self, user_id: String) -> Result<Option<PinnedIdentity>> {
        Ok(self.session().store().pinned_identity(&user_id)?.map(Into::into))
    }

    /// The user looked at the new safety number and accepts `user_id`'s changed identity key.
    pub fn accept_changed_identity(&self, user_id: String, identity_key: Vec<u8>) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Ok(self.session().store().replace_identity(&user_id, &identity_key, now)?)
    }

    pub fn mark_verified(&self, user_id: String, identity_key: Vec<u8>) -> Result<()> {
        Ok(self.session().store().mark_verified(&user_id, &identity_key)?)
    }

    // ── Key packages and groups ──

    pub fn generate_key_packages(&self, count: u32, last_resort: bool) -> Result<Vec<Vec<u8>>> {
        Ok(self.session().generate_key_packages(count as usize, last_resort)?)
    }

    pub fn create_group(&self, group_id: Vec<u8>) -> Result<()> {
        Ok(self.session().create_group(&group_id)?)
    }

    pub fn has_group(&self, group_id: Vec<u8>) -> Result<bool> {
        Ok(self.session().has_group(&group_id)?)
    }

    pub fn epoch(&self, group_id: Vec<u8>) -> Result<i64> {
        Ok(self.session().epoch(&group_id)? as i64)
    }

    pub fn members(&self, group_id: Vec<u8>) -> Result<Vec<GroupMember>> {
        Ok(self.session().members(&group_id)?.into_iter().map(Into::into).collect())
    }

    pub fn group_info(&self, group_id: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.session().group_info(&group_id)?)
    }

    pub fn add_members(&self, group_id: Vec<u8>, key_packages: Vec<Vec<u8>>) -> Result<PendingCommit> {
        Ok(self.session().add_members(&group_id, &key_packages)?.into())
    }

    pub fn remove_members(&self, group_id: Vec<u8>, leaf_indices: Vec<u32>) -> Result<PendingCommit> {
        Ok(self.session().remove_members(&group_id, &leaf_indices)?.into())
    }

    pub fn self_update(&self, group_id: Vec<u8>) -> Result<PendingCommit> {
        Ok(self.session().self_update(&group_id)?.into())
    }

    pub fn join_by_external_commit(&self, group_info: Vec<u8>) -> Result<ExternalJoin> {
        let (group_id, pending) = self.session().join_by_external_commit(&group_info)?;
        Ok(ExternalJoin {
            group_id,
            pending: pending.into(),
        })
    }

    pub fn join_from_welcome(&self, welcome: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.session().join_from_welcome(&welcome)?)
    }

    pub fn merge_pending_commit(&self, group_id: Vec<u8>) -> Result<i64> {
        Ok(self.session().merge_pending_commit(&group_id)? as i64)
    }

    pub fn discard_pending_commit(&self, group_id: Vec<u8>) -> Result<()> {
        Ok(self.session().discard_pending_commit(&group_id)?)
    }

    pub fn delete_group(&self, group_id: Vec<u8>) -> Result<()> {
        Ok(self.session().delete_group(&group_id)?)
    }

    // ── Messages ──

    pub fn encrypt(&self, group_id: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.session().encrypt(&group_id, &payload)?)
    }

    pub fn process(&self, message: Vec<u8>) -> Result<ProcessedMessage> {
        let (group_id, incoming) = self.session().process(&message)?;
        let mut processed = ProcessedMessage {
            kind: ProcessedKind::Proposal,
            group_id,
            epoch: 0,
            sender: None,
            payload: None,
            added: Vec::new(),
            removed: Vec::new(),
            removed_self: false,
        };
        match incoming {
            Incoming::Application { sender, epoch, payload } => {
                processed.kind = ProcessedKind::Application;
                processed.epoch = epoch as i64;
                processed.sender = Some(sender.into());
                processed.payload = Some(payload);
            }
            Incoming::Commit {
                epoch,
                added,
                removed,
                removed_self,
            } => {
                processed.kind = ProcessedKind::Commit;
                processed.epoch = epoch as i64;
                processed.added = added.into_iter().map(Into::into).collect();
                processed.removed = removed.into_iter().map(Into::into).collect();
                processed.removed_self = removed_self;
            }
            Incoming::Proposal => {}
            Incoming::OwnMessage { epoch } => {
                processed.kind = ProcessedKind::OwnMessage;
                processed.epoch = epoch as i64;
            }
        }
        Ok(processed)
    }

    pub fn receive_message(
        &self,
        message_id: String,
        sent_at_unix_ms: i64,
        message: Vec<u8>,
    ) -> Result<Option<CachedMessage>> {
        Ok(self
            .session()
            .receive_message(&message_id, sent_at_unix_ms, &message)?
            .map(Into::into))
    }

    pub fn remember_sent(
        &self,
        group_id: Vec<u8>,
        message_id: String,
        sent_at_unix_ms: i64,
        payload: Vec<u8>,
    ) -> Result<()> {
        Ok(self
            .session()
            .remember_sent(&group_id, &message_id, sent_at_unix_ms, &payload)?)
    }

    pub fn cached_messages(
        &self,
        group_id: Vec<u8>,
        before_unix_ms: Option<i64>,
        limit: u32,
    ) -> Result<Vec<CachedMessage>> {
        Ok(self
            .session()
            .store()
            .messages(&group_id, before_unix_ms, limit)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn forget_message(&self, group_id: Vec<u8>, message_id: String) -> Result<()> {
        Ok(self.session().store().delete_message(&group_id, &message_id)?)
    }

    pub fn export_secret(&self, group_id: Vec<u8>, label: String, context: Vec<u8>, length: u32) -> Result<Vec<u8>> {
        Ok(self
            .session()
            .export_secret(&group_id, &label, &context, length as usize)?)
    }
}

/// The 60-digit safety number two users compare. Symmetric in its arguments.
#[frb(sync)]
pub fn safety_number(user_a: String, key_a: Vec<u8>, user_b: String, key_b: Vec<u8>) -> String {
    raindrop_crypto::identity::safety_number(&user_a, &key_a, &user_b, &key_b)
}

/// Whether a backup needs a passphrase (rather than recovery words) to open.
#[frb(sync)]
pub fn backup_needs_passphrase(blob: Vec<u8>) -> Result<bool> {
    Ok(backup::needs_passphrase(&blob)?)
}
