//! One device's end-to-end encryption state on one server: its identity, its MLS groups, and the
//! local store. Everything the client does with encryption goes through a [`Session`].
//!
//! The session never talks to the network. It turns intentions ("send this", "add these devices")
//! into bytes for the caller to deliver, and turns delivered bytes into plaintext or state changes.
//! That keeps the transport, meaning Raindrop's delivery service and its ordering rules, out of the
//! crypto code, and keeps this crate testable with no server at all.
//!
//! ## Commits
//!
//! Any change to a group (adding or removing devices, rotating keys) produces a *pending* commit.
//! The caller sends it to the server, which accepts exactly one commit per epoch. When the server
//! accepts, call [`Session::merge_pending_commit`]. When it answers that another commit won, call
//! [`Session::discard_pending_commit`], process the winning commit, and try again if still needed.
//!
//! The server also fans a commit back out to its author. [`Session::process`] merges that echo only
//! when it is byte for byte the commit this device still holds as pending; an "own" commit it does
//! not hold is [`CryptoError::ResyncRequired`], and the caller resets the group ([`Session::reset_group`],
//! which keeps the cached messages) and rejoins it.
//!
//! ## Refusals after decryption
//!
//! OpenMLS spends a message's key as it decrypts it, before Raindrop checks who sent it, so a refusal
//! cannot be undone by trying again. An application message from a sender whose identity key changed
//! is therefore *held* ([`Session::receive_message`]) until the user accepts the new key
//! ([`Session::accept_changed_identity`]). A commit that fails the checks is refused for good, and
//! refusing a commit is leaving the group: the group is deleted (its cached messages are kept), and
//! the caller rejoins by external commit, which checks every member again.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer as _;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::backup::{BackedUpPin, BackupContents};
use crate::error::{CryptoError, Result, mls};
use crate::identity::{DeviceCertificate, UserIdentity};
use crate::link;
use crate::provider::RaindropProvider;
use crate::root::RootSecret;
use crate::store::{CachedMessage, HeldMessage, PendingIdentityChange, PinnedIdentity, Store};
use crate::validation::{CredentialValidator, PinnedIdentityValidator, certificate_of};

/// X25519, AES-128-GCM, SHA-256, Ed25519: MLS's mandatory-to-implement suite. Kept as a single
/// constant so a post-quantum suite can be introduced as a new group parameter later.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Application messages are padded to a multiple of this many bytes, so their size says less about
/// what they contain.
const PADDING: usize = 256;

/// How many past epochs' keys are kept, so a message sent just before a commit still decrypts when
/// it arrives just after. Small on purpose: every kept epoch is forward secrecy postponed.
const MAX_PAST_EPOCHS: usize = 2;

const META_USER_ID: &str = "identity.user_id";
const META_DEVICE_ID: &str = "identity.device_id";
const META_IDENTITY_SECRET: &str = "identity.uik_secret";
const META_DEVICE_KEY: &str = "identity.device_signature_public";
const META_CERTIFICATE: &str = "identity.device_certificate";
const META_LINK_OFFER: &str = "link.offer";
const META_LINK_EXCHANGE_SECRET: &str = "link.exchange_secret";
const META_LINK_CODE_SECRET: &str = "link.code_secret";
/// Followed by the group id in hex: SHA-256 of the exact commit bytes this device's pending commit
/// for that group was serialised to, so its echo can be told from a commit merely claiming to be it.
const META_PENDING_COMMIT_PREFIX: &str = "pending_commit.";

/// Prefixed to the server's nonce before signing, so the signature is good for nothing else.
const SESSION_BINDING_CONTEXT: &[u8] = b"raindrop/session-binding/v1\n";

/// Prefixed to the server's identity key and its nonce before a device signs them to sign in, so the
/// signature is good for that server and nothing else.
const AUTH_CONTEXT: &[u8] = b"raindrop/auth/v1\n";

/// Prefixed to a message's canonical encoding before its sender's device signs it (see
/// `sign_message_attestation`), so an attestation is never mistaken for any other signature.
const MESSAGE_ATTESTATION_CONTEXT: &[u8] = b"raindrop/message-attestation/v1\n";

/// The same, for a message that carries files: its canonical encoding goes on to list each file's id
/// and ciphertext hash, a different layout, so it is signed under its own context.
const MESSAGE_ATTESTATION_V2_CONTEXT: &[u8] = b"raindrop/message-attestation/v2\n";

/// This device's public identity, as the server and other users see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub user_id: String,
    pub device_id: String,
    pub user_identity_key: Vec<u8>,
    pub device_signature_key: Vec<u8>,
    /// [`DeviceCertificate::to_bytes`]; upload it with the device.
    pub certificate: Vec<u8>,
}

/// A change to a group, waiting for the server to accept it.
#[derive(Debug, Clone)]
pub struct PendingCommit {
    /// The MLS commit, for everyone already in the group.
    pub commit: Vec<u8>,
    /// For devices the commit adds, if any.
    pub welcome: Option<Vec<u8>>,
    /// The epoch the group will be in once this commit is merged.
    pub epoch_after: u64,
}

/// A device's place in a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMember {
    pub leaf_index: u32,
    pub user_id: String,
    pub device_id: String,
}

/// What an incoming group message turned out to be.
#[derive(Debug, Clone)]
pub enum Incoming {
    /// Somebody's message. Its plaintext payload is also written to the local message cache when
    /// processed through [`Session::receive_message`].
    Application {
        sender: GroupMember,
        epoch: u64,
        payload: Vec<u8>,
    },
    /// A commit moved the group to a new epoch. `removed_self` means this device is no longer in it.
    Commit {
        epoch: u64,
        added: Vec<GroupMember>,
        removed: Vec<GroupMember>,
        removed_self: bool,
    },
    /// Never returned: Raindrop changes groups only by commit, and `process` refuses standalone
    /// proposals. Kept so the bridge's `ProcessedKind` does not change.
    Proposal,
    /// This device's own application message echoed back; its plaintext is already in the cache.
    OwnMessage { epoch: u64 },
}

pub struct Session {
    store: Store,
    provider: RaindropProvider,
    device: Option<Device>,
}

struct Device {
    identity: DeviceIdentity,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

impl Session {
    /// Opens (creating on first use) the encrypted store at `path`, and loads this device's identity
    /// if it has one yet.
    pub fn open(path: &Path, key: &[u8; 32]) -> Result<Self> {
        let store = Store::open(path, key)?;
        let provider = RaindropProvider::open(path, key)?;
        let mut session = Self {
            store,
            provider,
            device: None,
        };
        session.device = session.load_device()?;
        Ok(session)
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn device(&self) -> Option<&DeviceIdentity> {
        self.device.as_ref().map(|d| &d.identity)
    }

    // ── Identity ─────────────────────────────────────────────────────────────────────────────

    /// A brand-new user: generates their identity key and this, their first device.
    pub fn create_identity(&mut self, user_id: &str, device_id: &str) -> Result<DeviceIdentity> {
        self.install_identity(UserIdentity::generate(), user_id, device_id)
    }

    /// This device's identity on the server whose identity key is `server_key`, derived from the
    /// person's root secret: the account id and identity key are the ones every other device of
    /// theirs derives, the device key is new, and the device certifies itself. Returns the identity
    /// to register; `user_id` in it is the account to sign in to.
    pub fn create_identity_from_root(
        &mut self,
        root: &RootSecret,
        server_key: &[u8],
        device_id: &str,
    ) -> Result<DeviceIdentity> {
        let account = root.account(server_key)?;
        self.install_identity(account.identity, &account.user_id, device_id)
    }

    /// As [`Session::create_identity_from_root`], for an account whose id is not the one the root
    /// derives: one the server's owner let a new identity reclaim, which keeps its old id. The
    /// identity key is still the root's for this server, so every device of the person certifies
    /// itself the same way; only the id it is certified for comes from outside.
    pub fn create_identity_from_root_for(
        &mut self,
        root: &RootSecret,
        server_key: &[u8],
        user_id: &str,
        device_id: &str,
    ) -> Result<DeviceIdentity> {
        if user_id.is_empty() {
            return Err(CryptoError::Store("an account id is needed".into()));
        }
        let account = root.account(server_key)?;
        self.install_identity(account.identity, user_id, device_id)
    }

    /// Every identity key this device has pinned, for the person's vault: trust decisions made on
    /// one device follow them to the next.
    pub fn export_pins(&self) -> Result<Vec<BackedUpPin>> {
        Ok(self
            .store
            .pinned_identities()?
            .into_iter()
            .map(|p: PinnedIdentity| BackedUpPin {
                user_id: p.user_id,
                identity_key: p.identity_key,
                verified: p.verified,
            })
            .collect())
    }

    /// Takes pins from the vault. Only users this device has not met are added: a pin made here is
    /// never overwritten by one that came from somewhere else, so a vault can add trust but cannot
    /// swap a key this device already holds.
    pub fn import_pins(&self, pins: &[BackedUpPin]) -> Result<()> {
        let now = now_unix();
        for pin in pins {
            if self.store.pinned_identity(&pin.user_id)?.is_some() {
                continue;
            }
            self.store.replace_identity(&pin.user_id, &pin.identity_key, now)?;
            if pin.verified {
                self.store.mark_verified(&pin.user_id, &pin.identity_key)?;
            }
        }
        Ok(())
    }

    /// The user looked at the new safety number and accepts `user_id`'s changed identity key. Every
    /// message held because it came under that key ([`Session::receive_message`]) moves into the
    /// message cache; ones held under any other key stay held. Returns how many were released.
    ///
    /// It also clears the record of the groups this device left because of that key
    /// ([`Session::pending_identity_changes`]), so the caller reads `left_group_ids` first and joins
    /// those groups again afterwards. In this order — pin, held messages, left groups — a failure
    /// part way leaves something still pending, and accepting again finishes the job.
    pub fn accept_changed_identity(&self, user_id: &str, identity_key: &[u8]) -> Result<usize> {
        self.store.replace_identity(user_id, identity_key, now_unix())?;
        let released = self.store.release_held_messages(user_id, identity_key)?;
        self.store.clear_left_groups(user_id, identity_key)?;
        Ok(released)
    }

    /// Every changed identity key waiting for the user's decision: for each user and key they
    /// presented, the key pinned now, how many of their messages are held and in which groups, and
    /// which groups this device left because of it. Read from the encrypted store, so it is
    /// complete after a restart. An entry goes when the key is accepted
    /// ([`Session::accept_changed_identity`]); its groups' part also when a group is joined again,
    /// deleted ([`Session::delete_group`]) or created.
    pub fn pending_identity_changes(&self) -> Result<Vec<PendingIdentityChange>> {
        self.store.pending_identity_changes()
    }

    /// A new device for a user restored from their backup. Keeps the user's identity key (so peers'
    /// safety numbers do not change) and the pins they had made; the device key is new.
    pub fn restore_identity(&mut self, backup: &BackupContents, device_id: &str) -> Result<DeviceIdentity> {
        let identity = UserIdentity::from_secret(&backup.user_identity_secret)?;
        let now = now_unix();
        for pin in &backup.pinned_identities {
            self.store.replace_identity(&pin.user_id, &pin.identity_key, now)?;
            if pin.verified {
                self.store.mark_verified(&pin.user_id, &pin.identity_key)?;
            }
        }
        self.install_identity(identity, &backup.user_id, device_id)
    }

    /// What goes into a backup of this user's keys.
    pub fn backup_contents(&self) -> Result<BackupContents> {
        let device = self.require_device()?;
        let secret = self
            .store
            .get_meta(META_IDENTITY_SECRET)?
            .ok_or_else(|| CryptoError::NotFound("identity secret".into()))?;
        let pinned_identities = self
            .store
            .pinned_identities()?
            .into_iter()
            .map(|p: PinnedIdentity| BackedUpPin {
                user_id: p.user_id,
                identity_key: p.identity_key,
                verified: p.verified,
            })
            .collect();
        Ok(BackupContents {
            user_id: device.identity.user_id.clone(),
            user_identity_secret: secret.to_vec(),
            pinned_identities,
        })
    }

    fn install_identity(&mut self, identity: UserIdentity, user_id: &str, device_id: &str) -> Result<DeviceIdentity> {
        if self.device.is_some() {
            return Err(CryptoError::Store("this store already holds a device identity".into()));
        }

        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(mls)?;
        signer.store(self.provider.storage()).map_err(mls)?;

        let certificate = identity.certify_device(user_id, device_id, signer.public(), now_unix())?;
        self.persist_identity(&identity, &certificate, signer.public())
    }

    /// Writes an identity and certificate for a device key already in MLS storage, then loads it.
    fn persist_identity(
        &mut self,
        identity: &UserIdentity,
        certificate: &DeviceCertificate,
        signature_public: &[u8],
    ) -> Result<DeviceIdentity> {
        let user_id = certificate.user_id.as_str();
        self.store.put_meta(META_USER_ID, user_id.as_bytes())?;
        self.store.put_meta(META_DEVICE_ID, certificate.device_id.as_bytes())?;
        self.store
            .put_meta(META_IDENTITY_SECRET, identity.secret().as_slice())?;
        self.store.put_meta(META_DEVICE_KEY, signature_public)?;
        self.store.put_meta(META_CERTIFICATE, &certificate.to_bytes()?)?;

        // A user trusts their own identity key from the start.
        self.store
            .replace_identity(user_id, &identity.public_key(), now_unix())?;
        self.store.mark_verified(user_id, &identity.public_key())?;

        self.device = self.load_device()?;
        Ok(self.require_device()?.identity.clone())
    }

    // ── Session binding ──────────────────────────────────────────────────────────────────────

    /// Signs the server's session-binding challenge with this device's key, proving the session
    /// runs here. The server checks it against the device key in the certificate it stored.
    pub fn sign_session_challenge(&self, nonce: &[u8]) -> Result<Vec<u8>> {
        let device = self.require_device()?;
        let mut payload = SESSION_BINDING_CONTEXT.to_vec();
        payload.extend_from_slice(nonce);
        device.signer.sign(&payload).map_err(mls)
    }

    /// Signs the server's sign-in challenge with this device's key. There is no password: holding
    /// a device key the account's identity key has certified *is* the credential. The server's own
    /// identity key is signed along with its nonce, so a challenge relayed from another server
    /// produces a signature that server cannot use.
    pub fn sign_auth_challenge(&self, server_key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        let device = self.require_device()?;
        let length = u16::try_from(server_key.len())
            .map_err(|_| CryptoError::Malformed("server identity key is too long".into()))?;
        let mut payload = AUTH_CONTEXT.to_vec();
        payload.extend_from_slice(&length.to_be_bytes());
        payload.extend_from_slice(server_key);
        payload.extend_from_slice(nonce);
        device.signer.sign(&payload).map_err(mls)
    }

    /// Signs a message attestation: the device's statement that it wrote this message, which a
    /// recipient can later reveal to moderators when reporting it. `canonical` is the message's
    /// canonical encoding (channel, client message id, time, type, body); the context string is
    /// added here so the signature is good for nothing else.
    pub fn sign_message_attestation(&self, canonical: &[u8]) -> Result<Vec<u8>> {
        self.sign_attestation(MESSAGE_ATTESTATION_CONTEXT, canonical)
    }

    /// [`Self::sign_message_attestation`] for a message that carries files, whose canonical encoding
    /// also binds each file's id and ciphertext hash — so a reporter cannot pair the author's words
    /// with somebody else's file.
    pub fn sign_message_attestation_v2(&self, canonical: &[u8]) -> Result<Vec<u8>> {
        self.sign_attestation(MESSAGE_ATTESTATION_V2_CONTEXT, canonical)
    }

    fn sign_attestation(&self, context: &[u8], canonical: &[u8]) -> Result<Vec<u8>> {
        let device = self.require_device()?;
        let mut payload = context.to_vec();
        payload.extend_from_slice(canonical);
        device.signer.sign(&payload).map_err(mls)
    }

    // ── Linking a new device ─────────────────────────────────────────────────────────────────

    /// On a **new** device with no identity yet: makes its device key and an offer for one of the
    /// user's existing devices to approve. Returns the offer (to upload), its commitment and the code
    /// secret (both to put in the link code the user carries across; the code secret is never
    /// uploaded). Starting again replaces an unfinished link.
    pub fn begin_device_link(
        &mut self,
        user_id: &str,
        device_id: &str,
    ) -> Result<(
        Vec<u8>,
        [u8; link::COMMITMENT_LENGTH],
        Zeroizing<[u8; link::CODE_SECRET_LENGTH]>,
    )> {
        if self.device.is_some() {
            return Err(CryptoError::Store("this store already holds a device identity".into()));
        }

        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(mls)?;
        signer.store(self.provider.storage()).map_err(mls)?;
        let exchange = link::new_exchange_secret();
        let code_secret = link::new_code_secret();

        let offer = link::Offer {
            user_id: user_id.to_owned(),
            device_id: device_id.to_owned(),
            device_signature_key: signer.public().to_vec(),
            exchange_key: link::exchange_public(&exchange),
        }
        .to_bytes()?;

        self.store.put_meta(META_LINK_OFFER, &offer)?;
        self.store.put_meta(META_LINK_EXCHANGE_SECRET, exchange.as_bytes())?;
        self.store.put_meta(META_LINK_CODE_SECRET, code_secret.as_slice())?;
        Ok((offer.clone(), link::commitment(&offer), code_secret))
    }

    /// On an **existing** device: checks the new device's offer against the commitment from the
    /// link code, certifies its key, and seals this user's identity secret and pins to it and to the
    /// link code's secret.
    pub fn approve_device_link(
        &self,
        offer_bytes: &[u8],
        expected_commitment: &[u8],
        code_secret: &[u8],
    ) -> Result<Vec<u8>> {
        let device = self.require_device()?;

        let actual = link::commitment(offer_bytes);
        if expected_commitment.len() != actual.len() || !subtle_eq(expected_commitment, &actual) {
            return Err(CryptoError::Verification(
                "the offer does not match the link code; it may have been tampered with".into(),
            ));
        }

        let offer = link::Offer::from_bytes(offer_bytes)?;
        if offer.user_id != device.identity.user_id {
            return Err(CryptoError::Verification("the offer is for a different user".into()));
        }
        if offer.device_signature_key.len() != 32 {
            return Err(CryptoError::Malformed(
                "the offered device key is not an Ed25519 key".into(),
            ));
        }

        let secret = self
            .store
            .get_meta(META_IDENTITY_SECRET)?
            .ok_or_else(|| CryptoError::NotFound("identity secret".into()))?;
        let identity = UserIdentity::from_secret(&secret)?;
        let certificate = identity.certify_device(
            &offer.user_id,
            &offer.device_id,
            &offer.device_signature_key,
            now_unix(),
        )?;

        let contents = link::ApprovalContents {
            certificate: certificate.to_bytes()?,
            user_identity_secret: secret.to_vec(),
            pinned_identities: self.backup_contents()?.pinned_identities.clone(),
        };
        link::seal_approval(offer_bytes, &offer, code_secret, &contents)
    }

    /// On the **new** device: opens the approval and becomes a full device of the user.
    pub fn complete_device_link(&mut self, approval: &[u8]) -> Result<DeviceIdentity> {
        if self.device.is_some() {
            return Err(CryptoError::Store("this store already holds a device identity".into()));
        }

        let offer_bytes = self
            .store
            .get_meta(META_LINK_OFFER)?
            .ok_or_else(|| CryptoError::NotFound("no device link is in progress".into()))?;
        let exchange_bytes: [u8; 32] = self
            .store
            .get_meta(META_LINK_EXCHANGE_SECRET)?
            .ok_or_else(|| CryptoError::NotFound("no device link is in progress".into()))?
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Store("corrupt device link secret".into()))?;
        let code_secret = self
            .store
            .get_meta(META_LINK_CODE_SECRET)?
            .ok_or_else(|| CryptoError::NotFound("no device link is in progress".into()))?;
        let offer = link::Offer::from_bytes(&offer_bytes)?;
        let contents = link::open_approval(approval, &offer_bytes, &exchange_bytes.into(), &code_secret)?;

        let identity = UserIdentity::from_secret(&contents.user_identity_secret)?;
        let certificate = DeviceCertificate::from_bytes(&contents.certificate)?;
        certificate.verify()?;
        if certificate.user_identity_key != identity.public_key()
            || certificate.device_signature_key != offer.device_signature_key
            || certificate.user_id != offer.user_id
            || certificate.device_id != offer.device_id
        {
            return Err(CryptoError::Verification(
                "the approval does not match this device's offer".into(),
            ));
        }

        let now = now_unix();
        for pin in &contents.pinned_identities {
            self.store.replace_identity(&pin.user_id, &pin.identity_key, now)?;
            if pin.verified {
                self.store.mark_verified(&pin.user_id, &pin.identity_key)?;
            }
        }

        let installed = self.persist_identity(&identity, &certificate, &offer.device_signature_key)?;
        self.store.delete_meta(META_LINK_OFFER)?;
        self.store.delete_meta(META_LINK_EXCHANGE_SECRET)?;
        self.store.delete_meta(META_LINK_CODE_SECRET)?;
        Ok(installed)
    }

    fn load_device(&self) -> Result<Option<Device>> {
        let Some(certificate_bytes) = self.store.get_meta(META_CERTIFICATE)? else {
            return Ok(None);
        };
        let certificate = DeviceCertificate::from_bytes(&certificate_bytes)?;
        let public = self
            .store
            .get_meta(META_DEVICE_KEY)?
            .ok_or_else(|| CryptoError::NotFound("device signature key".into()))?;
        let signer = SignatureKeyPair::read(self.provider.storage(), &public, CIPHERSUITE.signature_algorithm())
            .ok_or_else(|| CryptoError::NotFound("device signature key pair".into()))?;

        let credential = CredentialWithKey {
            credential: BasicCredential::new(certificate_bytes.to_vec()).into(),
            signature_key: signer.public().into(),
        };
        Ok(Some(Device {
            identity: DeviceIdentity {
                user_id: certificate.user_id.clone(),
                device_id: certificate.device_id.clone(),
                user_identity_key: certificate.user_identity_key.clone(),
                device_signature_key: certificate.device_signature_key.clone(),
                certificate: certificate_bytes.to_vec(),
            },
            signer,
            credential,
        }))
    }

    fn require_device(&self) -> Result<&Device> {
        self.device
            .as_ref()
            .ok_or_else(|| CryptoError::NotFound("this device has no identity yet".into()))
    }

    fn validator(&self) -> PinnedIdentityValidator<'_> {
        PinnedIdentityValidator {
            store: &self.store,
            now_unix: now_unix(),
        }
    }

    // ── Key packages ─────────────────────────────────────────────────────────────────────────

    /// `count` one-time key packages for the server to hand out, so others can add this device to
    /// groups while it is offline. Pass `last_resort` for the single reusable one the server falls
    /// back to when the one-time ones run out.
    pub fn generate_key_packages(&self, count: usize, last_resort: bool) -> Result<Vec<Vec<u8>>> {
        let device = self.require_device()?;
        (0..count)
            .map(|_| {
                let mut builder = KeyPackage::builder();
                if last_resort {
                    builder = builder.mark_as_last_resort();
                }
                let bundle = builder
                    .build(CIPHERSUITE, &self.provider, &device.signer, device.credential.clone())
                    .map_err(mls)?;
                // Wrapped as an MLSMessage (wire format key_package), the form RFC 9420 transports
                // them in and the one the delivery service checks for.
                MlsMessageOut::from(bundle.key_package().clone())
                    .to_bytes()
                    .map_err(mls)
            })
            .collect()
    }

    // ── Groups ───────────────────────────────────────────────────────────────────────────────

    /// Starts a group with this device as its only member. Raindrop uses one group per channel, and
    /// `group_id` is the channel's id.
    pub fn create_group(&self, group_id: &[u8]) -> Result<()> {
        let device = self.require_device()?;
        MlsGroup::builder()
            .with_group_id(GroupId::from_slice(group_id))
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .padding_size(PADDING)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .with_wire_format_policy(MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .build(&self.provider, &device.signer, device.credential.clone())
            .map_err(mls)?;
        self.store.forget_left_group(group_id)
    }

    pub fn has_group(&self, group_id: &[u8]) -> Result<bool> {
        Ok(self.load_group(group_id).is_ok())
    }

    pub fn epoch(&self, group_id: &[u8]) -> Result<u64> {
        Ok(self.load_group(group_id)?.epoch().as_u64())
    }

    /// Every device in the group, with who it belongs to.
    pub fn members(&self, group_id: &[u8]) -> Result<Vec<GroupMember>> {
        let group = self.load_group(group_id)?;
        group
            .members()
            .map(|m| member_of(&m.credential, &m.signature_key, m.index.u32()))
            .collect()
    }

    /// The signed group state a device needs to join by itself (an external commit). Upload it
    /// after every commit this device merges.
    pub fn group_info(&self, group_id: &[u8]) -> Result<Vec<u8>> {
        let device = self.require_device()?;
        let group = self.load_group(group_id)?;
        group
            .export_group_info(self.provider.crypto(), &device.signer, true)
            .map_err(mls)?
            .to_bytes()
            .map_err(mls)
    }

    /// Adds devices using the key packages the server handed out for them. Every key package's
    /// certificate is checked (and its user's identity key pinned) before anything is committed.
    pub fn add_members(&self, group_id: &[u8], key_packages: &[Vec<u8>]) -> Result<PendingCommit> {
        let device = self.require_device()?;
        let validator = self.validator();

        let key_packages = key_packages
            .iter()
            .map(|bytes| {
                let MlsMessageBodyIn::KeyPackage(key_package) = MlsMessageIn::tls_deserialize_exact(bytes)
                    .map_err(|e| CryptoError::Malformed(format!("key package: {e}")))?
                    .extract()
                else {
                    return Err(CryptoError::Malformed("not a key package message".into()));
                };
                let key_package = key_package
                    .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                    .map_err(|e| CryptoError::Verification(format!("key package: {e:?}")))?;
                let leaf = key_package.leaf_node();
                validator.validate(leaf.credential(), leaf.signature_key().as_slice())?;
                Ok(key_package)
            })
            .collect::<Result<Vec<_>>>()?;

        let mut group = self.load_group(group_id)?;
        // Only proposals this device makes here go into the commit, never a stored one.
        group.clear_pending_proposals(self.provider.storage()).map_err(mls)?;
        let (commit, welcome, _) = group
            .add_members(&self.provider, &device.signer, &key_packages)
            .map_err(mls)?;
        let commit = commit.to_bytes().map_err(mls)?;
        self.remember_pending_commit(group_id, &commit)?;
        Ok(PendingCommit {
            commit,
            welcome: Some(welcome.to_bytes().map_err(mls)?),
            epoch_after: group.epoch().as_u64() + 1,
        })
    }

    /// Removes devices, by leaf index, from the group; their keys stop working at the next epoch.
    pub fn remove_members(&self, group_id: &[u8], leaf_indices: &[u32]) -> Result<PendingCommit> {
        let device = self.require_device()?;
        let mut group = self.load_group(group_id)?;
        // Only proposals this device makes here go into the commit, never a stored one.
        group.clear_pending_proposals(self.provider.storage()).map_err(mls)?;
        let leaves: Vec<_> = leaf_indices.iter().map(|i| LeafNodeIndex::new(*i)).collect();
        let (commit, welcome, _) = group
            .remove_members(&self.provider, &device.signer, &leaves)
            .map_err(mls)?;
        let commit = commit.to_bytes().map_err(mls)?;
        self.remember_pending_commit(group_id, &commit)?;
        Ok(PendingCommit {
            commit,
            welcome: welcome.map(|w| w.to_bytes()).transpose().map_err(mls)?,
            epoch_after: group.epoch().as_u64() + 1,
        })
    }

    /// Rotates this device's keys in the group, moving everyone to a new epoch. Raindrop uses this
    /// to rekey calls when somebody leaves, and periodically.
    pub fn self_update(&self, group_id: &[u8]) -> Result<PendingCommit> {
        let device = self.require_device()?;
        let mut group = self.load_group(group_id)?;
        // Only proposals this device makes here go into the commit, never a stored one.
        group.clear_pending_proposals(self.provider.storage()).map_err(mls)?;
        let bundle = group
            .self_update(&self.provider, &device.signer, LeafNodeParameters::default())
            .map_err(mls)?;
        let commit = bundle.commit().to_bytes().map_err(mls)?;
        self.remember_pending_commit(group_id, &commit)?;
        Ok(PendingCommit {
            commit,
            welcome: None,
            epoch_after: group.epoch().as_u64() + 1,
        })
    }

    /// Joins a group by itself from its published [`Session::group_info`], without anybody online
    /// to add it. The server only accepts this from a device allowed in the channel.
    ///
    /// `expected_group_id` is the group the caller means to join (the channel's id); a group info
    /// for any other group is refused ([`CryptoError::Verification`]), and so is joining a group
    /// this device already holds, which the join would otherwise overwrite
    /// ([`CryptoError::Store`]). Every existing member's certificate is checked; OpenMLS stores
    /// and merges the group as it builds the commit, so a member that fails the check gets the
    /// group deleted again before the error returns, and nothing unvalidated stays in storage.
    ///
    /// The returned `epoch_after` is the epoch this device is already at: the group is merged here,
    /// so the caller's [`Session::merge_pending_commit`] after the server accepts the commit is a
    /// no-op that returns the same epoch. If the server refuses the commit, [`Session::reset_group`] (which keeps the cached messages, so the
    /// next attempt can start from the same history).
    pub fn join_by_external_commit(
        &self,
        expected_group_id: &[u8],
        group_info: &[u8],
    ) -> Result<(Vec<u8>, PendingCommit)> {
        let device = self.require_device()?;
        let MlsMessageBodyIn::GroupInfo(group_info) = MlsMessageIn::tls_deserialize_exact(group_info)
            .map_err(|e| CryptoError::Malformed(format!("group info: {e}")))?
            .extract()
        else {
            return Err(CryptoError::Malformed("not a group info message".into()));
        };

        if group_info.group_id().as_slice() != expected_group_id {
            return Err(CryptoError::Verification(format!(
                "group info is for group {}, not {}",
                hex(group_info.group_id().as_slice()),
                hex(expected_group_id)
            )));
        }
        if self.has_group(expected_group_id)? {
            return Err(CryptoError::Store(format!("group {} is already held by this device", hex(expected_group_id))));
        }

        let join_config = join_config();
        let (mut group, bundle) = MlsGroup::external_commit_builder()
            .with_config(join_config)
            .build_group(&self.provider, group_info, device.credential.clone())
            .map_err(mls)?
            .load_psks(self.provider.storage())
            .map_err(mls)?
            .build(self.provider.rand(), self.provider.crypto(), &device.signer, |_| true)
            .map_err(mls)?
            .finalize(&self.provider)
            .map_err(mls)?;

        let validator = self.validator();
        let own = group.own_leaf_index();
        let checked = group
            .members()
            .filter(|m| m.index != own)
            .try_for_each(|member| validator.validate(&member.credential, &member.signature_key).map(drop))
            .and_then(|()| bundle.commit().to_bytes().map_err(mls));
        let commit = match checked {
            Ok(commit) => commit,
            Err(refusal) => {
                // `finalize` already stored the group, at the new epoch, on a ratchet tree the
                // server supplied. Do not leave it behind.
                group.delete(self.provider.storage()).map_err(mls)?;
                self.note_left_group(expected_group_id, &refusal)?;
                return Err(refusal);
            }
        };

        let group_id = group.group_id().as_slice().to_vec();
        self.store.forget_left_group(&group_id)?;
        Ok((
            group_id,
            PendingCommit {
                commit,
                welcome: None,
                // `finalize` has merged the commit, so this is already the epoch after it.
                epoch_after: group.epoch().as_u64(),
            },
        ))
    }

    /// Joins a group this device was added to. Returns the group's id.
    pub fn join_from_welcome(&self, welcome: &[u8]) -> Result<Vec<u8>> {
        let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(|e| CryptoError::Malformed(format!("welcome: {e}")))?
            .extract()
        else {
            return Err(CryptoError::Malformed("not a welcome message".into()));
        };

        let staged = StagedWelcome::new_from_welcome(&self.provider, &join_config(), welcome, None).map_err(mls)?;

        let validator = self.validator();
        for member in staged.members() {
            if let Err(refusal) = validator.validate(&member.credential, &member.signature_key) {
                self.note_left_group(staged.group_context().group_id().as_slice(), &refusal)?;
                return Err(refusal);
            }
        }

        let group = staged.into_group(&self.provider).map_err(mls)?;
        let group_id = group.group_id().as_slice().to_vec();
        self.store.forget_left_group(&group_id)?;
        Ok(group_id)
    }

    /// The server accepted this device's commit: move to the new epoch.
    pub fn merge_pending_commit(&self, group_id: &[u8]) -> Result<u64> {
        let mut group = self.load_group(group_id)?;
        group.merge_pending_commit(&self.provider).map_err(mls)?;
        self.forget_pending_commit(group_id)?;
        Ok(group.epoch().as_u64())
    }

    /// The server accepted another commit for this epoch instead: forget this device's.
    pub fn discard_pending_commit(&self, group_id: &[u8]) -> Result<()> {
        let mut group = self.load_group(group_id)?;
        group.clear_pending_commit(self.provider.storage()).map_err(mls)?;
        self.forget_pending_commit(group_id)
    }

    /// Drops this device's MLS state for a group (and its pending commit) but **keeps the cached and
    /// held messages**, which are the only copy of their plaintext: MLS deleted the keys that
    /// decrypted them, so ciphertext fetched again cannot be read. Use it whenever the device is
    /// going to rejoin the group ([`Session::join_by_external_commit`], [`Session::join_from_welcome`]):
    /// after [`CryptoError::ResyncRequired`], a refused or failed join, or a commit the server
    /// refused. Does nothing if the group is not held.
    pub fn reset_group(&self, group_id: &[u8]) -> Result<()> {
        if let Ok(mut group) = self.load_group(group_id) {
            group.delete(self.provider.storage()).map_err(mls)?;
        }
        self.forget_pending_commit(group_id)
    }

    /// Forgets a group entirely (the channel was deleted, or this device left it), including its
    /// cached and held messages. For a group that is going to be rejoined, use
    /// [`Session::reset_group`], which keeps them.
    pub fn delete_group(&self, group_id: &[u8]) -> Result<()> {
        self.reset_group(group_id)?;
        self.store.delete_group_messages(group_id)
    }

    /// If `refusal` is a changed identity, records that it is why this device is out of `group_id`,
    /// so the client can list the group as waiting for the user's decision, also after a restart.
    /// Any other refusal is not something the user could reverse, so nothing is recorded.
    fn note_left_group(&self, group_id: &[u8], refusal: &CryptoError) -> Result<()> {
        if let CryptoError::IdentityChanged {
            user_id, presented_key, ..
        } = refusal
        {
            self.store
                .record_left_group(group_id, user_id, presented_key, now_unix())?;
        }
        Ok(())
    }

    /// Remembers which commit bytes this device's pending commit for the group is, replacing any
    /// earlier one (OpenMLS holds one pending commit per group, and creating one replaces it).
    fn remember_pending_commit(&self, group_id: &[u8], commit: &[u8]) -> Result<()> {
        self.store
            .put_meta(&pending_commit_key(group_id), Sha256::digest(commit).as_slice())
    }

    fn forget_pending_commit(&self, group_id: &[u8]) -> Result<()> {
        self.store.delete_meta(&pending_commit_key(group_id))
    }

    /// Whether `message` is, byte for byte, the commit this device's pending commit was sent as.
    fn is_pending_commit(&self, group_id: &[u8], message: &[u8]) -> Result<bool> {
        Ok(match self.store.get_meta(&pending_commit_key(group_id))? {
            Some(expected) => subtle_eq(&expected, Sha256::digest(message).as_slice()),
            None => false,
        })
    }

    // ── Messages ─────────────────────────────────────────────────────────────────────────────

    /// Encrypts an application payload for everyone in the group.
    pub fn encrypt(&self, group_id: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
        let device = self.require_device()?;
        let mut group = self.load_group(group_id)?;
        group
            .create_message(&self.provider, &device.signer, payload)
            .map_err(mls)?
            .to_bytes()
            .map_err(mls)
    }

    /// Processes one message from the group's delivery stream: a commit, a proposal, or somebody's
    /// application message. Commits are checked (every device they add must carry a valid
    /// certificate for a correctly pinned identity) and merged before this returns.
    ///
    /// A commit that fails those checks deletes the group before the error returns: MLS has already
    /// spent the key it was decrypted with, so the group could never move past it. Rejoin by
    /// external commit once the cause (most often a changed identity to accept) is dealt with.
    ///
    /// An application message from a sender whose identity key changed is
    /// [`CryptoError::IdentityChanged`], and its plaintext is lost; [`Session::receive_message`],
    /// which knows the message's id, holds it instead.
    pub fn process(&self, message: &[u8]) -> Result<(Vec<u8>, Incoming)> {
        self.process_or_withhold(message)?.map_err(|withheld| withheld.error)
    }

    /// [`Session::process`], except that an application message refused for its sender's changed
    /// identity comes back decrypted, as [`Withheld`], rather than dropped.
    fn process_or_withhold(&self, message: &[u8]) -> Result<std::result::Result<(Vec<u8>, Incoming), Withheld>> {
        let protocol_message: ProtocolMessage = match MlsMessageIn::tls_deserialize_exact(message)
            .map_err(|e| CryptoError::Malformed(format!("mls message: {e}")))?
            .extract()
        {
            MlsMessageBodyIn::PrivateMessage(m) => m.into(),
            MlsMessageBodyIn::PublicMessage(m) => m.into(),
            _ => return Err(CryptoError::Malformed("not a group message".into())),
        };

        let group_id = protocol_message.group_id().as_slice().to_vec();
        // Readable without decrypting: whether this is a commit, a proposal or application data.
        let is_commit = protocol_message.content_type() == ContentType::Commit;
        let mut group = self.load_group(&group_id)?;
        let processed = group.process_message(&self.provider, protocol_message).map_err(mls)?;
        let epoch = processed.epoch().as_u64();
        let validator = self.validator();

        // Application messages come from a member whose leaf is in the current tree; the leaf's
        // signature key is what the certificate must be about.
        let sender_leaf = match processed.sender() {
            Sender::Member(index) => Some(*index),
            _ => None,
        };
        let credential = processed.credential().clone();

        let incoming = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                let index = sender_leaf
                    .ok_or_else(|| CryptoError::Verification("application message from a non-member".into()))?;
                let leaf = group
                    .members()
                    .find(|m| m.index == index)
                    .ok_or_else(|| CryptoError::Verification("sender is not in the group".into()))?;
                let certificate = match validator.validate(&credential, &leaf.signature_key) {
                    Ok(certificate) => certificate,
                    // MLS has spent this message's key already. Keep the plaintext aside for the
                    // user's decision instead of losing it; `validate` checked the certificate
                    // itself before the pin refused it, so reading it again cannot fail.
                    Err(error @ CryptoError::IdentityChanged { .. }) => {
                        let certificate = certificate_of(&credential, &leaf.signature_key)?;
                        return Ok(Err(Withheld {
                            group_id,
                            sender_user_id: certificate.user_id,
                            sender_device_id: certificate.device_id,
                            sender_identity_key: certificate.user_identity_key,
                            epoch,
                            payload: application.into_bytes(),
                            error,
                        }));
                    }
                    Err(error) => return Err(error),
                };
                Incoming::Application {
                    sender: GroupMember {
                        leaf_index: index.u32(),
                        user_id: certificate.user_id,
                        device_id: certificate.device_id,
                    },
                    epoch,
                    payload: application.into_bytes(),
                }
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let checked = (|| -> Result<Vec<GroupMember>> {
                    let mut added = Vec::new();
                    for add in staged.add_proposals() {
                        let leaf = add.add_proposal().key_package().leaf_node();
                        let certificate = validator.validate(leaf.credential(), leaf.signature_key().as_slice())?;
                        added.push(GroupMember {
                            leaf_index: u32::MAX,
                            user_id: certificate.user_id,
                            device_id: certificate.device_id,
                        });
                    }
                    for update in staged.update_proposals() {
                        let leaf = update.update_proposal().leaf_node();
                        validator.validate(leaf.credential(), leaf.signature_key().as_slice())?;
                    }
                    // The committer's own new leaf — which, for an external commit, is the device
                    // that just joined.
                    if let Some(leaf) = staged.update_path_leaf_node() {
                        validator.validate(leaf.credential(), leaf.signature_key().as_slice())?;
                    }
                    Ok(added)
                })();
                let added = match checked {
                    Ok(added) => added,
                    Err(refusal) => {
                        // Refusing a commit is leaving the group. MLS spent the key that decrypted
                        // it, so it cannot be processed again, and every later commit builds on it:
                        // the group would be stuck at this epoch for good. Drop it (but not its
                        // cached messages, the only copy of their plaintext); rejoining by external
                        // commit checks every member again.
                        self.reset_group(&group_id)?;
                        self.note_left_group(&group_id, &refusal)?;
                        return Err(refusal);
                    }
                };

                let removed = staged
                    .remove_proposals()
                    .filter_map(|remove| {
                        let index = remove.remove_proposal().removed();
                        group.member(index).and_then(|credential| {
                            let leaf = group.members().find(|m| m.index == index)?;
                            member_of(credential, &leaf.signature_key, index.u32()).ok()
                        })
                    })
                    .collect();

                let removed_self = staged.self_removed();
                group.merge_staged_commit(&self.provider, *staged).map_err(mls)?;
                // Another commit took the epoch, so this device's pending one (if any) is gone.
                self.forget_pending_commit(&group_id)?;
                Incoming::Commit {
                    epoch: group.epoch().as_u64(),
                    added,
                    removed,
                    removed_self,
                }
            }
            // Our own commit, fanned back out by the server: it was accepted, so apply it.
            ProcessedMessageContent::OwnPendingCommit => {
                group.merge_pending_commit(&self.provider).map_err(mls)?;
                self.forget_pending_commit(&group_id)?;
                Incoming::Commit {
                    epoch: group.epoch().as_u64(),
                    added: Vec::new(),
                    removed: Vec::new(),
                    removed_self: false,
                }
            }
            // Something this device sent, encrypted, so MLS cannot open it (and has no need to).
            // If it is our application message, its plaintext was kept when it was sent
            // (`remember_sent`). If it is a commit, the server accepted it — but "this device sent
            // it" is only what the sender data says, which is not authenticated (any member can
            // forge it), and MLS cannot decrypt the commit to check. So it is applied only when it
            // is byte for byte the pending commit this device made. Anything else is a commit this
            // device does not hold (one it discarded after the server took it, or a forgery): the
            // group cannot follow it, and the caller has to rejoin.
            ProcessedMessageContent::OwnPrivateMessage if is_commit => {
                if group.pending_commit().is_none() || !self.is_pending_commit(&group_id, message)? {
                    return Err(CryptoError::ResyncRequired);
                }
                group.merge_pending_commit(&self.provider).map_err(mls)?;
                self.forget_pending_commit(&group_id)?;
                Incoming::Commit {
                    epoch: group.epoch().as_u64(),
                    added: Vec::new(),
                    removed: Vec::new(),
                    removed_self: false,
                }
            }
            ProcessedMessageContent::OwnPrivateMessage => Incoming::OwnMessage { epoch },
            // Raindrop changes a group only by commit. A standalone proposal is never stored: one
            // left in the proposal store would be swept into this device's next commit without its
            // credential ever being validated (an external Add from a non-member, say).
            ProcessedMessageContent::ProposalMessage(_) | ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                return Err(CryptoError::Verification("standalone proposals are not accepted".into()));
            }
        };
        Ok(Ok((group_id, incoming)))
    }

    /// Decrypts a channel message and keeps its plaintext in the local cache — the only copy there
    /// will ever be, since the epoch key that decrypted it is soon deleted. A message already in the
    /// cache is returned from there without touching MLS, because MLS would refuse to decrypt it a
    /// second time.
    ///
    /// A message from a sender whose identity key changed is [`CryptoError::IdentityChanged`], every
    /// time it is asked for, and its plaintext is held (in the same encrypted store) until the user
    /// accepts the new key with [`Session::accept_changed_identity`]; from then on it is in the
    /// cache and returned from there. A message the user never accepts stays held until its group
    /// is deleted.
    pub fn receive_message(
        &self,
        message_id: &str,
        sent_at_unix_ms: i64,
        message: &[u8],
    ) -> Result<Option<CachedMessage>> {
        if let Some(group_id) = peek_group_id(message)? {
            if let Some(cached) = self.store.message(&group_id, message_id)? {
                return Ok(Some(cached));
            }
            // Decrypted once already, and waiting on the user's decision.
            if let Some((user_id, presented_key)) = self.store.held_message_origin(&group_id, message_id)? {
                let pinned_key = self
                    .store
                    .pinned_identity(&user_id)?
                    .map(|pin| pin.identity_key)
                    .unwrap_or_default();
                return Err(CryptoError::IdentityChanged {
                    user_id,
                    pinned_key,
                    presented_key,
                });
            }
        }

        let processed = match self.process_or_withhold(message)? {
            Ok(processed) => processed,
            Err(withheld) => {
                self.store.hold_message(&HeldMessage {
                    message: CachedMessage {
                        group_id: withheld.group_id,
                        message_id: message_id.to_owned(),
                        sender_user_id: withheld.sender_user_id,
                        sender_device_id: withheld.sender_device_id,
                        epoch: withheld.epoch,
                        sent_at_unix_ms,
                        payload: withheld.payload,
                    },
                    sender_identity_key: withheld.sender_identity_key,
                })?;
                return Err(withheld.error);
            }
        };
        match processed {
            (group_id, Incoming::Application { sender, epoch, payload }) => {
                let cached = CachedMessage {
                    group_id,
                    message_id: message_id.to_owned(),
                    sender_user_id: sender.user_id,
                    sender_device_id: sender.device_id,
                    epoch,
                    sent_at_unix_ms,
                    payload,
                };
                self.store.put_message(&cached)?;
                Ok(Some(cached))
            }
            _ => Ok(None),
        }
    }

    /// Stores this device's own message, which it cannot decrypt from the server's echo.
    pub fn remember_sent(&self, group_id: &[u8], message_id: &str, sent_at_unix_ms: i64, payload: &[u8]) -> Result<()> {
        let device = self.require_device()?;
        self.store.put_message(&CachedMessage {
            group_id: group_id.to_vec(),
            message_id: message_id.to_owned(),
            sender_user_id: device.identity.user_id.clone(),
            sender_device_id: device.identity.device_id.clone(),
            epoch: self.epoch(group_id)?,
            sent_at_unix_ms,
            payload: payload.to_vec(),
        })
    }

    /// A secret every member of the group can derive and nobody else can, for the current epoch —
    /// how a voice call gets its media key. `label` separates uses; `context` binds it further.
    pub fn export_secret(&self, group_id: &[u8], label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
        self.load_group(group_id)?
            .export_secret(self.provider.crypto(), label, context, length)
            .map_err(mls)
    }

    fn load_group(&self, group_id: &[u8]) -> Result<MlsGroup> {
        MlsGroup::load(self.provider.storage(), &GroupId::from_slice(group_id))
            .map_err(mls)?
            .ok_or_else(|| CryptoError::NotFound(format!("group {}", hex(group_id))))
    }
}

/// An application message MLS decrypted whose sender failed the identity check: what
/// [`Session::receive_message`] needs to hold it, and the refusal to return.
struct Withheld {
    group_id: Vec<u8>,
    sender_user_id: String,
    sender_device_id: String,
    sender_identity_key: Vec<u8>,
    epoch: u64,
    payload: Vec<u8>,
    error: CryptoError,
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .padding_size(PADDING)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .wire_format_policy(MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .build()
}

fn member_of(credential: &Credential, signature_key: &[u8], leaf_index: u32) -> Result<GroupMember> {
    let certificate = crate::validation::certificate_of(credential, signature_key)?;
    Ok(GroupMember {
        leaf_index,
        user_id: certificate.user_id,
        device_id: certificate.device_id,
    })
}

/// The group a message is for, read from its cleartext framing without decrypting anything.
fn peek_group_id(message: &[u8]) -> Result<Option<Vec<u8>>> {
    Ok(
        match MlsMessageIn::tls_deserialize_exact(message)
            .map_err(|e| CryptoError::Malformed(format!("mls message: {e}")))?
            .extract()
        {
            MlsMessageBodyIn::PrivateMessage(m) => Some(ProtocolMessage::from(m).group_id().as_slice().to_vec()),
            MlsMessageBodyIn::PublicMessage(m) => Some(ProtocolMessage::from(m).group_id().as_slice().to_vec()),
            _ => None,
        },
    )
}

/// Compares without an early exit, so timing says nothing about how much of a commitment matched.
fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn pending_commit_key(group_id: &[u8]) -> String {
    format!("{META_PENDING_COMMIT_PREFIX}{}", hex(group_id))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
