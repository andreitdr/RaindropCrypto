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

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer as _;

use crate::backup::{BackedUpPin, BackupContents};
use crate::error::{CryptoError, Result, mls};
use crate::identity::{DeviceCertificate, UserIdentity};
use crate::link;
use crate::provider::RaindropProvider;
use crate::store::{CachedMessage, PinnedIdentity, Store};
use crate::validation::{CredentialValidator, PinnedIdentityValidator};

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

/// Prefixed to the server's nonce before signing, so the signature is good for nothing else.
const SESSION_BINDING_CONTEXT: &[u8] = b"raindrop/session-binding/v1\n";

/// Prefixed to a message's canonical encoding before its sender's device signs it (see
/// `sign_message_attestation`), so an attestation is never mistaken for any other signature.
const MESSAGE_ATTESTATION_CONTEXT: &[u8] = b"raindrop/message-attestation/v1\n";

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
    /// A proposal, stored until somebody commits it.
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

        let certificate = identity.certify_device(user_id, device_id, signer.public(), now_unix());
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
        self.store.put_meta(META_CERTIFICATE, &certificate.to_bytes())?;

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

    /// Signs a message attestation: the device's statement that it wrote this message, which a
    /// recipient can later reveal to moderators when reporting it. `canonical` is the message's
    /// canonical encoding (channel, client message id, time, type, body); the context string is
    /// added here so the signature is good for nothing else.
    pub fn sign_message_attestation(&self, canonical: &[u8]) -> Result<Vec<u8>> {
        let device = self.require_device()?;
        let mut payload = MESSAGE_ATTESTATION_CONTEXT.to_vec();
        payload.extend_from_slice(canonical);
        device.signer.sign(&payload).map_err(mls)
    }

    // ── Linking a new device ─────────────────────────────────────────────────────────────────

    /// On a **new** device with no identity yet: makes its device key and an offer for one of the
    /// user's existing devices to approve. Returns the offer (to upload) and its commitment (to put
    /// in the link code the user carries across). Starting again replaces an unfinished link.
    pub fn begin_device_link(
        &mut self,
        user_id: &str,
        device_id: &str,
    ) -> Result<(Vec<u8>, [u8; link::COMMITMENT_LENGTH])> {
        if self.device.is_some() {
            return Err(CryptoError::Store("this store already holds a device identity".into()));
        }

        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(mls)?;
        signer.store(self.provider.storage()).map_err(mls)?;
        let exchange = link::new_exchange_secret();

        let offer = link::Offer {
            user_id: user_id.to_owned(),
            device_id: device_id.to_owned(),
            device_signature_key: signer.public().to_vec(),
            exchange_key: link::exchange_public(&exchange),
        }
        .to_bytes();

        self.store.put_meta(META_LINK_OFFER, &offer)?;
        self.store.put_meta(META_LINK_EXCHANGE_SECRET, exchange.as_bytes())?;
        Ok((offer.clone(), link::commitment(&offer)))
    }

    /// On an **existing** device: checks the new device's offer against the commitment from the
    /// link code, certifies its key, and seals this user's identity secret and pins to it.
    pub fn approve_device_link(&self, offer_bytes: &[u8], expected_commitment: &[u8]) -> Result<Vec<u8>> {
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
        );

        let contents = link::ApprovalContents {
            certificate: certificate.to_bytes(),
            user_identity_secret: secret.to_vec(),
            pinned_identities: self.backup_contents()?.pinned_identities.clone(),
        };
        link::seal_approval(offer_bytes, &offer, &contents)
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
        let offer = link::Offer::from_bytes(&offer_bytes)?;
        let contents = link::open_approval(approval, &offer_bytes, &exchange_bytes.into())?;

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
        Ok(())
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
        let (commit, welcome, _) = group
            .add_members(&self.provider, &device.signer, &key_packages)
            .map_err(mls)?;
        Ok(PendingCommit {
            commit: commit.to_bytes().map_err(mls)?,
            welcome: Some(welcome.to_bytes().map_err(mls)?),
            epoch_after: group.epoch().as_u64() + 1,
        })
    }

    /// Removes devices, by leaf index, from the group; their keys stop working at the next epoch.
    pub fn remove_members(&self, group_id: &[u8], leaf_indices: &[u32]) -> Result<PendingCommit> {
        let device = self.require_device()?;
        let mut group = self.load_group(group_id)?;
        let leaves: Vec<_> = leaf_indices.iter().map(|i| LeafNodeIndex::new(*i)).collect();
        let (commit, welcome, _) = group
            .remove_members(&self.provider, &device.signer, &leaves)
            .map_err(mls)?;
        Ok(PendingCommit {
            commit: commit.to_bytes().map_err(mls)?,
            welcome: welcome.map(|w| w.to_bytes()).transpose().map_err(mls)?,
            epoch_after: group.epoch().as_u64() + 1,
        })
    }

    /// Rotates this device's keys in the group, moving everyone to a new epoch. Raindrop uses this
    /// to rekey calls when somebody leaves, and periodically.
    pub fn self_update(&self, group_id: &[u8]) -> Result<PendingCommit> {
        let device = self.require_device()?;
        let mut group = self.load_group(group_id)?;
        let bundle = group
            .self_update(&self.provider, &device.signer, LeafNodeParameters::default())
            .map_err(mls)?;
        Ok(PendingCommit {
            commit: bundle.commit().to_bytes().map_err(mls)?,
            welcome: None,
            epoch_after: group.epoch().as_u64() + 1,
        })
    }

    /// Joins a group by itself from its published [`Session::group_info`], without anybody online
    /// to add it. The server only accepts this from a device allowed in the channel. Every existing
    /// member's certificate is checked first.
    pub fn join_by_external_commit(&self, group_info: &[u8]) -> Result<(Vec<u8>, PendingCommit)> {
        let device = self.require_device()?;
        let MlsMessageBodyIn::GroupInfo(group_info) = MlsMessageIn::tls_deserialize_exact(group_info)
            .map_err(|e| CryptoError::Malformed(format!("group info: {e}")))?
            .extract()
        else {
            return Err(CryptoError::Malformed("not a group info message".into()));
        };

        let join_config = join_config();
        let (group, bundle) = MlsGroup::external_commit_builder()
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
        for member in group.members().filter(|m| m.index != own) {
            validator.validate(&member.credential, &member.signature_key)?;
        }

        let group_id = group.group_id().as_slice().to_vec();
        Ok((
            group_id,
            PendingCommit {
                commit: bundle.commit().to_bytes().map_err(mls)?,
                welcome: None,
                epoch_after: group.epoch().as_u64() + 1,
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
            validator.validate(&member.credential, &member.signature_key)?;
        }

        let group = staged.into_group(&self.provider).map_err(mls)?;
        Ok(group.group_id().as_slice().to_vec())
    }

    /// The server accepted this device's commit: move to the new epoch.
    pub fn merge_pending_commit(&self, group_id: &[u8]) -> Result<u64> {
        let mut group = self.load_group(group_id)?;
        group.merge_pending_commit(&self.provider).map_err(mls)?;
        Ok(group.epoch().as_u64())
    }

    /// The server accepted another commit for this epoch instead: forget this device's.
    pub fn discard_pending_commit(&self, group_id: &[u8]) -> Result<()> {
        let mut group = self.load_group(group_id)?;
        group.clear_pending_commit(self.provider.storage()).map_err(mls)?;
        Ok(())
    }

    /// Forgets a group entirely (the channel was deleted, or this device left it), including its
    /// cached messages.
    pub fn delete_group(&self, group_id: &[u8]) -> Result<()> {
        if let Ok(mut group) = self.load_group(group_id) {
            group.delete(self.provider.storage()).map_err(mls)?;
        }
        self.store.delete_group_messages(group_id)
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
    pub fn process(&self, message: &[u8]) -> Result<(Vec<u8>, Incoming)> {
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
                let certificate = validator.validate(&credential, &leaf.signature_key)?;
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
                // The committer's own new leaf — which, for an external commit, is the device that
                // just joined.
                if let Some(leaf) = staged.update_path_leaf_node() {
                    validator.validate(leaf.credential(), leaf.signature_key().as_slice())?;
                }

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
                Incoming::Commit {
                    epoch: group.epoch().as_u64(),
                    added: Vec::new(),
                    removed: Vec::new(),
                    removed_self: false,
                }
            }
            // Something this device sent, encrypted, so MLS cannot open it (and has no need to).
            // If it is our commit, the server accepted it: apply it. If it is our application
            // message, its plaintext was kept when it was sent (`remember_sent`).
            ProcessedMessageContent::OwnPrivateMessage if is_commit && group.pending_commit().is_some() => {
                group.merge_pending_commit(&self.provider).map_err(mls)?;
                Incoming::Commit {
                    epoch: group.epoch().as_u64(),
                    added: Vec::new(),
                    removed: Vec::new(),
                    removed_self: false,
                }
            }
            ProcessedMessageContent::OwnPrivateMessage => Incoming::OwnMessage { epoch },
            ProcessedMessageContent::ProposalMessage(proposal) => {
                group
                    .store_pending_proposal(self.provider.storage(), *proposal)
                    .map_err(mls)?;
                Incoming::Proposal
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                group
                    .store_pending_proposal(self.provider.storage(), *proposal)
                    .map_err(mls)?;
                Incoming::Proposal
            }
        };
        Ok((group_id, incoming))
    }

    /// Decrypts a channel message and keeps its plaintext in the local cache — the only copy there
    /// will ever be, since the epoch key that decrypted it is soon deleted. A message already in the
    /// cache is returned from there without touching MLS, because MLS would refuse to decrypt it a
    /// second time.
    pub fn receive_message(
        &self,
        message_id: &str,
        sent_at_unix_ms: i64,
        message: &[u8],
    ) -> Result<Option<CachedMessage>> {
        if let Some(group_id) = peek_group_id(message)?
            && let Some(cached) = self.store.message(&group_id, message_id)?
        {
            return Ok(Some(cached));
        }

        match self.process(message)? {
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
