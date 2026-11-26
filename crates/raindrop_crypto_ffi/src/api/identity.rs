//! The client's one identity, for Dart: the root secret, the accounts derived from it, the recovery
//! key, the vault, the app PIN, and pairing a new device. Free functions over plain bytes — none of
//! this belongs to a server's [`super::session::CryptoSession`]; Dart keeps the secrets in the
//! platform's secure storage and passes them in.

use raindrop_crypto::backup::RecoveryKey;
use raindrop_crypto::pairing;
use raindrop_crypto::root::{self, PinCost, RecoverySeed, RootSecret};

use super::session::CryptoFailure;

type Result<T> = std::result::Result<T, CryptoFailure>;

/// The account a root secret has on one server.
pub struct DerivedAccount {
    pub user_id: String,
    /// The public user identity key every device of this person certifies itself with there.
    pub identity_key: Vec<u8>,
}

/// A new recovery key: the 24 words to show the person once, and the seed the device keeps.
pub struct NewRecovery {
    pub words: String,
    pub seed: Vec<u8>,
}

/// A new device's pairing offer (hand it to the relay), the commitment and code secret for the
/// pairing code (the code secret never goes to the relay), and the secret to hold until the approval
/// arrives.
pub struct PairingOffer {
    pub offer: Vec<u8>,
    pub commitment: Vec<u8>,
    pub code_secret: Vec<u8>,
    pub exchange_secret: Vec<u8>,
}

/// What an offer says about the device that made it, to show the person approving.
pub struct PairingOfferInfo {
    pub device_name: String,
    pub platform: String,
}

/// A new root secret: once per person, on their first device.
pub fn new_root_secret() -> Vec<u8> {
    RootSecret::generate().as_bytes().to_vec()
}

/// The account `root` has on the server whose identity key is `server_key`.
pub fn derive_account(root: Vec<u8>, server_key: Vec<u8>) -> Result<DerivedAccount> {
    let account = RootSecret::from_bytes(&root)?.account(&server_key)?;
    Ok(DerivedAccount {
        user_id: account.user_id,
        identity_key: account.identity.public_key().to_vec(),
    })
}

pub fn new_recovery_key() -> NewRecovery {
    let key = RecoveryKey::generate();
    NewRecovery {
        words: key.to_words(),
        seed: RecoverySeed::from_recovery_key(&key).as_bytes().to_vec(),
    }
}

/// The seed for recovery words the person typed. A typo fails the checksum (`Malformed`).
pub fn recovery_seed_from_words(words: String) -> Result<Vec<u8>> {
    Ok(RecoverySeed::from_recovery_key(&RecoveryKey::from_words(&words)?)
        .as_bytes()
        .to_vec())
}

/// The name the sealed root is stored under on one server.
pub fn recovery_lookup_id(seed: Vec<u8>, server_key: Vec<u8>) -> Result<String> {
    Ok(RecoverySeed::from_bytes(&seed)?.lookup_id(&server_key)?)
}

pub fn seal_root(seed: Vec<u8>, server_key: Vec<u8>, root: Vec<u8>) -> Result<Vec<u8>> {
    Ok(RecoverySeed::from_bytes(&seed)?.seal_root(&server_key, &RootSecret::from_bytes(&root)?)?)
}

/// Opens a sealed root. `BackupLocked` when the words are wrong or the blob is another server's.
pub fn open_root(seed: Vec<u8>, server_key: Vec<u8>, blob: Vec<u8>) -> Result<Vec<u8>> {
    Ok(RecoverySeed::from_bytes(&seed)?
        .open_root(&server_key, &blob)?
        .as_bytes()
        .to_vec())
}

pub fn seal_vault(root: Vec<u8>, server_key: Vec<u8>, plaintext: Vec<u8>) -> Result<Vec<u8>> {
    Ok(RootSecret::from_bytes(&root)?.seal_vault(&server_key, &plaintext)?)
}

pub fn open_vault(root: Vec<u8>, server_key: Vec<u8>, blob: Vec<u8>) -> Result<Vec<u8>> {
    Ok(RootSecret::from_bytes(&root)?.open_vault(&server_key, &blob)?.to_vec())
}

/// Seals `plaintext` under the app PIN (Argon2id), for a device with no biometric or system lock.
pub fn seal_with_pin(plaintext: Vec<u8>, pin: String) -> Result<Vec<u8>> {
    Ok(root::seal_with_pin(&plaintext, &pin, PinCost::default())?)
}

/// Opens a PIN lock. `BackupLocked` when the PIN is wrong.
pub fn open_with_pin(blob: Vec<u8>, pin: String) -> Result<Vec<u8>> {
    Ok(root::open_with_pin(&blob, &pin)?.to_vec())
}

/// New device: makes a pairing offer.
pub fn begin_pairing(device_name: String, platform: String) -> Result<PairingOffer> {
    let begun = pairing::begin(&device_name, &platform)?;
    Ok(PairingOffer {
        offer: begun.offer,
        commitment: begun.commitment.to_vec(),
        code_secret: begun.code_secret.to_vec(),
        exchange_secret: begun.exchange_secret.to_vec(),
    })
}

/// Existing device: who is asking, once the offer has been checked against the pairing code.
pub fn read_pairing_offer(offer: Vec<u8>, commitment: Vec<u8>) -> Result<PairingOfferInfo> {
    if pairing::commitment(&offer).as_slice() != commitment.as_slice() {
        return Err(raindrop_crypto::CryptoError::Verification("the offer does not match the pairing code".into()).into());
    }
    let offer = pairing::Offer::from_bytes(&offer)?;
    Ok(PairingOfferInfo {
        device_name: offer.device_name,
        platform: offer.platform,
    })
}

/// Existing device: seals `payload` to the offer and the pairing code's secret, after checking the
/// offer against the pairing code.
pub fn approve_pairing(offer: Vec<u8>, commitment: Vec<u8>, code_secret: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>> {
    Ok(pairing::approve(&offer, &commitment, &code_secret, &payload)?)
}

/// New device: opens the approval.
pub fn complete_pairing(
    approval: Vec<u8>,
    offer: Vec<u8>,
    exchange_secret: Vec<u8>,
    code_secret: Vec<u8>,
) -> Result<Vec<u8>> {
    Ok(pairing::complete(&approval, &offer, &exchange_secret, &code_secret)?.to_vec())
}
