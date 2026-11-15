//! The encrypted key backup a user restores onto a new device when every old one is gone.
//!
//! It is sealed on the device and stored on the server as an opaque blob, so the server keeps it
//! without being able to read it. What unlocks it is either a **recovery key** (256 random bits,
//! shown once as 24 words) or a **passphrase** stretched with Argon2id.
//!
//! History is forward-only, so there are no message keys in here: only the user's identity secret
//! (so the restored device can certify itself and keep the same safety numbers) and the identity
//! keys the user had pinned (so trust decisions survive the move).
//!
//! Blob layout, every field big-endian:
//!
//! ```text
//! "RDBK" | version: u8 = 1 | kdf: u8 (0 = recovery key, 1 = Argon2id)
//!        | [kdf = 1: memory_kib: u32 | iterations: u32 | parallelism: u32 | salt: 16 bytes]
//!        | nonce: 24 bytes | XChaCha20-Poly1305 ciphertext of the JSON contents
//! ```
//!
//! Everything before the nonce is the AEAD's associated data, so the KDF parameters cannot be
//! weakened in storage without the blob failing to open.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CryptoError, Result};
use crate::random;

const MAGIC: &[u8; 4] = b"RDBK";
const VERSION: u8 = 1;
const KDF_RECOVERY_KEY: u8 = 0;
const KDF_ARGON2ID: u8 = 1;

/// What a backup restores.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone, PartialEq, Eq, Debug)]
pub struct BackupContents {
    pub user_id: String,
    #[serde(with = "serde_bytes")]
    pub user_identity_secret: Vec<u8>,
    pub pinned_identities: Vec<BackedUpPin>,
}

#[derive(Serialize, Deserialize, Zeroize, Clone, PartialEq, Eq, Debug)]
pub struct BackedUpPin {
    pub user_id: String,
    #[serde(with = "serde_bytes")]
    pub identity_key: Vec<u8>,
    pub verified: bool,
}

/// 256 random bits, written out as 24 BIP-39 words for the user to keep somewhere safe.
pub struct RecoveryKey(Zeroizing<[u8; 32]>);

impl RecoveryKey {
    pub fn generate() -> Self {
        Self(random::bytes::<32>())
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_words(&self) -> String {
        bip39::Mnemonic::from_entropy(self.0.as_slice())
            .expect("32 bytes is a valid BIP-39 entropy length")
            .to_string()
    }

    /// Parses the words back. Case and extra whitespace are forgiven; a typo is caught by the
    /// BIP-39 checksum rather than producing a wrong key.
    pub fn from_words(words: &str) -> Result<Self> {
        let normalized = words.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
        let mnemonic = bip39::Mnemonic::parse_normalized(&normalized)
            .map_err(|e| CryptoError::Malformed(format!("recovery key: {e}")))?;
        let entropy = Zeroizing::new(mnemonic.to_entropy());
        let bytes: [u8; 32] = entropy
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Malformed("a recovery key is 24 words".into()))?;
        Ok(Self(Zeroizing::new(bytes)))
    }
}

/// Argon2id cost. The default (256 MiB, 3 passes) makes each passphrase guess expensive for
/// anybody holding a copy of the blob — which includes the server.
#[derive(Clone, Copy, Debug)]
pub struct PassphraseCost {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for PassphraseCost {
    fn default() -> Self {
        Self {
            memory_kib: 256 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

pub fn seal_with_recovery_key(contents: &BackupContents, key: &RecoveryKey) -> Result<Vec<u8>> {
    let header = [MAGIC.as_slice(), &[VERSION, KDF_RECOVERY_KEY]].concat();
    seal(header, &key.0, contents)
}

pub fn seal_with_passphrase(contents: &BackupContents, passphrase: &str, cost: PassphraseCost) -> Result<Vec<u8>> {
    let salt = random::bytes::<16>();
    let key = stretch(passphrase, salt.as_slice(), cost)?;

    let mut header = [MAGIC.as_slice(), &[VERSION, KDF_ARGON2ID]].concat();
    header.extend_from_slice(&cost.memory_kib.to_be_bytes());
    header.extend_from_slice(&cost.iterations.to_be_bytes());
    header.extend_from_slice(&cost.parallelism.to_be_bytes());
    header.extend_from_slice(salt.as_slice());
    seal(header, &key, contents)
}

/// Opens a backup sealed with a recovery key.
pub fn open_with_recovery_key(blob: &[u8], key: &RecoveryKey) -> Result<BackupContents> {
    let (header_len, kdf) = parse_header(blob)?;
    if kdf != KDF_RECOVERY_KEY {
        return Err(CryptoError::BackupLocked);
    }
    open(blob, header_len, &key.0)
}

/// Opens a backup sealed with a passphrase. The cost is read from the blob itself.
pub fn open_with_passphrase(blob: &[u8], passphrase: &str) -> Result<BackupContents> {
    let (header_len, kdf) = parse_header(blob)?;
    if kdf != KDF_ARGON2ID {
        return Err(CryptoError::BackupLocked);
    }
    let read_u32 = |at: usize| u32::from_be_bytes(blob[at..at + 4].try_into().unwrap());
    let cost = PassphraseCost {
        memory_kib: read_u32(6),
        iterations: read_u32(10),
        parallelism: read_u32(14),
    };

    // A blob is attacker-controlled input: refuse costs that are too weak to have been made by
    // this code, or large enough to exhaust the device.
    if cost.memory_kib < 19 * 1024 || cost.memory_kib > 1024 * 1024 || cost.iterations == 0 || cost.iterations > 20 {
        return Err(CryptoError::Malformed("backup passphrase cost is out of range".into()));
    }

    let key = stretch(passphrase, &blob[18..34], cost)?;
    open(blob, header_len, &key)
}

/// Whether a blob was sealed with a passphrase (and so needs one to open) rather than a recovery key.
pub fn needs_passphrase(blob: &[u8]) -> Result<bool> {
    Ok(parse_header(blob)?.1 == KDF_ARGON2ID)
}

fn parse_header(blob: &[u8]) -> Result<(usize, u8)> {
    if blob.len() < 6 || &blob[..4] != MAGIC || blob[4] != VERSION {
        return Err(CryptoError::Malformed("not a Raindrop backup".into()));
    }
    let header_len = match blob[5] {
        KDF_RECOVERY_KEY => 6,
        KDF_ARGON2ID => 6 + 12 + 16,
        _ => return Err(CryptoError::Malformed("unknown backup key derivation".into())),
    };
    if blob.len() < header_len + 24 + 16 {
        return Err(CryptoError::Malformed("truncated backup".into()));
    }
    Ok((header_len, blob[5]))
}

fn stretch(passphrase: &str, salt: &[u8], cost: PassphraseCost) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(cost.memory_kib, cost.iterations, cost.parallelism, Some(32))
        .map_err(|e| CryptoError::Malformed(format!("argon2 parameters: {e}")))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|e| CryptoError::Malformed(format!("argon2: {e}")))?;
    Ok(key)
}

fn seal(mut header: Vec<u8>, key: &[u8; 32], contents: &BackupContents) -> Result<Vec<u8>> {
    let plaintext = Zeroizing::new(serde_json::to_vec(contents)?);
    let nonce = random::bytes::<24>();
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let ciphertext = cipher
        .encrypt(
            &XNonce::try_from(nonce.as_slice()).unwrap(),
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| CryptoError::Store("backup encryption failed".into()))?;

    header.extend_from_slice(nonce.as_slice());
    header.extend_from_slice(&ciphertext);
    Ok(header)
}

fn open(blob: &[u8], header_len: usize, key: &[u8; 32]) -> Result<BackupContents> {
    let (header, rest) = blob.split_at(header_len);
    let (nonce, ciphertext) = rest.split_at(24);
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::try_from(nonce).unwrap(),
                Payload {
                    msg: ciphertext,
                    aad: header,
                },
            )
            .map_err(|_| CryptoError::BackupLocked)?,
    );
    serde_json::from_slice(&plaintext).map_err(|_| CryptoError::BackupLocked)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contents() -> BackupContents {
        BackupContents {
            user_id: "user-1".into(),
            user_identity_secret: vec![7; 32],
            pinned_identities: vec![BackedUpPin {
                user_id: "bob".into(),
                identity_key: vec![1; 32],
                verified: true,
            }],
        }
    }

    // Cheap enough for tests, still inside the range a blob is allowed to claim.
    const TEST_COST: PassphraseCost = PassphraseCost {
        memory_kib: 19 * 1024,
        iterations: 1,
        parallelism: 1,
    };

    #[test]
    fn recovery_key_round_trip() {
        let key = RecoveryKey::generate();
        let words = key.to_words();
        assert_eq!(words.split(' ').count(), 24);

        let blob = seal_with_recovery_key(&contents(), &key).unwrap();
        let restored = RecoveryKey::from_words(&format!("  {}  ", words.to_uppercase())).unwrap();
        assert_eq!(open_with_recovery_key(&blob, &restored).unwrap(), contents());
        assert!(!needs_passphrase(&blob).unwrap());
    }

    #[test]
    fn the_wrong_recovery_key_does_not_open() {
        let blob = seal_with_recovery_key(&contents(), &RecoveryKey::generate()).unwrap();
        assert!(matches!(
            open_with_recovery_key(&blob, &RecoveryKey::generate()),
            Err(CryptoError::BackupLocked)
        ));
    }

    #[test]
    fn a_mistyped_word_is_caught_by_the_checksum() {
        let words = RecoveryKey::generate().to_words();
        let mut list: Vec<&str> = words.split(' ').collect();
        list.swap(0, 1);
        // Swapping two words almost always breaks the checksum; if it happens not to, the key is
        // simply different, which the AEAD then rejects.
        if let Ok(key) = RecoveryKey::from_words(&list.join(" ")) {
            let blob = seal_with_recovery_key(&contents(), &RecoveryKey::from_words(&words).unwrap()).unwrap();
            assert!(open_with_recovery_key(&blob, &key).is_err());
        }
    }

    #[test]
    fn passphrase_round_trip_and_tamper_detection() {
        let blob = seal_with_passphrase(&contents(), "correct horse battery staple", TEST_COST).unwrap();
        assert!(needs_passphrase(&blob).unwrap());
        assert_eq!(
            open_with_passphrase(&blob, "correct horse battery staple").unwrap(),
            contents()
        );
        assert!(matches!(
            open_with_passphrase(&blob, "wrong"),
            Err(CryptoError::BackupLocked)
        ));

        // Lowering the stored cost is caught: the header is authenticated.
        let mut weakened = blob.clone();
        weakened[13] ^= 1;
        assert!(open_with_passphrase(&weakened, "correct horse battery staple").is_err());
    }
}
