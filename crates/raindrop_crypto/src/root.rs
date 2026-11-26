//! The client's one identity, and everything derived from it.
//!
//! A user has a single **root secret**: 32 random bytes, made once, held by every device they have
//! paired and by nobody else. No server ever sees it. Each server the user joins gets its own account
//! *derived* from the root and that server's long-lived identity key:
//!
//! - the **user id**, so re-adding a server lands on the same account with nothing to remember;
//! - the **user identity key** (see [`crate::identity`]), so any paired device can certify itself there;
//! - the key the user's **vault** on that server is sealed under.
//!
//! Because the server's key is part of every derivation, two servers cannot tell that their accounts
//! belong to the same person, and nothing one server stores is of use on another.
//!
//! When every device is gone, the **recovery key** (24 words, [`crate::backup::RecoveryKey`]) brings
//! the root back. A [`RecoverySeed`] is what devices keep of it: enough to find and open the sealed
//! root on any one server, and to seal it again on a server joined later.
//!
//! Sealed blobs, every one XChaCha20-Poly1305 with the bytes before the nonce (and the server's
//! identity key) as associated data:
//!
//! ```text
//! sealed root:  "RDRT" | version: u8 = 1 | nonce: 24 bytes | ciphertext of the 32-byte root
//! vault:        "RDVT" | version: u8 = 1 | nonce: 24 bytes | ciphertext of the caller's bytes
//! PIN lock:     "RDPL" | version: u8 = 1 | memory_kib: u32 | iterations: u32 | parallelism: u32
//!                      | salt: 16 bytes | nonce: 24 bytes | ciphertext of the caller's bytes
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::backup::RecoveryKey;
use crate::error::{CryptoError, Result};
use crate::identity::UserIdentity;
use crate::random;

const USER_ID_CONTEXT: &[u8] = b"raindrop/root/user-id/v1\n";
const IDENTITY_CONTEXT: &[u8] = b"raindrop/root/identity-key/v1\n";
const VAULT_KEY_CONTEXT: &[u8] = b"raindrop/root/vault-key/v1\n";
const RECOVERY_SEED_CONTEXT: &[u8] = b"raindrop/recovery/seed/v1\n";
const RECOVERY_LOOKUP_CONTEXT: &[u8] = b"raindrop/recovery/lookup/v1\n";
const RECOVERY_SEAL_CONTEXT: &[u8] = b"raindrop/recovery/seal/v1\n";

const ROOT_MAGIC: &[u8; 4] = b"RDRT";
const VAULT_MAGIC: &[u8; 4] = b"RDVT";
const PIN_MAGIC: &[u8; 4] = b"RDPL";
const VERSION: u8 = 1;
/// Magic and version: all that precedes the nonce in a blob with no KDF parameters.
const FIXED_HEADER: usize = 5;

/// The user's root secret. Held only on their paired devices.
pub struct RootSecret(Zeroizing<[u8; 32]>);

/// What the root makes of one server: the account there, and the key that certifies its devices.
pub struct ServerAccount {
    /// The account's id on that server, formatted as a UUID.
    pub user_id: String,
    pub identity: UserIdentity,
}

impl RootSecret {
    /// A new root — once per person, on their first device.
    pub fn generate() -> Self {
        Self(random::bytes::<32>())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CryptoError::Malformed("a root secret is 32 bytes".into()))?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The account this root has on the server whose identity key is `server_key`. The same on every
    /// device that holds the root, and unrelated to the account on any other server.
    pub fn account(&self, server_key: &[u8]) -> Result<ServerAccount> {
        check_server_key(server_key)?;
        let mut id = *derive::<16>(&self.0, USER_ID_CONTEXT, server_key);
        // Shaped as a version-4 UUID, so a derived account looks like any other to the server.
        id[6] = (id[6] & 0x0f) | 0x40;
        id[8] = (id[8] & 0x3f) | 0x80;

        let secret = derive::<32>(&self.0, IDENTITY_CONTEXT, server_key);
        Ok(ServerAccount {
            user_id: format_uuid(&id),
            identity: UserIdentity::from_secret(secret.as_slice())?,
        })
    }

    /// Seals the user's vault for one server. `plaintext` is the caller's own encoding of what the
    /// vault holds; sealing it per server keeps two servers' copies from looking alike.
    pub fn seal_vault(&self, server_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        check_server_key(server_key)?;
        let key = derive::<32>(&self.0, VAULT_KEY_CONTEXT, server_key);
        seal(header(VAULT_MAGIC), &key, server_key, plaintext)
    }

    pub fn open_vault(&self, server_key: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        check_server_key(server_key)?;
        let key = derive::<32>(&self.0, VAULT_KEY_CONTEXT, server_key);
        open(VAULT_MAGIC, FIXED_HEADER, &key, server_key, blob)
    }
}

/// What a device keeps of the recovery key: enough to seal the root on each server and to say where
/// it is stored, without keeping the words themselves around.
pub struct RecoverySeed(Zeroizing<[u8; 32]>);

impl RecoverySeed {
    pub fn from_recovery_key(key: &RecoveryKey) -> Self {
        Self(derive::<32>(key.secret(), RECOVERY_SEED_CONTEXT, &[]))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CryptoError::Malformed("a recovery seed is 32 bytes".into()))?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The name the sealed root is stored under on one server: 32 hex characters. A device with
    /// nothing but the recovery words can compute it and ask for the blob before it has an account.
    pub fn lookup_id(&self, server_key: &[u8]) -> Result<String> {
        check_server_key(server_key)?;
        Ok(hex(derive::<16>(&self.0, RECOVERY_LOOKUP_CONTEXT, server_key).as_slice()))
    }

    pub fn seal_root(&self, server_key: &[u8], root: &RootSecret) -> Result<Vec<u8>> {
        check_server_key(server_key)?;
        let key = derive::<32>(&self.0, RECOVERY_SEAL_CONTEXT, server_key);
        seal(header(ROOT_MAGIC), &key, server_key, root.as_bytes())
    }

    /// Opens a sealed root. A wrong recovery key, a blob from another server and a damaged blob all
    /// fail the same way.
    pub fn open_root(&self, server_key: &[u8], blob: &[u8]) -> Result<RootSecret> {
        check_server_key(server_key)?;
        let key = derive::<32>(&self.0, RECOVERY_SEAL_CONTEXT, server_key);
        RootSecret::from_bytes(&open(ROOT_MAGIC, FIXED_HEADER, &key, server_key, blob)?).map_err(|_| CryptoError::BackupLocked)
    }
}

/// Argon2id cost for the app PIN that guards the identity on a device with no biometrics or system
/// credential to lean on. Lighter than a backup passphrase: it runs every time the app is unlocked,
/// and the blob it protects never leaves the device.
#[derive(Clone, Copy, Debug)]
pub struct PinCost {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for PinCost {
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

/// Seals `plaintext` under an app PIN.
pub fn seal_with_pin(plaintext: &[u8], pin: &str, cost: PinCost) -> Result<Vec<u8>> {
    let salt = random::bytes::<16>();
    let key = stretch(pin, salt.as_slice(), cost)?;

    let mut head = header(PIN_MAGIC);
    head.extend_from_slice(&cost.memory_kib.to_be_bytes());
    head.extend_from_slice(&cost.iterations.to_be_bytes());
    head.extend_from_slice(&cost.parallelism.to_be_bytes());
    head.extend_from_slice(salt.as_slice());
    seal(head, &key, &[], plaintext)
}

/// Opens a PIN lock. The cost is read from the blob; a wrong PIN is [`CryptoError::BackupLocked`].
pub fn open_with_pin(blob: &[u8], pin: &str) -> Result<Zeroizing<Vec<u8>>> {
    const HEADER: usize = FIXED_HEADER + 12 + 16;
    if blob.len() < HEADER || &blob[..4] != PIN_MAGIC || blob[4] != VERSION {
        return Err(CryptoError::Malformed("not a Raindrop PIN lock".into()));
    }
    let read_u32 = |at: usize| u32::from_be_bytes(blob[at..at + 4].try_into().unwrap());
    let cost = PinCost {
        memory_kib: read_u32(5),
        iterations: read_u32(9),
        parallelism: read_u32(13),
    };
    // The blob is read from disk, so treat the cost as untrusted: nothing weaker than this code
    // would write, nothing large enough to exhaust a phone (the default writes 64 MiB and 3 passes).
    if cost.memory_kib < 19 * 1024
        || cost.memory_kib > 512 * 1024
        || cost.iterations == 0
        || cost.iterations > 10
        || cost.parallelism == 0
        || cost.parallelism > 8
    {
        return Err(CryptoError::Malformed("PIN lock cost is out of range".into()));
    }
    let key = stretch(pin, &blob[17..33], cost)?;
    open(PIN_MAGIC, HEADER, &key, &[], blob)
}

fn stretch(pin: &str, salt: &[u8], cost: PinCost) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(cost.memory_kib, cost.iterations, cost.parallelism, Some(32))
        .map_err(|e| CryptoError::Malformed(format!("argon2 parameters: {e}")))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pin.as_bytes(), salt, &mut key[..])
        .map_err(|e| CryptoError::Malformed(format!("argon2: {e}")))?;
    Ok(key)
}

fn header(magic: &[u8; 4]) -> Vec<u8> {
    let mut out = magic.to_vec();
    out.push(VERSION);
    out
}

fn seal(mut head: Vec<u8>, key: &[u8; 32], bound_to: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = random::bytes::<24>();
    let aad = [head.as_slice(), bound_to].concat();
    let ciphertext = XChaCha20Poly1305::new_from_slice(key)
        .expect("32-byte key")
        .encrypt(
            &XNonce::try_from(nonce.as_slice()).unwrap(),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Store("sealing failed".into()))?;
    head.extend_from_slice(nonce.as_slice());
    head.extend_from_slice(&ciphertext);
    Ok(head)
}

/// `header_len` counts the bytes before the nonce (magic, version, and any KDF parameters).
fn open(magic: &[u8; 4], header_len: usize, key: &[u8; 32], bound_to: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < header_len + 24 + 16 || &blob[..4] != magic || blob[4] != VERSION {
        return Err(CryptoError::Malformed("not a Raindrop sealed blob".into()));
    }
    let (head, rest) = blob.split_at(header_len);
    let (nonce, ciphertext) = rest.split_at(24);
    let aad = [head, bound_to].concat();
    XChaCha20Poly1305::new_from_slice(key)
        .expect("32-byte key")
        .decrypt(
            &XNonce::try_from(nonce).unwrap(),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::BackupLocked)
}

fn derive<const N: usize>(secret: &[u8; 32], context: &[u8], server_key: &[u8]) -> Zeroizing<[u8; N]> {
    let info = [context, server_key].concat();
    let mut out = Zeroizing::new([0u8; N]);
    Hkdf::<Sha256>::new(None, secret)
        .expand(&info, &mut out[..])
        .expect("a short HKDF output");
    out
}

/// A server identity key is a public key; an empty one would quietly give every server the same
/// derivations, which is exactly what this module exists to prevent.
fn check_server_key(server_key: &[u8]) -> Result<()> {
    if server_key.len() < 32 {
        return Err(CryptoError::Malformed("a server identity key is at least 32 bytes".into()));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn format_uuid(id: &[u8; 16]) -> String {
    let h = hex(id);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_A: [u8; 65] = [4; 65];
    const SERVER_B: [u8; 65] = [5; 65];

    const TEST_COST: PinCost = PinCost {
        memory_kib: 19 * 1024,
        iterations: 1,
        parallelism: 1,
    };

    #[test]
    fn an_account_is_the_same_on_every_device_and_different_on_every_server() {
        let root = RootSecret::generate();
        let again = RootSecret::from_bytes(root.as_bytes()).unwrap();

        let (a, a_again) = (root.account(&SERVER_A).unwrap(), again.account(&SERVER_A).unwrap());
        assert_eq!(a.user_id, a_again.user_id);
        assert_eq!(a.identity.public_key(), a_again.identity.public_key());

        let b = root.account(&SERVER_B).unwrap();
        assert_ne!(a.user_id, b.user_id);
        assert_ne!(a.identity.public_key(), b.identity.public_key());

        let other = RootSecret::generate().account(&SERVER_A).unwrap();
        assert_ne!(a.user_id, other.user_id);
    }

    #[test]
    fn a_derived_user_id_is_a_version_4_uuid() {
        let id = RootSecret::generate().account(&SERVER_A).unwrap().user_id;
        let bytes = id.as_bytes();
        assert_eq!(id.len(), 36);
        assert_eq!(bytes[14], b'4');
        assert!(matches!(bytes[19], b'8' | b'9' | b'a' | b'b'));
        assert!(id.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
    }

    #[test]
    fn a_missing_server_key_is_refused() {
        let root = RootSecret::generate();
        assert!(root.account(&[]).is_err());
        assert!(root.seal_vault(&[1; 8], b"x").is_err());
    }

    #[test]
    fn the_vault_opens_only_with_its_root_on_its_server() {
        let root = RootSecret::generate();
        let blob = root.seal_vault(&SERVER_A, b"servers and devices").unwrap();
        assert_eq!(root.open_vault(&SERVER_A, &blob).unwrap().as_slice(), b"servers and devices");

        assert!(root.open_vault(&SERVER_B, &blob).is_err());
        assert!(RootSecret::generate().open_vault(&SERVER_A, &blob).is_err());

        // Two servers' copies of the same vault share nothing a server could compare.
        let other = root.seal_vault(&SERVER_B, b"servers and devices").unwrap();
        assert_ne!(blob[5..], other[5..]);
    }

    #[test]
    fn the_recovery_words_bring_the_root_back() {
        let root = RootSecret::generate();
        let key = RecoveryKey::generate();
        let seed = RecoverySeed::from_recovery_key(&key);
        let sealed = seed.seal_root(&SERVER_A, &root).unwrap();

        // A new device has only the words and one server's address.
        let typed = RecoverySeed::from_recovery_key(&RecoveryKey::from_words(&key.to_words()).unwrap());
        assert_eq!(typed.lookup_id(&SERVER_A).unwrap(), seed.lookup_id(&SERVER_A).unwrap());
        assert_eq!(typed.open_root(&SERVER_A, &sealed).unwrap().as_bytes(), root.as_bytes());

        let wrong = RecoverySeed::from_recovery_key(&RecoveryKey::generate());
        assert!(matches!(
            wrong.open_root(&SERVER_A, &sealed),
            Err(CryptoError::BackupLocked)
        ));
        assert!(typed.open_root(&SERVER_B, &sealed).is_err());
    }

    #[test]
    fn lookup_ids_do_not_link_servers() {
        let seed = RecoverySeed::from_recovery_key(&RecoveryKey::generate());
        let (a, b) = (seed.lookup_id(&SERVER_A).unwrap(), seed.lookup_id(&SERVER_B).unwrap());
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
    }

    #[test]
    fn a_pin_lock_round_trips_and_resists_tampering() {
        let blob = seal_with_pin(b"root and friends", "4821", TEST_COST).unwrap();
        assert_eq!(open_with_pin(&blob, "4821").unwrap().as_slice(), b"root and friends");
        assert!(matches!(open_with_pin(&blob, "4822"), Err(CryptoError::BackupLocked)));

        // Lowering the stored cost is caught: the header is authenticated.
        let mut weakened = blob.clone();
        weakened[12] ^= 1;
        assert!(open_with_pin(&weakened, "4821").is_err());
        assert!(open_with_pin(&blob[..20], "4821").is_err());
    }

    #[test]
    fn a_pin_lock_cost_out_of_range_is_refused_before_hashing() {
        // The header is read before it is authenticated, so each cost field is checked on its
        // own: memory (offset 5), iterations (9) and parallelism (13) just outside their limits.
        let blob = seal_with_pin(b"root", "4821", TEST_COST).unwrap();
        let cases: [(usize, u32); 6] = [
            (5, 512 * 1024 + 1),
            (5, 19 * 1024 - 1),
            (9, 0),
            (9, 11),
            (13, 0),
            (13, 9),
        ];
        for (at, value) in cases {
            let mut forged = blob.clone();
            forged[at..at + 4].copy_from_slice(&value.to_be_bytes());
            assert!(
                matches!(open_with_pin(&forged, "4821"), Err(CryptoError::Malformed(_))),
                "field at offset {at} set to {value} was not refused as malformed"
            );
        }
    }
}
