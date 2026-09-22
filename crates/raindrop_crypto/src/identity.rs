//! Who a device belongs to, provably.
//!
//! Every user has one **user identity key** (UIK, Ed25519). Its private half lives only on the
//! user's devices and inside their encrypted backup; the server stores the public half but can never
//! sign with it. Every device has its own MLS signature key, and the UIK signs a
//! [`DeviceCertificate`] binding that key to `(user id, device id)`.
//!
//! The certificate travels inside the device's MLS credential, so every member of a group can check
//! any leaf: *this device key belongs to this user*, and *this user's identity key is the one I
//! pinned* (see [`crate::validation`]). A server that invents a device for somebody cannot produce
//! the certificate; a server that swaps somebody's identity key trips the pin.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::random;

const CERTIFICATE_CONTEXT: &[u8] = b"raindrop/device-certificate/v1\n";
const CERTIFICATE_VERSION: u8 = 1;

/// A user's identity key pair. Held only on the user's own devices.
pub struct UserIdentity {
    key: SigningKey,
}

impl UserIdentity {
    /// A new, random identity — once per user, at registration.
    pub fn generate() -> Self {
        Self {
            key: SigningKey::from_bytes(&random::bytes::<32>()),
        }
    }

    /// Restores an identity from its 32-byte secret (from this device's store, or from a backup).
    pub fn from_secret(secret: &[u8]) -> Result<Self> {
        let secret: &[u8; 32] = secret
            .try_into()
            .map_err(|_| CryptoError::Malformed("an identity secret is 32 bytes".into()))?;
        Ok(Self {
            key: SigningKey::from_bytes(secret),
        })
    }

    pub fn secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.key.to_bytes())
    }

    /// The public identity key, which the server publishes and other users pin.
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Vouches for one of this user's devices.
    pub fn certify_device(
        &self,
        user_id: &str,
        device_id: &str,
        device_signature_key: &[u8],
        created_at_unix: i64,
    ) -> DeviceCertificate {
        let mut certificate = DeviceCertificate {
            user_id: user_id.to_owned(),
            device_id: device_id.to_owned(),
            device_signature_key: device_signature_key.to_vec(),
            user_identity_key: self.public_key().to_vec(),
            created_at_unix,
            signature: Vec::new(),
        };
        certificate.signature = self.key.sign(&certificate.signed_bytes()).to_bytes().to_vec();
        certificate
    }
}

/// A user identity key's statement that a device signature key belongs to one of the user's devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCertificate {
    pub user_id: String,
    pub device_id: String,
    /// The device's MLS signature public key (Ed25519).
    pub device_signature_key: Vec<u8>,
    /// The identity key that signed this. Carried so a verifier can pin it on first sight; it is
    /// only trusted after being compared with the pin.
    pub user_identity_key: Vec<u8>,
    pub created_at_unix: i64,
    pub signature: Vec<u8>,
}

impl DeviceCertificate {
    /// Checks the signature against the identity key the certificate carries. Whether that key is
    /// the *right* one is the caller's question — see [`crate::validation`].
    pub fn verify(&self) -> Result<()> {
        let key: &[u8; 32] = self
            .user_identity_key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Verification("identity key must be 32 bytes".into()))?;
        let key = VerifyingKey::from_bytes(key).map_err(|e| CryptoError::Verification(e.to_string()))?;
        let signature = Signature::from_slice(&self.signature).map_err(|e| CryptoError::Verification(e.to_string()))?;

        key.verify_strict(&self.signed_bytes(), &signature)
            .map_err(|_| CryptoError::Verification("device certificate signature is invalid".into()))
    }

    /// The exact bytes the identity key signs: a context string, then every field, length-prefixed
    /// so no two different certificates can serialise the same way.
    fn signed_bytes(&self) -> Vec<u8> {
        let mut out = CERTIFICATE_CONTEXT.to_vec();
        out.push(CERTIFICATE_VERSION);
        write_field(&mut out, self.user_id.as_bytes());
        write_field(&mut out, self.device_id.as_bytes());
        write_field(&mut out, &self.device_signature_key);
        write_field(&mut out, &self.user_identity_key);
        out.extend_from_slice(&self.created_at_unix.to_be_bytes());
        out
    }

    /// The wire form: what goes into the MLS credential and to the server.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![CERTIFICATE_VERSION];
        write_field(&mut out, self.user_id.as_bytes());
        write_field(&mut out, self.device_id.as_bytes());
        write_field(&mut out, &self.device_signature_key);
        write_field(&mut out, &self.user_identity_key);
        out.extend_from_slice(&self.created_at_unix.to_be_bytes());
        write_field(&mut out, &self.signature);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader(bytes);
        if reader.take(1)? != [CERTIFICATE_VERSION] {
            return Err(CryptoError::Malformed("unknown device certificate version".into()));
        }
        let user_id = reader.string()?;
        let device_id = reader.string()?;
        let device_signature_key = reader.field()?.to_vec();
        let user_identity_key = reader.field()?.to_vec();
        let created_at_unix = i64::from_be_bytes(reader.take(8)?.try_into().unwrap());
        let signature = reader.field()?.to_vec();
        if !reader.0.is_empty() {
            return Err(CryptoError::Malformed("trailing bytes after device certificate".into()));
        }
        Ok(Self {
            user_id,
            device_id,
            device_signature_key,
            user_identity_key,
            created_at_unix,
            signature,
        })
    }
}

fn write_field(out: &mut Vec<u8>, field: &[u8]) {
    let length = u16::try_from(field.len()).expect("certificate fields are short");
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(field);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(CryptoError::Malformed("truncated device certificate".into()));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn field(&mut self) -> Result<&'a [u8]> {
        let length = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as usize;
        self.take(length)
    }

    fn string(&mut self) -> Result<String> {
        String::from_utf8(self.field()?.to_vec())
            .map_err(|_| CryptoError::Malformed("certificate text is not UTF-8".into()))
    }
}

/// The 60-digit number two users read to each other (or scan as a QR code) to confirm neither
/// identity key was swapped in transit. Symmetric: both sides compute the same digits.
///
/// Each half is Signal's construction: SHA-512 iterated 5200 times over the identity key and the
/// user's id, the first 30 bytes read as six 5-byte groups, each reduced to 5 decimal digits.
pub fn safety_number(user_a: &str, key_a: &[u8], user_b: &str, key_b: &[u8]) -> String {
    let mut halves = [(user_a, half(user_a, key_a)), (user_b, half(user_b, key_b))];
    halves.sort_by(|left, right| left.0.cmp(right.0));
    format!("{}{}", halves[0].1, halves[1].1)
}

fn half(user_id: &str, identity_key: &[u8]) -> String {
    let mut digest = Sha512::new()
        .chain_update([0u8, 0u8])
        .chain_update(identity_key)
        .chain_update(user_id.as_bytes())
        .finalize()
        .to_vec();
    for _ in 1..5200 {
        digest = Sha512::new()
            .chain_update(&digest)
            .chain_update(identity_key)
            .finalize()
            .to_vec();
    }

    digest[..30]
        .chunks(5)
        .map(|chunk| {
            let value = chunk.iter().fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
            format!("{:05}", value % 100_000)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_certificate_round_trips_and_verifies() {
        let identity = UserIdentity::generate();
        let certificate = identity.certify_device("user-1", "device-1", &[9; 32], 1_700_000_000);

        let decoded = DeviceCertificate::from_bytes(&certificate.to_bytes()).unwrap();
        assert_eq!(decoded, certificate);
        decoded.verify().unwrap();
    }

    #[test]
    fn a_tampered_certificate_does_not_verify() {
        let identity = UserIdentity::generate();
        let mut certificate = identity.certify_device("user-1", "device-1", &[9; 32], 1);
        certificate.device_id = "device-2".into();
        assert!(certificate.verify().is_err());

        let mut swapped = identity.certify_device("user-1", "device-1", &[9; 32], 1);
        swapped.user_identity_key = UserIdentity::generate().public_key().to_vec();
        assert!(swapped.verify().is_err());
    }

    #[test]
    fn an_identity_survives_its_secret() {
        let identity = UserIdentity::generate();
        let restored = UserIdentity::from_secret(identity.secret().as_slice()).unwrap();
        assert_eq!(restored.public_key(), identity.public_key());
    }

    #[test]
    fn safety_numbers_are_symmetric_and_key_dependent() {
        let (a, b) = (UserIdentity::generate(), UserIdentity::generate());
        let ab = safety_number("alice", &a.public_key(), "bob", &b.public_key());
        let ba = safety_number("bob", &b.public_key(), "alice", &a.public_key());
        assert_eq!(ab, ba);
        assert_eq!(ab.len(), 60);
        assert!(ab.chars().all(|c| c.is_ascii_digit()));

        let c = UserIdentity::generate();
        assert_ne!(ab, safety_number("alice", &a.public_key(), "bob", &c.public_key()));
    }
}
