//! Linking a new device to a user who already has one: moving the user's identity secret from a
//! device that holds it to one that does not, through a server that must not be able to read or
//! substitute it.
//!
//! 1. The **new** device makes an [`Offer`]: its user and device ids, its device signature key and a
//!    fresh X25519 key. It uploads the offer and shows a link code carrying the server's link id and
//!    a [`commitment`] to the offer: 128 bits of SHA-256 over it.
//! 2. The user carries the link code to an **existing** device (a QR code, or typed). That device
//!    fetches the offer, refuses it unless it matches the commitment (so a server that swapped in its
//!    own keys is caught), certifies the new device key with the identity key, and seals the identity
//!    secret, certificate and pins to the offer's X25519 key ([`seal_approval`]).
//! 3. The new device opens the approval ([`open_approval`]) and installs the identity.
//!
//! Sealing is X25519 with a fresh sender key, then HKDF-SHA256 over the shared secret, bound to the
//! whole offer and both public keys, then XChaCha20-Poly1305.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::backup::BackedUpPin;
use crate::error::{CryptoError, Result};
use crate::random;

const OFFER_VERSION: u8 = 1;
const APPROVAL_VERSION: u8 = 1;
const CONTEXT: &[u8] = b"raindrop/device-link/v1\n";

/// Bytes of commitment in a link code. 128 bits makes finding a second offer with the same
/// commitment infeasible for a server that sees the first.
pub const COMMITMENT_LENGTH: usize = 16;

/// What a new device publishes about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub user_id: String,
    pub device_id: String,
    pub device_signature_key: Vec<u8>,
    pub exchange_key: [u8; 32],
}

impl Offer {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![OFFER_VERSION];
        field(&mut out, self.user_id.as_bytes());
        field(&mut out, self.device_id.as_bytes());
        field(&mut out, &self.device_signature_key);
        out.extend_from_slice(&self.exchange_key);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let malformed = || CryptoError::Malformed("not a device link offer".into());
        let (&version, mut rest) = bytes.split_first().ok_or_else(malformed)?;
        if version != OFFER_VERSION {
            return Err(malformed());
        }
        let take = |rest: &mut &[u8]| -> Result<Vec<u8>> {
            if rest.len() < 2 {
                return Err(malformed());
            }
            let length = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            if rest.len() < 2 + length {
                return Err(malformed());
            }
            let value = rest[2..2 + length].to_vec();
            *rest = &rest[2 + length..];
            Ok(value)
        };
        let user_id = String::from_utf8(take(&mut rest)?).map_err(|_| malformed())?;
        let device_id = String::from_utf8(take(&mut rest)?).map_err(|_| malformed())?;
        let device_signature_key = take(&mut rest)?;
        let exchange_key: [u8; 32] = rest.try_into().map_err(|_| malformed())?;
        Ok(Self {
            user_id,
            device_id,
            device_signature_key,
            exchange_key,
        })
    }
}

/// The part of the link code that pins the offer: the first 16 bytes of SHA-256 over it.
pub fn commitment(offer: &[u8]) -> [u8; COMMITMENT_LENGTH] {
    let digest = Sha256::new().chain_update(CONTEXT).chain_update(offer).finalize();
    digest[..COMMITMENT_LENGTH].try_into().unwrap()
}

/// What the existing device hands the new one: everything it needs to become a full device.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ApprovalContents {
    #[serde(with = "serde_bytes")]
    pub certificate: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub user_identity_secret: Vec<u8>,
    pub pinned_identities: Vec<BackedUpPin>,
}

/// A fresh X25519 key for a new device's offer.
pub(crate) fn new_exchange_secret() -> StaticSecret {
    StaticSecret::from(*random::bytes::<32>())
}

pub(crate) fn exchange_public(secret: &StaticSecret) -> [u8; 32] {
    PublicKey::from(secret).to_bytes()
}

/// Seals `contents` so only the holder of the offer's exchange key can open them.
pub(crate) fn seal_approval(offer_bytes: &[u8], offer: &Offer, contents: &ApprovalContents) -> Result<Vec<u8>> {
    let sender = new_exchange_secret();
    let sender_public = exchange_public(&sender);
    let shared = Zeroizing::new(sender.diffie_hellman(&PublicKey::from(offer.exchange_key)).to_bytes());
    let key = derive_key(&shared, offer_bytes, &sender_public)?;

    let plaintext = Zeroizing::new(serde_json::to_vec(contents)?);
    let nonce = random::bytes::<24>();
    let ciphertext = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .expect("32-byte key")
        .encrypt(
            &XNonce::try_from(nonce.as_slice()).unwrap(),
            Payload {
                msg: &plaintext,
                aad: &sender_public,
            },
        )
        .map_err(|_| CryptoError::Store("device link encryption failed".into()))?;

    let mut out = vec![APPROVAL_VERSION];
    out.extend_from_slice(&sender_public);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens an approval with the new device's exchange secret and the offer it made.
pub(crate) fn open_approval(approval: &[u8], offer_bytes: &[u8], secret: &StaticSecret) -> Result<ApprovalContents> {
    if approval.len() < 1 + 32 + 24 + 16 || approval[0] != APPROVAL_VERSION {
        return Err(CryptoError::Malformed("not a device link approval".into()));
    }
    let sender_public: [u8; 32] = approval[1..33].try_into().unwrap();
    let nonce = &approval[33..57];
    let ciphertext = &approval[57..];

    let shared = Zeroizing::new(secret.diffie_hellman(&PublicKey::from(sender_public)).to_bytes());
    let key = derive_key(&shared, offer_bytes, &sender_public)?;

    let plaintext = Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(key.as_slice())
            .expect("32-byte key")
            .decrypt(
                &XNonce::try_from(nonce).unwrap(),
                Payload {
                    msg: ciphertext,
                    aad: &sender_public,
                },
            )
            .map_err(|_| CryptoError::Verification("the device link approval does not open".into()))?,
    );
    serde_json::from_slice(&plaintext).map_err(|_| CryptoError::Malformed("device link approval contents".into()))
}

fn derive_key(shared: &[u8; 32], offer_bytes: &[u8], sender_public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    // A low-order public key would make the shared secret all zeros; refuse rather than derive a
    // key an attacker can predict.
    if shared.iter().all(|b| *b == 0) {
        return Err(CryptoError::Verification("invalid device link key".into()));
    }
    let mut info = CONTEXT.to_vec();
    info.extend_from_slice(offer_bytes);
    info.extend_from_slice(sender_public);

    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, shared)
        .expand(&info, key.as_mut())
        .map_err(|_| CryptoError::Store("hkdf".into()))?;
    Ok(key)
}

fn field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(exchange: &StaticSecret) -> Offer {
        Offer {
            user_id: "user".into(),
            device_id: "device".into(),
            device_signature_key: vec![7; 32],
            exchange_key: exchange_public(exchange),
        }
    }

    fn contents() -> ApprovalContents {
        ApprovalContents {
            certificate: vec![1, 2, 3],
            user_identity_secret: vec![9; 32],
            pinned_identities: vec![],
        }
    }

    #[test]
    fn an_offer_round_trips() {
        let secret = new_exchange_secret();
        let offer = offer(&secret);
        assert_eq!(Offer::from_bytes(&offer.to_bytes()).unwrap(), offer);
        assert!(Offer::from_bytes(&offer.to_bytes()[..10]).is_err());
    }

    #[test]
    fn only_the_offering_device_opens_the_approval() {
        let secret = new_exchange_secret();
        let offer = offer(&secret);
        let bytes = offer.to_bytes();
        let approval = seal_approval(&bytes, &offer, &contents()).unwrap();

        let opened = open_approval(&approval, &bytes, &secret).unwrap();
        assert_eq!(opened.user_identity_secret, vec![9; 32]);

        assert!(open_approval(&approval, &bytes, &new_exchange_secret()).is_err());

        // Bound to the exact offer: the same key with a different offer does not open it.
        let mut other = offer.clone();
        other.device_id = "other".into();
        assert!(open_approval(&approval, &other.to_bytes(), &secret).is_err());
    }

    #[test]
    fn the_commitment_changes_with_any_part_of_the_offer() {
        let secret = new_exchange_secret();
        let a = offer(&secret);
        let mut b = a.clone();
        b.exchange_key[0] ^= 1;
        assert_ne!(commitment(&a.to_bytes()), commitment(&b.to_bytes()));
    }
}
