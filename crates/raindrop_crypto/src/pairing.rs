//! Pairing a new device with a person who already has one: moving their root secret (see
//! [`crate::root`]) from a device that holds it to one that does not, through a server that must not
//! be able to read or substitute it.
//!
//! Unlike [`crate::link`], which moved one server's identity, pairing happens once per device and
//! covers every server: the new device has no account anywhere yet, so the offer names no user.
//!
//! 1. The **new** device makes an [`Offer`] — its name, its platform and a fresh X25519 key — hands
//!    it to a relay, and shows a pairing code carrying the relay's id for it, a [`commitment`] to the
//!    offer and a random code secret ([`CODE_SECRET_LENGTH`] bytes) that never goes to the relay.
//! 2. The person carries the code to an **existing** device (scanned, or typed: neither device needs
//!    a camera). That device fetches the offer, refuses it unless it matches the commitment — so a
//!    relay that swapped in its own key is caught — and seals the payload to the offer's key and the
//!    code secret ([`approve`]).
//! 3. The new device opens it ([`complete`]). Only a device that saw the code can have sealed it, so a
//!    relay that seals a payload of its own to the offer's key is caught too.
//!
//! The payload is the caller's: this module seals bytes. Sealing is X25519 with a fresh sender key,
//! HKDF-SHA256 over the shared secret, salted with the code secret and bound to the whole offer and
//! both public keys, then XChaCha20-Poly1305.
//!
//! ```text
//! offer:     version: u8 = 1 | name_len: u16 | name | platform_len: u16 | platform | exchange_key: 32
//! approval:  version: u8 = 2 | sender_key: 32 | nonce: 24 | ciphertext
//! ```

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::random;

const OFFER_VERSION: u8 = 1;
const APPROVAL_VERSION: u8 = 2;
const CONTEXT: &[u8] = b"raindrop/device-pairing/v2\n";

/// Bytes of commitment in a pairing code: 128 bits, so a relay that sees one offer cannot find
/// another with the same commitment.
pub const COMMITMENT_LENGTH: usize = 16;

/// Bytes of code secret in a pairing code: 128 bits the relay never sees, mixed into the key the
/// approval is sealed under, so only a device that saw the code can seal one the new device opens.
pub const CODE_SECRET_LENGTH: usize = 16;

/// Longest device name or platform an offer carries. They are shown to the person approving, so a
/// relay must not be able to fill the screen.
const MAX_LABEL: usize = 64;

/// What a new device says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// Shown on the approving device ("Ana's iPhone"). Chosen by the new device, so it is a label
    /// to help the person recognise it and never a reason to approve.
    pub device_name: String,
    pub platform: String,
    pub exchange_key: [u8; 32],
}

impl Offer {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = vec![OFFER_VERSION];
        field(&mut out, self.device_name.as_bytes())?;
        field(&mut out, self.platform.as_bytes())?;
        out.extend_from_slice(&self.exchange_key);
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let malformed = || CryptoError::Malformed("not a device pairing offer".into());
        let (&version, mut rest) = bytes.split_first().ok_or_else(malformed)?;
        if version != OFFER_VERSION {
            return Err(malformed());
        }
        let mut take = || -> Result<String> {
            if rest.len() < 2 {
                return Err(malformed());
            }
            let length = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            if length > MAX_LABEL || rest.len() < 2 + length {
                return Err(malformed());
            }
            let value = String::from_utf8(rest[2..2 + length].to_vec()).map_err(|_| malformed())?;
            rest = &rest[2 + length..];
            Ok(value)
        };
        let device_name = take()?;
        let platform = take()?;
        let exchange_key: [u8; 32] = rest.try_into().map_err(|_| malformed())?;
        Ok(Self {
            device_name,
            platform,
            exchange_key,
        })
    }
}

/// A new device's side of a pairing in progress.
pub struct Begun {
    /// Hand this to the relay.
    pub offer: Vec<u8>,
    /// Put this in the pairing code.
    pub commitment: [u8; COMMITMENT_LENGTH],
    /// Put this in the pairing code too, and never hand it to the relay. Keep it until the approval
    /// arrives, and nowhere longer.
    pub code_secret: Zeroizing<[u8; CODE_SECRET_LENGTH]>,
    /// Keep this until the approval arrives, and nowhere longer.
    pub exchange_secret: Zeroizing<[u8; 32]>,
}

/// On the **new** device: makes an offer for one of the person's existing devices to approve.
pub fn begin(device_name: &str, platform: &str) -> Result<Begun> {
    if device_name.len() > MAX_LABEL || platform.len() > MAX_LABEL {
        return Err(CryptoError::Malformed("a device name is at most 64 bytes".into()));
    }
    let secret = StaticSecret::from(*random::bytes::<32>());
    let offer = Offer {
        device_name: device_name.to_owned(),
        platform: platform.to_owned(),
        exchange_key: PublicKey::from(&secret).to_bytes(),
    }
    .to_bytes()?;
    Ok(Begun {
        commitment: commitment(&offer),
        offer,
        code_secret: random::bytes::<CODE_SECRET_LENGTH>(),
        exchange_secret: Zeroizing::new(secret.to_bytes()),
    })
}

/// The part of the pairing code that pins the offer: the first 16 bytes of SHA-256 over it.
pub fn commitment(offer: &[u8]) -> [u8; COMMITMENT_LENGTH] {
    let digest = Sha256::new().chain_update(CONTEXT).chain_update(offer).finalize();
    digest[..COMMITMENT_LENGTH].try_into().unwrap()
}

/// On an **existing** device: checks the offer against the commitment from the pairing code and
/// seals `payload` so only the device that made the offer, and showed the code, can open it.
pub fn approve(offer_bytes: &[u8], expected_commitment: &[u8], code_secret: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    if !constant_time_eq(expected_commitment, &commitment(offer_bytes)) {
        return Err(CryptoError::Verification(
            "the offer does not match the pairing code; it may have been tampered with".into(),
        ));
    }
    let offer = Offer::from_bytes(offer_bytes)?;
    let code_secret = code_secret_from(code_secret)?;

    let sender = StaticSecret::from(*random::bytes::<32>());
    let sender_public = PublicKey::from(&sender).to_bytes();
    let shared = Zeroizing::new(sender.diffie_hellman(&PublicKey::from(offer.exchange_key)).to_bytes());
    let key = derive_key(&shared, code_secret, offer_bytes, &sender_public)?;

    let nonce = random::bytes::<24>();
    let ciphertext = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .expect("32-byte key")
        .encrypt(
            &XNonce::try_from(nonce.as_slice()).unwrap(),
            Payload {
                msg: payload,
                aad: &sender_public,
            },
        )
        .map_err(|_| CryptoError::Store("device pairing encryption failed".into()))?;

    let mut out = vec![APPROVAL_VERSION];
    out.extend_from_slice(&sender_public);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// On the **new** device: opens the approval with the secrets from [`begin`] and the offer it made.
pub fn complete(
    approval: &[u8],
    offer_bytes: &[u8],
    exchange_secret: &[u8],
    code_secret: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if approval.len() < 1 + 32 + 24 + 16 || approval[0] != APPROVAL_VERSION {
        return Err(CryptoError::Malformed("not a device pairing approval".into()));
    }
    let secret: [u8; 32] = exchange_secret
        .try_into()
        .map_err(|_| CryptoError::Malformed("a pairing exchange secret is 32 bytes".into()))?;
    let secret = StaticSecret::from(secret);
    let code_secret = code_secret_from(code_secret)?;
    let sender_public: [u8; 32] = approval[1..33].try_into().unwrap();

    let shared = Zeroizing::new(secret.diffie_hellman(&PublicKey::from(sender_public)).to_bytes());
    let key = derive_key(&shared, code_secret, offer_bytes, &sender_public)?;

    XChaCha20Poly1305::new_from_slice(key.as_slice())
        .expect("32-byte key")
        .decrypt(
            &XNonce::try_from(&approval[33..57]).unwrap(),
            Payload {
                msg: &approval[57..],
                aad: &sender_public,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Verification("the device pairing approval does not open".into()))
}

fn code_secret_from(code_secret: &[u8]) -> Result<&[u8; CODE_SECRET_LENGTH]> {
    code_secret
        .try_into()
        .map_err(|_| CryptoError::Malformed("a pairing code secret is 16 bytes".into()))
}

fn derive_key(
    shared: &[u8; 32],
    code_secret: &[u8; CODE_SECRET_LENGTH],
    offer_bytes: &[u8],
    sender_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    // A low-order public key would make the shared secret all zeros; refuse rather than derive a
    // key an attacker can predict.
    if shared.iter().all(|b| *b == 0) {
        return Err(CryptoError::Verification("invalid device pairing key".into()));
    }
    let info = [CONTEXT, offer_bytes, sender_public.as_slice()].concat();
    let mut key = Zeroizing::new([0u8; 32]);
    // The code secret is the salt: it is what the relay does not have.
    Hkdf::<Sha256>::new(Some(code_secret), shared)
        .expand(&info, &mut key[..])
        .map_err(|_| CryptoError::Store("hkdf".into()))?;
    Ok(key)
}

fn field(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length = u16::try_from(value.len())
        .map_err(|_| CryptoError::Malformed("a device pairing field is longer than 65,535 bytes".into()))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_offer_round_trips() {
        let begun = begin("Ana's iPhone", "ios").unwrap();
        let offer = Offer::from_bytes(&begun.offer).unwrap();
        assert_eq!(offer.device_name, "Ana's iPhone");
        assert_eq!(offer.platform, "ios");
        assert_eq!(Offer::from_bytes(&offer.to_bytes().unwrap()).unwrap(), offer);

        assert!(Offer::from_bytes(&begun.offer[..10]).is_err());
        assert!(begin(&"x".repeat(65), "ios").is_err());
    }

    #[test]
    fn an_over_long_label_in_an_offer_is_malformed_not_a_panic() {
        // `begin` refuses long labels first; the encoder must not rely on that.
        let too_long = Offer {
            device_name: "x".repeat(u16::MAX as usize + 1),
            platform: "ios".into(),
            exchange_key: [7; 32],
        };
        assert!(matches!(too_long.to_bytes(), Err(CryptoError::Malformed(_))));
    }

    #[test]
    fn only_the_offering_device_opens_the_approval() {
        let begun = begin("Desk", "linux").unwrap();
        let code = begun.code_secret.as_slice();
        let approval = approve(&begun.offer, &begun.commitment, code, b"the root and the rest").unwrap();

        let opened = complete(&approval, &begun.offer, begun.exchange_secret.as_slice(), code).unwrap();
        assert_eq!(opened.as_slice(), b"the root and the rest");

        let stranger = begin("Desk", "linux").unwrap();
        assert!(complete(&approval, &begun.offer, stranger.exchange_secret.as_slice(), code).is_err());
        // Bound to the exact offer: the right key with a different offer does not open it.
        assert!(complete(&approval, &stranger.offer, begun.exchange_secret.as_slice(), code).is_err());
        // And to the code: the right key and offer with another code secret does not open it.
        assert!(
            complete(
                &approval,
                &begun.offer,
                begun.exchange_secret.as_slice(),
                stranger.code_secret.as_slice()
            )
            .is_err()
        );
    }

    #[test]
    fn a_relay_that_seals_its_own_payload_is_refused() {
        // The relay holds the offer, so it can compute the commitment and seal to the offer's key.
        // What it lacks is the code secret, which only travels in the code shown on the new device.
        let begun = begin("Desk", "linux").unwrap();
        let forged = approve(&begun.offer, &begun.commitment, &[0u8; CODE_SECRET_LENGTH], b"evil").unwrap();
        assert!(matches!(
            complete(
                &forged,
                &begun.offer,
                begun.exchange_secret.as_slice(),
                begun.code_secret.as_slice()
            ),
            Err(CryptoError::Verification(_))
        ));
    }

    #[test]
    fn a_code_secret_of_the_wrong_length_is_malformed() {
        let begun = begin("Desk", "linux").unwrap();
        assert!(matches!(
            approve(&begun.offer, &begun.commitment, &[0u8; 8], b"secret"),
            Err(CryptoError::Malformed(_))
        ));
        let approval = approve(&begun.offer, &begun.commitment, begun.code_secret.as_slice(), b"secret").unwrap();
        assert!(matches!(
            complete(&approval, &begun.offer, begun.exchange_secret.as_slice(), &[0u8; 17]),
            Err(CryptoError::Malformed(_))
        ));
    }

    #[test]
    fn a_swapped_offer_is_refused_before_anything_is_sealed() {
        let shown = begin("Desk", "linux").unwrap();
        let relay_own = begin("Desk", "linux").unwrap();
        let code = shown.code_secret.as_slice();
        assert!(matches!(
            approve(&relay_own.offer, &shown.commitment, code, b"secret"),
            Err(CryptoError::Verification(_))
        ));
        assert!(approve(&shown.offer, &shown.commitment[..8], code, b"secret").is_err());
    }
}
