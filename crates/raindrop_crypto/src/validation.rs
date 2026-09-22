//! Deciding whether a device in an MLS group really is who it claims to be.
//!
//! MLS authenticates *signature keys*; it says nothing about which person a key belongs to. Raindrop
//! answers that with the [`DeviceCertificate`] inside every credential. This module is the one place
//! that checks it, and it is a trait so a plugin, or a stricter deployment, can add rules of its own,
//! such as requiring every identity to be verified.

use openmls::prelude::{BasicCredential, Credential};

use crate::error::{CryptoError, Result};
use crate::identity::DeviceCertificate;
use crate::store::Store;

/// Judges one group member's credential.
pub trait CredentialValidator {
    /// Returns the member's certificate if the credential is acceptable. `signature_key` is the
    /// leaf's MLS signature key, which the certificate must be about.
    fn validate(&self, credential: &Credential, signature_key: &[u8]) -> Result<DeviceCertificate>;
}

/// Reads the certificate out of a credential and checks its internal consistency: well formed,
/// about this leaf's key, and signed by the identity key it carries. It does *not* decide whether
/// that identity key is the right one.
pub fn certificate_of(credential: &Credential, signature_key: &[u8]) -> Result<DeviceCertificate> {
    let basic = BasicCredential::try_from(credential.clone())
        .map_err(|_| CryptoError::Verification("only basic credentials are accepted".into()))?;
    let certificate = DeviceCertificate::from_bytes(basic.identity())?;

    if certificate.device_signature_key != signature_key {
        return Err(CryptoError::Verification(
            "the device certificate is for a different signature key".into(),
        ));
    }
    certificate.verify()?;
    Ok(certificate)
}

/// The default rule: a certificate must verify, and the identity key that signed it must match the
/// one pinned for that user. A user seen for the first time is pinned there and then (trust on
/// first use); a user whose key changed is refused until this device's owner accepts the change.
pub struct PinnedIdentityValidator<'a> {
    pub store: &'a Store,
    pub now_unix: i64,
}

impl CredentialValidator for PinnedIdentityValidator<'_> {
    fn validate(&self, credential: &Credential, signature_key: &[u8]) -> Result<DeviceCertificate> {
        let certificate = certificate_of(credential, signature_key)?;
        self.store
            .pin_identity(&certificate.user_id, &certificate.user_identity_key, self.now_unix)?;
        Ok(certificate)
    }
}
