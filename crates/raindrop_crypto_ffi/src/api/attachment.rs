//! File attachments for Dart: encrypt a file before it is uploaded, decrypt one after it is
//! downloaded. Everything goes through file paths so a large file never crosses the bridge; only the
//! in-memory pair, for thumbnails, carries bytes. Not tied to a session: a file's key is its own, and
//! travels inside the MLS message that shares it.

use std::path::PathBuf;

use raindrop_crypto::attachment;

use super::session::CryptoFailure;

type Result<T> = std::result::Result<T, CryptoFailure>;

/// A file after encryption. `key` and `ciphertext_sha256` go into the message that shares it.
pub struct SealedAttachment {
    pub key: Vec<u8>,
    pub ciphertext_sha256: Vec<u8>,
    pub ciphertext_length: u64,
}

impl From<attachment::SealedFile> for SealedAttachment {
    fn from(sealed: attachment::SealedFile) -> Self {
        Self {
            key: sealed.key.to_vec(),
            ciphertext_sha256: sealed.ciphertext_sha256.to_vec(),
            ciphertext_length: sealed.ciphertext_length,
        }
    }
}

/// A thumbnail, or any small file, encrypted in memory.
pub struct SealedAttachmentBytes {
    pub sealed: SealedAttachment,
    pub ciphertext: Vec<u8>,
}

/// Encrypts the file at `input_path` into `output_path` under a fresh key.
pub fn encrypt_attachment_file(input_path: String, output_path: String) -> Result<SealedAttachment> {
    Ok(attachment::encrypt_file(&PathBuf::from(input_path), &PathBuf::from(output_path))?.into())
}

/// Decrypts a downloaded attachment, refusing it unless its hash is `expected_sha256`. Returns the
/// plaintext length. `output_path` appears only once the whole file has opened.
pub fn decrypt_attachment_file(
    input_path: String,
    output_path: String,
    key: Vec<u8>,
    expected_sha256: Vec<u8>,
) -> Result<u64> {
    Ok(attachment::decrypt_file(
        &PathBuf::from(input_path),
        &PathBuf::from(output_path),
        &key,
        Some(&expected_sha256),
    )?)
}

/// Encrypts bytes already in memory, such as a generated thumbnail.
pub fn encrypt_attachment_bytes(plaintext: Vec<u8>) -> Result<SealedAttachmentBytes> {
    let (sealed, ciphertext) = attachment::encrypt_bytes(&plaintext)?;
    Ok(SealedAttachmentBytes {
        sealed: sealed.into(),
        ciphertext,
    })
}

/// Decrypts a small attachment held in memory, refusing it unless its hash is `expected_sha256`.
pub fn decrypt_attachment_bytes(ciphertext: Vec<u8>, key: Vec<u8>, expected_sha256: Vec<u8>) -> Result<Vec<u8>> {
    Ok(attachment::decrypt_bytes(&ciphertext, &key, Some(&expected_sha256))?.to_vec())
}

/// How many bytes of ciphertext a file of `plaintext_length` bytes becomes; what the server is told
/// when the upload is created.
#[flutter_rust_bridge::frb(sync)]
pub fn attachment_ciphertext_length(plaintext_length: u64) -> u64 {
    attachment::ciphertext_length(plaintext_length)
}
