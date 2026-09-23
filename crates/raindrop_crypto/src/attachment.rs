//! File attachments: a file encrypted once, with its own random key, and stored by the server as an
//! opaque blob. The key travels inside the MLS message that shares the file, so only the channel's
//! group can read it, and because the key sits in the decrypted-message cache, the group moving on to
//! a new epoch never strands the file.
//!
//! The format, `raindrop/attachment/v1`:
//!
//! ```text
//! | version: 1 byte (1) | nonce prefix: 19 bytes | segment 0 | segment 1 | … | segment n-1 |
//! ```
//!
//! The plaintext is cut into [`SEGMENT_LENGTH`] segments (the last one may be shorter, and an empty
//! file is one empty segment). Each is sealed with XChaCha20-Poly1305 under the file key, the context
//! string as associated data, and the nonce `prefix ‖ counter (u32 BE) ‖ last (1 byte: 1 on the final
//! segment, 0 otherwise)`. That is the STREAM construction: a segment cannot be moved, dropped or
//! spliced in from another file, and the file cannot be cut short at a segment boundary, because each
//! of those changes a nonce and the tag stops verifying.
//!
//! The ciphertext's length fixes the plaintext's exactly ([`ciphertext_length`],
//! [`plaintext_length`]), which is how the server enforces a size limit on a file it cannot read.
//! That formula is a contract with the server: change it only under a new version.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::random;

/// The format version byte this build writes and reads.
pub const VERSION: u8 = 1;

/// Associated data on every segment, so a segment sealed for any other purpose never opens here.
const CONTEXT: &[u8] = b"raindrop/attachment/v1\n";

/// Plaintext bytes per segment.
pub const SEGMENT_LENGTH: usize = 64 * 1024;

/// Bytes the AEAD adds to each segment.
pub const TAG_LENGTH: usize = 16;

/// Random bytes at the start of every segment's nonce.
pub const NONCE_PREFIX_LENGTH: usize = 19;

/// The version byte and the nonce prefix.
pub const HEADER_LENGTH: usize = 1 + NONCE_PREFIX_LENGTH;

/// Bytes in a file key.
pub const KEY_LENGTH: usize = 32;

/// A file after encryption: what the sender puts in its message so recipients can fetch and open it.
pub struct SealedFile {
    /// The file's own key. Never reused for another file.
    pub key: Zeroizing<[u8; KEY_LENGTH]>,
    /// SHA-256 of the whole ciphertext, header included. The server checks an upload against it and
    /// recipients check a download against it, so the file in the message is the file on disk.
    pub ciphertext_sha256: [u8; 32],
    /// Bytes of ciphertext, as [`ciphertext_length`] gives for the plaintext.
    pub ciphertext_length: u64,
}

/// How many bytes of ciphertext a file of `plaintext` bytes becomes.
pub fn ciphertext_length(plaintext: u64) -> u64 {
    let segments = plaintext.div_ceil(SEGMENT_LENGTH as u64).max(1);
    HEADER_LENGTH as u64 + plaintext + TAG_LENGTH as u64 * segments
}

/// The plaintext length behind `ciphertext` bytes of ciphertext, or `None` when no file encrypts to
/// that length.
pub fn plaintext_length(ciphertext: u64) -> Option<u64> {
    let body = ciphertext.checked_sub(HEADER_LENGTH as u64)?;
    if body < TAG_LENGTH as u64 {
        return None;
    }
    let segments = body.div_ceil((SEGMENT_LENGTH + TAG_LENGTH) as u64).max(1);
    let plaintext = body.checked_sub(TAG_LENGTH as u64 * segments)?;
    (ciphertext_length(plaintext) == ciphertext).then_some(plaintext)
}

/// Encrypts the file at `input` into `output` under a fresh key. The ciphertext is written beside
/// `output` first and moved into place only once it is complete, so `output` is never half a file.
pub fn encrypt_file(input: &Path, output: &Path) -> Result<SealedFile> {
    let reader = BufReader::new(File::open(input).map_err(io)?);
    write_atomically(output, |writer| encrypt(reader, writer))
}

/// Decrypts the file at `input` into `output`. With `expected_sha256`, a ciphertext whose hash
/// differs is refused even if it would decrypt. Like [`encrypt_file`], `output` only ever appears
/// complete; a file that fails to open leaves nothing behind.
pub fn decrypt_file(input: &Path, output: &Path, key: &[u8], expected_sha256: Option<&[u8]>) -> Result<u64> {
    let reader = BufReader::new(File::open(input).map_err(io)?);
    write_atomically(output, |writer| decrypt(reader, writer, key, expected_sha256))
}

/// [`encrypt_file`] for bytes already in memory, such as a thumbnail.
pub fn encrypt_bytes(plaintext: &[u8]) -> Result<(SealedFile, Vec<u8>)> {
    let mut out = Vec::with_capacity(ciphertext_length(plaintext.len() as u64) as usize);
    let sealed = encrypt(plaintext, &mut out)?;
    Ok((sealed, out))
}

/// [`decrypt_file`] for bytes already in memory.
pub fn decrypt_bytes(ciphertext: &[u8], key: &[u8], expected_sha256: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(
        plaintext_length(ciphertext.len() as u64).unwrap_or(0) as usize,
    ));
    decrypt(ciphertext, &mut *out, key, expected_sha256)?;
    Ok(out)
}

/// Encrypts everything `reader` holds into `writer`.
pub fn encrypt<R: Read, W: Write>(mut reader: R, mut writer: W) -> Result<SealedFile> {
    let key = random::bytes::<KEY_LENGTH>();
    let prefix = random::bytes::<NONCE_PREFIX_LENGTH>();
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).expect("32-byte key");
    let mut hash = Sha256::new();
    let mut length = 0u64;

    let mut emit = |bytes: &[u8]| -> Result<()> {
        hash.update(bytes);
        length += bytes.len() as u64;
        writer.write_all(bytes).map_err(io)
    };

    let mut header = [0u8; HEADER_LENGTH];
    header[0] = VERSION;
    header[1..].copy_from_slice(prefix.as_slice());
    emit(&header)?;

    // One segment of lookahead: a segment is the last one exactly when nothing follows it, which a
    // file whose length is a multiple of the segment size only reveals by reading on.
    let mut current = Zeroizing::new(Vec::with_capacity(SEGMENT_LENGTH + TAG_LENGTH));
    let mut next = Zeroizing::new(Vec::with_capacity(SEGMENT_LENGTH + TAG_LENGTH));
    read_segment(&mut reader, &mut current, SEGMENT_LENGTH)?;
    let mut counter = 0u32;
    loop {
        let last = current.len() < SEGMENT_LENGTH || {
            read_segment(&mut reader, &mut next, SEGMENT_LENGTH)?;
            next.is_empty()
        };
        cipher
            .encrypt_in_place(&nonce(&prefix, counter, last), CONTEXT, &mut *current)
            .map_err(|_| CryptoError::Malformed("attachment segment could not be encrypted".into()))?;
        emit(&current)?;
        if last {
            break;
        }
        counter = counter
            .checked_add(1)
            .ok_or_else(|| CryptoError::Malformed("file too large to encrypt".into()))?;
        std::mem::swap(&mut current, &mut next);
    }
    writer.flush().map_err(io)?;

    Ok(SealedFile {
        key,
        ciphertext_sha256: hash.finalize().into(),
        ciphertext_length: length,
    })
}

/// Decrypts an attachment from `reader` into `writer`, returning the plaintext length. What was
/// written before a failure must be thrown away; the file-based entry points do that themselves.
pub fn decrypt<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    key: &[u8],
    expected_sha256: Option<&[u8]>,
) -> Result<u64> {
    let refused = || CryptoError::Verification("the attachment does not open with this key".into());
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::Malformed(format!("an attachment key is {KEY_LENGTH} bytes")))?;
    let mut hash = Sha256::new();

    let mut header = [0u8; HEADER_LENGTH];
    reader.read_exact(&mut header).map_err(|e| match e.kind() {
        ErrorKind::UnexpectedEof => CryptoError::Malformed("not an attachment".into()),
        _ => io(e),
    })?;
    if header[0] != VERSION {
        return Err(CryptoError::Malformed(format!(
            "attachment format version {}",
            header[0]
        )));
    }
    hash.update(header);
    let prefix: [u8; NONCE_PREFIX_LENGTH] = header[1..].try_into().unwrap();

    let sealed_segment = SEGMENT_LENGTH + TAG_LENGTH;
    let mut current = Zeroizing::new(Vec::with_capacity(sealed_segment));
    let mut next = Zeroizing::new(Vec::with_capacity(sealed_segment));
    read_segment(&mut reader, &mut current, sealed_segment)?;
    let mut counter = 0u32;
    let mut length = 0u64;
    loop {
        if current.len() < TAG_LENGTH {
            return Err(refused());
        }
        let last = current.len() < sealed_segment || {
            read_segment(&mut reader, &mut next, sealed_segment)?;
            next.is_empty()
        };
        hash.update(&*current);
        cipher
            .decrypt_in_place(&nonce(&prefix, counter, last), CONTEXT, &mut *current)
            .map_err(|_| refused())?;
        length += current.len() as u64;
        writer.write_all(&current).map_err(io)?;
        if last {
            break;
        }
        counter = counter.checked_add(1).ok_or_else(refused)?;
        std::mem::swap(&mut current, &mut next);
    }

    if let Some(expected) = expected_sha256 {
        let actual: [u8; 32] = hash.finalize().into();
        if expected != actual {
            return Err(CryptoError::Verification(
                "the attachment is not the one the message names".into(),
            ));
        }
    }
    writer.flush().map_err(io)?;
    Ok(length)
}

fn nonce(prefix: &[u8; NONCE_PREFIX_LENGTH], counter: u32, last: bool) -> XNonce {
    let mut nonce = [0u8; 24];
    nonce[..NONCE_PREFIX_LENGTH].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LENGTH..NONCE_PREFIX_LENGTH + 4].copy_from_slice(&counter.to_be_bytes());
    nonce[23] = last as u8;
    XNonce::from(nonce)
}

/// Fills `buffer` with up to `limit` bytes, fewer only at the end of the input.
fn read_segment<R: Read>(reader: &mut R, buffer: &mut Vec<u8>, limit: usize) -> Result<()> {
    buffer.clear();
    reader.take(limit as u64).read_to_end(buffer).map_err(io)?;
    Ok(())
}

/// Runs `write` against a temporary file beside `output`, renaming it into place on success and
/// deleting it on failure.
fn write_atomically<T>(output: &Path, write: impl FnOnce(&mut BufWriter<File>) -> Result<T>) -> Result<T> {
    let partial = partial_path(output);
    let result = (|| {
        let mut writer = BufWriter::new(File::create(&partial).map_err(io)?);
        let value = write(&mut writer)?;
        writer
            .into_inner()
            .map_err(|e| io(e.into_error()))?
            .sync_all()
            .map_err(io)?;
        fs::rename(&partial, output).map_err(io)?;
        Ok(value)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result
}

fn partial_path(output: &Path) -> PathBuf {
    let mut name = output.file_name().unwrap_or_default().to_os_string();
    name.push(".part");
    output.with_file_name(name)
}

fn io(error: std::io::Error) -> CryptoError {
    CryptoError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(length: usize) -> Vec<u8> {
        (0..length).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn round_trips_across_segment_boundaries() {
        for length in [
            0,
            1,
            SEGMENT_LENGTH - 1,
            SEGMENT_LENGTH,
            SEGMENT_LENGTH + 1,
            3 * SEGMENT_LENGTH,
            3 * SEGMENT_LENGTH + 17,
        ] {
            let plaintext = sample(length);
            let (sealed, ciphertext) = encrypt_bytes(&plaintext).unwrap();
            assert_eq!(
                ciphertext.len() as u64,
                ciphertext_length(length as u64),
                "length {length}"
            );
            assert_eq!(sealed.ciphertext_length, ciphertext.len() as u64);
            assert_eq!(sealed.ciphertext_sha256, <[u8; 32]>::from(Sha256::digest(&ciphertext)));
            let opened = decrypt_bytes(&ciphertext, sealed.key.as_slice(), Some(&sealed.ciphertext_sha256)).unwrap();
            assert_eq!(*opened, plaintext, "length {length}");
        }
    }

    #[test]
    fn length_formula_inverts_exactly() {
        for plaintext in (0..300_000u64).step_by(997).chain([65_535, 65_536, 65_537, 131_072]) {
            assert_eq!(plaintext_length(ciphertext_length(plaintext)), Some(plaintext));
        }
        // No file encrypts to a length that is a whole segment plus a partial tag.
        for impossible in [0, 19, 20, 35, 20 + 65_552 + 1, 20 + 65_552 + 16] {
            assert_eq!(plaintext_length(impossible), None, "{impossible}");
        }
        assert_eq!(ciphertext_length(0), 36);
        assert_eq!(ciphertext_length(65_536), 20 + 65_536 + 16);
        assert_eq!(ciphertext_length(65_537), 20 + 65_537 + 32);
    }

    #[test]
    fn every_file_gets_its_own_key_and_nonce() {
        let (a, ca) = encrypt_bytes(b"same").unwrap();
        let (b, cb) = encrypt_bytes(b"same").unwrap();
        assert_ne!(*a.key, *b.key);
        assert_ne!(ca[1..HEADER_LENGTH], cb[1..HEADER_LENGTH]);
    }

    #[test]
    fn tampering_is_refused() {
        let plaintext = sample(2 * SEGMENT_LENGTH + 100);
        let (sealed, ciphertext) = encrypt_bytes(&plaintext).unwrap();
        let key = sealed.key.as_slice();
        let segment = SEGMENT_LENGTH + TAG_LENGTH;

        let mut flipped = ciphertext.clone();
        flipped[HEADER_LENGTH + 10] ^= 1;
        assert!(matches!(
            decrypt_bytes(&flipped, key, None),
            Err(CryptoError::Verification(_))
        ));

        // Cut at a segment boundary: what is left looks whole but its last segment was not sealed as last.
        let truncated = &ciphertext[..HEADER_LENGTH + 2 * segment];
        assert!(matches!(
            decrypt_bytes(truncated, key, None),
            Err(CryptoError::Verification(_))
        ));

        let mut reordered = ciphertext[..HEADER_LENGTH].to_vec();
        reordered.extend_from_slice(&ciphertext[HEADER_LENGTH + segment..HEADER_LENGTH + 2 * segment]);
        reordered.extend_from_slice(&ciphertext[HEADER_LENGTH..HEADER_LENGTH + segment]);
        reordered.extend_from_slice(&ciphertext[HEADER_LENGTH + 2 * segment..]);
        assert!(matches!(
            decrypt_bytes(&reordered, key, None),
            Err(CryptoError::Verification(_))
        ));

        let wrong_key = [7u8; KEY_LENGTH];
        assert!(matches!(
            decrypt_bytes(&ciphertext, &wrong_key, None),
            Err(CryptoError::Verification(_))
        ));

        let mut wrong_version = ciphertext.clone();
        wrong_version[0] = 2;
        assert!(matches!(
            decrypt_bytes(&wrong_version, key, None),
            Err(CryptoError::Malformed(_))
        ));

        assert!(matches!(
            decrypt_bytes(&ciphertext[..5], key, None),
            Err(CryptoError::Malformed(_))
        ));
        assert!(matches!(
            decrypt_bytes(&[1; 25], key, None),
            Err(CryptoError::Verification(_))
        ));
    }

    #[test]
    fn a_different_file_under_the_expected_hash_is_refused() {
        let (sealed, ciphertext) = encrypt_bytes(b"the real file").unwrap();
        let other = [0u8; 32];
        assert!(matches!(
            decrypt_bytes(&ciphertext, sealed.key.as_slice(), Some(&other)),
            Err(CryptoError::Verification(_))
        ));
    }

    #[test]
    fn files_round_trip_and_failures_leave_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("photo.png");
        let sealed_path = dir.path().join("photo.png.rda");
        let output = dir.path().join("photo-out.png");
        let plaintext = sample(SEGMENT_LENGTH * 2 + 5);
        fs::write(&input, &plaintext).unwrap();

        let sealed = encrypt_file(&input, &sealed_path).unwrap();
        assert_eq!(fs::metadata(&sealed_path).unwrap().len(), sealed.ciphertext_length);
        let length = decrypt_file(
            &sealed_path,
            &output,
            sealed.key.as_slice(),
            Some(&sealed.ciphertext_sha256),
        )
        .unwrap();
        assert_eq!(length, plaintext.len() as u64);
        assert_eq!(fs::read(&output).unwrap(), plaintext);

        let refused = dir.path().join("refused.png");
        assert!(decrypt_file(&sealed_path, &refused, &[9u8; KEY_LENGTH], None).is_err());
        assert!(!refused.exists());
        assert!(!partial_path(&refused).exists());
    }
}
