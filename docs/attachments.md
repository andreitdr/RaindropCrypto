# Attachments

`crates/raindrop_crypto/src/attachment.rs`; bridge in `crates/raindrop_crypto_ffi/src/api/attachment.rs`.

A file shared in a channel is encrypted once, on the sender's device, under a **key of its own** — not a
key derived from the channel's MLS group. The server stores the ciphertext as an opaque blob; the key,
the file's name and type and the ciphertext's SHA-256 travel inside the MLS application message that
shares it (the client's `files` payload, see the client's
[`docs/attachments.md`](../../RaindropClient/docs/attachments.md)).

Why a per-file key rather than an exported group secret: MLS deletes an epoch's secrets once the group
moves on. A file keyed to the epoch it was sent in would become unreadable the moment somebody joined
or left. The per-file key sits in the [message cache](local-store.md#the-message-cache) alongside the
message that carries it, so the file stays readable exactly as long as the message does. The group
still decides who can read the file, because only its members can decrypt the message holding the key.

## Format: `raindrop/attachment/v1`

```text
| version: u8 = 1 | nonce prefix: 19 random bytes | segment 0 | segment 1 | … | segment n-1 |
```

- The plaintext is cut into **64 KiB segments** (`SEGMENT_LENGTH`); the last may be shorter, and an
  empty file is a single empty segment.
- Each segment is sealed separately with **XChaCha20-Poly1305** under the file's 32-byte key, with
  associated data `"raindrop/attachment/v1\n"` and the 24-byte nonce
  `prefix (19) ‖ segment counter (u32 big-endian) ‖ last (1 byte: 1 on the final segment, else 0)`.
- That is the STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizár): moving, dropping or duplicating
  a segment changes the nonce it is opened with, and so does cutting the file off at a segment boundary,
  because the new final segment was not sealed as the last one. Each fails its tag.
- Key and prefix come from `random::bytes`, fresh for every file.

### The length contract

The ciphertext length fixes the plaintext length exactly:

```text
ciphertext = 20 + plaintext + 16 × max(1, ⌈plaintext / 65536⌉)
```

`ciphertext_length` and its inverse `plaintext_length` (which answers `None` for a length no file
encrypts to). The server applies the same formula (`AttachmentFormat` in
`RaindropServer/Attachments/`) to enforce the owner's size limit on a file it cannot read, and refuses an
upload whose declared length is impossible. It is listed in [Wire contracts](wire-contracts.md#attachment).

## API

| Rust (`attachment::`) | Bridge | What it does |
|---|---|---|
| `encrypt_file(input, output)` | `encrypt_attachment_file` | Streams a file into a fresh ciphertext; returns `SealedFile { key, ciphertext_sha256, ciphertext_length }` |
| `decrypt_file(input, output, key, expected_sha256)` | `decrypt_attachment_file` | Streams it back, refusing a ciphertext whose hash differs from the one the message named |
| `encrypt_bytes` / `decrypt_bytes` | `encrypt_attachment_bytes` / `decrypt_attachment_bytes` | The same for bytes in memory (thumbnails) |
| `ciphertext_length` | `attachment_ciphertext_length` (`sync`) | What an upload of this file will declare |
| `encrypt` / `decrypt` | — | The streaming core over any `Read`/`Write` |

The file functions write to `<output>.part` and rename it into place only when the whole file has been
written (and, for decryption, every segment has verified), so a failed or refused file leaves nothing
behind — a half-decrypted file is never mistaken for a whole one. Nothing but paths crosses the bridge
for a file, so a large video never becomes a Dart `Uint8List`.

Failures: a wrong key, a tampered, reordered or truncated ciphertext, or a hash that does not match
are `Verification`; a wrong version byte or something too short to be an attachment is `Malformed`;
the file system is `Io` (bridged as `Other`).

## Tests

`attachment::tests`: round trips at every segment boundary (0, 1, 64 KiB ± 1, several segments); the
length formula inverts exactly and rejects impossible lengths; two encryptions of the same bytes share
neither key nor nonce; a flipped byte, a cut at a segment boundary, swapped segments, a wrong key, a
wrong version and a wrong expected hash are all refused; and the file functions leave no output behind
when they fail.
