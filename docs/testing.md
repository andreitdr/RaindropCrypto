# Testing & building

## Toolchain

Homebrew's `rustup` is keg-only and not on the shell's `PATH` by default:

```bash
export PATH=/opt/homebrew/opt/rustup/bin:$PATH
```

This workspace builds with stable. The Flutter app's build hook uses the exact toolchain pinned in
`crates/raindrop_crypto_ffi/rust-toolchain.toml`, which only builds started inside that folder see.

From this folder (`RaindropCrypto/`):

```bash
cargo test                           # unit + multi-device integration tests
cargo clippy --all-targets
cargo fmt --all                      # rustfmt.toml: max_width = 120
cargo build -p raindrop_crypto_ffi   # the library the client's Dart bridge test loads
```

`[profile.dev.package."*"] opt-level = 2` in the workspace `Cargo.toml` is deliberate: crypto code is
slow and hard to profile unoptimised, and the tests exercise real key derivations (Argon2id, MLS), so a
debug build without it would make `cargo test` noticeably slower.

## What `cargo test` covers

**`raindrop_crypto`, unit tests (40)** — one `#[cfg(test)] mod tests` per module:

| Module | Covers |
|---|---|
| `attachment` | Round trips at every segment boundary; the length formula inverts exactly and rejects impossible lengths; fresh key and nonce per file; a flipped byte, a truncation at a segment boundary, reordered segments, a wrong key, version or expected hash are refused; failed file operations leave no output. See [Attachments](attachments.md#tests) |
| `backup` | Recovery-key round trip; a wrong recovery key refused; a mistyped word caught by the BIP-39 checksum; passphrase round trip and tamper detection (a flipped header byte fails to open) |
| `identity` | A certificate round-trips and verifies; a tampered one does not; an identity survives being reconstructed from its secret; safety numbers are symmetric and depend on the keys |
| `link` | An offer round-trips (and a truncated one fails); only the offering device's exchange key opens an approval, and only for the exact offer it was sealed to; an approval sealed without the link code's secret does not open; the commitment changes with any part of the offer |
| `store` | A wrong key is refused (`StoreLocked`); the file on disk (database and WAL) contains no SQLite header or a known plaintext marker; identity pins refuse a changed key until explicitly replaced, and record verification; messages page newest-first; groups left for a changed identity are recorded per key (a second refusal replaces the first), cleared by that key or by deleting the group, and listed with the pin |

**`raindrop_crypto`, integration tests (38, `tests/session.rs`, plus one `#[ignore]`d fixture printer)** — several devices, each with its own
encrypted store on disk, exchanging the bytes a delivery service would carry (no networking):

- Two devices exchange messages
- A message is decrypted once, then served from the cache on a repeat delivery
- State and plaintext survive a restart (closing and reopening the store)
- Every member derives the same exported secret for an epoch, and it rotates
- A device joins by itself from a published group info (external commit), and its `epoch_after` is the epoch it and everyone else is at
- An external join is refused, and leaves no group behind, when a member fails validation (a different pinned identity key), when the group info is for another group, and when the device already holds the group
- A removed device cannot read what follows its removal
- An impostor with a different identity key is refused
- A message from a sender whose identity key no longer matches the pin is `IdentityChanged`, held (not in the cache) and `IdentityChanged` again on a repeat delivery; accepting the key moves it into the cache, and the sender's next message is ordinary
- A held message stays held while the change is not accepted: accepting a different key releases nothing, and it survives a restart
- `IdentityChanged` carries both keys (the pin and the presented key), from a held message and from a refused key package; accepting the key taken from that error releases the held message
- `pending_identity_changes` is empty until a change is met; then it lists the held messages (count, groups, pin, presented key) and, after a refused commit, the group left; it is identical after reopening the store; accepting another key changes none of it, accepting the presented key empties it
- A refused external join is listed as a left group; deleting the group, or accepting the key and joining, clears it
- Deleting a group clears its held messages and its cached messages
- Resetting a group keeps its held messages (still `IdentityChanged`, released by accepting the key), and does nothing for a group that is not held
- A resync (`ResyncRequired` after a discarded own commit) followed by `reset_group` keeps the cached messages, and a rejoin by external commit works over them: repeated message ids are served from the cache without duplicates, and messages flow both ways
- A commit from a member whose identity changed takes the device out of the group (`!has_group`, the `pending_commit.<hex>` record gone, cached messages kept); rejoining is refused until the change is accepted, then succeeds and messages flow again
- A standalone external join proposal is refused, and the next commit does not add its device
- Of two racing commits for the same epoch, only one wins
- An own commit this device discarded (the server kept it but answered with an error) is `ResyncRequired` when echoed, not a silent `OwnMessage`; with a different commit pending, that echo still merges nothing and leaves the epoch as it was, and the pending commit's own echo merges afterwards
- The echo of a pending `add_members` and `remove_members` commit still merges
- A backup restores the identity onto a new device
- A new device is linked from an existing one
- A link offer that does not match its code is refused
- A link approval the server sealed itself, without the code secret, is refused, and the real one still completes the link
- The session-challenge signature is plain Ed25519 by the device key

Add new multi-device behaviour here; add single-module logic (a new format, a new validation rule) as a
unit test beside the code it tests.

**`raindrop_crypto_ffi`** has no tests of its own — it is a thin conversion layer over `Session`, exercised
by the client's Dart tests instead.

**`raindrop_video` (29 in `tests/effects.rs`, four of them only with the segmentation model
present, plus two in `blur.rs`)** — the camera effects, driven over real frames with real stride padding. Full detail in [Camera effects](video-effects.md#tests); what carries them is two test
doubles worth knowing about:

- **A hand-wound clock** whose every *read* advances it by a set step. `Effects::process` reads it once
  at the start of a frame and once at the end, so the step is exactly how long that frame appears to
  have taken — which drives the degradation ladder to any state with no real waiting.
- **Segmenters that answer in known ways.** The default `CentreOvalSegmenter` is itself one: a real,
  deterministic segmenter that finds a circle in the middle of the frame. Every assertion is therefore
  about the pixel work, and a regression shows up as a wrong picture rather than as a worse mask.

The groups: the frame boundary (stride padding untouched, odd dimensions, refusals), blur (background
variance drops, foreground variance does not), replacement, the mask (centring, soft edges,
convergence), the ladder (each step in order; one slow frame triggers nothing), colour round-tripping,
and determinism.

## Testing from the client

The client (Flutter) has its own tests that exercise this crate through the bridge; see its
[crypto doc](../../RaindropClient/docs/crypto.md#tests) for the current list. In outline:

- A Dart test runs the facade against the **real built library** — build it first with `cargo build -p
  raindrop_crypto_ffi` here; without it, the test skips itself rather than failing.
  It checks, among other things, that `CryptoFailure` carries the pinned and presented keys across the
  bridge, and that a refused join shows up in `pendingIdentityChanges` and is cleared by accepting the
  presented key. The generated Dart must be regenerated first or this test cannot compile.
- An integration test runs the real Rust core against a **real RaindropServer**, covering the parts that
  need a server: registering the first device, session binding (including a signature from the wrong
  key), an impostor certificate, linking a device through the relay, revocation ending a session,
  restoring from the recovery key, the unbound-session restriction, and an identity reset. It skips
  itself unless `RAINDROP_TEST_SERVER=host:port` names a server with a fresh database.

## Regenerating the Dart bindings

Covered in full in [Flutter bridge](flutter-bridge.md#building-and-regenerating). In short: after
touching `crates/raindrop_crypto_ffi/src/api/`, run `flutter_rust_bridge_codegen generate` from
`RaindropClient/`, and keep `flutter_rust_bridge` at exactly 2.13.0 in this crate, the client's
`pubspec.yaml`, and the installed codegen.
