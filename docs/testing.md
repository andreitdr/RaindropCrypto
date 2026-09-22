# Testing & building

## Toolchain

Homebrew's `rustup` is keg-only and not on the shell's `PATH` by default:

```bash
export PATH=/opt/homebrew/opt/rustup/bin:$PATH
```

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

**`raindrop_crypto`, unit tests (15)** — one `#[cfg(test)] mod tests` per module:

| Module | Covers |
|---|---|
| `backup` | Recovery-key round trip; a wrong recovery key refused; a mistyped word caught by the BIP-39 checksum; passphrase round trip and tamper detection (a flipped header byte fails to open) |
| `identity` | A certificate round-trips and verifies; a tampered one does not; an identity survives being reconstructed from its secret; safety numbers are symmetric and depend on the keys |
| `link` | An offer round-trips (and a truncated one fails); only the offering device's exchange key opens an approval, and only for the exact offer it was sealed to; the commitment changes with any part of the offer |
| `store` | A wrong key is refused (`StoreLocked`); the file on disk (database and WAL) contains no SQLite header or a known plaintext marker; identity pins refuse a changed key until explicitly replaced, and record verification; messages page newest-first |

**`raindrop_crypto`, integration tests (12, `tests/session.rs`)** — several devices, each with its own
encrypted store on disk, exchanging the bytes a delivery service would carry (no networking):

- Two devices exchange messages
- A message is decrypted once, then served from the cache on a repeat delivery
- State and plaintext survive a restart (closing and reopening the store)
- Every member derives the same exported secret for an epoch, and it rotates
- A device joins by itself from a published group info (external commit)
- A removed device cannot read what follows its removal
- An impostor with a different identity key is refused
- Of two racing commits for the same epoch, only one wins
- A backup restores the identity onto a new device
- A new device is linked from an existing one
- A link offer that does not match its code is refused
- The session-challenge signature is plain Ed25519 by the device key

Add new multi-device behaviour here; add single-module logic (a new format, a new validation rule) as a
unit test beside the code it tests.

**`raindrop_crypto_ffi`** has no tests of its own — it is a thin conversion layer over `Session`, exercised
by the client's Dart tests instead.

## Testing from the client

The client (Flutter) has its own tests that exercise this crate through the bridge; see its
[crypto doc](../../RaindropClient/docs/crypto.md#tests) for the current list. In outline:

- A Dart test runs the facade against the **real built library** — build it first with `cargo build -p
  raindrop_crypto_ffi` here; without it, the test skips itself rather than failing.
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
