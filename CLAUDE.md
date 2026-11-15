# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Documentation wiki

[`docs/`](docs/README.md) is a per-feature documentation wiki for this project, meant to stay current.
**Whenever you change a feature or add a new one — a new `Session` method, a changed byte format, a new
error kind, a new bridge function, a new dependency — update the matching file(s) under `docs/` as part
of that same change**, not as a follow-up. If nothing existing fits, add a new file and link it from
`docs/README.md`.

RaindropCrypto is the end-to-end encryption core for Raindrop, a decentralised, self-hosted chat
platform — **and, since camera video, the client's camera-effects core as well**
([`docs/video-effects.md`](docs/video-effects.md)). The effects have nothing to do with encryption;
they live here because they are Rust that has to reach all five of the client's targets, which is
exactly what this workspace's cargokit build already does, and because the Flutter media library
exposes no way to touch a camera frame from Dart at all.

It is shared by two other projects, and several of its byte formats are a contract with them:

- [RaindropClient](../RaindropClient/CLAUDE.md) (Flutter) is the only consumer of the code. It compiles
  `raindrop_crypto_ffi` into the app and reaches it through generated Dart bindings.
- [RaindropServer](../RaindropServer/CLAUDE.md) (.NET) never links this code. It parses the device
  certificate and verifies session-binding signatures against the formats defined here, and stores the
  opaque backup and link blobs this crate produces.

If a change touches a format listed in [`docs/wire-contracts.md`](docs/wire-contracts.md), update the
server's [`docs/e2ee.md`](../RaindropServer/docs/e2ee.md) and the client's
[`docs/crypto.md`](../RaindropClient/docs/crypto.md) in the same change, and the C# and Dart code that
reads it. Neither can be checked against another implementation than the one in this crate.

This project is Rust, and the Rust lives here, in its own top-level folder, on purpose: it is never
placed inside the Flutter client or the .NET server trees.

## Commands

Homebrew's `rustup` is keg-only and not on this shell's `PATH`; put it there first:

```bash
export PATH=/opt/homebrew/opt/rustup/bin:$PATH
```

Build and test (from this folder):

```bash
cargo test                           # unit tests + the multi-device integration tests
cargo clippy --all-targets
cargo fmt --all
cargo build -p raindrop_crypto_ffi   # the library the client's Dart bridge test loads
```

`rustfmt.toml` sets `max_width = 120`. The workspace is edition 2024, `publish = false`, licence
`UNLICENSED`.

After changing anything under `crates/raindrop_crypto_ffi/src/api/`, regenerate the Dart bindings from
`RaindropClient/`, which holds `flutter_rust_bridge.yaml`:

```bash
flutter_rust_bridge_codegen generate
```

`flutter_rust_bridge` must be exactly **2.13.0** in three places: this crate's `Cargo.toml`
(`=2.13.0`), `RaindropClient/pubspec.yaml`, and the installed codegen. `frb_generated.rs` is generated —
never edit it by hand, and that includes `cargo fmt`: it reorders three `use` groups in that file
(edition 2024 sorts `transform_result_dco` differently), so `cargo fmt --all --check` always reports
it. **Leave it as the codegen wrote it** and check that every other diff it reports is dealt with.

The Flutter app builds `raindrop_crypto_ffi` by itself through `RaindropClient/native/
raindrop_crypto_builder` (cargokit); there is no separate build step for the app. The first build takes
a few minutes, mostly SQLCipher and OpenMLS. `[profile.dev.package."*"] opt-level = 2` keeps debug test
runs quick, because the tests run real key derivations.

## Warnings are errors; no release with either

**A release cannot be published while any platform has a compilation error, and every warning is an
error.** `Cargo.toml`'s `[workspace.lints.rust]` denies `warnings` for every crate (each has
`[lints] workspace = true`; a new crate must too), so a warning fails `cargo build` here, in CI on
Linux, macOS and Windows, and in the client's cargokit build for Android and iOS — and a failing CI
stops `release.yml` before anything is published. When you see a warning, fix it in the same change;
never ship around it with `#[allow(...)]` or by loosening the lint. An `allow` is only for a lint that is
wrong about correct code, scoped to the item, with a comment saying why. Code behind
`cfg(target_os = ...)` is only compiled on that platform, so check it there (or in CI) before calling
it clean. See [`docs/ci-and-releases.md`](docs/ci-and-releases.md).

## Architecture

A Cargo workspace of three crates under `crates/`:

- **`raindrop_crypto`** — the core, plain Rust, no Flutter. **It does no networking**: it turns
  intentions ("send this", "add these devices") into bytes for the caller to deliver, and delivered
  bytes into plaintext or state changes. That keeps the delivery service out of the crypto code and
  makes the whole crate testable without a server.
- **`raindrop_crypto_ffi`** — the flutter_rust_bridge layer (`src/api/`), a thin wrapper over
  `Session`. `src/frb_generated.rs` is generated. It also carries the camera effects, which have two
  more surfaces because frames must not cross the bridge: `src/c_api.rs`, one `extern "C"` function
  Apple's capture pipeline calls by address, and `src/jni_api.rs`, the same for Android, bound by name
  as `com.raindrop.video.NativeFrameProcessor.processI420` — **a Java class name this workspace owns**
  and the client declares. See [`docs/video-effects.md`](docs/video-effects.md#the-three-surfaces).
- **`raindrop_video`** — the camera-effects core: background blur and background replacement, applied
  to I420 camera frames **in place**, so there is no second track and the frame cryptor never notices.
  It depends on neither of the others and holds no key material. Its one `unsafe` is `frame.rs`, the
  borrowed-frame boundary; everything else is safe Rust over slices. Segmentation is behind the
  `Segmenter` trait: MediaPipe's Selfie Segmentation as ONNX, run by `tract` (pure Rust, so cargokit
  needs no toolchain of its own), with a deterministic fallback. The model **is** committed
  (`models/selfie_segmenter_v1.onnx`, Apache-2.0, ~440 KB, `include_bytes!`d when `build.rs` sees it),
  and `models/convert.py` rebuilds and re-verifies it from Google's published TensorFlow Lite file —
  read its README before touching either. A checkout without the file still builds: `cfg(bundled_model)`
  goes off, `onnx::best()` falls back and four tests skip. See
  [`docs/video-effects.md`](docs/video-effects.md).

`raindrop_crypto/src/`:

| Module | Holds |
|---|---|
| `session.rs` | `Session`, the entry point: one device's state on one server. Identity, session binding, device linking, key packages, MLS groups, commits, message encrypt/decrypt, the message cache, exported secrets |
| `identity.rs` | `UserIdentity` (Ed25519), `DeviceCertificate`, `safety_number` |
| `validation.rs` | `CredentialValidator` (trait) and `PinnedIdentityValidator`, the default |
| `attachment.rs` | Files: the per-file key and the chunked `raindrop/attachment/v1` format (XChaCha20-Poly1305 STREAM), whose length formula the server relies on |
| `backup.rs` | `RecoveryKey` (24 BIP-39 words), the Argon2id passphrase path, the sealed blob format |
| `root.rs` | `RootSecret` and the per-server account derived from it, `RecoverySeed`, the sealed root and vault, the app PIN lock |
| `pairing.rs` | Pairing a new device: `Offer`, the pairing-code `commitment`, the sealed approval carrying the root |
| `link.rs` | Device linking: `Offer`, the link-code `commitment`, the X25519 + HKDF + XChaCha20-Poly1305 approval |
| `store.rs` | `Store`: the SQLCipher-encrypted local database (own keys, identity pins, decrypted message cache) |
| `provider.rs` | `RaindropProvider`: the OpenMLS provider (RustCrypto primitives, SQLite storage in the same file) |
| `error.rs` | `CryptoError`, the one error type |
| `random.rs` | The single source of key material (OS CSPRNG), crate-private |

Full reference: [`docs/architecture-overview.md`](docs/architecture-overview.md).

### Design rules to keep

- **One `Session` per server profile per device.** Its store is one SQLCipher file; `Store` and the
  OpenMLS storage provider each hold a connection to it (WAL lets them coexist).
- **Every channel is one MLS group**, whose group id is the channel UUID. The ciphersuite is
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, kept in the single constant `CIPHERSUITE`.
- **Identity is a certificate, not an MLS feature.** MLS authenticates signature keys only. Who a key
  belongs to is answered by the `DeviceCertificate` in the leaf's credential, checked by a
  `CredentialValidator` for *every* member a device meets (adds, welcomes, external joins, incoming
  commits, application messages). Identity keys are pinned trust-on-first-use, and a changed key is
  `IdentityChanged` — never resolved silently. See [`docs/identity-and-trust.md`](docs/identity-and-trust.md).
- **The message cache is the only copy of plaintext.** MLS deletes an epoch's keys once the group
  moves on, so ciphertext fetched again later cannot be decrypted. `receive_message` writes the
  plaintext to the store and serves repeats from there; `remember_sent` stores this device's own
  messages, which it cannot decrypt from the server's echo.
- **Secrets are `Zeroizing`.** Anything that holds key material uses `zeroize` (`Zeroizing`,
  `ZeroizeOnDrop`); keep it that way when adding fields.
- **All randomness goes through `random::bytes`**, so every key comes from one place.
- **Formats are versioned and domain-separated.** Each has a version byte and, where signed or hashed,
  a context string (`raindrop/device-certificate/v1\n`, `raindrop/session-binding/v1\n`,
  `raindrop/device-link/v1\n`, `raindrop/attachment/v1\n`). A new version is a new context, not a change to the old one.
- **Errors are coarse on purpose.** `CryptoError` variants say *what kind* of failure it was; the detail
  string is for logs and is never parsed. The bridge maps them to `CryptoFailureKind`, which the Dart
  side branches on.
- **The bridge uses flat structs, not data-carrying enums** (`CryptoFailure`, `ProcessedMessage` carry a
  `kind` plus optional fields), so the generated Dart needs no `freezed` and there is no `build_runner`
  step. Keep new bridge types flat.

### Extension points

This core will be opened to third-party plugin developers along with the rest of the platform, so new
behaviour should be a swappable seam rather than a hard-coded branch:

- `validation::CredentialValidator` decides whether a group member is who they claim to be. The default
  is `PinnedIdentityValidator`. **Caveat:** `Session::validator()` currently constructs the default
  directly, so a custom validator is a trait to implement but not yet something a `Session` accepts.
  Making it injectable (and exposing it through the bridge) is the next step for this seam.
- The MLS provider (`RaindropProvider`) and the store are separate types behind `Session`, so a storage
  or crypto backend can change without touching the group logic.

## Testing

`cargo test` runs 31 unit tests (store, certificates, backup, link, root, pairing, attachments), 27 camera-effects
tests in `crates/raindrop_video/tests/effects.rs` (four of them only with the segmentation model
present) plus two in `blur.rs` over its reciprocal division, and 16 integration tests in
`crates/raindrop_crypto/tests/session.rs`, which drive several devices, each with its own encrypted
store on disk, exchanging the bytes a delivery service would carry. Add multi-device behaviour there.
The client has Dart tests that load the built library, and an integration test against a live server;
see [`docs/testing.md`](docs/testing.md).
