# Flutter bridge

`raindrop_crypto_ffi` is the only way anything outside this workspace reaches `raindrop_crypto`. It is a
thin layer: plain data in and out, one error type Dart can switch on, and a mutex so the one session per
server can be shared across the isolate's calls (flutter_rust_bridge runs them on a thread pool). Code:
`crates/raindrop_crypto_ffi/src/api/session.rs` (hand-written) and `src/frb_generated.rs` (generated —
never edit it).

It also carries the [camera effects](video-effects.md), which are not crypto and not a session: one
Flutter plugin, one cargokit build and one library for both cores. Those have **three** surfaces rather
than one, because frames must not cross this bridge — `api/video.rs` over flutter_rust_bridge for
control, `c_api.rs` as plain C for Apple's capture pipeline, and `jni_api.rs` for Android's. See
[Camera effects → The three surfaces](video-effects.md#the-three-surfaces); the rest of this file is
about the encryption core.

## `CryptoSession`

`#[frb(opaque)] pub struct CryptoSession { inner: Mutex<Session> }` wraps one `raindrop_crypto::Session`.
`open(path, key)` builds it; every other method locks the mutex, calls the matching `Session` method, and
converts the result. A panic while the lock is held does not poison future calls — `session()` recovers
the guard from a `PoisonError` rather than propagating it, since a panic mid-call leaves nothing
half-written that SQLite's own transactions did not already roll back.

The method surface mirrors `Session` one-for-one; see [Architecture overview](architecture-overview.md#how-a-session-is-used)
for what each group does. Two free functions sit outside `CryptoSession`: `safety_number` and
`backup_needs_passphrase`, both `#[frb(sync)]` since neither touches the store.

`api/attachment.rs` holds the [attachment](attachments.md) functions, also free-standing because a
file's key is its own rather than the session's: `encrypt_attachment_file`, `decrypt_attachment_file`,
`encrypt_attachment_bytes`, `decrypt_attachment_bytes` (async, on the bridge's thread pool, since they do
file and crypto work) and `attachment_ciphertext_length` (`sync`). They return the flat
`SealedAttachment { key, ciphertext_sha256, ciphertext_length }` and `SealedAttachmentBytes { sealed,
ciphertext }`.

## Why the bridge types are flat

The generated Dart avoids `freezed`, so there is no `build_runner` step in the client. That means bridge
types cannot be data-carrying enums (`enum Foo { A(x), B(y) }`); instead they are **plain structs with a
`kind` discriminant** and optional fields, and the Dart facade (`MlsCryptoEngine` in the client) turns
them into sealed classes for the rest of the app to match on.

| Type | `kind` field | Payload |
|---|---|---|
| `CryptoFailure` | `CryptoFailureKind` | `message`, and `user_id` when `kind` is `IdentityChanged` |
| `ProcessedMessage` | `ProcessedKind` | `sender`/`payload` for `Application`, `added`/`removed`/`removed_self` for `Commit`; `epoch` on both |

Keep this shape for new bridge types: a `kind` enum plus fields that are meaningful only for some of its
values, documented per-field like the two above, rather than a Rust enum with data.

## Errors

`CryptoFailure { kind: CryptoFailureKind, message: String, user_id: Option<String> }` is built with
`From<CryptoError>`:

| `CryptoError` | `CryptoFailureKind` | `user_id` |
|---|---|---|
| `StoreLocked` | `StoreLocked` | — |
| `IdentityChanged { user_id }` | `IdentityChanged` | set |
| `BackupLocked` | `BackupLocked` | — |
| `Verification(_)` | `Verification` | — |
| `NotFound(_)` | `NotFound` | — |
| `Malformed(_)` | `Malformed` | — |
| `Store(_)`, `Io(_)`, `Mls(_)` | `Other` | — |

`message` is always `error.to_string()` — for logs, never for the UI to parse (same rule as
`CryptoError` itself). The client's `CryptoEngine` turns this into `CryptoException` with a
`CryptoErrorKind`; see its [crypto doc](../../RaindropClient/docs/crypto.md#the-dart-api).

## Building and regenerating

- **The Rust crate is compiled by the client**, not built standalone for the app: `RaindropClient/native/
  raindrop_crypto_builder` (cargokit) compiles `raindrop_crypto_ffi` at `flutter build` / `flutter run`
  time, on every platform the client targets. `cargo build -p raindrop_crypto_ffi` in this repo is only
  for running the Dart bridge test directly (see [Testing & building](testing.md)).
- **After changing anything under `src/api/`, regenerate the Dart bindings** from `RaindropClient/`
  (`flutter_rust_bridge.yaml` lives there and points `rust_root` back at this crate):

  ```bash
  flutter_rust_bridge_codegen generate
  ```

- **The version pin.** `flutter_rust_bridge` must be exactly **2.13.0** in three places at once: this
  crate's `Cargo.toml` (`=2.13.0`), `RaindropClient/pubspec.yaml`, and the installed
  `flutter_rust_bridge_codegen`. A mismatch is a build error, not a subtle bug, so keep the three moving
  together.
- `#[flutter_rust_bridge::frb(init)]` on `api::init_app` (called once from Dart) runs
  `setup_default_user_utils()`; nothing in this crate depends on Flutter beyond that.
